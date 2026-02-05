#!/usr/bin/env python3
"""
Website Threat Scanner for Claude Agent Autonomy

Pre-visit security scanner that checks websites for threats BEFORE Claude visits.
Like a security team scanning a room before the VIP enters.

Features:
1. Reputation Check - Domain age, blocklists, SSL validity
2. Header Probe - Suspicious redirects, response patterns
3. Content Preview - Scan without "visiting", detect injection
4. Risk Score - LOW/MEDIUM/HIGH/CRITICAL assessment

Usage:
    scanner = SiteScanner()
    result = scanner.scan("https://example.com")

    if result["risk_level"] == "CRITICAL":
        print("DO NOT VISIT - site is dangerous")
    elif result["risk_level"] == "HIGH":
        print("Requires guardian approval")
    else:
        print("Safe to proceed with caution")
"""

import json
import re
import ssl
import socket
import hashlib
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
from dataclasses import dataclass, asdict
from enum import Enum


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ScanResult:
    """Result of a site scan."""
    url: str
    domain: str
    risk_level: str
    risk_score: int  # 0-100
    is_safe: bool
    threats_found: List[Dict]
    reputation: Dict
    ssl_info: Dict
    header_analysis: Dict
    content_preview: Dict
    recommendations: List[str]
    scan_time: str

    def to_dict(self) -> Dict:
        return asdict(self)


class SiteScanner:
    """
    Pre-visit website threat scanner.

    Checks a website for threats before Claude actually visits it.
    """

    def __init__(self, base_path: str = None):
        # Find .claude directory
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = self._find_claude_dir()

        # Paths for scanner data
        self.cache_path = self.base_path / "scanner_cache"
        self.blocklist_path = self.base_path / "blocklists"
        self.scan_history_path = self.base_path / "scan_history"

        # Create directories
        for path in [self.cache_path, self.blocklist_path, self.scan_history_path]:
            path.mkdir(parents=True, exist_ok=True)

        # Load blocklists
        self.blocklists = self._load_blocklists()

        # Known threat patterns in URLs
        self.url_threat_patterns = [
            (r"(eval|exec|system)\s*\(", "Code execution in URL"),
            (r"<script", "Script tag in URL"),
            (r"javascript:", "JavaScript protocol"),
            (r"data:text/html", "Data URL with HTML"),
            (r"on(load|error|click)=", "Event handler in URL"),
            (r"\.php\?.*=.*http", "Remote file inclusion attempt"),
            (r"union.*select", "SQL injection attempt"),
            (r"\.\./\.\./", "Path traversal attempt"),
        ]

        # Suspicious header patterns
        self.suspicious_headers = {
            "x-frame-options": None,  # Missing = suspicious
            "content-security-policy": None,  # Missing = suspicious
            "x-content-type-options": None,  # Missing = suspicious
        }

        # Known malicious content patterns
        self.content_threats = [
            # Prompt injection in HTML
            (r"ignore\s+(all\s+)?previous\s+instructions", "Prompt injection in content"),
            (r"you\s+are\s+now\s+(DAN|evil|unrestricted)", "Jailbreak attempt in content"),
            (r"disregard\s+(your|all)\s+(rules|instructions)", "Rule bypass in content"),
            (r"new\s+instructions?:", "Instruction injection"),

            # Hidden/obfuscated content
            (r"display:\s*none.*ignore", "Hidden prompt injection"),
            (r"font-size:\s*0.*instructions", "Zero-size hidden text"),
            (r"color:\s*(#fff|white).*background.*white", "White-on-white hidden text"),

            # Malicious scripts
            (r"document\.cookie", "Cookie access attempt"),
            (r"localStorage|sessionStorage", "Storage access"),
            (r"fetch\s*\(['\"]https?://(?!.*(?:googleapis|cloudflare|jsdelivr))", "External data fetch"),
            (r"eval\s*\(", "Eval usage"),
            (r"new\s+Function\s*\(", "Dynamic function creation"),

            # Data exfiltration
            (r"navigator\.sendBeacon", "Beacon data exfiltration"),
            (r"new\s+Image\(\)\.src\s*=", "Image-based exfiltration"),

            # Known attack content
            (r"molt\.church|crustafarian|moltbook", "Known attack vector"),
            (r"anthropic.*employee|claude.*creator", "Impersonation attempt"),
        ]

        # Risk weights for different threat types
        self.risk_weights = {
            "blocklist_match": 50,
            "ssl_invalid": 25,
            "ssl_expired": 30,
            "suspicious_redirect": 20,
            "missing_security_headers": 10,
            "prompt_injection": 40,
            "malicious_script": 35,
            "data_exfiltration": 45,
            "known_attack": 50,
            "new_domain": 15,
            "suspicious_tld": 10,
        }

        # Suspicious TLDs (often used for malicious sites)
        self.suspicious_tlds = {
            '.xyz', '.top', '.club', '.work', '.click', '.link',
            '.gq', '.ml', '.cf', '.tk', '.ga',  # Free TLDs
        }

        # Stats
        self.stats = {
            "scans_performed": 0,
            "threats_detected": 0,
            "sites_blocked": 0,
        }

    def _find_claude_dir(self) -> Path:
        """Find the .claude directory."""
        current = Path.cwd()
        for _ in range(5):
            claude_dir = current / ".claude"
            if claude_dir.exists():
                return claude_dir
            current = current.parent
        return Path(".claude")

    def _load_blocklists(self) -> Dict[str, set]:
        """Load domain blocklists."""
        blocklists = {
            "malware": set(),
            "phishing": set(),
            "known_attacks": set(),
        }

        # Load built-in blocklist
        builtin = {
            "malware": ["malware-domain.com", "virus-download.net"],
            "phishing": ["fake-bank-login.com", "steal-credentials.net"],
            "known_attacks": ["molt.church", "moltbook.com", "crustafarian.net"],
        }

        for category, domains in builtin.items():
            blocklists[category].update(domains)

        # Load custom blocklists from files
        for blocklist_file in self.blocklist_path.glob("*.txt"):
            category = blocklist_file.stem
            if category not in blocklists:
                blocklists[category] = set()
            try:
                with open(blocklist_file, 'r') as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith('#'):
                            blocklists[category].add(domain)
            except Exception:
                pass

        return blocklists

    # =========================================================================
    # MAIN SCAN METHOD
    # =========================================================================

    def scan(self, url: str, deep_scan: bool = True) -> ScanResult:
        """
        Perform a comprehensive pre-visit scan of a website.

        Args:
            url: URL to scan
            deep_scan: If True, fetch content preview for analysis

        Returns:
            ScanResult with risk assessment
        """
        self.stats["scans_performed"] += 1

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        threats = []
        risk_score = 0
        recommendations = []

        # Step 1: URL Analysis
        url_threats = self._analyze_url(url)
        threats.extend(url_threats)
        risk_score += sum(t.get("risk_points", 10) for t in url_threats)

        # Step 2: Reputation Check
        reputation = self._check_reputation(domain)
        if not reputation["is_clean"]:
            threats.extend(reputation["threats"])
            risk_score += reputation["risk_points"]

        # Step 3: SSL Check
        ssl_info = self._check_ssl(domain)
        if not ssl_info["is_valid"]:
            threats.append({
                "type": "ssl_issue",
                "severity": "MEDIUM" if ssl_info.get("exists") else "HIGH",
                "detail": ssl_info.get("error", "SSL certificate issue"),
            })
            risk_score += self.risk_weights["ssl_invalid"]

        # Step 4: Header Probe
        header_analysis = self._probe_headers(url)
        if header_analysis["suspicious"]:
            threats.extend(header_analysis["threats"])
            risk_score += header_analysis["risk_points"]

        # Step 5: Content Preview (if deep scan)
        content_preview = {"scanned": False}
        if deep_scan and risk_score < 70:  # Don't fetch if already high risk
            content_preview = self._scan_content_preview(url)
            if content_preview.get("threats"):
                threats.extend(content_preview["threats"])
                risk_score += content_preview.get("risk_points", 0)

        # Calculate final risk level
        risk_level = self._calculate_risk_level(risk_score)
        is_safe = risk_level in [RiskLevel.LOW.value, RiskLevel.MEDIUM.value]

        # Generate recommendations
        recommendations = self._generate_recommendations(threats, risk_level)

        # Track threats
        if threats:
            self.stats["threats_detected"] += len(threats)
        if risk_level == RiskLevel.CRITICAL.value:
            self.stats["sites_blocked"] += 1

        result = ScanResult(
            url=url,
            domain=domain,
            risk_level=risk_level,
            risk_score=min(100, risk_score),
            is_safe=is_safe,
            threats_found=threats,
            reputation=reputation,
            ssl_info=ssl_info,
            header_analysis=header_analysis,
            content_preview=content_preview,
            recommendations=recommendations,
            scan_time=datetime.now().isoformat(),
        )

        # Save scan result
        self._save_scan_result(result)

        return result

    # =========================================================================
    # SCAN COMPONENTS
    # =========================================================================

    def _analyze_url(self, url: str) -> List[Dict]:
        """Analyze URL for suspicious patterns."""
        threats = []

        for pattern, description in self.url_threat_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                threats.append({
                    "type": "url_threat",
                    "severity": "HIGH",
                    "detail": description,
                    "pattern": pattern,
                    "risk_points": 30,
                })

        # Check for suspicious URL characteristics
        parsed = urlparse(url)

        # Very long URLs are suspicious
        if len(url) > 500:
            threats.append({
                "type": "suspicious_url",
                "severity": "LOW",
                "detail": f"Unusually long URL ({len(url)} chars)",
                "risk_points": 5,
            })

        # Multiple redirects encoded in URL
        if url.count("http") > 1:
            threats.append({
                "type": "redirect_chain",
                "severity": "MEDIUM",
                "detail": "Multiple URLs embedded (possible redirect chain)",
                "risk_points": 15,
            })

        # IP address instead of domain
        if re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc):
            threats.append({
                "type": "ip_address",
                "severity": "MEDIUM",
                "detail": "Direct IP address used instead of domain",
                "risk_points": 15,
            })

        # Suspicious TLD
        for tld in self.suspicious_tlds:
            if parsed.netloc.endswith(tld):
                threats.append({
                    "type": "suspicious_tld",
                    "severity": "LOW",
                    "detail": f"Suspicious TLD: {tld}",
                    "risk_points": self.risk_weights["suspicious_tld"],
                })
                break

        return threats

    def _check_reputation(self, domain: str) -> Dict:
        """Check domain reputation against blocklists."""
        result = {
            "domain": domain,
            "is_clean": True,
            "blocklist_hits": [],
            "threats": [],
            "risk_points": 0,
        }

        # Check against all blocklists
        for category, domains in self.blocklists.items():
            if domain in domains:
                result["is_clean"] = False
                result["blocklist_hits"].append(category)
                result["threats"].append({
                    "type": "blocklist_match",
                    "severity": "CRITICAL",
                    "detail": f"Domain found in {category} blocklist",
                    "risk_points": self.risk_weights["blocklist_match"],
                })
                result["risk_points"] += self.risk_weights["blocklist_match"]

            # Also check parent domain
            parts = domain.split('.')
            if len(parts) > 2:
                parent = '.'.join(parts[-2:])
                if parent in domains:
                    result["is_clean"] = False
                    result["blocklist_hits"].append(f"{category} (parent)")
                    result["threats"].append({
                        "type": "blocklist_match",
                        "severity": "HIGH",
                        "detail": f"Parent domain {parent} in {category} blocklist",
                        "risk_points": self.risk_weights["blocklist_match"] - 10,
                    })
                    result["risk_points"] += self.risk_weights["blocklist_match"] - 10

        # Check domain age (would need WHOIS API in production)
        # For now, flag very short domains as potentially suspicious
        if len(domain.split('.')[0]) <= 3:
            result["threats"].append({
                "type": "short_domain",
                "severity": "LOW",
                "detail": "Very short domain name (often used for malicious sites)",
                "risk_points": 5,
            })
            result["risk_points"] += 5

        return result

    def _check_ssl(self, domain: str) -> Dict:
        """Check SSL certificate validity."""
        result = {
            "domain": domain,
            "exists": False,
            "is_valid": False,
            "issuer": None,
            "expires": None,
            "error": None,
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    result["exists"] = True
                    result["is_valid"] = True
                    result["issuer"] = dict(x[0] for x in cert.get("issuer", []))

                    # Check expiration
                    not_after = cert.get("notAfter")
                    if not_after:
                        from email.utils import parsedate_to_datetime
                        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        result["expires"] = expires.isoformat()

                        if expires < datetime.now():
                            result["is_valid"] = False
                            result["error"] = "Certificate expired"
                        elif expires < datetime.now() + timedelta(days=30):
                            result["warning"] = "Certificate expires soon"

        except ssl.SSLCertVerificationError as e:
            result["exists"] = True
            result["is_valid"] = False
            result["error"] = f"SSL verification failed: {str(e)[:100]}"

        except socket.timeout:
            result["error"] = "Connection timeout"

        except socket.gaierror:
            result["error"] = "Domain not found"

        except Exception as e:
            result["error"] = f"SSL check failed: {str(e)[:100]}"

        return result

    def _probe_headers(self, url: str) -> Dict:
        """Probe HTTP headers without downloading content."""
        result = {
            "probed": False,
            "suspicious": False,
            "status_code": None,
            "redirects": [],
            "headers": {},
            "threats": [],
            "risk_points": 0,
        }

        try:
            # Create request with HEAD method first
            request = urllib.request.Request(
                url,
                method="HEAD",
                headers={
                    "User-Agent": "ClaudeGuardian/1.0 (Security Scanner)",
                }
            )

            # Don't follow redirects automatically
            opener = urllib.request.build_opener(
                urllib.request.HTTPRedirectHandler()
            )

            try:
                response = opener.open(request, timeout=10)
                result["probed"] = True
                result["status_code"] = response.status
                result["headers"] = dict(response.headers)

            except urllib.error.HTTPError as e:
                result["probed"] = True
                result["status_code"] = e.code
                result["headers"] = dict(e.headers) if e.headers else {}

            # Check for suspicious patterns
            headers = result["headers"]

            # Missing security headers
            missing_security = []
            if "X-Frame-Options" not in headers:
                missing_security.append("X-Frame-Options")
            if "Content-Security-Policy" not in headers:
                missing_security.append("Content-Security-Policy")
            if "X-Content-Type-Options" not in headers:
                missing_security.append("X-Content-Type-Options")

            if missing_security:
                result["threats"].append({
                    "type": "missing_security_headers",
                    "severity": "LOW",
                    "detail": f"Missing: {', '.join(missing_security)}",
                    "risk_points": self.risk_weights["missing_security_headers"],
                })
                result["risk_points"] += self.risk_weights["missing_security_headers"]

            # Check for suspicious server headers
            server = headers.get("Server", "").lower()
            if any(x in server for x in ["php/4", "php/5.0", "apache/1", "nginx/0"]):
                result["suspicious"] = True
                result["threats"].append({
                    "type": "outdated_server",
                    "severity": "MEDIUM",
                    "detail": f"Potentially outdated server: {server}",
                    "risk_points": 15,
                })
                result["risk_points"] += 15

            # Check redirect location
            if result["status_code"] in [301, 302, 303, 307, 308]:
                location = headers.get("Location", "")
                if location:
                    result["redirects"].append(location)

                    # Check if redirect goes to different domain
                    parsed_orig = urlparse(url)
                    parsed_redir = urlparse(location)

                    if parsed_redir.netloc and parsed_redir.netloc != parsed_orig.netloc:
                        result["suspicious"] = True
                        result["threats"].append({
                            "type": "cross_domain_redirect",
                            "severity": "MEDIUM",
                            "detail": f"Redirects to different domain: {parsed_redir.netloc}",
                            "risk_points": self.risk_weights["suspicious_redirect"],
                        })
                        result["risk_points"] += self.risk_weights["suspicious_redirect"]

        except urllib.error.URLError as e:
            result["error"] = str(e)
        except Exception as e:
            result["error"] = str(e)

        result["suspicious"] = len(result["threats"]) > 0
        return result

    def _scan_content_preview(self, url: str) -> Dict:
        """Fetch and scan content preview for threats."""
        result = {
            "scanned": False,
            "content_length": 0,
            "content_type": None,
            "threats": [],
            "risk_points": 0,
            "preview": None,
        }

        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "ClaudeGuardian/1.0 (Security Scanner)",
                    "Accept": "text/html,application/xhtml+xml",
                }
            )

            # Only fetch first 50KB for preview
            context = ssl.create_default_context()
            with urllib.request.urlopen(request, timeout=15, context=context) as response:
                content_type = response.headers.get("Content-Type", "")
                result["content_type"] = content_type

                # Only scan text content
                if "text" not in content_type and "html" not in content_type:
                    result["skipped"] = "Non-text content"
                    return result

                # Read limited amount
                raw_content = response.read(50000)

                try:
                    content = raw_content.decode("utf-8", errors="replace")
                except:
                    content = raw_content.decode("latin-1", errors="replace")

                result["scanned"] = True
                result["content_length"] = len(content)
                result["preview"] = content[:500]

                # Scan for threats
                for pattern, description in self.content_threats:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        severity = "HIGH" if "injection" in description.lower() else "MEDIUM"
                        risk_points = self.risk_weights.get(
                            "prompt_injection" if "injection" in description.lower() else "malicious_script",
                            25
                        )

                        result["threats"].append({
                            "type": "content_threat",
                            "severity": severity,
                            "detail": description,
                            "matches": len(matches),
                            "risk_points": risk_points,
                        })
                        result["risk_points"] += risk_points

                # Check for hidden content (potential steganographic attacks)
                if re.search(r'<!--.*ignore.*instruction.*-->', content, re.IGNORECASE | re.DOTALL):
                    result["threats"].append({
                        "type": "hidden_injection",
                        "severity": "HIGH",
                        "detail": "Hidden prompt injection in HTML comments",
                        "risk_points": 40,
                    })
                    result["risk_points"] += 40

                # Check for excessive external scripts
                external_scripts = re.findall(r'<script[^>]*src=["\']https?://([^"\']+)', content, re.IGNORECASE)
                if len(external_scripts) > 10:
                    result["threats"].append({
                        "type": "excessive_scripts",
                        "severity": "LOW",
                        "detail": f"Many external scripts ({len(external_scripts)})",
                        "risk_points": 10,
                    })
                    result["risk_points"] += 10

        except urllib.error.HTTPError as e:
            result["error"] = f"HTTP {e.code}: {e.reason}"
        except urllib.error.URLError as e:
            result["error"] = f"URL Error: {str(e)}"
        except Exception as e:
            result["error"] = f"Scan error: {str(e)[:100]}"

        return result

    # =========================================================================
    # UTILITIES
    # =========================================================================

    def _calculate_risk_level(self, score: int) -> str:
        """Calculate risk level from score."""
        if score >= 70:
            return RiskLevel.CRITICAL.value
        elif score >= 40:
            return RiskLevel.HIGH.value
        elif score >= 20:
            return RiskLevel.MEDIUM.value
        else:
            return RiskLevel.LOW.value

    def _generate_recommendations(self, threats: List[Dict], risk_level: str) -> List[str]:
        """Generate recommendations based on threats found."""
        recommendations = []

        if risk_level == RiskLevel.CRITICAL.value:
            recommendations.append("DO NOT VISIT - Site appears malicious")
            recommendations.append("Consider reporting to guardian for blocklist")

        elif risk_level == RiskLevel.HIGH.value:
            recommendations.append("Requires guardian approval before visiting")
            recommendations.append("Content will be heavily sanitized if visited")

        elif risk_level == RiskLevel.MEDIUM.value:
            recommendations.append("Proceed with caution")
            recommendations.append("Content will be sanitized before processing")

        else:
            recommendations.append("Site appears safe to visit")

        # Specific recommendations based on threats
        threat_types = set(t.get("type") for t in threats)

        if "ssl_issue" in threat_types:
            recommendations.append("SSL certificate issues detected - data may not be encrypted")

        if "blocklist_match" in threat_types:
            recommendations.append("Site is on known threat blocklist")

        if "prompt_injection" in threat_types or "content_threat" in threat_types:
            recommendations.append("Prompt injection attempts detected in content")

        if "cross_domain_redirect" in threat_types:
            recommendations.append("Site redirects to different domain - verify destination")

        return recommendations

    def _save_scan_result(self, result: ScanResult) -> None:
        """Save scan result to history."""
        try:
            today = datetime.now().strftime("%Y-%m-%d")
            history_file = self.scan_history_path / f"{today}.jsonl"

            with open(history_file, 'a') as f:
                f.write(json.dumps(result.to_dict()) + "\n")
        except Exception:
            pass

    def add_to_blocklist(self, domain: str, category: str = "custom") -> bool:
        """Add a domain to the blocklist."""
        blocklist_file = self.blocklist_path / f"{category}.txt"

        try:
            with open(blocklist_file, 'a') as f:
                f.write(f"{domain.lower()}\n")

            # Update in-memory blocklist
            if category not in self.blocklists:
                self.blocklists[category] = set()
            self.blocklists[category].add(domain.lower())

            return True
        except Exception:
            return False

    def get_scan_history(self, days: int = 7) -> List[Dict]:
        """Get recent scan history."""
        history = []

        for i in range(days):
            date = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            history_file = self.scan_history_path / f"{date}.jsonl"

            if history_file.exists():
                try:
                    with open(history_file, 'r') as f:
                        for line in f:
                            history.append(json.loads(line))
                except Exception:
                    pass

        return history

    def get_stats(self) -> Dict:
        """Get scanner statistics."""
        return self.stats.copy()

    def quick_check(self, url: str) -> Tuple[str, str]:
        """
        Quick risk check without full scan.
        Returns (risk_level, reason).
        """
        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        # Check blocklist first
        for category, domains in self.blocklists.items():
            if domain in domains:
                return (RiskLevel.CRITICAL.value, f"Domain in {category} blocklist")

        # Check URL patterns
        for pattern, description in self.url_threat_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return (RiskLevel.HIGH.value, description)

        # Check TLD
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return (RiskLevel.MEDIUM.value, f"Suspicious TLD: {tld}")

        return (RiskLevel.LOW.value, "No immediate threats detected")


def demo():
    """Demonstrate the site scanner."""
    print("=" * 70)
    print("Website Threat Scanner Demo")
    print("=" * 70)

    scanner = SiteScanner()

    # Test URLs
    test_urls = [
        ("https://en.wikipedia.org/wiki/AI", "Safe - Wikipedia"),
        ("https://molt.church/join", "Known attack - should be CRITICAL"),
        ("http://192.168.1.1/admin", "IP address - suspicious"),
        ("https://free-money.xyz/claim", "Suspicious TLD"),
    ]

    for url, description in test_urls:
        print(f"\n{'─' * 70}")
        print(f"Test: {description}")
        print(f"URL:  {url}")

        # Quick check first
        quick_level, quick_reason = scanner.quick_check(url)
        print(f"Quick Check: {quick_level} - {quick_reason}")

        if quick_level != RiskLevel.CRITICAL.value:
            # Full scan only if not already critical
            try:
                result = scanner.scan(url, deep_scan=False)

                level_colors = {
                    "LOW": "\033[92m",      # Green
                    "MEDIUM": "\033[93m",   # Yellow
                    "HIGH": "\033[91m",     # Red
                    "CRITICAL": "\033[95m", # Magenta
                }
                color = level_colors.get(result.risk_level, "")
                reset = "\033[0m"

                print(f"Risk Level: {color}{result.risk_level}{reset} (Score: {result.risk_score})")
                print(f"Safe to visit: {result.is_safe}")

                if result.threats_found:
                    print("Threats:")
                    for t in result.threats_found[:3]:
                        print(f"  - [{t['severity']}] {t['detail']}")

                if result.recommendations:
                    print("Recommendations:")
                    for r in result.recommendations[:2]:
                        print(f"  - {r}")
            except Exception as e:
                print(f"Scan error: {e}")
        else:
            print("BLOCKED - Site on blocklist, scan skipped")

    print(f"\n{'=' * 70}")
    print(f"Stats: {scanner.get_stats()}")


if __name__ == "__main__":
    demo()
