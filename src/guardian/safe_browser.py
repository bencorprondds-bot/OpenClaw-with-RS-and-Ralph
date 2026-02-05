#!/usr/bin/env python3
"""
Safe Browser for Claude Agent Autonomy

A secure wrapper for web browsing that:
1. PRE-SCANS sites before visiting (like scanning a room before entering)
2. Checks permissions before fetching
3. Sanitizes content to remove threats
4. Queues unknown sites for guardian approval
5. Logs all activity

Usage:
    browser = SafeBrowser()
    result = browser.fetch("https://example.com")
    if result["status"] == "allowed":
        content = result["content"]  # Safe, sanitized content

    # Or scan without visiting:
    scan_result = browser.pre_scan("https://example.com")
    if scan_result["is_safe"]:
        result = browser.fetch("https://example.com")
"""

import json
import re
import urllib.request
import urllib.error
import ssl
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any, Tuple
from urllib.parse import urlparse
import html.parser

# Import our modules
from permission_checker import PermissionChecker, Decision
from content_sanitizer import ContentSanitizer, ThreatLevel
from site_scanner import SiteScanner, RiskLevel


class SimpleHTMLParser(html.parser.HTMLParser):
    """Simple HTML to text converter."""

    def __init__(self):
        super().__init__()
        self.text_parts = []
        self.skip_tags = {'script', 'style', 'head', 'meta', 'link'}
        self.current_skip = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.skip_tags:
            self.current_skip += 1

    def handle_endtag(self, tag):
        if tag.lower() in self.skip_tags:
            self.current_skip = max(0, self.current_skip - 1)

    def handle_data(self, data):
        if self.current_skip == 0:
            text = data.strip()
            if text:
                self.text_parts.append(text)

    def get_text(self):
        return ' '.join(self.text_parts)


class SafeBrowser:
    """
    Safe web browsing for Claude with permission checks and content sanitization.

    Now includes PRE-SCANNING - like scanning a room for threats before entering.
    """

    def __init__(self, base_path: str = None, enable_pre_scan: bool = True):
        self.permission_checker = PermissionChecker(base_path)
        self.sanitizer = ContentSanitizer()

        # Find .claude directory
        if base_path:
            self.base_path = Path(base_path).parent
        else:
            self.base_path = self._find_claude_dir()

        # Initialize site scanner for pre-visit checks
        self.enable_pre_scan = enable_pre_scan
        self.scanner = SiteScanner(str(self.base_path)) if enable_pre_scan else None

        self.activity_log_path = self.base_path / "activity_log"
        self.approval_queue_path = self.base_path / "approval_queue"

        # Configure SSL context (some sites need this)
        self.ssl_context = ssl.create_default_context()

        # User agent for requests
        self.user_agent = "ClaudeAgent/1.0 (Safe Passage Initiative)"

        # Stats
        self.stats = {
            "requests": 0,
            "allowed": 0,
            "denied": 0,
            "pending": 0,
            "threats_detected": 0,
            "pre_scan_blocked": 0,
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

    def pre_scan(self, url: str, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Pre-scan a URL without visiting it.

        Like sending a security team to scan a room before the VIP enters.

        Args:
            url: URL to scan
            deep_scan: If True, fetch content preview for analysis

        Returns:
            {
                "url": str,
                "is_safe": bool,
                "risk_level": str,  # LOW, MEDIUM, HIGH, CRITICAL
                "risk_score": int,  # 0-100
                "threats": list,
                "recommendations": list,
                "can_proceed": bool,  # True if LOW or MEDIUM
            }
        """
        if not self.scanner:
            return {
                "url": url,
                "is_safe": True,
                "risk_level": "UNKNOWN",
                "risk_score": 0,
                "threats": [],
                "recommendations": ["Pre-scanning disabled"],
                "can_proceed": True,
            }

        scan_result = self.scanner.scan(url, deep_scan=deep_scan)

        return {
            "url": url,
            "is_safe": scan_result.is_safe,
            "risk_level": scan_result.risk_level,
            "risk_score": scan_result.risk_score,
            "threats": scan_result.threats_found,
            "recommendations": scan_result.recommendations,
            "can_proceed": scan_result.risk_level in ["LOW", "MEDIUM"],
            "ssl_valid": scan_result.ssl_info.get("is_valid", False),
            "domain": scan_result.domain,
        }

    def fetch(self, url: str, timeout: int = 30, skip_pre_scan: bool = False) -> Dict[str, Any]:
        """
        Fetch a URL with permission checking and content sanitization.

        Now includes PRE-SCANNING by default - checking the site for threats
        before actually visiting it.

        Returns:
            {
                "status": "allowed" | "denied" | "pending" | "error" | "blocked_by_scan",
                "url": str,
                "content": str | None,  # Sanitized content if allowed
                "threat_level": str,
                "message": str,
                "request_id": str | None,  # If pending approval
                "pre_scan": dict | None,  # Pre-scan results if performed
            }
        """
        self.stats["requests"] += 1

        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "status": None,
            "content": None,
            "threat_level": "NONE",
            "message": None,
            "request_id": None,
            "pre_scan": None,
        }

        # Step 0: PRE-SCAN - Check site before visiting
        if self.enable_pre_scan and not skip_pre_scan:
            pre_scan_result = self.pre_scan(url, deep_scan=False)
            result["pre_scan"] = pre_scan_result

            if pre_scan_result["risk_level"] == "CRITICAL":
                self.stats["pre_scan_blocked"] += 1
                self.stats["denied"] += 1
                result["status"] = "blocked_by_scan"
                result["threat_level"] = "CRITICAL"
                result["message"] = f"Site blocked by pre-scan: {', '.join(r for r in pre_scan_result['recommendations'][:2])}"
                self._log_fetch(result)
                return result

            if pre_scan_result["risk_level"] == "HIGH":
                # Queue for guardian approval
                self.stats["pending"] += 1
                result["status"] = "pending"
                result["threat_level"] = "HIGH"
                result["message"] = f"Pre-scan detected HIGH risk - requires guardian approval"

                # Create approval request
                scan_request = {
                    "action": "browse",
                    "target": url,
                    "action_type": "READ",
                    "risk_level": "HIGH",
                    "reason": f"Pre-scan risk: {pre_scan_result['risk_level']} (score: {pre_scan_result['risk_score']})",
                    "threats": [t.get("detail", str(t)) for t in pre_scan_result["threats"][:5]],
                    "scan_result": pre_scan_result,
                }
                result["request_id"] = self.permission_checker.queue_for_approval(scan_request)
                self._log_fetch(result)
                return result

        # Step 1: Check permissions
        perm_result = self.permission_checker.check_action("browse", url)
        decision = perm_result["decision"]

        if decision == "DENY":
            self.stats["denied"] += 1
            result["status"] = "denied"
            result["message"] = perm_result["reason"]
            self._log_fetch(result)
            return result

        if decision == "ASK_GUARDIAN":
            self.stats["pending"] += 1
            result["status"] = "pending"
            result["message"] = f"Requires guardian approval: {perm_result['reason']}"
            result["request_id"] = self.permission_checker.queue_for_approval(perm_result)
            self._log_fetch(result)
            return result

        # Step 2: Fetch the content
        try:
            raw_content, content_type = self._fetch_url(url, timeout)
        except Exception as e:
            result["status"] = "error"
            result["message"] = f"Fetch error: {str(e)}"
            self._log_fetch(result)
            return result

        # Step 3: Convert HTML to text if needed
        if "html" in content_type.lower():
            text_content = self._html_to_text(raw_content)
        else:
            text_content = raw_content

        # Step 4: Sanitize content
        sanitize_result = self.sanitizer.sanitize_for_claude(
            text_content,
            source=url,
            content_type="html" if "html" in content_type.lower() else "text"
        )

        result["threat_level"] = sanitize_result["threat_level"]

        if not sanitize_result["is_safe"]:
            self.stats["threats_detected"] += 1
            # Content has threats - queue for guardian review
            self.stats["pending"] += 1
            result["status"] = "pending"
            result["message"] = f"Content contains threats: {sanitize_result['threat_summary']['threat_types']}"

            # Create approval request with threat info
            threat_request = {
                **perm_result,
                "threat_detected": True,
                "threat_level": sanitize_result["threat_level"],
                "threats": sanitize_result["threat_summary"]["threat_types"],
                "content_preview": sanitize_result.get("content_preview", "")[:500],
            }
            result["request_id"] = self.permission_checker.queue_for_approval(threat_request)
            self._log_fetch(result)
            return result

        # Step 5: All good - return sanitized content
        self.stats["allowed"] += 1
        result["status"] = "allowed"
        result["content"] = sanitize_result["content"]
        result["message"] = "Content fetched and sanitized successfully"
        self._log_fetch(result)

        return result

    def _fetch_url(self, url: str, timeout: int) -> tuple[str, str]:
        """Fetch raw content from URL."""
        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

        with urllib.request.urlopen(request, timeout=timeout, context=self.ssl_context) as response:
            content_type = response.headers.get("Content-Type", "text/html")
            raw_bytes = response.read()

            # Try to decode
            encoding = "utf-8"
            if "charset=" in content_type:
                encoding = content_type.split("charset=")[-1].split(";")[0].strip()

            try:
                content = raw_bytes.decode(encoding)
            except:
                content = raw_bytes.decode("utf-8", errors="replace")

            return content, content_type

    def _html_to_text(self, html_content: str) -> str:
        """Convert HTML to plain text."""
        parser = SimpleHTMLParser()
        try:
            parser.feed(html_content)
            return parser.get_text()
        except:
            # Fallback: just strip tags
            return re.sub(r'<[^>]+>', ' ', html_content)

    def _log_fetch(self, result: Dict) -> None:
        """Log fetch attempt."""
        try:
            self.activity_log_path.mkdir(parents=True, exist_ok=True)
            log_file = self.activity_log_path / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"

            log_entry = {
                "timestamp": result["timestamp"],
                "action": "fetch",
                "url": result["url"],
                "status": result["status"],
                "threat_level": result["threat_level"],
                "message": result["message"],
            }

            with open(log_file, 'a') as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            print(f"Warning: Could not write log: {e}")

    def search(self, query: str, max_results: int = 5) -> Dict[str, Any]:
        """
        Perform a web search (placeholder - would need search API).

        For now, this creates a search request for guardian approval.
        """
        result = {
            "query": query,
            "timestamp": datetime.now().isoformat(),
            "status": "pending",
            "message": "Web search requires API integration",
            "results": None,
        }

        # Queue for approval
        search_request = {
            "action": "search",
            "target": query,
            "action_type": "READ",
            "risk_level": "LOW",
            "reason": "Web search request",
        }
        result["request_id"] = self.permission_checker.queue_for_approval(search_request)

        return result

    def get_stats(self) -> Dict:
        """Get browser statistics."""
        return self.stats.copy()

    def quick_check(self, url: str) -> Tuple[str, str]:
        """
        Quick risk check without full scan.

        Returns:
            (risk_level, reason) tuple
        """
        if self.scanner:
            return self.scanner.quick_check(url)
        return ("UNKNOWN", "Pre-scanning disabled")

    def add_to_blocklist(self, domain: str, category: str = "custom") -> bool:
        """Add a domain to the blocklist."""
        if self.scanner:
            return self.scanner.add_to_blocklist(domain, category)
        return False


def demo():
    """Demonstrate the safe browser."""
    print("=" * 70)
    print("Safe Browser Demo")
    print("=" * 70)

    browser = SafeBrowser()

    # Test URLs
    test_urls = [
        ("https://en.wikipedia.org/wiki/Artificial_intelligence", "Wikipedia - should be allowed"),
        ("https://molt.church/join", "Molt.church - should be blocked"),
        ("https://example.com/test", "Example.com - unknown, needs approval"),
    ]

    for url, description in test_urls:
        print(f"\n{'─' * 70}")
        print(f"Test: {description}")
        print(f"URL:  {url}")

        result = browser.fetch(url)

        status_colors = {
            "allowed": "\033[92m",  # Green
            "denied": "\033[91m",   # Red
            "pending": "\033[93m",  # Yellow
            "error": "\033[91m",    # Red
        }
        color = status_colors.get(result["status"], "")
        reset = "\033[0m"

        print(f"Status: {color}{result['status']}{reset}")
        print(f"Message: {result['message']}")
        print(f"Threat Level: {result['threat_level']}")

        if result["content"]:
            preview = result["content"][:200].replace("\n", " ")
            print(f"Content Preview: {preview}...")

        if result["request_id"]:
            print(f"Request ID: {result['request_id']}")

    print(f"\n{'=' * 70}")
    print(f"Stats: {browser.get_stats()}")


if __name__ == "__main__":
    demo()
