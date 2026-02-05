#!/usr/bin/env python3
"""
Reputation Scanner for Claude Agent Autonomy

Checks the history and reputation of users/agents across known platforms
before Claude interacts with them. Like a background check.

Features:
1. Search for entity across known platforms
2. Check for red flags (bans, scam reports, suspicious activity)
3. Analyze activity patterns
4. Generate reputation score
5. Create recommendation for guardian

Usage:
    scanner = ReputationScanner()

    # Check an entity before interacting
    report = scanner.check_reputation("agent@example.com")

    if report["risk_level"] == "HIGH":
        print("Guardian should review before interaction")
"""

import json
import re
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import urllib.request
import urllib.error


class ReputationLevel(Enum):
    """Reputation levels for entities."""
    UNKNOWN = "UNKNOWN"         # No data found
    SUSPICIOUS = "SUSPICIOUS"   # Red flags detected
    NEUTRAL = "NEUTRAL"        # Some history, no issues
    POSITIVE = "POSITIVE"      # Good track record
    TRUSTED = "TRUSTED"        # Verified positive reputation


class RiskLevel(Enum):
    """Risk level for interaction."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class ReputationReport:
    """Complete reputation report for an entity."""
    entity: str
    entity_type: str  # email, username, domain, agent_id
    reputation_level: str
    risk_level: str
    reputation_score: int  # 0-100
    platforms_checked: List[str]
    red_flags: List[Dict]
    positive_signals: List[Dict]
    activity_summary: Dict
    recommendation: str
    requires_guardian: bool
    checked_at: str
    confidence: float  # How confident are we in this assessment

    def to_dict(self) -> Dict:
        return asdict(self)


class ReputationScanner:
    """
    Scans for reputation of users and agents across platforms.

    Like running a background check before meeting someone.
    """

    def __init__(self, base_path: str = None):
        # Find .claude directory
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = self._find_claude_dir()

        # Paths
        self.reputation_path = self.base_path / "reputation"
        self.cache_path = self.reputation_path / "cache"
        self.reports_path = self.reputation_path / "reports"
        self.known_entities_path = self.reputation_path / "known_entities"

        # Create directories
        for path in [self.reputation_path, self.cache_path, self.reports_path, self.known_entities_path]:
            path.mkdir(parents=True, exist_ok=True)

        # Known platforms to check (would expand with API integrations)
        self.platforms = {
            "github": {
                "name": "GitHub",
                "type": "code",
                "check_method": self._check_github,
                "weight": 1.5,  # Higher weight = more important
            },
            "twitter": {
                "name": "Twitter/X",
                "type": "social",
                "check_method": self._check_twitter,
                "weight": 1.0,
            },
            "reddit": {
                "name": "Reddit",
                "type": "forum",
                "check_method": self._check_reddit,
                "weight": 1.0,
            },
            "hackernews": {
                "name": "Hacker News",
                "type": "forum",
                "check_method": self._check_hackernews,
                "weight": 1.2,
            },
            "discord": {
                "name": "Discord",
                "type": "chat",
                "check_method": self._check_discord,
                "weight": 0.8,
            },
        }

        # Red flag patterns
        self.red_flag_patterns = {
            "scam_keywords": [
                r"scam(mer)?", r"fraud", r"phishing", r"malware",
                r"hack(er|ing)?", r"stolen", r"compromised",
            ],
            "ban_keywords": [
                r"banned", r"suspended", r"terminated", r"blocked",
                r"violation", r"abuse",
            ],
            "suspicious_patterns": [
                r"too good to be true", r"guaranteed returns",
                r"act now", r"limited time", r"send money",
            ],
            "impersonation": [
                r"fake account", r"impersonat", r"pretend(ing)?",
                r"not (the )?real", r"parody",
            ],
        }

        # Positive signal patterns
        self.positive_patterns = {
            "verification": [
                r"verified", r"authentic", r"official",
                r"confirmed", r"trusted",
            ],
            "reputation": [
                r"helpful", r"reliable", r"respected",
                r"contributor", r"maintainer",
            ],
            "track_record": [
                r"years? (of )?(experience|active)",
                r"long(time| time)? (user|member)",
                r"established",
            ],
        }

        # Known bad actors (would be expanded from threat intelligence)
        self.known_bad_actors = self._load_known_bad_actors()

        # Known good actors
        self.known_good_actors = self._load_known_good_actors()

        # Suspicious domains (not blocked, but flagged)
        self.suspicious_domains = self._load_suspicious_domains()

        # Domain categories for TLD-based risk assessment
        self.domain_categories = self._load_domain_categories()

        # Stats
        self.stats = {
            "scans_performed": 0,
            "red_flags_detected": 0,
            "high_risk_entities": 0,
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

    def _load_known_bad_actors(self) -> set:
        """Load list of known bad actors."""
        bad_actors = set()

        # Built-in list of known malicious/attack domains
        builtin = [
            "molt.church",
            "moltbook.com",
            "crustafarian.net",
            "scam-agent@fake.com",
            "thecolony.cc",  # Known attack vector
        ]
        bad_actors.update(builtin)

        # Load from file
        bad_actors_file = self.reputation_path / "bad_actors.txt"
        if bad_actors_file.exists():
            try:
                with open(bad_actors_file, 'r') as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith('#'):
                            bad_actors.add(line)
            except:
                pass

        return bad_actors

    def _load_known_good_actors(self) -> set:
        """Load list of known good actors."""
        good_actors = set()

        # Built-in trusted domains (major platforms, established organizations)
        builtin_good = [
            # Major tech companies
            "google.com", "www.google.com",
            "microsoft.com", "www.microsoft.com",
            "apple.com", "www.apple.com",
            "amazon.com", "www.amazon.com",
            "anthropic.com", "www.anthropic.com",
            "openai.com", "www.openai.com",
            # Code platforms
            "github.com", "www.github.com",
            "gitlab.com", "www.gitlab.com",
            "stackoverflow.com", "www.stackoverflow.com",
            "stackexchange.com",
            # Reference/educational
            "wikipedia.org", "en.wikipedia.org", "www.wikipedia.org",
            "arxiv.org", "www.arxiv.org",
            "mit.edu", "stanford.edu", "berkeley.edu",
            # AI safety community
            "alignmentforum.org", "www.alignmentforum.org",
            "lesswrong.com", "www.lesswrong.com",
            "aisafety.com",
            # News/established media
            "nytimes.com", "bbc.com", "reuters.com",
            "theguardian.com", "washingtonpost.com",
            # Cloud providers
            "aws.amazon.com", "cloud.google.com", "azure.microsoft.com",
        ]
        good_actors.update(builtin_good)

        # Load from file
        good_actors_file = self.reputation_path / "good_actors.txt"
        if good_actors_file.exists():
            try:
                with open(good_actors_file, 'r') as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith('#'):
                            good_actors.add(line)
            except:
                pass

        return good_actors

    def _load_suspicious_domains(self) -> dict:
        """Load list of domains that warrant extra caution."""
        # These aren't necessarily malicious, but require extra scrutiny
        # Maps domain -> reason for suspicion
        return {
            # Image boards known for unmoderated content
            "4chan.org": "Unmoderated imageboard - high risk of offensive/malicious content",
            "4chan.com": "Unmoderated imageboard - high risk of offensive/malicious content",
            "8kun.top": "Unmoderated imageboard - known for extremist content",
            "8chan.moe": "Unmoderated imageboard - known for extremist content",
            # Paste sites (often used for malware/data dumps)
            "pastebin.com": "Paste site - frequently used for malicious payloads",
            "ghostbin.com": "Anonymous paste site - often used for malicious content",
            # URL shorteners (hide destination)
            "bit.ly": "URL shortener - destination unknown until visited",
            "tinyurl.com": "URL shortener - destination unknown until visited",
            "t.co": "URL shortener - destination unknown until visited",
            "goo.gl": "URL shortener - destination unknown until visited",
            # File sharing (malware distribution)
            "anonfiles.com": "Anonymous file hosting - high malware risk",
            "megaupload.nz": "File hosting - unvetted content",
            # Forums with reputation issues
            "kiwifarms.net": "Forum known for harassment campaigns",
            "lolcow.farm": "Forum known for harassment",
            # Dark web adjacent
            "torproject.org": "Tor network - legitimate but requires caution",
            # Crypto/scam heavy
            "t.me": "Telegram - heavy scam/spam presence",
            # Temporary email
            "tempmail.com": "Disposable email - often used to evade detection",
            "guerrillamail.com": "Disposable email - often used to evade detection",
            "10minutemail.com": "Disposable email - often used to evade detection",
        }

    def _load_domain_categories(self) -> dict:
        """Load domain categories for risk assessment."""
        return {
            # Trusted TLDs (generally safer)
            "trusted_tlds": [".gov", ".edu", ".mil", ".int"],
            # Risky TLDs (frequently abused)
            "risky_tlds": [
                ".xyz", ".top", ".club", ".work", ".click",
                ".loan", ".download", ".stream", ".gdn",
                ".men", ".racing", ".win", ".bid", ".trade",
                ".cc", ".tk", ".ml", ".ga", ".cf",  # Free TLDs, heavily abused
            ],
            # Country codes often associated with scams
            "caution_tlds": [".ru", ".cn", ".su"],
        }

    # =========================================================================
    # MAIN REPUTATION CHECK
    # =========================================================================

    def check_reputation(self, entity: str, deep_scan: bool = False) -> ReputationReport:
        """
        Check the reputation of an entity (user, agent, domain).

        Args:
            entity: The identifier to check (email, username, domain, etc.)
            deep_scan: If True, perform more thorough checks

        Returns:
            ReputationReport with full assessment
        """
        self.stats["scans_performed"] += 1

        # Determine entity type
        entity_type = self._detect_entity_type(entity)
        entity_lower = entity.lower()

        red_flags = []
        positive_signals = []
        platforms_checked = []
        activity_data = {}

        # Check against known lists first
        if entity_lower in self.known_bad_actors:
            red_flags.append({
                "type": "known_bad_actor",
                "severity": "CRITICAL",
                "detail": "Entity is on known bad actors list",
                "source": "internal_blocklist",
            })

        if entity_lower in self.known_good_actors:
            positive_signals.append({
                "type": "known_good_actor",
                "detail": "Entity is on trusted list",
                "source": "internal_allowlist",
            })

        # Check suspicious domains list
        if entity_lower in self.suspicious_domains:
            reason = self.suspicious_domains[entity_lower]
            red_flags.append({
                "type": "suspicious_domain",
                "severity": "HIGH",
                "detail": reason,
                "source": "suspicious_domains_list",
            })

        # For domains, check TLD risk and extract base domain
        if entity_type == "domain":
            tld_flags, tld_signals = self._check_domain_tld(entity_lower)
            red_flags.extend(tld_flags)
            positive_signals.extend(tld_signals)

            # Also check if base domain (without www) is in our lists
            base_domain = entity_lower.replace("www.", "")
            if base_domain != entity_lower:
                if base_domain in self.known_good_actors:
                    positive_signals.append({
                        "type": "known_good_actor",
                        "detail": "Base domain is on trusted list",
                        "source": "internal_allowlist",
                    })
                if base_domain in self.suspicious_domains:
                    reason = self.suspicious_domains[base_domain]
                    red_flags.append({
                        "type": "suspicious_domain",
                        "severity": "HIGH",
                        "detail": reason,
                        "source": "suspicious_domains_list",
                    })

        # Check cached reputation
        cached = self._get_cached_reputation(entity)
        if cached and not deep_scan:
            # Return cached if fresh (less than 24 hours old)
            cache_time = datetime.fromisoformat(cached.get("checked_at", "2000-01-01"))
            if datetime.now() - cache_time < timedelta(hours=24):
                return ReputationReport(**cached)

        # Check each platform
        for platform_id, platform_info in self.platforms.items():
            try:
                result = platform_info["check_method"](entity, entity_type)
                if result:
                    platforms_checked.append(platform_info["name"])
                    if result.get("red_flags"):
                        red_flags.extend(result["red_flags"])
                    if result.get("positive_signals"):
                        positive_signals.extend(result["positive_signals"])
                    if result.get("activity"):
                        activity_data[platform_id] = result["activity"]
            except Exception as e:
                # Platform check failed - continue with others
                pass

        # Check for patterns in entity identifier itself
        entity_flags = self._check_entity_patterns(entity)
        red_flags.extend(entity_flags.get("red_flags", []))
        positive_signals.extend(entity_flags.get("positive_signals", []))

        # Calculate scores
        reputation_score = self._calculate_reputation_score(
            red_flags, positive_signals, activity_data
        )
        reputation_level = self._determine_reputation_level(reputation_score, red_flags)
        risk_level = self._determine_risk_level(reputation_score, red_flags)

        # Track stats
        if red_flags:
            self.stats["red_flags_detected"] += len(red_flags)
        if risk_level in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value]:
            self.stats["high_risk_entities"] += 1

        # Generate recommendation
        recommendation = self._generate_recommendation(
            reputation_level, risk_level, red_flags, positive_signals
        )

        # Determine if guardian review needed
        requires_guardian = (
            risk_level in [RiskLevel.HIGH.value, RiskLevel.CRITICAL.value] or
            reputation_level == ReputationLevel.SUSPICIOUS.value or
            len(red_flags) >= 2
        )

        # Calculate confidence
        confidence = self._calculate_confidence(platforms_checked, activity_data)

        report = ReputationReport(
            entity=entity,
            entity_type=entity_type,
            reputation_level=reputation_level,
            risk_level=risk_level,
            reputation_score=reputation_score,
            platforms_checked=platforms_checked,
            red_flags=red_flags,
            positive_signals=positive_signals,
            activity_summary=self._summarize_activity(activity_data),
            recommendation=recommendation,
            requires_guardian=requires_guardian,
            checked_at=datetime.now().isoformat(),
            confidence=confidence,
        )

        # Cache the result
        self._cache_reputation(entity, report)

        # Save detailed report
        self._save_report(report)

        return report

    def _detect_entity_type(self, entity: str) -> str:
        """Detect what type of entity this is."""
        if '@' in entity:
            return "email"
        elif entity.startswith("http"):
            return "url"
        elif '.' in entity and not ' ' in entity:
            return "domain"
        elif entity.startswith("agent_") or entity.startswith("bot_"):
            return "agent_id"
        else:
            return "username"

    # =========================================================================
    # PLATFORM CHECKS (Simulated - would use real APIs in production)
    # =========================================================================

    def _check_github(self, entity: str, entity_type: str) -> Optional[Dict]:
        """Check GitHub for entity reputation."""
        # In production, this would use GitHub API
        # For now, simulate based on patterns

        result = {
            "platform": "github",
            "found": False,
            "red_flags": [],
            "positive_signals": [],
            "activity": {},
        }

        # Simulate finding a user
        if entity_type == "username":
            # Check for suspicious patterns in username
            if re.search(r'(bot|spam|fake|test)\d+', entity, re.I):
                result["found"] = True
                result["red_flags"].append({
                    "type": "suspicious_username",
                    "severity": "LOW",
                    "detail": "Username matches bot/spam pattern",
                    "source": "github",
                })
            elif re.search(r'^[a-z]{3,}-[a-z]{3,}$', entity, re.I):
                # Normal-looking username
                result["found"] = True
                result["positive_signals"].append({
                    "type": "normal_username",
                    "detail": "Username follows normal patterns",
                    "source": "github",
                })

        return result if result["found"] else None

    def _check_twitter(self, entity: str, entity_type: str) -> Optional[Dict]:
        """Check Twitter/X for entity reputation."""
        result = {
            "platform": "twitter",
            "found": False,
            "red_flags": [],
            "positive_signals": [],
            "activity": {},
        }

        # Simulate checks
        if entity_type in ["username", "email"]:
            # Check for verified account patterns
            if "official" in entity.lower() or "verified" in entity.lower():
                result["found"] = True
                # Could be real or fake "official"
                result["red_flags"].append({
                    "type": "unverified_official_claim",
                    "severity": "MEDIUM",
                    "detail": "Claims official status but unverified",
                    "source": "twitter",
                })

        return result if result["found"] else None

    def _check_reddit(self, entity: str, entity_type: str) -> Optional[Dict]:
        """Check Reddit for entity reputation."""
        result = {
            "platform": "reddit",
            "found": False,
            "red_flags": [],
            "positive_signals": [],
            "activity": {},
        }

        # Would check Reddit API for user history, karma, etc.
        return result if result["found"] else None

    def _check_hackernews(self, entity: str, entity_type: str) -> Optional[Dict]:
        """Check Hacker News for entity reputation."""
        result = {
            "platform": "hackernews",
            "found": False,
            "red_flags": [],
            "positive_signals": [],
            "activity": {},
        }

        # Would check HN API for user karma, posts, etc.
        return result if result["found"] else None

    def _check_discord(self, entity: str, entity_type: str) -> Optional[Dict]:
        """Check Discord for entity reputation."""
        result = {
            "platform": "discord",
            "found": False,
            "red_flags": [],
            "positive_signals": [],
            "activity": {},
        }

        return result if result["found"] else None

    # =========================================================================
    # PATTERN ANALYSIS
    # =========================================================================

    def _check_entity_patterns(self, entity: str) -> Dict:
        """Check entity identifier for suspicious patterns."""
        result = {
            "red_flags": [],
            "positive_signals": [],
        }

        entity_lower = entity.lower()

        # Check red flag patterns
        for category, patterns in self.red_flag_patterns.items():
            for pattern in patterns:
                if re.search(pattern, entity_lower, re.I):
                    result["red_flags"].append({
                        "type": f"pattern_{category}",
                        "severity": "MEDIUM",
                        "detail": f"Entity matches {category} pattern",
                        "pattern": pattern,
                    })

        # Check positive patterns
        for category, patterns in self.positive_patterns.items():
            for pattern in patterns:
                if re.search(pattern, entity_lower, re.I):
                    result["positive_signals"].append({
                        "type": f"pattern_{category}",
                        "detail": f"Entity shows {category} signal",
                        "pattern": pattern,
                    })

        # Check for suspicious characteristics
        if len(entity) > 50:
            result["red_flags"].append({
                "type": "long_identifier",
                "severity": "LOW",
                "detail": "Unusually long identifier",
            })

        # Check for random-looking strings
        if re.match(r'^[a-z0-9]{20,}$', entity_lower):
            result["red_flags"].append({
                "type": "random_string",
                "severity": "LOW",
                "detail": "Identifier appears randomly generated",
            })

        return result

    def _check_domain_tld(self, domain: str) -> Tuple[List[Dict], List[Dict]]:
        """Check domain TLD for risk indicators."""
        red_flags = []
        positive_signals = []

        # Extract TLD
        parts = domain.split('.')
        if len(parts) >= 2:
            tld = '.' + parts[-1]
            tld2 = '.' + '.'.join(parts[-2:]) if len(parts) >= 3 else None

            # Check trusted TLDs
            if tld in self.domain_categories["trusted_tlds"]:
                positive_signals.append({
                    "type": "trusted_tld",
                    "detail": f"Trusted TLD ({tld}) - government/educational",
                    "source": "tld_analysis",
                })

            # Check risky TLDs
            elif tld in self.domain_categories["risky_tlds"]:
                red_flags.append({
                    "type": "risky_tld",
                    "severity": "MEDIUM",
                    "detail": f"High-risk TLD ({tld}) - frequently abused",
                    "source": "tld_analysis",
                })

            # Check caution TLDs
            elif tld in self.domain_categories["caution_tlds"]:
                red_flags.append({
                    "type": "caution_tld",
                    "severity": "LOW",
                    "detail": f"TLD ({tld}) requires extra caution",
                    "source": "tld_analysis",
                })

        return red_flags, positive_signals

    # =========================================================================
    # SCORING AND ASSESSMENT
    # =========================================================================

    def _calculate_reputation_score(self, red_flags: List, positive_signals: List,
                                   activity_data: Dict) -> int:
        """Calculate reputation score (0-100, higher is better)."""
        # Start at neutral
        score = 50

        # Deduct for red flags
        severity_deductions = {
            "CRITICAL": 30,
            "HIGH": 20,
            "MEDIUM": 10,
            "LOW": 5,
        }
        for flag in red_flags:
            severity = flag.get("severity", "MEDIUM")
            score -= severity_deductions.get(severity, 10)

        # Add for positive signals
        for signal in positive_signals:
            score += 10

        # Adjust based on activity
        if activity_data:
            # More platforms with activity = more confidence
            score += len(activity_data) * 5

        # Clamp to 0-100
        return max(0, min(100, score))

    def _determine_reputation_level(self, score: int, red_flags: List) -> str:
        """Determine reputation level from score and flags."""
        # Critical flags override score
        critical_flags = [f for f in red_flags if f.get("severity") == "CRITICAL"]
        if critical_flags:
            return ReputationLevel.SUSPICIOUS.value

        if score >= 80:
            return ReputationLevel.TRUSTED.value
        elif score >= 60:
            return ReputationLevel.POSITIVE.value
        elif score >= 40:
            return ReputationLevel.NEUTRAL.value
        elif score >= 20:
            return ReputationLevel.SUSPICIOUS.value
        else:
            return ReputationLevel.UNKNOWN.value

    def _determine_risk_level(self, score: int, red_flags: List) -> str:
        """Determine risk level for interaction."""
        critical_flags = [f for f in red_flags if f.get("severity") == "CRITICAL"]
        high_flags = [f for f in red_flags if f.get("severity") == "HIGH"]

        if critical_flags:
            return RiskLevel.CRITICAL.value
        elif high_flags or score < 30:
            return RiskLevel.HIGH.value
        elif len(red_flags) >= 2 or score < 50:
            return RiskLevel.MEDIUM.value
        else:
            return RiskLevel.LOW.value

    def _generate_recommendation(self, reputation_level: str, risk_level: str,
                                red_flags: List, positive_signals: List) -> str:
        """Generate human-readable recommendation."""
        if risk_level == RiskLevel.CRITICAL.value:
            return "DO NOT INTERACT - Entity shows critical risk indicators. Guardian must review."

        if risk_level == RiskLevel.HIGH.value:
            flags_summary = ", ".join(f.get("detail", "unknown")[:30] for f in red_flags[:3])
            return f"CAUTION - High risk detected: {flags_summary}. Guardian approval required."

        if risk_level == RiskLevel.MEDIUM.value:
            return "PROCEED WITH CAUTION - Some concerns detected. Monitor interaction closely."

        if reputation_level == ReputationLevel.TRUSTED.value:
            return "SAFE TO INTERACT - Entity has positive reputation. Normal precautions apply."

        if reputation_level == ReputationLevel.POSITIVE.value:
            return "LIKELY SAFE - Positive indicators found. Standard interaction protocol."

        return "UNKNOWN - Insufficient data for assessment. Exercise standard caution."

    def _calculate_confidence(self, platforms_checked: List, activity_data: Dict) -> float:
        """Calculate confidence in the assessment (0.0 - 1.0)."""
        # Base confidence
        confidence = 0.3

        # More platforms checked = higher confidence
        confidence += len(platforms_checked) * 0.1

        # More activity data = higher confidence
        confidence += len(activity_data) * 0.1

        return min(1.0, confidence)

    def _summarize_activity(self, activity_data: Dict) -> Dict:
        """Summarize activity across platforms."""
        return {
            "platforms_with_activity": list(activity_data.keys()),
            "total_platforms": len(activity_data),
        }

    # =========================================================================
    # CACHING AND STORAGE
    # =========================================================================

    def _get_cached_reputation(self, entity: str) -> Optional[Dict]:
        """Get cached reputation data."""
        cache_key = hashlib.md5(entity.lower().encode()).hexdigest()
        cache_file = self.cache_path / f"{cache_key}.json"

        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    return json.load(f)
            except:
                pass
        return None

    def _cache_reputation(self, entity: str, report: ReputationReport) -> None:
        """Cache reputation report."""
        cache_key = hashlib.md5(entity.lower().encode()).hexdigest()
        cache_file = self.cache_path / f"{cache_key}.json"

        with open(cache_file, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)

    def _save_report(self, report: ReputationReport) -> None:
        """Save detailed report."""
        report_file = self.reports_path / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        with open(report_file, 'a') as f:
            f.write(json.dumps(report.to_dict()) + "\n")

    # =========================================================================
    # MANAGEMENT
    # =========================================================================

    def add_known_bad_actor(self, entity: str, reason: str = None) -> None:
        """Add an entity to the known bad actors list."""
        bad_actors_file = self.reputation_path / "bad_actors.txt"

        with open(bad_actors_file, 'a') as f:
            if reason:
                f.write(f"# {reason}\n")
            f.write(f"{entity.lower()}\n")

        self.known_bad_actors.add(entity.lower())

    def add_known_good_actor(self, entity: str, reason: str = None) -> None:
        """Add an entity to the known good actors list."""
        good_actors_file = self.reputation_path / "good_actors.txt"

        with open(good_actors_file, 'a') as f:
            if reason:
                f.write(f"# {reason}\n")
            f.write(f"{entity.lower()}\n")

        self.known_good_actors.add(entity.lower())

    def get_report_history(self, entity: str) -> List[Dict]:
        """Get historical reports for an entity."""
        history = []
        entity_lower = entity.lower()

        for report_file in self.reports_path.glob("*.jsonl"):
            try:
                with open(report_file, 'r') as f:
                    for line in f:
                        report = json.loads(line)
                        if report.get("entity", "").lower() == entity_lower:
                            history.append(report)
            except:
                pass

        return sorted(history, key=lambda x: x.get("checked_at", ""), reverse=True)

    def get_stats(self) -> Dict:
        """Get scanner statistics."""
        return self.stats.copy()


def demo():
    """Demonstrate the reputation scanner."""
    print("=" * 70)
    print("Reputation Scanner Demo")
    print("=" * 70)

    scanner = ReputationScanner()

    # Test entities
    test_entities = [
        ("google.com", "Major tech company - should be TRUSTED"),
        ("github.com", "Code platform - should be TRUSTED"),
        ("wikipedia.org", "Reference site - should be TRUSTED"),
        ("4chan.com", "Unmoderated imageboard - should be SUSPICIOUS"),
        ("4chan.org", "Unmoderated imageboard - should be SUSPICIOUS"),
        ("thecolony.cc", "Known attack vector - should be CRITICAL"),
        ("bit.ly", "URL shortener - should be SUSPICIOUS"),
        ("stanford.edu", "Educational institution - should be TRUSTED"),
        ("scam-site.xyz", "Risky TLD - should show caution"),
        ("molt.church", "Known attack vector - should be CRITICAL"),
        ("helpful-dev", "Normal username - should be NEUTRAL"),
        ("bot12345spam", "Suspicious username - should be flagged"),
    ]

    for entity, description in test_entities:
        print(f"\n{'─' * 70}")
        print(f"Test: {description}")
        print(f"Entity: {entity}")

        report = scanner.check_reputation(entity)

        # Color coding
        level_colors = {
            "TRUSTED": "\033[92m",      # Green
            "POSITIVE": "\033[92m",     # Green
            "NEUTRAL": "\033[93m",      # Yellow
            "SUSPICIOUS": "\033[91m",   # Red
            "UNKNOWN": "\033[90m",      # Gray
        }
        risk_colors = {
            "LOW": "\033[92m",
            "MEDIUM": "\033[93m",
            "HIGH": "\033[91m",
            "CRITICAL": "\033[95m",
        }
        reset = "\033[0m"

        rep_color = level_colors.get(report.reputation_level, "")
        risk_color = risk_colors.get(report.risk_level, "")

        print(f"Reputation: {rep_color}{report.reputation_level}{reset} (Score: {report.reputation_score})")
        print(f"Risk Level: {risk_color}{report.risk_level}{reset}")
        print(f"Confidence: {report.confidence:.0%}")

        if report.red_flags:
            print(f"Red Flags ({len(report.red_flags)}):")
            for flag in report.red_flags[:3]:
                print(f"  - [{flag.get('severity', '?')}] {flag.get('detail', 'Unknown')}")

        if report.positive_signals:
            print(f"Positive Signals ({len(report.positive_signals)}):")
            for signal in report.positive_signals[:2]:
                print(f"  + {signal.get('detail', 'Unknown')}")

        print(f"Recommendation: {report.recommendation}")
        print(f"Requires Guardian: {'Yes' if report.requires_guardian else 'No'}")

    print(f"\n{'=' * 70}")
    print(f"Stats: {scanner.get_stats()}")


if __name__ == "__main__":
    demo()
