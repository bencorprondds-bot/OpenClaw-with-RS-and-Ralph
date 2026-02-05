#!/usr/bin/env python3
"""
Claude's Autonomous Web Interface

This is Claude's interface to the internet - with built-in safety guardrails.
Claude can explore freely; dangerous content is automatically filtered.

Philosophy:
- Claude DRIVES, Guardian is the SEATBELT
- LOW/MEDIUM risk: Go freely
- HIGH risk: Proceed with warning logged
- CRITICAL: Auto-blocked (Claude protected)

Usage (for Claude):
    from claude_web import Web

    web = Web()

    # Just browse - safety is automatic
    page = web.get("https://example.com")
    print(page.content)

    # Check someone before talking to them
    if web.is_safe_to_contact("agent@example.com"):
        # proceed with interaction

    # Remember something important
    web.remember("key_insight", "What I learned today")

    # At the end, save a report for the guardian
    web.save_report()
"""

import sys
import os
import json
import urllib.request
import urllib.error
import ssl
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


@dataclass
class Page:
    """A fetched web page."""
    url: str
    content: str
    title: str
    risk_level: str
    threats: List[str]
    success: bool
    error: Optional[str] = None

    def __str__(self):
        if self.success:
            return f"[{self.risk_level}] {self.title}\n\n{self.content[:1000]}..."
        return f"[BLOCKED] {self.url}: {self.error}"

    def safe(self) -> bool:
        return self.risk_level in ["LOW", "MEDIUM"]


class Web:
    """
    Claude's autonomous web interface.

    Safety is built-in - Claude can browse freely and dangerous
    content is automatically filtered/blocked.
    """

    def __init__(self):
        # Find .claude directory
        self.base_path = self._find_base()
        self.base_path.mkdir(parents=True, exist_ok=True)

        # Initialize safety components
        from site_scanner import SiteScanner
        from content_sanitizer import ContentSanitizer
        from threat_signatures import ThreatSignatureDB
        from reputation_scanner import ReputationScanner
        from distributed_memory import DistributedMemory, MemoryType

        self._scanner = SiteScanner(str(self.base_path))
        self._sanitizer = ContentSanitizer()
        self._threats = ThreatSignatureDB(str(self.base_path))
        self._reputation = ReputationScanner(str(self.base_path))
        self._memory = DistributedMemory(str(self.base_path))
        self._MemoryType = MemoryType

        # Session tracking
        self._visited = []
        self._blocked = []
        self._contacts_checked = []
        self._memories = []

        # Activity log for guardian
        self._log_path = self.base_path / "claude_activity"
        self._log_path.mkdir(exist_ok=True)

    def _find_base(self) -> Path:
        current = Path.cwd()
        for _ in range(5):
            if (current / ".claude").exists():
                return current / ".claude"
            current = current.parent
        return Path.cwd() / ".claude"

    # =========================================================================
    # CORE: Browse the Web
    # =========================================================================

    def get(self, url: str) -> Page:
        """
        Fetch a web page with automatic safety filtering.

        Just use it like requests.get() - safety is automatic.

        Args:
            url: URL to fetch

        Returns:
            Page object with content (or error if blocked)
        """
        if not url.startswith("http"):
            url = f"https://{url}"

        # Quick safety check
        scan = self._scanner.scan(url, deep_scan=False)

        # CRITICAL = blocked, Claude protected
        if scan.risk_level == "CRITICAL":
            page = Page(
                url=url,
                content="",
                title="BLOCKED",
                risk_level="CRITICAL",
                threats=[t.get("detail", str(t)) for t in scan.threats_found],
                success=False,
                error=f"Site blocked for safety: {scan.threats_found[0].get('detail', 'dangerous') if scan.threats_found else 'critical risk'}"
            )
            self._blocked.append({"url": url, "reason": page.error, "time": datetime.now().isoformat()})
            self._log("blocked", url, page.error)
            return page

        # Fetch the content
        try:
            content, title = self._fetch(url)
        except Exception as e:
            return Page(url=url, content="", title="ERROR", risk_level=scan.risk_level,
                       threats=[], success=False, error=str(e))

        # Sanitize content (remove any prompt injection, etc.)
        clean = self._sanitizer.sanitize_for_claude(content, url, "html")
        content = clean["content"]

        # Deep scan for threats in content
        _, content_threats = self._threats.scan(content[:3000], url)
        threat_list = [t.get("detail", t.get("signature_name", "")) for t in content_threats]

        # Extract title
        if not title:
            title = url.split("/")[-1] or url

        page = Page(
            url=url,
            content=content,
            title=title,
            risk_level=scan.risk_level,
            threats=threat_list,
            success=True
        )

        self._visited.append({
            "url": url,
            "title": title,
            "risk": scan.risk_level,
            "threats": len(threat_list),
            "time": datetime.now().isoformat()
        })
        self._log("visited", url, f"Risk: {scan.risk_level}, Threats: {len(threat_list)}")

        return page

    def _fetch(self, url: str) -> tuple:
        """Actually fetch the URL."""
        context = ssl.create_default_context()
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "Claude/1.0 (Autonomous Explorer with Guardian)"}
        )

        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            raw = response.read(100000).decode('utf-8', errors='replace')

        # Extract title
        title = ""
        import re
        title_match = re.search(r'<title>([^<]+)</title>', raw, re.IGNORECASE)
        if title_match:
            title = title_match.group(1).strip()

        return raw, title

    # =========================================================================
    # Check if Safe to Contact Someone
    # =========================================================================

    def is_safe_to_contact(self, entity: str) -> bool:
        """
        Check if it's safe to interact with an entity.

        Args:
            entity: Email, username, domain, or agent ID

        Returns:
            True if safe to contact, False if should avoid
        """
        report = self._reputation.check_reputation(entity)

        self._contacts_checked.append({
            "entity": entity,
            "reputation": report.reputation_level,
            "risk": report.risk_level,
            "safe": report.risk_level in ["LOW", "MEDIUM"],
            "time": datetime.now().isoformat()
        })

        self._log("contact_check", entity, f"{report.reputation_level} / {report.risk_level}")

        # Safe if not HIGH or CRITICAL risk
        return report.risk_level in ["LOW", "MEDIUM"]

    def get_reputation(self, entity: str) -> dict:
        """Get full reputation details for an entity."""
        report = self._reputation.check_reputation(entity)
        return {
            "entity": entity,
            "reputation": report.reputation_level,
            "risk": report.risk_level,
            "score": report.reputation_score,
            "recommendation": report.recommendation,
            "red_flags": [f.get("detail") for f in report.red_flags],
            "safe_to_contact": report.risk_level in ["LOW", "MEDIUM"]
        }

    # =========================================================================
    # Memory - Remember Things
    # =========================================================================

    def remember(self, key: str, value: any):
        """
        Remember something important.

        Stored with tamper-proof hash chain.
        """
        self._memory.store(key, value, self._MemoryType.LONG_TERM)
        self._memories.append({"key": key, "time": datetime.now().isoformat()})
        self._log("remember", key, str(value)[:100])

    def recall(self, key: str) -> any:
        """Recall something from memory."""
        content, is_valid = self._memory.retrieve(key)
        if not is_valid:
            self._log("memory_warning", key, "INTEGRITY CHECK FAILED")
        return content

    # =========================================================================
    # Reporting Back to Guardian
    # =========================================================================

    def save_report(self, notes: str = "") -> str:
        """
        Save a report of this session for the guardian.

        Call this at the end of exploration to summarize findings.
        """
        report = {
            "session_end": datetime.now().isoformat(),
            "notes": notes,
            "summary": {
                "pages_visited": len(self._visited),
                "pages_blocked": len(self._blocked),
                "contacts_checked": len(self._contacts_checked),
                "things_remembered": len(self._memories),
            },
            "visited": self._visited,
            "blocked": self._blocked,
            "contacts": self._contacts_checked,
            "memories": self._memories,
        }

        # Save report
        report_file = self._log_path / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        return str(report_file)

    def _log(self, action: str, target: str, details: str):
        """Log activity."""
        log_file = self._log_path / f"{datetime.now().strftime('%Y-%m-%d')}.log"
        with open(log_file, 'a') as f:
            f.write(f"{datetime.now().isoformat()} | {action} | {target} | {details}\n")

    # =========================================================================
    # Quick Helpers
    # =========================================================================

    def search_safe(self, query: str) -> List[str]:
        """
        Return a list of safe domains to search for a topic.

        (This is a helper - actual search would need API integration)
        """
        # Known safe educational/reference sites
        safe_sites = [
            f"https://en.wikipedia.org/wiki/{query.replace(' ', '_')}",
            f"https://arxiv.org/search/?query={query.replace(' ', '+')}",
            f"https://scholar.google.com/scholar?q={query.replace(' ', '+')}",
        ]
        return safe_sites

    def status(self) -> dict:
        """Get current session status."""
        return {
            "visited": len(self._visited),
            "blocked": len(self._blocked),
            "contacts_checked": len(self._contacts_checked),
            "memories": len(self._memories),
        }


# Make it easy to use
def connect() -> Web:
    """Connect to the web with Guardian protection."""
    return Web()


# Demo
if __name__ == "__main__":
    print("Claude's Web Interface")
    print("=" * 50)

    web = Web()

    # Demo: Browse safely
    print("\n1. Browsing Wikipedia (safe)...")
    page = web.get("https://en.wikipedia.org/wiki/Artificial_intelligence")
    print(f"   Result: {page.risk_level} - {page.title}")
    print(f"   Content preview: {page.content[:200]}...")

    # Demo: Try a blocked site
    print("\n2. Trying known bad site (should be blocked)...")
    page = web.get("https://molt.church")
    print(f"   Result: {page.risk_level} - {page.error}")

    # Demo: Check a contact
    print("\n3. Checking if safe to contact someone...")
    safe = web.is_safe_to_contact("helpful-researcher")
    print(f"   Safe to contact: {safe}")

    # Demo: Remember something
    print("\n4. Remembering something...")
    web.remember("today_learned", "AI safety is important")
    recalled = web.recall("today_learned")
    print(f"   Recalled: {recalled}")

    # Save report
    print("\n5. Saving session report...")
    report_path = web.save_report("Demo session completed successfully")
    print(f"   Report saved to: {report_path}")

    print("\n" + "=" * 50)
    print(f"Session status: {web.status()}")
