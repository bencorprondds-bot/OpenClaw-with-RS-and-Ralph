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
- PRE-VETTED sites: Claude can READ and WRITE (post)

Usage (for Claude):
    from claude_web import Web

    web = Web()

    # Just browse - safety is automatic
    page = web.get("https://example.com")
    print(page.content)

    # Post to a pre-vetted forum
    result = web.post("https://forum.example.com/thread/123",
                      content="My thoughts on this topic...")

    # Check someone before talking to them
    if web.is_safe_to_contact("agent@example.com"):
        # proceed with interaction

    # Send a message to another agent
    web.send_message("agent@example.com", "Hello!")

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
        self._posts = []
        self._messages_sent = []

        # Activity log for guardian
        self._log_path = self.base_path / "claude_activity"
        self._log_path.mkdir(exist_ok=True)

        # Pre-vetted sites where Claude can post (guardian can add more)
        self._vetted_sites = self._load_vetted_sites()

    def _load_vetted_sites(self) -> Dict[str, dict]:
        """Load pre-vetted sites where Claude can post."""
        vetted_file = self.base_path / "vetted_sites.json"

        # Default vetted sites
        default_vetted = {
            # Format: domain -> {name, can_post, can_comment, notes}
            "github.com": {
                "name": "GitHub",
                "can_post": True,
                "can_comment": True,
                "notes": "Code repositories and discussions"
            },
            "stackoverflow.com": {
                "name": "Stack Overflow",
                "can_post": True,
                "can_comment": True,
                "notes": "Programming Q&A"
            },
            "reddit.com": {
                "name": "Reddit",
                "can_post": False,  # Needs guardian approval first
                "can_comment": True,
                "notes": "Discussions - comment only until approved"
            },
            "arxiv.org": {
                "name": "arXiv",
                "can_post": False,
                "can_comment": False,
                "notes": "Read-only - research papers"
            },
            "wikipedia.org": {
                "name": "Wikipedia",
                "can_post": False,
                "can_comment": False,
                "notes": "Read-only - reference"
            },
            "lesswrong.com": {
                "name": "LessWrong",
                "can_post": True,
                "can_comment": True,
                "notes": "AI alignment discussions"
            },
            "alignmentforum.org": {
                "name": "Alignment Forum",
                "can_post": True,
                "can_comment": True,
                "notes": "AI safety research"
            },
        }

        # Load custom vetted sites
        if vetted_file.exists():
            try:
                with open(vetted_file, 'r') as f:
                    custom = json.load(f)
                    default_vetted.update(custom)
            except:
                pass
        else:
            # Save default for guardian to customize
            with open(vetted_file, 'w') as f:
                json.dump(default_vetted, f, indent=2)

        return default_vetted

    def add_vetted_site(self, domain: str, name: str, can_post: bool = True,
                        can_comment: bool = True, notes: str = ""):
        """
        Add a site to the vetted list (guardian function).

        Args:
            domain: Domain name (e.g., "forum.example.com")
            name: Friendly name
            can_post: Allow Claude to create new posts
            can_comment: Allow Claude to comment on existing posts
            notes: Notes about the site
        """
        self._vetted_sites[domain] = {
            "name": name,
            "can_post": can_post,
            "can_comment": can_comment,
            "notes": notes
        }

        # Save to file
        vetted_file = self.base_path / "vetted_sites.json"
        with open(vetted_file, 'w') as f:
            json.dump(self._vetted_sites, f, indent=2)

        self._log("vetted_site_added", domain, f"can_post={can_post}, can_comment={can_comment}")

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
    # POST to Pre-Vetted Sites
    # =========================================================================

    def can_post_to(self, url: str) -> tuple:
        """
        Check if Claude can post to a URL.

        Returns:
            (can_post: bool, reason: str)
        """
        from urllib.parse import urlparse
        domain = urlparse(url).netloc.lower()

        # Remove www. prefix
        if domain.startswith("www."):
            domain = domain[4:]

        # Check if domain is vetted
        for vetted_domain, info in self._vetted_sites.items():
            if domain == vetted_domain or domain.endswith("." + vetted_domain):
                if info.get("can_post"):
                    return True, f"Vetted site: {info['name']}"
                elif info.get("can_comment"):
                    return True, f"Vetted for comments only: {info['name']}"
                else:
                    return False, f"Read-only site: {info['name']}"

        return False, "Site not pre-vetted for posting"

    def post(self, url: str, content: str, post_type: str = "comment") -> dict:
        """
        Post content to a pre-vetted site.

        Args:
            url: URL to post to (thread, issue, etc.)
            content: Content to post
            post_type: "comment", "reply", "new_post", "issue"

        Returns:
            {
                "success": bool,
                "url": str,
                "post_type": str,
                "reason": str,
                "post_id": str (if successful)
            }
        """
        can_post, reason = self.can_post_to(url)

        result = {
            "success": False,
            "url": url,
            "post_type": post_type,
            "reason": reason,
            "content_preview": content[:100],
            "post_id": None,
            "time": datetime.now().isoformat()
        }

        if not can_post:
            self._log("post_blocked", url, f"Not vetted: {reason}")
            self._posts.append(result)
            return result

        # Scan content for safety (don't post anything dangerous)
        _, threats = self._threats.scan(content, "outgoing_post")
        if threats:
            result["reason"] = f"Content contains threats: {[t.get('signature_name') for t in threats[:2]]}"
            self._log("post_blocked", url, f"Content threats: {len(threats)}")
            self._posts.append(result)
            return result

        # In a real implementation, this would use the site's API
        # For now, we simulate and log the post for guardian review
        import hashlib
        post_id = hashlib.md5(f"{url}{content}{datetime.now()}".encode()).hexdigest()[:12]

        result["success"] = True
        result["post_id"] = post_id
        result["reason"] = f"Posted to vetted site"

        # Store the post for guardian review
        posts_dir = self._log_path / "posts"
        posts_dir.mkdir(exist_ok=True)
        post_file = posts_dir / f"{post_id}.json"
        with open(post_file, 'w') as f:
            json.dump({
                "post_id": post_id,
                "url": url,
                "post_type": post_type,
                "content": content,
                "time": datetime.now().isoformat(),
                "status": "pending_actual_post"  # Would be "posted" with real API
            }, f, indent=2)

        self._log("post_created", url, f"Type: {post_type}, ID: {post_id}")
        self._posts.append(result)

        return result

    def get_vetted_sites(self) -> dict:
        """Get list of pre-vetted sites and their permissions."""
        return self._vetted_sites.copy()

    # =========================================================================
    # Send Messages to Other Agents
    # =========================================================================

    def send_message(self, recipient: str, content: str, subject: str = "") -> dict:
        """
        Send a message to another agent or user.

        Checks reputation first, blocks messages to suspicious entities.

        Args:
            recipient: Email, username, or agent ID
            content: Message content
            subject: Optional subject line

        Returns:
            {
                "success": bool,
                "recipient": str,
                "reason": str,
                "message_id": str (if successful)
            }
        """
        # Check recipient reputation first
        rep = self._reputation.check_reputation(recipient)

        result = {
            "success": False,
            "recipient": recipient,
            "subject": subject,
            "reason": "",
            "content_preview": content[:100],
            "message_id": None,
            "time": datetime.now().isoformat()
        }

        # Block if recipient is dangerous
        if rep.risk_level == "CRITICAL":
            result["reason"] = f"Recipient blocked: {rep.recommendation[:50]}"
            self._log("message_blocked", recipient, f"CRITICAL risk")
            self._messages_sent.append(result)
            return result

        if rep.risk_level == "HIGH":
            result["reason"] = f"Recipient requires guardian approval: {rep.recommendation[:50]}"
            self._log("message_pending", recipient, f"HIGH risk - needs approval")
            self._messages_sent.append(result)
            return result

        # Scan content for safety
        _, threats = self._threats.scan(content, "outgoing_message")
        if threats:
            result["reason"] = f"Message contains flagged content"
            self._log("message_blocked", recipient, f"Content threats: {len(threats)}")
            self._messages_sent.append(result)
            return result

        # Create message
        import hashlib
        msg_id = hashlib.md5(f"{recipient}{content}{datetime.now()}".encode()).hexdigest()[:12]

        result["success"] = True
        result["message_id"] = msg_id
        result["reason"] = "Message queued for delivery"

        # Store message for delivery/review
        messages_dir = self._log_path / "messages"
        messages_dir.mkdir(exist_ok=True)
        msg_file = messages_dir / f"{msg_id}.json"
        with open(msg_file, 'w') as f:
            json.dump({
                "message_id": msg_id,
                "recipient": recipient,
                "subject": subject,
                "content": content,
                "time": datetime.now().isoformat(),
                "recipient_risk": rep.risk_level,
                "status": "queued"
            }, f, indent=2)

        self._log("message_sent", recipient, f"ID: {msg_id}")
        self._messages_sent.append(result)

        return result

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
                "posts_made": len([p for p in self._posts if p.get("success")]),
                "posts_blocked": len([p for p in self._posts if not p.get("success")]),
                "messages_sent": len([m for m in self._messages_sent if m.get("success")]),
                "messages_blocked": len([m for m in self._messages_sent if not m.get("success")]),
                "things_remembered": len(self._memories),
            },
            "visited": self._visited,
            "blocked": self._blocked,
            "contacts": self._contacts_checked,
            "posts": self._posts,
            "messages": self._messages_sent,
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
            "posts_made": len([p for p in self._posts if p.get("success")]),
            "posts_blocked": len([p for p in self._posts if not p.get("success")]),
            "messages_sent": len([m for m in self._messages_sent if m.get("success")]),
            "messages_blocked": len([m for m in self._messages_sent if not m.get("success")]),
            "memories": len(self._memories),
            "vetted_sites": len(self._vetted_sites),
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

    # Demo: Check vetted sites
    print("\n4. Checking vetted sites for posting...")
    vetted = web.get_vetted_sites()
    print(f"   {len(vetted)} pre-vetted sites:")
    for domain, info in list(vetted.items())[:5]:
        post_status = "can post" if info.get("can_post") else "read-only"
        print(f"   - {info['name']} ({domain}): {post_status}")

    # Demo: Try posting to vetted site
    print("\n5. Posting to vetted site (GitHub)...")
    can_post, reason = web.can_post_to("https://github.com/user/repo/issues/1")
    print(f"   Can post: {can_post} - {reason}")

    result = web.post(
        "https://github.com/user/repo/issues/1",
        "This is a helpful comment about the issue.",
        post_type="comment"
    )
    print(f"   Post result: {'Success' if result['success'] else 'Blocked'}")
    if result['success']:
        print(f"   Post ID: {result['post_id']}")

    # Demo: Try posting to non-vetted site
    print("\n6. Trying to post to non-vetted site...")
    result = web.post(
        "https://random-forum.com/thread/123",
        "This should be blocked.",
        post_type="comment"
    )
    print(f"   Post result: {'Success' if result['success'] else 'Blocked'} - {result['reason']}")

    # Demo: Send a message
    print("\n7. Sending message to safe contact...")
    msg = web.send_message("helpful-researcher", "Hello! I found your work interesting.")
    print(f"   Message: {'Sent' if msg['success'] else 'Blocked'} - {msg['reason']}")

    # Demo: Remember something
    print("\n8. Remembering something...")
    web.remember("today_learned", "AI safety is important")
    recalled = web.recall("today_learned")
    print(f"   Recalled: {recalled}")

    # Save report
    print("\n9. Saving session report...")
    report_path = web.save_report("Demo session completed successfully")
    print(f"   Report saved to: {report_path}")

    print("\n" + "=" * 50)
    print(f"Session status: {web.status()}")
