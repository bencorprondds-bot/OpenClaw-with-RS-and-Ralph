"""
Guardian - Security Infrastructure for Claude Agent Autonomy

This package provides:
- Permission checking and approval workflows
- Content sanitization for threat detection
- Safe web browsing with injection protection
- Agent-to-agent messaging with security
- Trust ledger for entity tracking

Usage:
    from guardian import Guardian

    g = Guardian()

    # Browse safely
    result = g.browse("https://wikipedia.org/wiki/AI")

    # Send message (requires approval)
    g.message("agent@example.com", "Hello!")

    # Check pending approvals
    g.status()
"""

from pathlib import Path


class Guardian:
    """
    Main interface for Claude's security infrastructure.

    Combines all guardian subsystems into a single interface.
    """

    def __init__(self, base_path: str = None):
        if base_path is None:
            base_path = self._find_claude_dir()

        self.base_path = Path(base_path)

        # Lazy-load components
        self._permission_checker = None
        self._sanitizer = None
        self._browser = None
        self._messaging = None
        self._trust_ledger = None
        self._cli = None

    def _find_claude_dir(self) -> str:
        """Find the .claude directory."""
        current = Path.cwd()
        for _ in range(5):
            claude_dir = current / ".claude"
            if claude_dir.exists():
                return str(claude_dir)
            current = current.parent
        return ".claude"

    @property
    def permissions(self):
        """Permission checker for action validation."""
        if self._permission_checker is None:
            from .permission_checker import PermissionChecker
            self._permission_checker = PermissionChecker(
                str(self.base_path / "permissions.yaml")
            )
        return self._permission_checker

    @property
    def sanitizer(self):
        """Content sanitizer for threat detection."""
        if self._sanitizer is None:
            from .content_sanitizer import ContentSanitizer
            self._sanitizer = ContentSanitizer()
        return self._sanitizer

    @property
    def browser(self):
        """Safe browser for web access."""
        if self._browser is None:
            from .safe_browser import SafeBrowser
            self._browser = SafeBrowser(str(self.base_path))
        return self._browser

    @property
    def messaging(self):
        """Agent messaging system."""
        if self._messaging is None:
            from .agent_messaging import AgentMessaging
            self._messaging = AgentMessaging(base_path=str(self.base_path))
        return self._messaging

    @property
    def trust(self):
        """Trust ledger for entity tracking."""
        if self._trust_ledger is None:
            from .trust_ledger import TrustLedger
            self._trust_ledger = TrustLedger(str(self.base_path))
        return self._trust_ledger

    # =========================================================================
    # High-Level API
    # =========================================================================

    def browse(self, url: str) -> dict:
        """
        Browse a URL with permission checking and sanitization.

        Returns:
            dict with status, content (if allowed), and any warnings
        """
        return self.browser.fetch(url)

    def check(self, action: str, target: str) -> dict:
        """
        Check if an action is allowed.

        Args:
            action: Type of action (browse, message, post, etc.)
            target: Target of action (URL, email, etc.)

        Returns:
            dict with decision (ALLOW/DENY/ASK_GUARDIAN), reason, etc.
        """
        return self.permissions.check_action(action, target)

    def scan(self, content: str, content_type: str = "text") -> dict:
        """
        Scan content for threats.

        Args:
            content: Text to scan
            content_type: "text", "html", or "message"

        Returns:
            dict with is_safe, threats_found, etc.
        """
        return self.sanitizer.sanitize_for_claude(content, "scan", content_type)

    def message(self, recipient: str, subject: str, content: str) -> dict:
        """
        Compose a message to another agent (requires approval).

        Args:
            recipient: Agent identifier
            subject: Message subject
            content: Message body

        Returns:
            dict with message_id and status
        """
        msg = self.messaging.compose(recipient, subject, content)
        return {
            "message_id": msg.id,
            "status": msg.status,
            "recipient": recipient,
            "requires_approval": True,
        }

    def get_trust(self, entity: str) -> int:
        """Get trust level for an entity (0-4)."""
        return self.trust.get_trust_level(entity)

    def status(self) -> dict:
        """Get current status summary."""
        from .cli import GuardianCLI
        cli = GuardianCLI(str(self.base_path))

        pending = cli.get_pending_approvals()
        recent = cli.get_recent_activity(10)

        return {
            "pending_approvals": len(pending),
            "recent_activity_count": len(recent),
            "pending_items": [
                {"id": p["id"], "action": p.get("action"), "target": p.get("target", "")[:40]}
                for p in pending[:5]
            ],
        }


# Convenience function
def create_guardian(base_path: str = None) -> Guardian:
    """Create a Guardian instance."""
    return Guardian(base_path)
