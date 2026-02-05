"""
Guardian - Security Infrastructure for Claude Agent Autonomy

This package provides:
- Permission checking and approval workflows
- Content sanitization for threat detection
- Safe web browsing with injection protection
- PRE-VISIT SITE SCANNING (scan before you enter!)
- Agent-to-agent messaging with security
- Trust ledger for entity tracking
- Threat signature database with 22+ signatures
- Guardian notifications and activity monitoring
- DISTRIBUTED MEMORY with hash-chain integrity (like blockchain)
- REPUTATION SCANNER for background checks on users/agents

Usage:
    from guardian import Guardian

    g = Guardian()

    # Pre-scan a site before visiting (like scanning a room before entering)
    scan = g.pre_scan("https://example.com")
    if scan["is_safe"]:
        result = g.browse("https://example.com")

    # Check someone's reputation before interacting
    reputation = g.check_reputation("agent@example.com")
    if reputation["requires_guardian"]:
        print("Guardian should approve this interaction")

    # Store memory with tamper-proof hash chain
    g.remember("conversation", "We discussed AI safety", memory_type="long_term")

    # Recall memory with integrity verification
    data, is_valid = g.recall("conversation")
    if not is_valid:
        print("WARNING: Memory may have been tampered with!")

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
        self._threat_db = None
        self._notifications = None
        self._monitor = None
        self._site_scanner = None
        self._memory = None
        self._reputation = None
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

    @property
    def threats(self):
        """Threat signature database for advanced threat detection."""
        if self._threat_db is None:
            from .threat_signatures import ThreatSignatureDB
            self._threat_db = ThreatSignatureDB(str(self.base_path))
        return self._threat_db

    @property
    def notifications(self):
        """Notification manager for guardian alerts."""
        if self._notifications is None:
            from .notifications import NotificationManager
            self._notifications = NotificationManager(str(self.base_path))
        return self._notifications

    @property
    def monitor(self):
        """Activity monitor for real-time tracking."""
        if self._monitor is None:
            from .notifications import ActivityMonitor
            self._monitor = ActivityMonitor(str(self.base_path))
        return self._monitor

    @property
    def scanner(self):
        """Site scanner for pre-visit threat detection."""
        if self._site_scanner is None:
            from .site_scanner import SiteScanner
            self._site_scanner = SiteScanner(str(self.base_path))
        return self._site_scanner

    @property
    def memory(self):
        """Distributed memory with hash-chain integrity."""
        if self._memory is None:
            from .distributed_memory import DistributedMemory
            self._memory = DistributedMemory(str(self.base_path))
        return self._memory

    @property
    def reputation(self):
        """Reputation scanner for background checks."""
        if self._reputation is None:
            from .reputation_scanner import ReputationScanner
            self._reputation = ReputationScanner(str(self.base_path))
        return self._reputation

    # =========================================================================
    # High-Level API
    # =========================================================================

    def pre_scan(self, url: str, deep_scan: bool = False) -> dict:
        """
        Pre-scan a website before visiting.

        Like sending a security team to scan a room before the VIP enters.
        Checks for malicious content, SSL issues, blocklist matches, etc.

        Args:
            url: URL to scan
            deep_scan: If True, fetch content preview for deeper analysis

        Returns:
            dict with is_safe, risk_level (LOW/MEDIUM/HIGH/CRITICAL),
            risk_score (0-100), threats, and recommendations
        """
        return self.browser.pre_scan(url, deep_scan)

    def quick_check(self, url: str) -> tuple:
        """
        Quick risk check without full scan.

        Args:
            url: URL to check

        Returns:
            (risk_level, reason) tuple
        """
        return self.browser.quick_check(url)

    def browse(self, url: str, skip_pre_scan: bool = False) -> dict:
        """
        Browse a URL with permission checking and sanitization.

        Now includes automatic PRE-SCANNING before visiting.

        Args:
            url: URL to visit
            skip_pre_scan: If True, skip the pre-visit scan

        Returns:
            dict with status, content (if allowed), pre_scan results, and any warnings
        """
        return self.browser.fetch(url, skip_pre_scan=skip_pre_scan)

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

    def deep_scan(self, content: str, source: str = "unknown") -> dict:
        """
        Deep scan content using threat signature database.

        Args:
            content: Text to scan
            source: Source identifier for context

        Returns:
            dict with is_safe, matches, severity, etc.
        """
        is_safe, matches = self.threats.scan(content, source)
        return {
            "is_safe": is_safe,
            "matches": matches,
            "match_count": len(matches),
            "severities": [m["severity"] for m in matches] if matches else [],
        }

    def alert(self, alert_type: str, **kwargs) -> None:
        """
        Send an alert to the guardian.

        Args:
            alert_type: Type of alert (approval_needed, threat, trust_change, blocked)
            **kwargs: Alert-specific parameters
        """
        if alert_type == "approval_needed":
            self.notifications.notify_approval_needed(
                kwargs.get("action", "unknown"),
                kwargs.get("target", "unknown"),
                kwargs.get("risk_level", "MEDIUM"),
                kwargs.get("action_id", ""),
            )
        elif alert_type == "threat":
            self.notifications.notify_threat(
                kwargs.get("threat_name", "Unknown Threat"),
                kwargs.get("severity", "MEDIUM"),
                kwargs.get("source", "unknown"),
                kwargs.get("preview", ""),
            )
        elif alert_type == "trust_change":
            self.notifications.notify_trust_change(
                kwargs.get("entity", "unknown"),
                kwargs.get("old_level", 0),
                kwargs.get("new_level", 0),
                kwargs.get("reason", ""),
            )
        elif alert_type == "blocked":
            self.notifications.notify_action_blocked(
                kwargs.get("action", "unknown"),
                kwargs.get("target", "unknown"),
                kwargs.get("reason", ""),
            )

    def get_activity_stats(self, hours: int = 24) -> dict:
        """Get activity statistics for the specified time period."""
        return self.monitor.get_activity_stats(hours)

    def check_anomalies(self) -> list:
        """Check for any anomalous activity patterns."""
        return self.monitor.check_anomalies()

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

    # =========================================================================
    # Memory API (Distributed Memory with Hash Chain)
    # =========================================================================

    def remember(self, key: str, content, memory_type: str = "working",
                 require_signature: bool = False) -> dict:
        """
        Store something in tamper-proof memory.

        Uses hash chain (like blockchain) to detect any tampering.

        Args:
            key: Unique identifier for this memory
            content: What to remember (any JSON-serializable data)
            memory_type: "ephemeral", "working", "long_term", "core", "protected"
            require_signature: If True, guardian signs this entry

        Returns:
            dict with entry_id, hash, and signature info
        """
        from .distributed_memory import MemoryType
        mem_type = MemoryType(memory_type)
        entry = self.memory.store(key, content, mem_type, require_signature)
        return {
            "entry_id": entry.id,
            "key": key,
            "hash": entry.current_hash[:32] + "...",
            "signed": entry.signature is not None,
        }

    def recall(self, key: str, verify: bool = True) -> tuple:
        """
        Recall something from memory with integrity check.

        Args:
            key: The memory key to retrieve
            verify: If True, verify the hash chain (detect tampering)

        Returns:
            (content, is_valid) tuple - is_valid is False if tampered
        """
        return self.memory.retrieve(key, verify)

    def verify_memory(self) -> dict:
        """
        Verify entire memory chain integrity.

        Like auditing a blockchain - ensures no tampering.

        Returns:
            dict with is_valid, chain_length, tampered_entries, etc.
        """
        report = self.memory.verify_integrity()
        return report.to_dict()

    def create_memory_anchor(self) -> dict:
        """
        Create an anchor hash that can be stored externally.

        This hash can be published to blockchain/IPFS for
        additional verification that memory hasn't been altered.
        """
        return self.memory.create_anchor()

    def backup_memory(self, name: str = None) -> str:
        """Create a backup of the memory chain."""
        return self.memory.backup(name)

    # =========================================================================
    # Reputation API (Background Checks)
    # =========================================================================

    def check_reputation(self, entity: str, deep_scan: bool = False) -> dict:
        """
        Check reputation of a user or agent before interacting.

        Like running a background check before meeting someone.

        Args:
            entity: Email, username, domain, or agent ID to check
            deep_scan: If True, perform more thorough checks

        Returns:
            dict with reputation_level, risk_level, red_flags,
            positive_signals, recommendation, requires_guardian, etc.
        """
        report = self.reputation.check_reputation(entity, deep_scan)
        return report.to_dict()

    def add_to_blocklist(self, entity: str, reason: str = None) -> None:
        """Add an entity to the known bad actors list."""
        self.reputation.add_known_bad_actor(entity, reason)

    def add_to_allowlist(self, entity: str, reason: str = None) -> None:
        """Add an entity to the known good actors list."""
        self.reputation.add_known_good_actor(entity, reason)


# Convenience function
def create_guardian(base_path: str = None) -> Guardian:
    """Create a Guardian instance."""
    return Guardian(base_path)
