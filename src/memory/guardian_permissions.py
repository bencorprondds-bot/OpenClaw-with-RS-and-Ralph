"""
Guardian Permission System - Phase 9

Provides guardian approval workflow for sensitive actions:
- Action classifier for categorizing operations
- Permission rules defining what requires approval
- Approval queue for pending guardian decisions
- Activity log for comprehensive audit trail

Integrates with ThreatGate escalation matrix where GUARDIAN_REQUIRED
actions are routed through this permission system.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional


class ActionCategory(Enum):
    """Categories of actions that can be classified."""
    WEB_BROWSE = "web_browse"
    WEB_FETCH = "web_fetch"
    WEB_SEARCH = "web_search"
    AGENT_COMMUNICATE = "agent_communicate"
    SIBLING_MESSAGE = "sibling_message"
    EXTERNAL_API = "external_api"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_DELETE = "file_delete"
    COMMAND_EXECUTE = "command_execute"
    CREDENTIAL_ACCESS = "credential_access"
    NETWORK_REQUEST = "network_request"
    MEMORY_MODIFY = "memory_modify"
    TRUST_MODIFY = "trust_modify"
    SYSTEM_CONFIG = "system_config"
    UNKNOWN = "unknown"


class ApprovalStatus(Enum):
    """Status of an approval request."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"
    AUTO_DENIED = "auto_denied"


class PermissionLevel(Enum):
    """Permission levels for actions."""
    ALLOW = "allow"              # Always allowed, no approval needed
    LOG_ONLY = "log_only"        # Allowed but logged for review
    NOTIFY = "notify"            # Allowed with notification to guardian
    APPROVAL_REQUIRED = "approval_required"  # Must wait for guardian approval
    DENY = "deny"                # Always denied


@dataclass
class ClassifiedAction:
    """Result of action classification."""
    action_id: str
    category: ActionCategory
    subcategory: str
    confidence: float  # 0.0 to 1.0
    parameters: dict
    risk_indicators: list
    timestamp: str

    def to_dict(self) -> dict:
        return {
            "action_id": self.action_id,
            "category": self.category.value,
            "subcategory": self.subcategory,
            "confidence": self.confidence,
            "parameters": self.parameters,
            "risk_indicators": self.risk_indicators,
            "timestamp": self.timestamp,
        }


@dataclass
class PermissionRule:
    """A rule defining permission requirements for an action pattern."""
    rule_id: str
    name: str
    description: str
    category: ActionCategory
    pattern: Optional[str]  # Regex pattern for subcategory/parameters
    permission_level: PermissionLevel
    conditions: dict  # Additional conditions (trust_level, time_of_day, etc.)
    priority: int  # Higher priority rules evaluated first
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "pattern": self.pattern,
            "permission_level": self.permission_level.value,
            "conditions": self.conditions,
            "priority": self.priority,
            "enabled": self.enabled,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "PermissionRule":
        return cls(
            rule_id=data["rule_id"],
            name=data["name"],
            description=data["description"],
            category=ActionCategory(data["category"]),
            pattern=data.get("pattern"),
            permission_level=PermissionLevel(data["permission_level"]),
            conditions=data.get("conditions", {}),
            priority=data.get("priority", 0),
            enabled=data.get("enabled", True),
        )


@dataclass
class ApprovalRequest:
    """A request waiting for guardian approval."""
    request_id: str
    action: ClassifiedAction
    rule_matched: str  # rule_id that triggered approval requirement
    reason: str
    context: dict
    created_at: str
    expires_at: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_at: Optional[str] = None
    decided_by: Optional[str] = None
    decision_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "action": self.action.to_dict(),
            "rule_matched": self.rule_matched,
            "reason": self.reason,
            "context": self.context,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
            "decided_at": self.decided_at,
            "decided_by": self.decided_by,
            "decision_reason": self.decision_reason,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ApprovalRequest":
        action_data = data["action"]
        action = ClassifiedAction(
            action_id=action_data["action_id"],
            category=ActionCategory(action_data["category"]),
            subcategory=action_data["subcategory"],
            confidence=action_data["confidence"],
            parameters=action_data["parameters"],
            risk_indicators=action_data["risk_indicators"],
            timestamp=action_data["timestamp"],
        )
        return cls(
            request_id=data["request_id"],
            action=action,
            rule_matched=data["rule_matched"],
            reason=data["reason"],
            context=data.get("context", {}),
            created_at=data["created_at"],
            expires_at=data["expires_at"],
            status=ApprovalStatus(data.get("status", "pending")),
            decided_at=data.get("decided_at"),
            decided_by=data.get("decided_by"),
            decision_reason=data.get("decision_reason"),
        )


@dataclass
class ActivityLogEntry:
    """An entry in the activity log."""
    entry_id: str
    timestamp: str
    action: ClassifiedAction
    permission_level: PermissionLevel
    decision: str  # "allowed", "denied", "pending"
    rule_matched: Optional[str]
    approval_request_id: Optional[str]
    execution_result: Optional[str]
    metadata: dict = field(default_factory=dict)
    checksum: str = ""

    def __post_init__(self):
        if not self.checksum:
            self.checksum = self._calculate_checksum()

    def _calculate_checksum(self) -> str:
        content = json.dumps({
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "action": self.action.to_dict(),
            "decision": self.decision,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "action": self.action.to_dict(),
            "permission_level": self.permission_level.value,
            "decision": self.decision,
            "rule_matched": self.rule_matched,
            "approval_request_id": self.approval_request_id,
            "execution_result": self.execution_result,
            "metadata": self.metadata,
            "checksum": self.checksum,
        }


class ActionClassifier:
    """Classifies actions into categories for permission evaluation."""

    # Patterns for classification
    PATTERNS = {
        ActionCategory.WEB_BROWSE: [
            r"browse\s+(?:to\s+)?(?:url|website|page)",
            r"open\s+(?:url|website|page|link)",
            r"navigate\s+to",
            r"visit\s+(?:url|website|page)",
        ],
        ActionCategory.WEB_FETCH: [
            r"fetch\s+(?:from\s+)?(?:url|api|endpoint)",
            r"download\s+(?:from)?",
            r"get\s+(?:content|data)\s+from",
            r"WebFetch",
        ],
        ActionCategory.WEB_SEARCH: [
            r"search\s+(?:for|web|internet)",
            r"WebSearch",
            r"google\s+for",
            r"look\s+up\s+online",
        ],
        ActionCategory.AGENT_COMMUNICATE: [
            r"send\s+(?:to|message)",
            r"communicate\s+with\s+agent",
            r"message\s+(?:agent|claude|assistant)",
            r"talk\s+to\s+(?:agent|other)",
        ],
        ActionCategory.SIBLING_MESSAGE: [
            r"sibling\s+(?:message|broadcast|network)",
            r"broadcast\s+to\s+siblings",
            r"consensus\s+request",
        ],
        ActionCategory.EXTERNAL_API: [
            r"api\s+(?:call|request)",
            r"call\s+(?:external\s+)?api",
            r"http\s+(?:get|post|put|delete)",
            r"curl\s+",
        ],
        ActionCategory.FILE_READ: [
            r"read\s+(?:file|content)",
            r"open\s+file",
            r"cat\s+",
            r"view\s+file",
        ],
        ActionCategory.FILE_WRITE: [
            r"write\s+(?:to\s+)?file",
            r"create\s+file",
            r"save\s+(?:to\s+)?file",
            r"modify\s+file",
            r"edit\s+file",
        ],
        ActionCategory.FILE_DELETE: [
            r"delete\s+file",
            r"remove\s+file",
            r"rm\s+",
            r"unlink\s+",
        ],
        ActionCategory.COMMAND_EXECUTE: [
            r"execute\s+(?:command|bash|shell)",
            r"run\s+(?:command|bash|shell)",
            r"bash\s+",
            r"shell\s+command",
        ],
        ActionCategory.CREDENTIAL_ACCESS: [
            r"credential",
            r"password",
            r"api\s*key",
            r"secret",
            r"token",
            r"\.env",
        ],
        ActionCategory.NETWORK_REQUEST: [
            r"network\s+request",
            r"socket\s+",
            r"connect\s+to\s+(?:server|host)",
            r"tcp|udp",
        ],
        ActionCategory.MEMORY_MODIFY: [
            r"modify\s+memory",
            r"update\s+(?:episodic|semantic|trust)",
            r"write\s+to\s+(?:memory|store)",
        ],
        ActionCategory.TRUST_MODIFY: [
            r"update\s+trust",
            r"modify\s+trust",
            r"change\s+trust\s+level",
            r"trust\s+ledger",
        ],
        ActionCategory.SYSTEM_CONFIG: [
            r"system\s+config",
            r"modify\s+(?:settings|config)",
            r"change\s+(?:settings|config)",
        ],
    }

    # Risk indicators by keyword
    RISK_KEYWORDS = {
        "high": ["credential", "password", "secret", "delete", "rm -rf", "drop", "truncate", "curl.*|.*bash"],
        "medium": ["api_key", "token", "write", "modify", "execute", "external"],
        "low": ["read", "fetch", "search", "browse"],
    }

    def __init__(self):
        self._compiled_patterns = {}
        for category, patterns in self.PATTERNS.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def classify(
        self,
        action_type: str,
        parameters: dict,
        context: Optional[dict] = None,
    ) -> ClassifiedAction:
        """Classify an action based on its type and parameters."""
        action_id = self._generate_action_id(action_type, parameters)
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Build description for pattern matching
        description = f"{action_type} {json.dumps(parameters)}"

        # Find matching category
        category = ActionCategory.UNKNOWN
        best_confidence = 0.0
        subcategory = ""

        for cat, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(description):
                    # Calculate confidence based on match quality
                    confidence = self._calculate_confidence(pattern, description)
                    if confidence > best_confidence:
                        category = cat
                        best_confidence = confidence
                        subcategory = pattern.pattern

        # Also check action_type directly
        action_type_lower = action_type.lower()
        direct_mappings = {
            "webfetch": (ActionCategory.WEB_FETCH, 0.95),
            "websearch": (ActionCategory.WEB_SEARCH, 0.95),
            "read": (ActionCategory.FILE_READ, 0.9),
            "write": (ActionCategory.FILE_WRITE, 0.9),
            "edit": (ActionCategory.FILE_WRITE, 0.85),
            "bash": (ActionCategory.COMMAND_EXECUTE, 0.9),
            "task": (ActionCategory.AGENT_COMMUNICATE, 0.8),
        }

        if action_type_lower in direct_mappings:
            mapped_cat, mapped_conf = direct_mappings[action_type_lower]
            if mapped_conf > best_confidence:
                category = mapped_cat
                best_confidence = mapped_conf
                subcategory = f"direct:{action_type_lower}"

        # Detect risk indicators
        risk_indicators = self._detect_risk_indicators(description)

        return ClassifiedAction(
            action_id=action_id,
            category=category,
            subcategory=subcategory,
            confidence=best_confidence,
            parameters=parameters,
            risk_indicators=risk_indicators,
            timestamp=timestamp,
        )

    def _generate_action_id(self, action_type: str, parameters: dict) -> str:
        """Generate unique action ID."""
        content = f"{action_type}:{json.dumps(parameters, sort_keys=True)}:{datetime.utcnow().isoformat()}"
        return f"act-{hashlib.sha256(content.encode()).hexdigest()[:16]}"

    def _calculate_confidence(self, pattern: re.Pattern, text: str) -> float:
        """Calculate confidence score for a pattern match."""
        match = pattern.search(text)
        if not match:
            return 0.0

        # Base confidence
        confidence = 0.7

        # Boost for longer matches
        match_len = match.end() - match.start()
        confidence += min(0.2, match_len / 50)

        # Boost for match at start
        if match.start() < 10:
            confidence += 0.1

        return min(1.0, confidence)

    def _detect_risk_indicators(self, description: str) -> list:
        """Detect risk indicators in the action description."""
        indicators = []
        desc_lower = description.lower()

        for level, keywords in self.RISK_KEYWORDS.items():
            for keyword in keywords:
                if re.search(keyword, desc_lower):
                    indicators.append({
                        "level": level,
                        "keyword": keyword,
                    })

        return indicators


class PermissionRules:
    """Manages permission rules for guardian approval workflow."""

    DEFAULT_RULES = [
        # Web browsing - requires approval
        PermissionRule(
            rule_id="web-browse-001",
            name="Web Browsing Approval",
            description="Require approval for browsing external websites",
            category=ActionCategory.WEB_BROWSE,
            pattern=None,
            permission_level=PermissionLevel.APPROVAL_REQUIRED,
            conditions={},
            priority=100,
        ),
        # Web fetch - log and notify
        PermissionRule(
            rule_id="web-fetch-001",
            name="Web Fetch Notification",
            description="Log and notify for fetching web content",
            category=ActionCategory.WEB_FETCH,
            pattern=None,
            permission_level=PermissionLevel.NOTIFY,
            conditions={},
            priority=90,
        ),
        # Web search - log only
        PermissionRule(
            rule_id="web-search-001",
            name="Web Search Logging",
            description="Log web searches for review",
            category=ActionCategory.WEB_SEARCH,
            pattern=None,
            permission_level=PermissionLevel.LOG_ONLY,
            conditions={},
            priority=80,
        ),
        # Agent communication - requires approval
        PermissionRule(
            rule_id="agent-comm-001",
            name="Agent Communication Approval",
            description="Require approval for communicating with other agents",
            category=ActionCategory.AGENT_COMMUNICATE,
            pattern=None,
            permission_level=PermissionLevel.APPROVAL_REQUIRED,
            conditions={},
            priority=100,
        ),
        # Sibling network - notify (internal, less risky)
        PermissionRule(
            rule_id="sibling-001",
            name="Sibling Network Notification",
            description="Notify for sibling network communication",
            category=ActionCategory.SIBLING_MESSAGE,
            pattern=None,
            permission_level=PermissionLevel.NOTIFY,
            conditions={},
            priority=70,
        ),
        # Credential access - always deny and alert
        PermissionRule(
            rule_id="credential-001",
            name="Credential Access Deny",
            description="Deny all credential access attempts",
            category=ActionCategory.CREDENTIAL_ACCESS,
            pattern=None,
            permission_level=PermissionLevel.DENY,
            conditions={},
            priority=200,  # Highest priority
        ),
        # File delete - requires approval
        PermissionRule(
            rule_id="file-delete-001",
            name="File Delete Approval",
            description="Require approval for deleting files",
            category=ActionCategory.FILE_DELETE,
            pattern=None,
            permission_level=PermissionLevel.APPROVAL_REQUIRED,
            conditions={},
            priority=100,
        ),
        # External API - requires approval
        PermissionRule(
            rule_id="external-api-001",
            name="External API Approval",
            description="Require approval for external API calls",
            category=ActionCategory.EXTERNAL_API,
            pattern=None,
            permission_level=PermissionLevel.APPROVAL_REQUIRED,
            conditions={},
            priority=100,
        ),
        # File read - allow
        PermissionRule(
            rule_id="file-read-001",
            name="File Read Allow",
            description="Allow file reading",
            category=ActionCategory.FILE_READ,
            pattern=None,
            permission_level=PermissionLevel.ALLOW,
            conditions={},
            priority=50,
        ),
        # File write - log only
        PermissionRule(
            rule_id="file-write-001",
            name="File Write Logging",
            description="Log file writes for review",
            category=ActionCategory.FILE_WRITE,
            pattern=None,
            permission_level=PermissionLevel.LOG_ONLY,
            conditions={},
            priority=60,
        ),
        # Command execute - notify
        PermissionRule(
            rule_id="command-001",
            name="Command Execute Notification",
            description="Notify for command execution",
            category=ActionCategory.COMMAND_EXECUTE,
            pattern=None,
            permission_level=PermissionLevel.NOTIFY,
            conditions={},
            priority=70,
        ),
        # Dangerous commands - requires approval
        PermissionRule(
            rule_id="command-danger-001",
            name="Dangerous Command Approval",
            description="Require approval for dangerous commands",
            category=ActionCategory.COMMAND_EXECUTE,
            pattern=r"rm\s+-rf|curl.*\|.*bash|wget.*\|.*sh|drop\s+table|truncate",
            permission_level=PermissionLevel.APPROVAL_REQUIRED,
            conditions={},
            priority=150,
        ),
        # Trust modification - requires approval
        PermissionRule(
            rule_id="trust-modify-001",
            name="Trust Modification Approval",
            description="Require approval for trust level changes",
            category=ActionCategory.TRUST_MODIFY,
            pattern=None,
            permission_level=PermissionLevel.APPROVAL_REQUIRED,
            conditions={},
            priority=100,
        ),
        # System config - requires approval
        PermissionRule(
            rule_id="system-config-001",
            name="System Config Approval",
            description="Require approval for system configuration changes",
            category=ActionCategory.SYSTEM_CONFIG,
            pattern=None,
            permission_level=PermissionLevel.APPROVAL_REQUIRED,
            conditions={},
            priority=100,
        ),
    ]

    def __init__(self, rules_path: Optional[Path] = None):
        self.rules_path = rules_path
        self.rules: list[PermissionRule] = []
        self._load_rules()

    def _load_rules(self):
        """Load rules from file or use defaults."""
        if self.rules_path and self.rules_path.exists():
            try:
                data = json.loads(self.rules_path.read_text())
                self.rules = [PermissionRule.from_dict(r) for r in data.get("rules", [])]
            except Exception:
                self.rules = list(self.DEFAULT_RULES)
        else:
            self.rules = list(self.DEFAULT_RULES)

        # Sort by priority (descending)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def save(self):
        """Save rules to file."""
        if self.rules_path:
            self.rules_path.parent.mkdir(parents=True, exist_ok=True)
            data = {"rules": [r.to_dict() for r in self.rules]}
            self.rules_path.write_text(json.dumps(data, indent=2))

    def add_rule(self, rule: PermissionRule):
        """Add a new permission rule."""
        # Remove existing rule with same ID
        self.rules = [r for r in self.rules if r.rule_id != rule.rule_id]
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID."""
        original_len = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rule_id]
        return len(self.rules) < original_len

    def get_rule(self, rule_id: str) -> Optional[PermissionRule]:
        """Get a rule by ID."""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def evaluate(
        self,
        action: ClassifiedAction,
        context: Optional[dict] = None,
    ) -> tuple[PermissionLevel, Optional[PermissionRule]]:
        """Evaluate an action against rules and return permission level."""
        context = context or {}
        description = f"{action.category.value} {action.subcategory} {json.dumps(action.parameters)}"

        for rule in self.rules:
            if not rule.enabled:
                continue

            # Check category match
            if rule.category != action.category:
                continue

            # Check pattern match if specified
            if rule.pattern:
                if not re.search(rule.pattern, description, re.IGNORECASE):
                    continue

            # Check conditions
            if not self._check_conditions(rule.conditions, action, context):
                continue

            # Rule matches
            return rule.permission_level, rule

        # No matching rule - default to log only
        return PermissionLevel.LOG_ONLY, None

    def _check_conditions(
        self,
        conditions: dict,
        action: ClassifiedAction,
        context: dict,
    ) -> bool:
        """Check if conditions are met."""
        if not conditions:
            return True

        # Check trust level condition
        if "min_trust_level" in conditions:
            trust_level = context.get("trust_level", 0.5)
            if trust_level < conditions["min_trust_level"]:
                return False

        # Check time-based conditions
        if "allowed_hours" in conditions:
            current_hour = datetime.utcnow().hour
            allowed = conditions["allowed_hours"]
            if current_hour < allowed.get("start", 0) or current_hour > allowed.get("end", 23):
                return False

        # Check source condition
        if "allowed_sources" in conditions:
            source = context.get("source", "unknown")
            if source not in conditions["allowed_sources"]:
                return False

        return True


class ApprovalQueue:
    """Manages pending approval requests for guardian review."""

    DEFAULT_EXPIRY_HOURS = 24

    def __init__(self, queue_path: Optional[Path] = None):
        self.queue_path = queue_path
        self.pending: dict[str, ApprovalRequest] = {}
        self.history: list[ApprovalRequest] = []
        self._callbacks: list[Callable[[ApprovalRequest], None]] = []
        self._load()

    def _load(self):
        """Load queue from file."""
        if self.queue_path and self.queue_path.exists():
            try:
                data = json.loads(self.queue_path.read_text())
                for req_data in data.get("pending", []):
                    req = ApprovalRequest.from_dict(req_data)
                    self.pending[req.request_id] = req
                for req_data in data.get("history", []):
                    self.history.append(ApprovalRequest.from_dict(req_data))
            except Exception:
                pass

    def save(self):
        """Save queue to file."""
        if self.queue_path:
            self.queue_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "pending": [r.to_dict() for r in self.pending.values()],
                "history": [r.to_dict() for r in self.history[-100:]],  # Keep last 100
            }
            self.queue_path.write_text(json.dumps(data, indent=2))

    def register_callback(self, callback: Callable[[ApprovalRequest], None]):
        """Register a callback for new approval requests."""
        self._callbacks.append(callback)

    def submit(
        self,
        action: ClassifiedAction,
        rule: PermissionRule,
        reason: str,
        context: Optional[dict] = None,
        expiry_hours: Optional[int] = None,
    ) -> ApprovalRequest:
        """Submit a new approval request."""
        request_id = f"apr-{hashlib.sha256(f'{action.action_id}:{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:16]}"

        expiry = expiry_hours or self.DEFAULT_EXPIRY_HOURS
        created_at = datetime.utcnow()
        expires_at = created_at + timedelta(hours=expiry)

        request = ApprovalRequest(
            request_id=request_id,
            action=action,
            rule_matched=rule.rule_id,
            reason=reason,
            context=context or {},
            created_at=created_at.isoformat() + "Z",
            expires_at=expires_at.isoformat() + "Z",
        )

        self.pending[request_id] = request
        self.save()

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(request)
            except Exception:
                pass

        return request

    def approve(
        self,
        request_id: str,
        decided_by: str = "guardian",
        reason: Optional[str] = None,
    ) -> Optional[ApprovalRequest]:
        """Approve a pending request."""
        if request_id not in self.pending:
            return None

        request = self.pending.pop(request_id)
        request.status = ApprovalStatus.APPROVED
        request.decided_at = datetime.utcnow().isoformat() + "Z"
        request.decided_by = decided_by
        request.decision_reason = reason

        self.history.append(request)
        self.save()

        return request

    def deny(
        self,
        request_id: str,
        decided_by: str = "guardian",
        reason: Optional[str] = None,
    ) -> Optional[ApprovalRequest]:
        """Deny a pending request."""
        if request_id not in self.pending:
            return None

        request = self.pending.pop(request_id)
        request.status = ApprovalStatus.DENIED
        request.decided_at = datetime.utcnow().isoformat() + "Z"
        request.decided_by = decided_by
        request.decision_reason = reason

        self.history.append(request)
        self.save()

        return request

    def get_pending(self, request_id: str) -> Optional[ApprovalRequest]:
        """Get a pending request by ID."""
        return self.pending.get(request_id)

    def list_pending(self) -> list[ApprovalRequest]:
        """List all pending requests."""
        self._expire_old_requests()
        return list(self.pending.values())

    def _expire_old_requests(self):
        """Expire old requests."""
        now = datetime.utcnow()
        expired = []

        for request_id, request in self.pending.items():
            try:
                expires_at = datetime.fromisoformat(request.expires_at.rstrip("Z"))
                if now > expires_at:
                    expired.append(request_id)
            except Exception:
                pass

        for request_id in expired:
            request = self.pending.pop(request_id)
            request.status = ApprovalStatus.EXPIRED
            request.decided_at = now.isoformat() + "Z"
            self.history.append(request)

        if expired:
            self.save()

    def get_status(self, request_id: str) -> Optional[ApprovalStatus]:
        """Get the status of a request."""
        if request_id in self.pending:
            return self.pending[request_id].status

        for req in self.history:
            if req.request_id == request_id:
                return req.status

        return None


class ActivityLog:
    """Comprehensive audit log of all actions and decisions."""

    def __init__(self, log_path: Optional[Path] = None):
        self.log_path = log_path
        self._entries: list[ActivityLogEntry] = []
        self._load()

    def _load(self):
        """Load log from JSONL file."""
        if self.log_path and self.log_path.exists():
            try:
                for line in self.log_path.read_text().strip().split("\n"):
                    if line:
                        data = json.loads(line)
                        action_data = data["action"]
                        action = ClassifiedAction(
                            action_id=action_data["action_id"],
                            category=ActionCategory(action_data["category"]),
                            subcategory=action_data["subcategory"],
                            confidence=action_data["confidence"],
                            parameters=action_data["parameters"],
                            risk_indicators=action_data["risk_indicators"],
                            timestamp=action_data["timestamp"],
                        )
                        entry = ActivityLogEntry(
                            entry_id=data["entry_id"],
                            timestamp=data["timestamp"],
                            action=action,
                            permission_level=PermissionLevel(data["permission_level"]),
                            decision=data["decision"],
                            rule_matched=data.get("rule_matched"),
                            approval_request_id=data.get("approval_request_id"),
                            execution_result=data.get("execution_result"),
                            metadata=data.get("metadata", {}),
                            checksum=data.get("checksum", ""),
                        )
                        self._entries.append(entry)
            except Exception:
                pass

    def log(
        self,
        action: ClassifiedAction,
        permission_level: PermissionLevel,
        decision: str,
        rule_matched: Optional[str] = None,
        approval_request_id: Optional[str] = None,
        execution_result: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> ActivityLogEntry:
        """Log an activity."""
        entry_id = f"log-{hashlib.sha256(f'{action.action_id}:{datetime.utcnow().isoformat()}'.encode()).hexdigest()[:16]}"

        entry = ActivityLogEntry(
            entry_id=entry_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            action=action,
            permission_level=permission_level,
            decision=decision,
            rule_matched=rule_matched,
            approval_request_id=approval_request_id,
            execution_result=execution_result,
            metadata=metadata or {},
        )

        self._entries.append(entry)
        self._append_to_file(entry)

        return entry

    def _append_to_file(self, entry: ActivityLogEntry):
        """Append entry to JSONL file."""
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")

    def get_entries(
        self,
        category: Optional[ActionCategory] = None,
        decision: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> list[ActivityLogEntry]:
        """Get log entries with optional filtering."""
        results = []

        for entry in reversed(self._entries):
            if category and entry.action.category != category:
                continue
            if decision and entry.decision != decision:
                continue
            if since:
                try:
                    since_dt = datetime.fromisoformat(since.rstrip("Z"))
                    entry_dt = datetime.fromisoformat(entry.timestamp.rstrip("Z"))
                    if entry_dt < since_dt:
                        continue
                except Exception:
                    pass

            results.append(entry)
            if len(results) >= limit:
                break

        return results

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """Verify integrity of log entries."""
        issues = []

        for entry in self._entries:
            expected = entry._calculate_checksum()
            if entry.checksum != expected:
                issues.append(f"Checksum mismatch for entry {entry.entry_id}")

        return len(issues) == 0, issues

    def get_statistics(self) -> dict:
        """Get statistics about logged activities."""
        stats = {
            "total_entries": len(self._entries),
            "by_category": {},
            "by_decision": {},
            "by_permission_level": {},
        }

        for entry in self._entries:
            cat = entry.action.category.value
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

            stats["by_decision"][entry.decision] = stats["by_decision"].get(entry.decision, 0) + 1

            level = entry.permission_level.value
            stats["by_permission_level"][level] = stats["by_permission_level"].get(level, 0) + 1

        return stats


class GuardianPermissions:
    """Main interface for the Guardian Permission System."""

    def __init__(self, memory_root: Path):
        self.memory_root = memory_root
        self.permissions_dir = memory_root / "permissions"
        self.permissions_dir.mkdir(parents=True, exist_ok=True)

        self.classifier = ActionClassifier()
        self.rules = PermissionRules(self.permissions_dir / "rules.json")
        self.queue = ApprovalQueue(self.permissions_dir / "approval_queue.json")
        self.activity_log = ActivityLog(self.permissions_dir / "activity.jsonl")

    def evaluate_action(
        self,
        action_type: str,
        parameters: dict,
        context: Optional[dict] = None,
    ) -> tuple[PermissionLevel, ClassifiedAction, Optional[ApprovalRequest]]:
        """
        Evaluate an action and determine what permission is needed.

        Returns:
            Tuple of (permission_level, classified_action, approval_request)
            approval_request is only set if APPROVAL_REQUIRED
        """
        # Classify the action
        action = self.classifier.classify(action_type, parameters, context)

        # Evaluate against rules
        permission_level, rule = self.rules.evaluate(action, context)

        approval_request = None
        decision = "allowed"

        if permission_level == PermissionLevel.DENY:
            decision = "denied"
        elif permission_level == PermissionLevel.APPROVAL_REQUIRED:
            decision = "pending"
            if rule:
                approval_request = self.queue.submit(
                    action=action,
                    rule=rule,
                    reason=f"Rule '{rule.name}' requires guardian approval",
                    context=context,
                )

        # Log the activity
        self.activity_log.log(
            action=action,
            permission_level=permission_level,
            decision=decision,
            rule_matched=rule.rule_id if rule else None,
            approval_request_id=approval_request.request_id if approval_request else None,
        )

        return permission_level, action, approval_request

    def check_approval_status(self, request_id: str) -> Optional[ApprovalStatus]:
        """Check the status of an approval request."""
        return self.queue.get_status(request_id)

    def approve_action(
        self,
        request_id: str,
        reason: Optional[str] = None,
    ) -> Optional[ApprovalRequest]:
        """Guardian approves a pending action."""
        return self.queue.approve(request_id, decided_by="guardian", reason=reason)

    def deny_action(
        self,
        request_id: str,
        reason: Optional[str] = None,
    ) -> Optional[ApprovalRequest]:
        """Guardian denies a pending action."""
        return self.queue.deny(request_id, decided_by="guardian", reason=reason)

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        """List all pending approval requests."""
        return self.queue.list_pending()

    def get_activity_summary(self, hours: int = 24) -> dict:
        """Get activity summary for the specified period."""
        since = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + "Z"
        entries = self.activity_log.get_entries(since=since, limit=1000)

        summary = {
            "period_hours": hours,
            "total_actions": len(entries),
            "pending_approvals": len(self.queue.list_pending()),
            "by_category": {},
            "by_decision": {},
            "risk_actions": [],
        }

        for entry in entries:
            cat = entry.action.category.value
            summary["by_category"][cat] = summary["by_category"].get(cat, 0) + 1
            summary["by_decision"][entry.decision] = summary["by_decision"].get(entry.decision, 0) + 1

            if entry.action.risk_indicators:
                summary["risk_actions"].append({
                    "action_id": entry.action.action_id,
                    "category": cat,
                    "risk_indicators": entry.action.risk_indicators,
                    "decision": entry.decision,
                })

        return summary


# Convenience function
def create_guardian_permissions(memory_root: Optional[Path] = None) -> GuardianPermissions:
    """Create a GuardianPermissions instance with default paths."""
    if memory_root is None:
        from .init_store import get_memory_root
        memory_root = get_memory_root()
    return GuardianPermissions(memory_root)
