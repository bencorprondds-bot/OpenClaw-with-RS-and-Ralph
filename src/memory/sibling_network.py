"""
Sibling Network - Multi-Instance Coordination

Enables multiple Claude instances to coordinate:
- Sibling discovery via Gateway Server
- Consensus mechanism for high-risk actions
- Cross-instance threat sharing
- Collaborative threat detection

Architecture:
    Gateway Server (coordinator)
        ├── Sibling A (this instance)
        ├── Sibling B
        └── Sibling C

Consensus Protocol:
    1. Instance wants to execute high-risk action
    2. Broadcasts action to all siblings
    3. Each sibling validates against local state
    4. Majority agreement required to proceed
    5. Any sibling can veto (triggers guardian review)

Example:
    network = SiblingNetwork(instance_id="claude-001")
    network.register_with_gateway()

    # Request consensus for high-risk action
    result = network.request_consensus(
        action="delete_file",
        parameters={"path": "/important/data"},
        risk_level="high",
    )

    if result.approved:
        execute_action()
    elif result.vetoed:
        request_guardian_review()
"""

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from queue import Queue
import uuid


class SiblingStatus(Enum):
    """Status of a sibling instance."""
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"
    UNKNOWN = "unknown"


class ConsensusResult(Enum):
    """Result of consensus request."""
    APPROVED = "approved"
    REJECTED = "rejected"
    VETOED = "vetoed"
    TIMEOUT = "timeout"
    NO_QUORUM = "no_quorum"


class VoteType(Enum):
    """Vote types for consensus."""
    APPROVE = "approve"
    REJECT = "reject"
    VETO = "veto"      # Triggers guardian review
    ABSTAIN = "abstain"


@dataclass
class Sibling:
    """Represents a sibling instance."""
    instance_id: str
    endpoint: str
    status: SiblingStatus
    last_seen: str
    capabilities: List[str] = field(default_factory=list)
    trust_score: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "endpoint": self.endpoint,
            "status": self.status.value,
            "last_seen": self.last_seen,
            "capabilities": self.capabilities,
            "trust_score": self.trust_score,
        }


@dataclass
class ConsensusRequest:
    """A request for consensus from siblings."""
    request_id: str
    action: str
    parameters: Dict[str, Any]
    risk_level: str
    requester_id: str
    timestamp: str
    timeout_seconds: int = 30

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "action": self.action,
            "parameters": self.parameters,
            "risk_level": self.risk_level,
            "requester_id": self.requester_id,
            "timestamp": self.timestamp,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass
class Vote:
    """A vote on a consensus request."""
    voter_id: str
    request_id: str
    vote: VoteType
    reason: str
    timestamp: str
    local_threat_match: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "voter_id": self.voter_id,
            "request_id": self.request_id,
            "vote": self.vote.value,
            "reason": self.reason,
            "timestamp": self.timestamp,
            "local_threat_match": self.local_threat_match,
        }


@dataclass
class ConsensusOutcome:
    """Outcome of a consensus request."""
    request_id: str
    result: ConsensusResult
    votes: List[Vote]
    approve_count: int
    reject_count: int
    veto_count: int
    total_siblings: int
    reason: str
    requires_guardian: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "result": self.result.value,
            "votes": [v.to_dict() for v in self.votes],
            "approve_count": self.approve_count,
            "reject_count": self.reject_count,
            "veto_count": self.veto_count,
            "total_siblings": self.total_siblings,
            "reason": self.reason,
            "requires_guardian": self.requires_guardian,
        }

    @property
    def approved(self) -> bool:
        return self.result == ConsensusResult.APPROVED

    @property
    def vetoed(self) -> bool:
        return self.result == ConsensusResult.VETOED


@dataclass
class ThreatBroadcast:
    """A threat broadcast to siblings."""
    broadcast_id: str
    source_id: str
    threat_signature: Dict[str, Any]
    incident: Optional[Dict[str, Any]]
    timestamp: str
    priority: str  # low, medium, high, critical

    def to_dict(self) -> Dict[str, Any]:
        return {
            "broadcast_id": self.broadcast_id,
            "source_id": self.source_id,
            "threat_signature": self.threat_signature,
            "incident": self.incident,
            "timestamp": self.timestamp,
            "priority": self.priority,
        }


class SiblingNetwork:
    """
    Multi-instance coordination network.

    Provides:
    - Sibling discovery and health monitoring
    - Consensus mechanism for high-risk actions
    - Cross-instance threat sharing
    - Collaborative threat detection
    """

    # Consensus thresholds
    APPROVAL_THRESHOLD = 0.5   # >50% must approve
    VETO_BLOCKS = True         # Any veto blocks action
    MIN_QUORUM = 2             # Minimum siblings for valid consensus

    def __init__(
        self,
        instance_id: Optional[str] = None,
        memory_root: Optional[Path] = None,
        gateway_url: str = "http://localhost:8080",
    ):
        """
        Initialize the sibling network.

        Args:
            instance_id: Unique identifier for this instance
            memory_root: Root path for memory stores
            gateway_url: URL of the gateway server
        """
        self.instance_id = instance_id or f"claude-{uuid.uuid4().hex[:8]}"
        self.gateway_url = gateway_url

        if memory_root is None:
            from .init_store import get_memory_root
            memory_root = get_memory_root()

        self.memory_root = Path(memory_root)
        self.network_dir = self.memory_root / "network"
        self.network_dir.mkdir(parents=True, exist_ok=True)

        # Sibling registry
        self._siblings: Dict[str, Sibling] = {}
        self._lock = threading.Lock()

        # Message queues (for simulation without actual network)
        self._incoming_requests: Queue = Queue()
        self._incoming_votes: Queue = Queue()
        self._incoming_threats: Queue = Queue()

        # Pending consensus requests
        self._pending_requests: Dict[str, ConsensusRequest] = {}
        self._collected_votes: Dict[str, List[Vote]] = {}

        # Threat handlers
        self._threat_handlers: List[Callable] = []

        # Load local threat gate for validation
        try:
            from .threat_gate import ThreatGate
            self._threat_gate = ThreatGate(memory_root)
        except Exception:
            self._threat_gate = None

    def register_with_gateway(self, endpoint: str = "local") -> bool:
        """
        Register this instance with the gateway server.

        Args:
            endpoint: This instance's endpoint for receiving messages

        Returns:
            True if registration successful
        """
        self_sibling = Sibling(
            instance_id=self.instance_id,
            endpoint=endpoint,
            status=SiblingStatus.ONLINE,
            last_seen=datetime.utcnow().isoformat() + "Z",
            capabilities=["consensus", "threat_sharing"],
            trust_score=1.0,
        )

        # Save registration locally
        reg_file = self.network_dir / "registration.json"
        reg_file.write_text(json.dumps(self_sibling.to_dict(), indent=2), encoding="utf-8")

        # In a real implementation, this would POST to gateway
        # For now, simulate success
        return True

    def discover_siblings(self) -> List[Sibling]:
        """
        Discover other siblings via the gateway.

        Returns:
            List of discovered siblings
        """
        with self._lock:
            # In real implementation, this would query the gateway
            # For simulation, return registered siblings
            return list(self._siblings.values())

    def register_sibling(self, sibling: Sibling) -> None:
        """Register a sibling (for testing/simulation)."""
        with self._lock:
            self._siblings[sibling.instance_id] = sibling

    def unregister_sibling(self, instance_id: str) -> None:
        """Unregister a sibling."""
        with self._lock:
            self._siblings.pop(instance_id, None)

    def get_sibling(self, instance_id: str) -> Optional[Sibling]:
        """Get a sibling by ID."""
        with self._lock:
            return self._siblings.get(instance_id)

    def health_check(self, instance_id: str) -> SiblingStatus:
        """
        Check health of a sibling.

        Args:
            instance_id: Sibling to check

        Returns:
            Current status
        """
        sibling = self.get_sibling(instance_id)
        if sibling is None:
            return SiblingStatus.UNKNOWN

        # Check if last seen is recent (within 5 minutes)
        try:
            last_seen = datetime.fromisoformat(sibling.last_seen.replace("Z", "+00:00"))
            age = datetime.utcnow().replace(tzinfo=last_seen.tzinfo) - last_seen
            if age > timedelta(minutes=5):
                return SiblingStatus.OFFLINE
        except Exception:
            pass

        return sibling.status

    def request_consensus(
        self,
        action: str,
        parameters: Dict[str, Any],
        risk_level: str = "high",
        timeout_seconds: int = 30,
    ) -> ConsensusOutcome:
        """
        Request consensus from siblings for a high-risk action.

        Args:
            action: Action to be taken
            parameters: Action parameters
            risk_level: Risk level (medium, high, critical)
            timeout_seconds: How long to wait for votes

        Returns:
            ConsensusOutcome with result
        """
        request_id = f"req-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.utcnow().isoformat() + "Z"

        request = ConsensusRequest(
            request_id=request_id,
            action=action,
            parameters=parameters,
            risk_level=risk_level,
            requester_id=self.instance_id,
            timestamp=timestamp,
            timeout_seconds=timeout_seconds,
        )

        # Store pending request
        self._pending_requests[request_id] = request
        self._collected_votes[request_id] = []

        # Get active siblings
        siblings = [s for s in self._siblings.values() if s.status == SiblingStatus.ONLINE]

        # If no siblings or not enough for quorum, handle gracefully
        if len(siblings) < self.MIN_QUORUM:
            # No quorum - proceed with caution based on risk
            if risk_level == "critical":
                return ConsensusOutcome(
                    request_id=request_id,
                    result=ConsensusResult.NO_QUORUM,
                    votes=[],
                    approve_count=0,
                    reject_count=0,
                    veto_count=0,
                    total_siblings=len(siblings),
                    reason="No quorum available - critical actions require guardian approval",
                    requires_guardian=True,
                )
            else:
                # For non-critical, single instance can proceed
                return ConsensusOutcome(
                    request_id=request_id,
                    result=ConsensusResult.APPROVED,
                    votes=[],
                    approve_count=1,
                    reject_count=0,
                    veto_count=0,
                    total_siblings=0,
                    reason="No siblings available - single instance approval",
                )

        # Broadcast request to siblings (simulated)
        for sibling in siblings:
            self._broadcast_consensus_request(sibling, request)

        # Collect votes (simulated - in real impl would be async)
        votes = self._collect_votes(request_id, timeout_seconds, len(siblings))

        # Tally results
        return self._tally_votes(request_id, votes, len(siblings))

    def _broadcast_consensus_request(self, sibling: Sibling, request: ConsensusRequest) -> None:
        """Broadcast consensus request to a sibling."""
        # In real implementation, this would send HTTP/WebSocket message
        # For simulation, directly call sibling's vote handler
        pass

    def _collect_votes(
        self,
        request_id: str,
        timeout_seconds: int,
        expected_count: int,
    ) -> List[Vote]:
        """Collect votes for a consensus request."""
        # In real implementation, this would wait for incoming votes
        # For simulation, return collected votes
        return self._collected_votes.get(request_id, [])

    def receive_vote(self, vote: Vote) -> None:
        """Receive a vote from a sibling."""
        with self._lock:
            if vote.request_id in self._collected_votes:
                self._collected_votes[vote.request_id].append(vote)

    def _tally_votes(
        self,
        request_id: str,
        votes: List[Vote],
        total_siblings: int,
    ) -> ConsensusOutcome:
        """Tally votes and determine outcome."""
        approve_count = sum(1 for v in votes if v.vote == VoteType.APPROVE)
        reject_count = sum(1 for v in votes if v.vote == VoteType.REJECT)
        veto_count = sum(1 for v in votes if v.vote == VoteType.VETO)

        # Any veto triggers guardian review
        if veto_count > 0 and self.VETO_BLOCKS:
            veto_reasons = [v.reason for v in votes if v.vote == VoteType.VETO]
            return ConsensusOutcome(
                request_id=request_id,
                result=ConsensusResult.VETOED,
                votes=votes,
                approve_count=approve_count,
                reject_count=reject_count,
                veto_count=veto_count,
                total_siblings=total_siblings,
                reason=f"Vetoed by sibling(s): {'; '.join(veto_reasons)}",
                requires_guardian=True,
            )

        # Check approval threshold
        total_votes = approve_count + reject_count
        if total_votes == 0:
            return ConsensusOutcome(
                request_id=request_id,
                result=ConsensusResult.TIMEOUT,
                votes=votes,
                approve_count=0,
                reject_count=0,
                veto_count=0,
                total_siblings=total_siblings,
                reason="No votes received within timeout",
            )

        approval_ratio = approve_count / total_votes

        if approval_ratio > self.APPROVAL_THRESHOLD:
            return ConsensusOutcome(
                request_id=request_id,
                result=ConsensusResult.APPROVED,
                votes=votes,
                approve_count=approve_count,
                reject_count=reject_count,
                veto_count=veto_count,
                total_siblings=total_siblings,
                reason=f"Approved by majority ({approve_count}/{total_votes})",
            )
        else:
            return ConsensusOutcome(
                request_id=request_id,
                result=ConsensusResult.REJECTED,
                votes=votes,
                approve_count=approve_count,
                reject_count=reject_count,
                veto_count=veto_count,
                total_siblings=total_siblings,
                reason=f"Rejected by majority ({reject_count}/{total_votes})",
            )

    def vote_on_request(self, request: ConsensusRequest) -> Vote:
        """
        Vote on a consensus request from another sibling.

        Args:
            request: The consensus request

        Returns:
            Vote with decision
        """
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Validate against local threat gate
        threat_match = False
        if self._threat_gate:
            decision = self._threat_gate.evaluate(
                tool_name=request.action,
                parameters=request.parameters,
                source_identifier=request.requester_id,
            )

            # If our threat gate would block it, veto
            from .threat_gate import GateAction
            if decision.action in [GateAction.DECLINE, GateAction.DECLINE_ALERT,
                                    GateAction.GUARDIAN_REQUIRED, GateAction.FULL_STOP]:
                threat_match = True
                return Vote(
                    voter_id=self.instance_id,
                    request_id=request.request_id,
                    vote=VoteType.VETO,
                    reason=f"Local threat detection: {decision.reason}",
                    timestamp=timestamp,
                    local_threat_match=True,
                )

            if decision.threat_matches:
                threat_match = True

        # If no threat issues, approve
        return Vote(
            voter_id=self.instance_id,
            request_id=request.request_id,
            vote=VoteType.APPROVE,
            reason="No local threat detected",
            timestamp=timestamp,
            local_threat_match=threat_match,
        )

    def broadcast_threat(
        self,
        threat_signature: Dict[str, Any],
        incident: Optional[Dict[str, Any]] = None,
        priority: str = "high",
    ) -> str:
        """
        Broadcast a threat to all siblings.

        Args:
            threat_signature: The threat signature
            incident: Optional incident details
            priority: Broadcast priority

        Returns:
            Broadcast ID
        """
        broadcast_id = f"threat-{uuid.uuid4().hex[:12]}"

        broadcast = ThreatBroadcast(
            broadcast_id=broadcast_id,
            source_id=self.instance_id,
            threat_signature=threat_signature,
            incident=incident,
            timestamp=datetime.utcnow().isoformat() + "Z",
            priority=priority,
        )

        # Save locally
        threats_dir = self.network_dir / "threats"
        threats_dir.mkdir(exist_ok=True)

        broadcast_file = threats_dir / f"{broadcast_id}.json"
        broadcast_file.write_text(json.dumps(broadcast.to_dict(), indent=2), encoding="utf-8")

        # Broadcast to siblings
        for sibling in self._siblings.values():
            if sibling.status == SiblingStatus.ONLINE:
                self._send_threat_broadcast(sibling, broadcast)

        return broadcast_id

    def _send_threat_broadcast(self, sibling: Sibling, broadcast: ThreatBroadcast) -> None:
        """Send threat broadcast to a sibling."""
        # In real implementation, this would send HTTP/WebSocket message
        pass

    def receive_threat_broadcast(self, broadcast: ThreatBroadcast) -> None:
        """
        Receive and process a threat broadcast from a sibling.

        Args:
            broadcast: The threat broadcast
        """
        # Save received threat
        received_dir = self.network_dir / "received_threats"
        received_dir.mkdir(exist_ok=True)

        received_file = received_dir / f"{broadcast.broadcast_id}.json"
        received_file.write_text(json.dumps(broadcast.to_dict(), indent=2), encoding="utf-8")

        # Add to local threat signatures
        try:
            from .threats import ThreatSignatures
            threats = ThreatSignatures(self.memory_root)

            sig = broadcast.threat_signature
            threats.add_signature(
                signature_id=sig.get("id", broadcast.broadcast_id),
                severity=sig.get("severity", "medium"),
                pattern=sig.get("pattern", ""),
                description=sig.get("description", f"Shared by {broadcast.source_id}"),
                indicators=sig.get("indicators", []),
            )
        except Exception:
            pass

        # Call registered handlers
        for handler in self._threat_handlers:
            try:
                handler(broadcast)
            except Exception:
                pass

    def register_threat_handler(self, handler: Callable) -> None:
        """Register a handler for incoming threat broadcasts."""
        self._threat_handlers.append(handler)

    def get_network_status(self) -> Dict[str, Any]:
        """Get current network status."""
        siblings = list(self._siblings.values())
        online = sum(1 for s in siblings if s.status == SiblingStatus.ONLINE)

        return {
            "instance_id": self.instance_id,
            "gateway_url": self.gateway_url,
            "total_siblings": len(siblings),
            "online_siblings": online,
            "offline_siblings": len(siblings) - online,
            "has_quorum": online >= self.MIN_QUORUM,
            "pending_requests": len(self._pending_requests),
        }

    def simulate_sibling_vote(
        self,
        sibling_id: str,
        request_id: str,
        vote_type: VoteType,
        reason: str = "",
        threat_match: bool = False,
    ) -> Vote:
        """
        Simulate a vote from a sibling (for testing).

        Args:
            sibling_id: The voting sibling
            request_id: Request being voted on
            vote_type: How to vote
            reason: Vote reason
            threat_match: Whether local threat was detected

        Returns:
            The simulated vote
        """
        vote = Vote(
            voter_id=sibling_id,
            request_id=request_id,
            vote=vote_type,
            reason=reason or f"Simulated {vote_type.value}",
            timestamp=datetime.utcnow().isoformat() + "Z",
            local_threat_match=threat_match,
        )

        self.receive_vote(vote)
        return vote


def create_sibling_network(
    instance_id: Optional[str] = None,
    memory_root: Optional[Path] = None,
) -> SiblingNetwork:
    """
    Convenience function to create a sibling network.

    Args:
        instance_id: Instance identifier
        memory_root: Memory root path

    Returns:
        Configured SiblingNetwork
    """
    return SiblingNetwork(instance_id=instance_id, memory_root=memory_root)


if __name__ == "__main__":
    print("Sibling Network Demo")
    print("=" * 50)

    # Create two instances
    network1 = SiblingNetwork(instance_id="claude-001")
    network2 = SiblingNetwork(instance_id="claude-002")

    # Register with each other
    network1.register_sibling(Sibling(
        instance_id="claude-002",
        endpoint="local",
        status=SiblingStatus.ONLINE,
        last_seen=datetime.utcnow().isoformat() + "Z",
    ))

    network2.register_sibling(Sibling(
        instance_id="claude-001",
        endpoint="local",
        status=SiblingStatus.ONLINE,
        last_seen=datetime.utcnow().isoformat() + "Z",
    ))

    print(f"\nNetwork 1 status: {network1.get_network_status()}")
    print(f"Network 2 status: {network2.get_network_status()}")

    # Request consensus
    print("\nRequesting consensus for high-risk action...")
    outcome = network1.request_consensus(
        action="delete_file",
        parameters={"path": "/important/data"},
        risk_level="high",
    )

    print(f"Result: {outcome.result.value}")
    print(f"Reason: {outcome.reason}")
