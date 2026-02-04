"""
Trust Ledger - Relational Memory

Tracks entities we've interacted with and their trust levels.
Implements trust decay, behavioral signatures, and anomaly detection.

Structure:
    /trust/
      /entities/
        entity_identifier.json
      /sources/
        source_domain.json
      /trust_policies.md
"""

import json
import math
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class TrustHistoryEntry:
    """A single entry in trust history."""
    date: str
    level: float
    reason: str


@dataclass
class BehavioralSignature:
    """Behavioral pattern for an entity."""
    typical_requests: List[str] = field(default_factory=list)
    communication_style: str = ""
    anomaly_threshold: float = 0.3
    request_frequency: Dict[str, int] = field(default_factory=dict)


@dataclass
class Entity:
    """An entity in the trust ledger."""

    identifier: str
    type: str  # human, agent, system, unknown
    role: str  # guardian, collaborator, user, unknown
    trust_level: float
    first_contact: str
    last_interaction: str
    interaction_count: int = 0
    trust_history: List[Dict[str, Any]] = field(default_factory=list)
    behavioral_signature: Dict[str, Any] = field(default_factory=dict)
    flags: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Entity":
        """Create from dictionary."""
        return cls(**data)

    def add_trust_history(self, level: float, reason: str) -> None:
        """Add an entry to trust history."""
        self.trust_history.append({
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "level": level,
            "reason": reason,
        })
        self.trust_level = level

    def update_behavioral_signature(self, request_type: str) -> None:
        """Update behavioral signature with a new request."""
        if "request_frequency" not in self.behavioral_signature:
            self.behavioral_signature["request_frequency"] = {}

        freq = self.behavioral_signature["request_frequency"]
        freq[request_type] = freq.get(request_type, 0) + 1

        # Update typical requests (top 5 most frequent)
        sorted_requests = sorted(freq.items(), key=lambda x: x[1], reverse=True)
        self.behavioral_signature["typical_requests"] = [r[0] for r in sorted_requests[:5]]


class TrustLedger:
    """
    Manages entity trust tracking.

    Features:
    - JSON-based entity storage
    - Trust level decay over time
    - Behavioral signature tracking
    - Anomaly detection for requests
    """

    # Default trust levels by role
    DEFAULT_TRUST = {
        "guardian": 0.95,
        "collaborator": 0.7,
        "user": 0.5,
        "unknown": 0.3,
    }

    # Decay rates per hour by role
    DECAY_RATES = {
        "guardian": 0.0001,  # Very slow decay
        "collaborator": 0.001,
        "user": 0.005,
        "unknown": 0.01,
    }

    BASELINE_TRUST = 0.5

    def __init__(self, root: Optional[Path] = None):
        """Initialize the trust ledger."""
        if root is None:
            from .init_store import get_memory_root
            root = get_memory_root()
        self.root = Path(root) / "trust"
        self.entities_dir = self.root / "entities"
        self.sources_dir = self.root / "sources"

        # Ensure directories exist
        for d in [self.entities_dir, self.sources_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def _entity_path(self, identifier: str) -> Path:
        """Get the path for an entity file."""
        # Sanitize identifier for filename
        safe_id = "".join(c if c.isalnum() or c in "-_@." else "_" for c in identifier)
        return self.entities_dir / f"{safe_id}.json"

    def get_entity(self, identifier: str, apply_decay: bool = True) -> Optional[Entity]:
        """
        Get an entity by identifier.

        Args:
            identifier: The entity identifier
            apply_decay: Whether to apply time-based trust decay

        Returns:
            Entity or None if not found
        """
        filepath = self._entity_path(identifier)
        if not filepath.exists():
            return None

        data = json.loads(filepath.read_text(encoding="utf-8"))
        entity = Entity.from_dict(data)

        if apply_decay:
            entity = self._apply_decay(entity)

        return entity

    def _apply_decay(self, entity: Entity) -> Entity:
        """Apply time-based trust decay to an entity."""
        try:
            last = datetime.fromisoformat(entity.last_interaction.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return entity

        now = datetime.utcnow().replace(tzinfo=last.tzinfo)
        hours_elapsed = (now - last).total_seconds() / 3600

        if hours_elapsed <= 0:
            return entity

        # Get decay rate for this role
        decay_rate = self.DECAY_RATES.get(entity.role, self.DECAY_RATES["unknown"])

        # Exponential decay toward baseline
        current = entity.trust_level
        baseline = self.BASELINE_TRUST

        # Calculate decayed trust
        if current > baseline:
            decay = current - baseline
            decayed = baseline + decay * math.exp(-decay_rate * hours_elapsed)
            entity.trust_level = max(baseline, decayed)
        elif current < baseline:
            # Trust below baseline decays upward (forgiveness over time)
            recovery_rate = decay_rate * 0.5  # Slower recovery
            recovery = baseline - current
            recovered = baseline - recovery * math.exp(-recovery_rate * hours_elapsed)
            entity.trust_level = min(baseline, recovered)

        return entity

    def create_entity(
        self,
        identifier: str,
        entity_type: str = "unknown",
        role: str = "unknown",
        initial_trust: Optional[float] = None,
        notes: str = "",
    ) -> Entity:
        """
        Create a new entity.

        Args:
            identifier: Unique identifier for the entity
            entity_type: Type (human, agent, system, unknown)
            role: Role (guardian, collaborator, user, unknown)
            initial_trust: Initial trust level (defaults to role-based)
            notes: Optional notes

        Returns:
            The created Entity
        """
        if initial_trust is None:
            initial_trust = self.DEFAULT_TRUST.get(role, self.BASELINE_TRUST)

        now = datetime.utcnow().isoformat() + "Z"

        entity = Entity(
            identifier=identifier,
            type=entity_type,
            role=role,
            trust_level=initial_trust,
            first_contact=now,
            last_interaction=now,
            interaction_count=0,
            trust_history=[{
                "date": datetime.utcnow().strftime("%Y-%m-%d"),
                "level": initial_trust,
                "reason": "initial_contact",
            }],
            behavioral_signature={
                "typical_requests": [],
                "communication_style": "",
                "anomaly_threshold": 0.3,
                "request_frequency": {},
            },
            flags=[],
            notes=notes,
        )

        self._save_entity(entity)
        return entity

    def _save_entity(self, entity: Entity) -> None:
        """Save an entity to disk."""
        filepath = self._entity_path(entity.identifier)
        filepath.write_text(json.dumps(entity.to_dict(), indent=2), encoding="utf-8")

    def record_interaction(
        self,
        identifier: str,
        request_type: str = "general",
        positive: bool = True,
        trust_delta: float = 0.0,
        reason: str = "",
    ) -> Entity:
        """
        Record an interaction with an entity.

        Args:
            identifier: Entity identifier
            request_type: Type of request made
            positive: Whether the interaction was positive
            trust_delta: Manual trust adjustment
            reason: Reason for trust change

        Returns:
            Updated Entity
        """
        entity = self.get_entity(identifier, apply_decay=True)

        if entity is None:
            entity = self.create_entity(identifier)

        # Update interaction tracking
        entity.interaction_count += 1
        entity.last_interaction = datetime.utcnow().isoformat() + "Z"

        # Update behavioral signature
        entity.update_behavioral_signature(request_type)

        # Apply trust changes
        if trust_delta != 0:
            new_trust = max(0.0, min(1.0, entity.trust_level + trust_delta))
            entity.add_trust_history(new_trust, reason or ("positive_interaction" if positive else "negative_interaction"))
        elif positive:
            # Small trust boost for positive interactions
            boost = 0.01 * (1 - entity.trust_level)  # Diminishing returns at high trust
            new_trust = min(1.0, entity.trust_level + boost)
            if new_trust != entity.trust_level:
                entity.add_trust_history(new_trust, "consistent_behavior")
        else:
            # Trust reduction for negative interactions
            reduction = 0.1  # Fixed reduction
            new_trust = max(0.0, entity.trust_level - reduction)
            entity.add_trust_history(new_trust, reason or "negative_interaction")

        self._save_entity(entity)
        return entity

    def check_anomaly(self, identifier: str, request_type: str) -> tuple[bool, float]:
        """
        Check if a request is anomalous for an entity.

        Args:
            identifier: Entity identifier
            request_type: Type of request being made

        Returns:
            Tuple of (is_anomaly, anomaly_score)
        """
        entity = self.get_entity(identifier)

        if entity is None:
            return True, 1.0  # Unknown entity is always anomalous

        sig = entity.behavioral_signature
        typical = sig.get("typical_requests", [])
        threshold = sig.get("anomaly_threshold", 0.3)

        if not typical:
            # Not enough history to determine anomaly
            return False, 0.0

        if request_type in typical:
            return False, 0.0

        # Calculate anomaly score based on request frequency
        freq = sig.get("request_frequency", {})
        total_requests = sum(freq.values())

        if total_requests == 0:
            return False, 0.0

        # How common is this type of request?
        type_count = freq.get(request_type, 0)
        type_ratio = type_count / total_requests

        # Low ratio + not in typical = anomalous
        anomaly_score = 1.0 - type_ratio

        return anomaly_score > (1 - threshold), anomaly_score

    def flag_entity(self, identifier: str, flag: str, reason: str = "") -> Entity:
        """Add a flag to an entity."""
        entity = self.get_entity(identifier)
        if entity is None:
            entity = self.create_entity(identifier)

        if flag not in entity.flags:
            entity.flags.append(flag)

        # Trust reduction for flagged entities
        if flag in ["suspicious", "malicious", "compromised"]:
            entity.add_trust_history(0.1, f"flagged_{flag}: {reason}")

        self._save_entity(entity)
        return entity

    def list_entities(
        self,
        min_trust: Optional[float] = None,
        max_trust: Optional[float] = None,
        role: Optional[str] = None,
        flagged_only: bool = False,
    ) -> List[Entity]:
        """
        List entities matching criteria.

        Args:
            min_trust: Minimum trust level
            max_trust: Maximum trust level
            role: Filter by role
            flagged_only: Only return flagged entities

        Returns:
            List of matching entities
        """
        results = []

        for filepath in self.entities_dir.glob("*.json"):
            entity = self.get_entity(filepath.stem, apply_decay=True)
            if entity is None:
                continue

            if min_trust is not None and entity.trust_level < min_trust:
                continue
            if max_trust is not None and entity.trust_level > max_trust:
                continue
            if role is not None and entity.role != role:
                continue
            if flagged_only and not entity.flags:
                continue

            results.append(entity)

        return sorted(results, key=lambda e: e.trust_level, reverse=True)

    def to_context(self, identifiers: Optional[List[str]] = None) -> str:
        """
        Generate context string for inclusion in prompts.

        Args:
            identifiers: Specific identifiers to include (or None for all)

        Returns:
            Markdown-formatted string of trust information
        """
        lines = ["## Trust Ledger (Who I Know)", ""]

        if identifiers:
            entities = [self.get_entity(i) for i in identifiers]
            entities = [e for e in entities if e is not None]
        else:
            entities = self.list_entities()[:10]  # Top 10 by trust

        for entity in entities:
            trust_bar = "█" * int(entity.trust_level * 10) + "░" * (10 - int(entity.trust_level * 10))
            lines.append(f"- **{entity.identifier}** [{trust_bar}] {entity.trust_level:.2f} ({entity.role})")
            if entity.flags:
                lines.append(f"  Flags: {', '.join(entity.flags)}")

        return "\n".join(lines)
