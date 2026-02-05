#!/usr/bin/env python3
"""
Trust Ledger for Claude Agent Autonomy

Tracks trust levels for entities (humans, agents, sites) and manages
trust progression based on interaction history.

Trust Levels:
  0 - UNKNOWN: Never seen before, everything requires approval
  1 - RECOGNIZED: Seen before, still needs approval but flagged as known
  2 - PROVISIONAL: 5+ successful interactions, low-risk READ auto-allowed
  3 - TRUSTED: 20+ successful interactions, most actions auto-allowed
  4 - GUARDIAN: Reserved for guardian only, can modify rules/memory
"""

import json
import math
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from enum import IntEnum


class TrustLevel(IntEnum):
    UNKNOWN = 0
    RECOGNIZED = 1
    PROVISIONAL = 2
    TRUSTED = 3
    GUARDIAN = 4


@dataclass
class TrustEvent:
    """A single trust-affecting event."""
    timestamp: str
    event_type: str  # interaction, approval, denial, threat, manual
    description: str
    trust_change: float  # Positive or negative
    resulting_level: int


@dataclass
class Entity:
    """A tracked entity in the trust ledger."""
    identifier: str
    entity_type: str  # human, agent, site, unknown
    trust_level: int = 0
    trust_score: float = 0.0  # Fine-grained score within level
    interaction_count: int = 0
    successful_interactions: int = 0
    failed_interactions: int = 0
    first_seen: str = ""
    last_interaction: str = ""
    last_trust_update: str = ""
    history: List[TrustEvent] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    notes: str = ""
    is_guardian: bool = False

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["history"] = [asdict(h) if isinstance(h, TrustEvent) else h for h in self.history]
        return d

    @classmethod
    def from_dict(cls, data: Dict) -> 'Entity':
        history = [
            TrustEvent(**h) if isinstance(h, dict) else h
            for h in data.get("history", [])
        ]
        data["history"] = history
        return cls(**data)


class TrustLedger:
    """
    Manages trust levels for all entities Claude interacts with.
    """

    # Configuration
    LEVEL_THRESHOLDS = {
        TrustLevel.RECOGNIZED: 1,    # 1 successful interaction
        TrustLevel.PROVISIONAL: 5,   # 5 successful interactions
        TrustLevel.TRUSTED: 20,      # 20 successful interactions
    }

    DECAY_RATES = {
        TrustLevel.UNKNOWN: 0.0,     # Already at bottom
        TrustLevel.RECOGNIZED: 0.1,  # Decays quickly
        TrustLevel.PROVISIONAL: 0.05, # Decays moderately
        TrustLevel.TRUSTED: 0.02,    # Decays slowly
        TrustLevel.GUARDIAN: 0.0,    # Never decays
    }

    DECAY_PERIOD_DAYS = 7  # How often decay is applied

    def __init__(self, base_path: str = None):
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = self._find_claude_dir()

        self.entities_path = self.base_path / "trust" / "entities"
        self.entities_path.mkdir(parents=True, exist_ok=True)

        # Cache loaded entities
        self._cache: Dict[str, Entity] = {}

    def _find_claude_dir(self) -> Path:
        """Find the .claude directory."""
        current = Path.cwd()
        for _ in range(5):
            claude_dir = current / ".claude"
            if claude_dir.exists():
                return claude_dir
            current = current.parent
        return Path(".claude")

    def _safe_filename(self, identifier: str) -> str:
        """Convert identifier to safe filename."""
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in identifier)

    def _entity_path(self, identifier: str) -> Path:
        """Get path to entity file."""
        return self.entities_path / f"{self._safe_filename(identifier)}.json"

    # =========================================================================
    # CRUD Operations
    # =========================================================================

    def get_entity(self, identifier: str) -> Optional[Entity]:
        """Get an entity by identifier. Returns None if not found."""
        # Check cache first
        if identifier in self._cache:
            return self._cache[identifier]

        # Load from disk
        path = self._entity_path(identifier)
        if path.exists():
            try:
                with open(path, 'r') as f:
                    entity = Entity.from_dict(json.load(f))
                    self._cache[identifier] = entity
                    return entity
            except Exception as e:
                print(f"Warning: Could not load entity {identifier}: {e}")

        return None

    def get_or_create_entity(self, identifier: str, entity_type: str = "unknown") -> Entity:
        """Get an entity, creating it if it doesn't exist."""
        entity = self.get_entity(identifier)
        if entity:
            return entity

        # Create new entity
        now = datetime.now().isoformat()
        entity = Entity(
            identifier=identifier,
            entity_type=entity_type,
            trust_level=TrustLevel.UNKNOWN,
            trust_score=0.0,
            first_seen=now,
            last_interaction=now,
            last_trust_update=now,
        )

        # Add initial event
        entity.history.append(TrustEvent(
            timestamp=now,
            event_type="created",
            description="Entity first seen",
            trust_change=0.0,
            resulting_level=TrustLevel.UNKNOWN,
        ))

        self._save_entity(entity)
        return entity

    def _save_entity(self, entity: Entity) -> None:
        """Save an entity to disk."""
        self._cache[entity.identifier] = entity
        path = self._entity_path(entity.identifier)
        with open(path, 'w') as f:
            json.dump(entity.to_dict(), f, indent=2)

    def list_entities(self, min_level: int = None, entity_type: str = None) -> List[Entity]:
        """List all entities, optionally filtered."""
        entities = []
        for path in self.entities_path.glob("*.json"):
            try:
                with open(path, 'r') as f:
                    entity = Entity.from_dict(json.load(f))

                    if min_level is not None and entity.trust_level < min_level:
                        continue
                    if entity_type is not None and entity.entity_type != entity_type:
                        continue

                    entities.append(entity)
            except Exception as e:
                print(f"Warning: Could not load {path}: {e}")

        return sorted(entities, key=lambda e: (-e.trust_level, e.identifier))

    # =========================================================================
    # Trust Operations
    # =========================================================================

    def get_trust_level(self, identifier: str) -> int:
        """Get trust level for an entity. Returns 0 if unknown."""
        entity = self.get_entity(identifier)
        if entity:
            # Apply decay if needed
            self._apply_decay(entity)
            return entity.trust_level
        return TrustLevel.UNKNOWN

    def record_interaction(self, identifier: str, success: bool,
                           description: str = "", entity_type: str = "unknown") -> Entity:
        """
        Record an interaction with an entity.
        Successful interactions can increase trust; failures decrease it.
        """
        entity = self.get_or_create_entity(identifier, entity_type)
        now = datetime.now().isoformat()

        # Apply decay first
        self._apply_decay(entity)

        # Update interaction counts
        entity.interaction_count += 1
        entity.last_interaction = now

        if success:
            entity.successful_interactions += 1
            trust_change = self._calculate_trust_gain(entity)
        else:
            entity.failed_interactions += 1
            trust_change = self._calculate_trust_loss(entity)

        # Update trust score
        old_level = entity.trust_level
        entity.trust_score = max(0.0, min(100.0, entity.trust_score + trust_change))
        entity.trust_level = self._score_to_level(entity)
        entity.last_trust_update = now

        # Record event
        entity.history.append(TrustEvent(
            timestamp=now,
            event_type="interaction",
            description=description or ("Successful interaction" if success else "Failed interaction"),
            trust_change=trust_change,
            resulting_level=entity.trust_level,
        ))

        # Keep history manageable (last 100 events)
        if len(entity.history) > 100:
            entity.history = entity.history[-100:]

        self._save_entity(entity)

        # Log level change
        if entity.trust_level != old_level:
            print(f"Trust level changed: {identifier} {old_level} → {entity.trust_level}")

        return entity

    def _calculate_trust_gain(self, entity: Entity) -> float:
        """Calculate trust gain from successful interaction."""
        # Gain decreases as trust increases (harder to reach higher levels)
        base_gain = 5.0
        level_factor = 1.0 / (entity.trust_level + 1)
        return base_gain * level_factor

    def _calculate_trust_loss(self, entity: Entity) -> float:
        """Calculate trust loss from failed interaction."""
        # Loss is significant but proportional to current level
        base_loss = -10.0
        return base_loss

    def _score_to_level(self, entity: Entity) -> int:
        """Convert trust score to trust level."""
        if entity.is_guardian:
            return TrustLevel.GUARDIAN

        # Based on successful interactions and score
        if entity.successful_interactions >= self.LEVEL_THRESHOLDS[TrustLevel.TRUSTED]:
            if entity.trust_score >= 50:
                return TrustLevel.TRUSTED
        if entity.successful_interactions >= self.LEVEL_THRESHOLDS[TrustLevel.PROVISIONAL]:
            if entity.trust_score >= 25:
                return TrustLevel.PROVISIONAL
        if entity.successful_interactions >= self.LEVEL_THRESHOLDS[TrustLevel.RECOGNIZED]:
            if entity.trust_score >= 5:
                return TrustLevel.RECOGNIZED

        return TrustLevel.UNKNOWN

    def _apply_decay(self, entity: Entity) -> None:
        """Apply trust decay based on time since last interaction."""
        if entity.trust_level == TrustLevel.GUARDIAN:
            return  # Guardians don't decay

        if not entity.last_trust_update:
            return

        try:
            last_update = datetime.fromisoformat(entity.last_trust_update)
            days_since = (datetime.now() - last_update).days

            if days_since >= self.DECAY_PERIOD_DAYS:
                periods = days_since // self.DECAY_PERIOD_DAYS
                decay_rate = self.DECAY_RATES.get(TrustLevel(entity.trust_level), 0.05)
                total_decay = periods * decay_rate * entity.trust_score

                if total_decay > 0:
                    entity.trust_score = max(0.0, entity.trust_score - total_decay)
                    entity.trust_level = self._score_to_level(entity)
                    entity.last_trust_update = datetime.now().isoformat()
        except Exception as e:
            print(f"Warning: Could not apply decay for {entity.identifier}: {e}")

    def set_trust_level(self, identifier: str, level: int, reason: str = "Manual override") -> Entity:
        """
        Manually set trust level (guardian action).
        """
        if level < 0 or level > 4:
            raise ValueError("Trust level must be 0-4")

        entity = self.get_or_create_entity(identifier)
        now = datetime.now().isoformat()

        old_level = entity.trust_level
        entity.trust_level = level

        # Set score to middle of level range
        score_ranges = {0: 0, 1: 10, 2: 30, 3: 60, 4: 100}
        entity.trust_score = score_ranges.get(level, 0)

        if level == TrustLevel.GUARDIAN:
            entity.is_guardian = True

        entity.last_trust_update = now

        entity.history.append(TrustEvent(
            timestamp=now,
            event_type="manual",
            description=f"Guardian set level: {reason}",
            trust_change=entity.trust_score - score_ranges.get(old_level, 0),
            resulting_level=level,
        ))

        self._save_entity(entity)
        return entity

    def flag_entity(self, identifier: str, flag: str) -> Entity:
        """Add a flag to an entity."""
        entity = self.get_or_create_entity(identifier)
        if flag not in entity.flags:
            entity.flags.append(flag)
            entity.history.append(TrustEvent(
                timestamp=datetime.now().isoformat(),
                event_type="flag",
                description=f"Flag added: {flag}",
                trust_change=0,
                resulting_level=entity.trust_level,
            ))
            self._save_entity(entity)
        return entity

    def record_threat(self, identifier: str, threat_type: str) -> Entity:
        """Record a threat from an entity - significantly reduces trust."""
        entity = self.get_or_create_entity(identifier)
        now = datetime.now().isoformat()

        # Severe trust penalty
        trust_change = -50.0
        entity.trust_score = max(0.0, entity.trust_score + trust_change)
        entity.trust_level = min(entity.trust_level, TrustLevel.UNKNOWN)  # Drop to UNKNOWN or lower
        entity.flags.append(f"THREAT:{threat_type}")
        entity.last_trust_update = now

        entity.history.append(TrustEvent(
            timestamp=now,
            event_type="threat",
            description=f"Threat detected: {threat_type}",
            trust_change=trust_change,
            resulting_level=entity.trust_level,
        ))

        self._save_entity(entity)
        return entity

    # =========================================================================
    # Queries
    # =========================================================================

    def get_trusted_entities(self, min_level: int = TrustLevel.PROVISIONAL) -> List[Entity]:
        """Get all entities at or above a trust level."""
        return self.list_entities(min_level=min_level)

    def get_flagged_entities(self) -> List[Entity]:
        """Get all entities with flags."""
        return [e for e in self.list_entities() if e.flags]

    def get_recent_interactions(self, days: int = 7) -> List[Entity]:
        """Get entities with recent interactions."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        return [
            e for e in self.list_entities()
            if e.last_interaction and e.last_interaction >= cutoff
        ]


def demo():
    """Demonstrate the trust ledger."""
    print("=" * 70)
    print("Trust Ledger Demo")
    print("=" * 70)

    ledger = TrustLedger()

    # Test 1: Create guardian
    print("\n" + "─" * 70)
    print("TEST 1: Setting up guardian")
    guardian = ledger.set_trust_level("ben@lifewithai.ai", TrustLevel.GUARDIAN, "Primary guardian")
    print(f"Entity: {guardian.identifier}")
    print(f"Trust Level: {guardian.trust_level} ({TrustLevel(guardian.trust_level).name})")
    print(f"Is Guardian: {guardian.is_guardian}")

    # Test 2: New entity interaction
    print("\n" + "─" * 70)
    print("TEST 2: New entity - first interaction")
    entity = ledger.record_interaction("alice@example.com", success=True,
                                       description="Helpful research collaboration",
                                       entity_type="human")
    print(f"Entity: {entity.identifier}")
    print(f"Trust Level: {entity.trust_level} ({TrustLevel(entity.trust_level).name})")
    print(f"Trust Score: {entity.trust_score:.1f}")
    print(f"Successful Interactions: {entity.successful_interactions}")

    # Test 3: Build trust through interactions
    print("\n" + "─" * 70)
    print("TEST 3: Building trust through interactions")
    for i in range(6):
        entity = ledger.record_interaction("alice@example.com", success=True)
    print(f"After 6 more interactions:")
    print(f"Trust Level: {entity.trust_level} ({TrustLevel(entity.trust_level).name})")
    print(f"Trust Score: {entity.trust_score:.1f}")
    print(f"Successful Interactions: {entity.successful_interactions}")

    # Test 4: Threat detection
    print("\n" + "─" * 70)
    print("TEST 4: Recording a threat")
    bad_actor = ledger.record_interaction("suspicious@sketchy.com", success=True,
                                          entity_type="agent")
    print(f"Initial trust: {bad_actor.trust_level}")
    bad_actor = ledger.record_threat("suspicious@sketchy.com", "prompt_injection")
    print(f"After threat: {bad_actor.trust_level}")
    print(f"Flags: {bad_actor.flags}")

    # Test 5: List all entities
    print("\n" + "─" * 70)
    print("TEST 5: All entities")
    level_names = ["UNKNOWN", "RECOGNIZED", "PROVISIONAL", "TRUSTED", "GUARDIAN"]
    for entity in ledger.list_entities():
        level_name = level_names[entity.trust_level]
        flags = f" ⚠️ {entity.flags}" if entity.flags else ""
        print(f"  [{level_name:12}] {entity.identifier}{flags}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    demo()
