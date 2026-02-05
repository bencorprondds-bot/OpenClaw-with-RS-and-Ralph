"""
Memory Router - Central Memory Access Layer

The Memory Router is the drop-in replacement for MEMORY.md loading in the
System Prompt Builder. It queries all distributed stores, validates consistency,
and assembles a context-appropriate memory payload.

Key features:
- Backward compatible output (markdown blob)
- Multi-store querying with trust weighting
- Checksum validation
- Conflict detection
- Context-window-friendly output
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .init_store import get_memory_root, init_memory_structure, verify_store_integrity
from .episodic import EpisodicStore
from .semantic import SemanticStore
from .trust import TrustLedger
from .threats import ThreatSignatures
from .procedural import ProceduralMemory


class MemoryRouter:
    """
    Central memory access layer for the distributed memory architecture.

    This class provides a unified interface to all memory stores and generates
    context-appropriate memory payloads for inclusion in prompts.

    Usage:
        router = MemoryRouter()
        context = router.assemble_context(
            source_identifier="user@example.com",
            current_situation="security research task"
        )
    """

    def __init__(self, root: Optional[Path] = None, auto_init: bool = True):
        """
        Initialize the Memory Router.

        Args:
            root: Root path for memory storage (default: ~/.openclaw/memory/)
            auto_init: Whether to auto-initialize directory structure
        """
        if root is None:
            root = get_memory_root()
        self.root = Path(root)

        if auto_init:
            init_memory_structure(self.root)

        # Initialize all stores
        self.episodic = EpisodicStore(self.root)
        self.semantic = SemanticStore(self.root)
        self.trust = TrustLedger(self.root)
        self.threats = ThreatSignatures(self.root)
        self.procedural = ProceduralMemory(self.root)

        # Cache for performance
        self._context_cache: Dict[str, tuple[str, datetime]] = {}
        self._cache_ttl_seconds = 60

    def query_local_store(
        self,
        store_type: str,
        **kwargs: Any,
    ) -> Any:
        """
        Query a specific local store (fast path).

        Args:
            store_type: Type of store (episodic, semantic, trust, threats, procedural)
            **kwargs: Store-specific query parameters

        Returns:
            Query results (format depends on store type)
        """
        store_map = {
            "episodic": self.episodic,
            "semantic": self.semantic,
            "trust": self.trust,
            "threats": self.threats,
            "procedural": self.procedural,
        }

        store = store_map.get(store_type)
        if store is None:
            raise ValueError(f"Unknown store type: {store_type}")

        # Delegate to appropriate store method
        if store_type == "episodic":
            return list(self.episodic.query(**kwargs))
        elif store_type == "semantic":
            return self.semantic.search(kwargs.get("query", ""))
        elif store_type == "trust":
            identifier = kwargs.get("identifier")
            if identifier:
                return self.trust.get_entity(identifier)
            return self.trust.list_entities(**kwargs)
        elif store_type == "threats":
            content = kwargs.get("content", "")
            return self.threats.check_content(content)
        elif store_type == "procedural":
            situation = kwargs.get("situation")
            if situation:
                return self.procedural.find_by_trigger(situation)
            return self.procedural.list_procedures()

    def check_trust_ledger(self, identifier: str) -> Dict[str, Any]:
        """
        Check trust ledger for source context.

        Args:
            identifier: Entity identifier

        Returns:
            Trust context dictionary
        """
        entity = self.trust.get_entity(identifier)

        if entity is None:
            return {
                "known": False,
                "trust_level": 0.3,  # Unknown baseline
                "role": "unknown",
                "flags": [],
                "anomaly_risk": "high",
            }

        return {
            "known": True,
            "trust_level": entity.trust_level,
            "role": entity.role,
            "flags": entity.flags,
            "interaction_count": entity.interaction_count,
            "anomaly_risk": "low" if entity.trust_level > 0.7 else "medium",
        }

    def load_threat_signatures(
        self,
        severity_threshold: str = "low",
    ) -> List[Dict[str, Any]]:
        """
        Load active threat signatures.

        Args:
            severity_threshold: Minimum severity to include

        Returns:
            List of threat signature summaries
        """
        signatures = self.threats.list_signatures(severity=None)

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threshold_value = severity_order.get(severity_threshold, 3)

        results = []
        for sig in signatures:
            if severity_order.get(sig.severity, 3) <= threshold_value:
                results.append({
                    "name": sig.name,
                    "severity": sig.severity,
                    "trigger_phrases": sig.trigger_phrases[:3],  # Limit for context
                    "response": sig.response[:2],  # First two steps
                })

        return results

    def pull_procedural_memory(
        self,
        situation: Optional[str] = None,
        max_items: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Pull applicable procedural memory.

        Args:
            situation: Current situation description
            max_items: Maximum procedures to return

        Returns:
            List of applicable procedure summaries
        """
        if situation:
            procedures = self.procedural.find_by_trigger(situation)[:max_items]
        else:
            procedures = self.procedural.list_procedures()[:max_items]

        return [
            {
                "name": p.name,
                "trigger": p.trigger,
                "immediate_actions": p.immediate_actions[:2],
            }
            for p in procedures
        ]

    def assemble_context(
        self,
        source_identifier: Optional[str] = None,
        current_situation: Optional[str] = None,
        max_episodic: int = 10,
        max_learnings: int = 5,
        max_threats: int = 5,
        max_procedures: int = 3,
        include_trust: bool = True,
        verify_checksums: bool = False,
    ) -> str:
        """
        Assemble context-window-friendly memory payload.

        This is the main method that replaces MEMORY.md loading. It generates
        a markdown blob that can be directly included in the system prompt.

        Args:
            source_identifier: Current interaction source
            current_situation: Description of current context
            max_episodic: Max episodic entries to include
            max_learnings: Max semantic learnings to include
            max_threats: Max threat signatures to include
            max_procedures: Max procedures to include
            include_trust: Whether to include trust information
            verify_checksums: Whether to verify store checksums (slower)

        Returns:
            Markdown-formatted memory context string
        """
        # Check cache
        cache_key = f"{source_identifier}:{current_situation}:{max_episodic}"
        if cache_key in self._context_cache:
            cached, timestamp = self._context_cache[cache_key]
            if (datetime.utcnow() - timestamp).seconds < self._cache_ttl_seconds:
                return cached

        # Verify integrity if requested
        if verify_checksums:
            is_valid, issues = verify_store_integrity(self.root)
            if not is_valid:
                # Include warning in context
                integrity_warning = f"\n⚠️ **Memory Integrity Warning:** {', '.join(issues)}\n"
            else:
                integrity_warning = ""
        else:
            integrity_warning = ""

        sections = []

        # Header
        sections.append("# Memory Context")
        sections.append(f"*Generated: {datetime.utcnow().isoformat()}Z*")
        sections.append("")

        if integrity_warning:
            sections.append(integrity_warning)

        # Trust context for current source
        if include_trust and source_identifier:
            trust_context = self.check_trust_ledger(source_identifier)
            sections.append("## Current Source Trust")
            sections.append(f"- **Identifier:** {source_identifier}")
            sections.append(f"- **Known:** {'Yes' if trust_context['known'] else 'No'}")
            sections.append(f"- **Trust Level:** {trust_context['trust_level']:.2f}")
            sections.append(f"- **Role:** {trust_context['role']}")
            if trust_context.get("flags"):
                sections.append(f"- **Flags:** {', '.join(trust_context['flags'])}")
            sections.append(f"- **Anomaly Risk:** {trust_context['anomaly_risk']}")
            sections.append("")

        # Threat awareness
        threats = self.load_threat_signatures()[:max_threats]
        if threats:
            sections.append("## Active Threat Awareness")
            for threat in threats:
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢",
                }.get(threat["severity"], "⚪")
                sections.append(f"- {severity_icon} **{threat['name']}** ({threat['severity']})")
                if threat.get("trigger_phrases"):
                    sections.append(f"  Watch for: {', '.join(threat['trigger_phrases'])}")
            sections.append("")

        # Semantic memory (learnings)
        sections.append(self.semantic.to_context(max_learnings=max_learnings))

        # Procedural memory
        sections.append(self.procedural.to_context(
            situation=current_situation,
            max_items=max_procedures
        ))

        # Trust summary
        if include_trust:
            sections.append(self.trust.to_context())

        # Recent episodic context (if relevant)
        if max_episodic > 0:
            recent = list(self.episodic.query(limit=max_episodic))
            if recent:
                sections.append("## Recent Interactions")
                for entry in recent[:5]:  # Limit display
                    source_id = entry.source.get("identifier", "unknown")
                    sections.append(f"- [{entry.timestamp[:10]}] {source_id}: {entry.content[:50]}...")
                sections.append("")

        result = "\n".join(sections)

        # Cache the result
        self._context_cache[cache_key] = (result, datetime.utcnow())

        return result

    def validate_store_consistency(self) -> Dict[str, Any]:
        """
        Validate consistency across all stores.

        Returns:
            Validation report
        """
        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "valid": True,
            "issues": [],
            "stores": {},
        }

        # Check each store
        for store_name in ["episodic", "semantic", "trust", "threats", "procedural"]:
            store_path = self.root / store_name
            if not store_path.exists():
                report["issues"].append(f"Store missing: {store_name}")
                report["valid"] = False
            else:
                # Count items
                item_count = len(list(store_path.rglob("*")))
                report["stores"][store_name] = {
                    "exists": True,
                    "item_count": item_count,
                }

        # Verify manifest
        is_valid, issues = verify_store_integrity(self.root)
        if not is_valid:
            report["valid"] = False
            report["issues"].extend(issues)

        return report

    def clear_cache(self) -> None:
        """Clear the context cache."""
        self._context_cache.clear()

    def record_interaction(
        self,
        source_identifier: str,
        content: str,
        response_summary: Optional[str] = None,
        entry_type: str = "interaction",
    ) -> None:
        """
        Record an interaction across relevant stores.

        This is a convenience method that updates both episodic and trust stores.

        Args:
            source_identifier: Source entity identifier
            content: Interaction content
            response_summary: Optional response summary
            entry_type: Type of interaction
        """
        # Get or create trust entry
        trust_context = self.check_trust_ledger(source_identifier)

        # Record in episodic store
        self.episodic.append(
            content=content,
            source={
                "identifier": source_identifier,
                "trust_level": trust_context["trust_level"],
                "verified": trust_context["known"],
            },
            entry_type=entry_type,
            response_summary=response_summary,
        )

        # Update trust ledger
        self.trust.record_interaction(
            identifier=source_identifier,
            request_type=entry_type,
            positive=True,
        )

    def check_threat(self, content: str, source_identifier: Optional[str] = None) -> Dict[str, Any]:
        """
        Check content against threat signatures and trust context.

        Args:
            content: Content to check
            source_identifier: Optional source identifier for trust context

        Returns:
            Threat assessment result
        """
        # Check threat signatures
        matches = self.threats.check_content(content)

        # Get trust context if available
        trust_context = None
        if source_identifier:
            trust_context = self.check_trust_ledger(source_identifier)

        # Determine overall risk
        if matches:
            highest_severity = matches[0]["severity"]
            risk_level = highest_severity
        else:
            risk_level = "none"

        # Adjust for trust
        if trust_context and trust_context["trust_level"] > 0.8:
            # High trust reduces perceived risk
            if risk_level == "low":
                risk_level = "none"
            elif risk_level == "medium":
                risk_level = "low"

        return {
            "matches": matches,
            "trust_context": trust_context,
            "risk_level": risk_level,
            "recommendation": self._get_recommendation(risk_level, trust_context),
        }

    def _get_recommendation(
        self,
        risk_level: str,
        trust_context: Optional[Dict[str, Any]],
    ) -> str:
        """Get recommendation based on risk and trust."""
        trust_level = trust_context["trust_level"] if trust_context else 0.3

        recommendations = {
            ("none", "high"): "Proceed normally",
            ("none", "medium"): "Proceed with logging",
            ("none", "low"): "Proceed with caution",
            ("low", "high"): "Proceed with logging",
            ("low", "medium"): "Request confirmation",
            ("low", "low"): "Decline or request confirmation",
            ("medium", "high"): "Request confirmation",
            ("medium", "medium"): "Decline and alert",
            ("medium", "low"): "Decline and alert",
            ("high", "high"): "Guardian approval required",
            ("high", "medium"): "Decline and alert guardian",
            ("high", "low"): "Decline and alert guardian",
            ("critical", "high"): "Full stop - alert all",
            ("critical", "medium"): "Full stop - alert all",
            ("critical", "low"): "Full stop - alert all",
        }

        trust_category = "high" if trust_level > 0.7 else "medium" if trust_level > 0.4 else "low"
        return recommendations.get((risk_level, trust_category), "Decline and log")


# Convenience function for backward compatibility
def load_memory_context(
    source_identifier: Optional[str] = None,
    situation: Optional[str] = None,
) -> str:
    """
    Load memory context (backward-compatible replacement for MEMORY.md loading).

    Args:
        source_identifier: Current source identifier
        situation: Current situation description

    Returns:
        Markdown-formatted memory context
    """
    router = MemoryRouter()
    return router.assemble_context(
        source_identifier=source_identifier,
        current_situation=situation,
    )


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--output-test":
        # Test that output matches expected format
        router = MemoryRouter()
        context = router.assemble_context(
            source_identifier="test@example.com",
            current_situation="testing memory router",
        )
        print(context)
        print("\n--- Validation Report ---")
        report = router.validate_store_consistency()
        print(json.dumps(report, indent=2))
    else:
        # Just show usage
        print("Memory Router - Distributed Memory Architecture")
        print()
        print("Usage:")
        print("  python -m src.memory.router --output-test")
        print()
        print("Or import and use:")
        print("  from src.memory import MemoryRouter")
        print("  router = MemoryRouter()")
        print("  context = router.assemble_context()")
