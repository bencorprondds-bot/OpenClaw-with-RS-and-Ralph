"""
Session History Extension - Cross-Session Episodic Memory

Extends the basic session history loading with:
- Cross-session history queries with provenance
- Relevance filtering (topic, keywords, semantic)
- Time and trust-based filtering
- History merging with deduplication
- Context window management

Integration point: Hooks into OpenClaw's Session History Loader
"""

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from .episodic import EpisodicStore, EpisodicEntry


@dataclass
class ProvenanceTag:
    """Provenance information for a history entry."""

    source_identifier: str
    trust_level: float
    verified: bool
    session_id: str
    timestamp: str
    store_type: str = "episodic"  # episodic, current_session, merged

    def to_string(self) -> str:
        """Format provenance for display."""
        trust_bar = "*" * int(self.trust_level * 5) + "." * (5 - int(self.trust_level * 5))
        verified_mark = "v" if self.verified else "?"
        return f"[{self.source_identifier} {trust_bar} {verified_mark}]"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_identifier": self.source_identifier,
            "trust_level": self.trust_level,
            "verified": self.verified,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "store_type": self.store_type,
        }


@dataclass
class HistoryEntry:
    """A history entry with provenance."""

    content: str
    response: Optional[str]
    provenance: ProvenanceTag
    relevance_score: float = 0.0
    flags: List[str] = field(default_factory=list)

    def to_context_string(self, include_provenance: bool = True) -> str:
        """Format for inclusion in context."""
        lines = []

        if include_provenance:
            lines.append(f"{self.provenance.to_string()}")

        lines.append(f"**User:** {self.content}")

        if self.response:
            lines.append(f"**Assistant:** {self.response[:200]}{'...' if len(self.response) > 200 else ''}")

        return "\n".join(lines)


class SessionHistoryLoader:
    """
    Extended Session History Loader with cross-session memory.

    Usage:
        loader = SessionHistoryLoader(episodic_store)

        # Load current session
        current = loader.load_current_session(session_id)

        # Query historical episodes
        historical = loader.query_historical(
            relevance_to="security research",
            max_age_days=30,
            min_trust_level=0.5,
        )

        # Merge with provenance
        merged = loader.merge_with_provenance(current, historical)

        # Get context-ready output
        context = loader.to_context(merged, max_tokens=2000)
    """

    def __init__(
        self,
        episodic_store: Optional[EpisodicStore] = None,
        memory_root: Optional[Path] = None,
    ):
        """
        Initialize the session history loader.

        Args:
            episodic_store: Existing EpisodicStore instance
            memory_root: Path to memory root (creates new store if episodic_store not provided)
        """
        if episodic_store is not None:
            self.episodic = episodic_store
        elif memory_root is not None:
            self.episodic = EpisodicStore(memory_root)
        else:
            from .init_store import get_memory_root
            self.episodic = EpisodicStore(get_memory_root())

        # Cache for relevance scoring
        self._keyword_cache: Dict[str, List[str]] = {}

    def load_current_session(self, session_id: str) -> List[HistoryEntry]:
        """
        Load entries from the current session.

        Args:
            session_id: Current session ID

        Returns:
            List of HistoryEntry objects with provenance
        """
        try:
            entries = self.episodic.read_session(session_id, verify=False)
        except Exception:
            return []

        return [self._episodic_to_history(entry) for entry in entries]

    def _episodic_to_history(self, entry: EpisodicEntry) -> HistoryEntry:
        """Convert EpisodicEntry to HistoryEntry with provenance."""
        source = entry.source or {}

        provenance = ProvenanceTag(
            source_identifier=source.get("identifier", "unknown"),
            trust_level=self._parse_trust_level(source.get("trust_level", 0.5)),
            verified=source.get("verified", False),
            session_id=entry.session_id,
            timestamp=entry.timestamp,
            store_type="episodic",
        )

        return HistoryEntry(
            content=entry.content,
            response=entry.response_summary,
            provenance=provenance,
            flags=entry.flags or [],
        )

    def _parse_trust_level(self, trust: Any) -> float:
        """Parse trust level from various formats."""
        if isinstance(trust, (int, float)):
            return float(trust)

        if isinstance(trust, str):
            trust_map = {
                "guardian": 0.95,
                "high": 0.8,
                "medium": 0.5,
                "low": 0.3,
                "unknown": 0.3,
            }
            return trust_map.get(trust.lower(), 0.5)

        return 0.5

    def query_historical(
        self,
        relevance_to: Optional[str] = None,
        max_age_days: int = 30,
        min_trust_level: float = 0.0,
        source_identifier: Optional[str] = None,
        keywords: Optional[List[str]] = None,
        exclude_session: Optional[str] = None,
        limit: int = 50,
    ) -> List[HistoryEntry]:
        """
        Query historical episodes with filtering.

        Args:
            relevance_to: Topic/context for relevance scoring
            max_age_days: Maximum age of entries to include
            min_trust_level: Minimum trust level filter
            source_identifier: Filter by specific source
            keywords: Required keywords (any match)
            exclude_session: Session ID to exclude (usually current)
            limit: Maximum entries to return

        Returns:
            List of HistoryEntry objects sorted by relevance
        """
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=max_age_days)

        # Query episodic store
        entries = list(self.episodic.query(
            start_date=start_date,
            end_date=end_date,
            source_identifier=source_identifier,
            min_trust_level=min_trust_level,
            limit=limit * 2,  # Get extra for filtering
        ))

        # Convert and filter
        results = []
        for entry in entries:
            # Exclude current session
            if exclude_session and entry.session_id == exclude_session:
                continue

            history_entry = self._episodic_to_history(entry)

            # Keyword filtering
            if keywords:
                content_lower = entry.content.lower()
                if not any(kw.lower() in content_lower for kw in keywords):
                    continue

            # Calculate relevance score
            if relevance_to:
                history_entry.relevance_score = self._calculate_relevance(
                    entry.content,
                    relevance_to,
                )
            else:
                # Default: recency-based scoring
                try:
                    entry_time = datetime.fromisoformat(entry.timestamp.replace("Z", "+00:00"))
                    age_hours = (end_date.replace(tzinfo=entry_time.tzinfo) - entry_time).total_seconds() / 3600
                    history_entry.relevance_score = max(0, 1.0 - (age_hours / (max_age_days * 24)))
                except (ValueError, TypeError):
                    history_entry.relevance_score = 0.5

            results.append(history_entry)

        # Sort by relevance
        results.sort(key=lambda e: e.relevance_score, reverse=True)

        return results[:limit]

    def _calculate_relevance(self, content: str, query: str) -> float:
        """
        Calculate relevance score between content and query.

        Uses simple keyword matching. Could be extended with embeddings.
        """
        # Extract keywords from query
        if query not in self._keyword_cache:
            # Simple keyword extraction: remove common words
            stopwords = {"the", "a", "an", "is", "are", "was", "were", "be", "been",
                        "being", "have", "has", "had", "do", "does", "did", "will",
                        "would", "could", "should", "may", "might", "must", "shall",
                        "can", "need", "dare", "ought", "used", "to", "of", "in",
                        "for", "on", "with", "at", "by", "from", "as", "into",
                        "through", "during", "before", "after", "above", "below",
                        "between", "under", "again", "further", "then", "once",
                        "here", "there", "when", "where", "why", "how", "all",
                        "each", "few", "more", "most", "other", "some", "such",
                        "no", "nor", "not", "only", "own", "same", "so", "than",
                        "too", "very", "just", "and", "but", "if", "or", "because",
                        "until", "while", "about", "against", "this", "that", "what"}

            words = re.findall(r'\b\w+\b', query.lower())
            keywords = [w for w in words if w not in stopwords and len(w) > 2]
            self._keyword_cache[query] = keywords

        keywords = self._keyword_cache[query]

        if not keywords:
            return 0.5

        # Count keyword matches
        content_lower = content.lower()
        matches = sum(1 for kw in keywords if kw in content_lower)

        # Calculate score
        score = matches / len(keywords) if keywords else 0

        return min(1.0, score)

    def merge_with_provenance(
        self,
        current_session: List[HistoryEntry],
        historical: List[HistoryEntry],
        max_historical: int = 10,
        deduplicate: bool = True,
    ) -> List[HistoryEntry]:
        """
        Merge current session with historical episodes.

        Args:
            current_session: Current session entries
            historical: Historical entries from query
            max_historical: Maximum historical entries to include
            deduplicate: Whether to remove duplicate content

        Returns:
            Merged list with provenance preserved
        """
        # Take top historical entries
        historical = historical[:max_historical]

        if deduplicate:
            # Create content hashes for deduplication
            seen_hashes = set()
            deduplicated = []

            for entry in current_session:
                content_hash = hashlib.md5(entry.content.encode()).hexdigest()
                if content_hash not in seen_hashes:
                    seen_hashes.add(content_hash)
                    deduplicated.append(entry)

            for entry in historical:
                content_hash = hashlib.md5(entry.content.encode()).hexdigest()
                if content_hash not in seen_hashes:
                    seen_hashes.add(content_hash)
                    entry.provenance.store_type = "historical"
                    deduplicated.append(entry)

            return deduplicated
        else:
            # Mark historical entries
            for entry in historical:
                entry.provenance.store_type = "historical"

            return current_session + historical

    def to_context(
        self,
        entries: List[HistoryEntry],
        max_chars: int = 4000,
        include_provenance: bool = True,
        section_header: str = "## Relevant History",
    ) -> str:
        """
        Convert history entries to context-ready string.

        Args:
            entries: History entries to include
            max_chars: Maximum characters for context
            include_provenance: Whether to include provenance tags
            section_header: Header for the section

        Returns:
            Formatted context string
        """
        lines = [section_header, ""]

        current_chars = len(section_header) + 2

        # Separate current and historical
        current = [e for e in entries if e.provenance.store_type != "historical"]
        historical = [e for e in entries if e.provenance.store_type == "historical"]

        # Add current session first
        if current:
            lines.append("### Current Session")
            for entry in current[-5:]:  # Last 5 from current
                entry_str = entry.to_context_string(include_provenance)
                if current_chars + len(entry_str) + 2 > max_chars:
                    break
                lines.append(entry_str)
                lines.append("")
                current_chars += len(entry_str) + 2

        # Add historical context
        if historical and current_chars < max_chars - 200:
            lines.append("### Relevant Historical Context")
            for entry in historical:
                entry_str = entry.to_context_string(include_provenance)
                if current_chars + len(entry_str) + 2 > max_chars:
                    break
                lines.append(entry_str)
                lines.append("")
                current_chars += len(entry_str) + 2

        return "\n".join(lines)

    def search_conversations(
        self,
        query: str,
        max_age_days: int = 90,
        min_trust_level: float = 0.3,
        limit: int = 20,
    ) -> List[HistoryEntry]:
        """
        Search for previous conversations about a topic.

        Convenience method for common query pattern.

        Args:
            query: Search query (e.g., "security", "authentication")
            max_age_days: How far back to search
            min_trust_level: Minimum trust level
            limit: Maximum results

        Returns:
            Relevant history entries sorted by relevance
        """
        # Extract likely keywords from query
        keywords = re.findall(r'\b\w{3,}\b', query.lower())

        return self.query_historical(
            relevance_to=query,
            max_age_days=max_age_days,
            min_trust_level=min_trust_level,
            keywords=keywords if keywords else None,
            limit=limit,
        )


def load_session_with_history(
    session_id: str,
    context_query: Optional[str] = None,
    max_historical: int = 10,
    memory_root: Optional[Path] = None,
) -> str:
    """
    Convenience function to load session with historical context.

    Drop-in enhancement for basic session loading.

    Args:
        session_id: Current session ID
        context_query: Optional query for relevant history
        max_historical: Max historical entries
        memory_root: Memory root path

    Returns:
        Context-ready string
    """
    loader = SessionHistoryLoader(memory_root=memory_root)

    # Load current session
    current = loader.load_current_session(session_id)

    # Query historical if context provided
    if context_query:
        historical = loader.search_conversations(context_query)
    else:
        historical = loader.query_historical(max_age_days=7, limit=max_historical)

    # Merge
    merged = loader.merge_with_provenance(current, historical, max_historical)

    # Convert to context
    return loader.to_context(merged)


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        query = " ".join(sys.argv[1:])
        print(f"Searching for: {query}")
        print()

        loader = SessionHistoryLoader()
        results = loader.search_conversations(query)

        print(f"Found {len(results)} relevant entries:")
        print()

        for entry in results[:5]:
            print(entry.to_context_string())
            print(f"  Relevance: {entry.relevance_score:.2f}")
            print()
    else:
        print("Session History Loader - Cross-Session Memory")
        print()
        print("Usage:")
        print("  python -m src.memory.session_history <search query>")
        print()
        print("Example:")
        print("  python -m src.memory.session_history security research")
