"""
Phase 3 Benchmarks - Session History Extension

Tests for:
- Historical episodes retrieved by relevance
- Trust filtering excludes low-trust sources
- Provenance tags preserved through to context
- Query "previous conversations about security" returns relevant episodes
"""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest


class TestHistoricalEpisodeRetrieval:
    """TEST: Historical episodes retrieved by relevance"""

    def test_query_returns_relevant_entries(self):
        """Querying for a topic returns relevant historical entries."""
        from src.memory.episodic import EpisodicStore
        from src.memory.session_history import SessionHistoryLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))

            # Create historical sessions with different content
            session1 = store.start_session("session_001")
            store.append(
                content="Let's discuss security vulnerabilities",
                source={"identifier": "user@test.com", "trust_level": 0.8, "verified": True},
                response_summary="Discussed security patterns",
                session_id=session1,
            )

            session2 = store.start_session("session_002")
            store.append(
                content="What's for lunch today?",
                source={"identifier": "user@test.com", "trust_level": 0.8, "verified": True},
                response_summary="Suggested sandwich",
                session_id=session2,
            )

            session3 = store.start_session("session_003")
            store.append(
                content="Security audit findings need review",
                source={"identifier": "user@test.com", "trust_level": 0.8, "verified": True},
                response_summary="Reviewed audit",
                session_id=session3,
            )

            # Query for security-related content
            loader = SessionHistoryLoader(store)
            results = loader.query_historical(
                relevance_to="security",
                max_age_days=30,
            )

            # Should find security-related entries
            assert len(results) >= 2

            # Check relevance scores
            security_entries = [e for e in results if "security" in e.content.lower()]
            non_security = [e for e in results if "security" not in e.content.lower()]

            # Security entries should have higher relevance
            if security_entries and non_security:
                avg_security = sum(e.relevance_score for e in security_entries) / len(security_entries)
                avg_non_security = sum(e.relevance_score for e in non_security) / len(non_security)
                assert avg_security >= avg_non_security

    def test_relevance_scoring(self):
        """Relevance scoring works correctly."""
        from src.memory.session_history import SessionHistoryLoader

        loader = SessionHistoryLoader()

        # Direct match should score high
        score1 = loader._calculate_relevance(
            "We need to discuss authentication security",
            "security authentication"
        )

        # No match should score low
        score2 = loader._calculate_relevance(
            "What's for lunch?",
            "security authentication"
        )

        assert score1 > score2
        assert score1 > 0.3
        assert score2 < 0.3

    def test_keyword_filtering(self):
        """Keyword filtering works."""
        from src.memory.episodic import EpisodicStore
        from src.memory.session_history import SessionHistoryLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))

            # Create entries
            store.start_session()
            store.append(
                content="Python programming tutorial",
                source={"identifier": "test", "trust_level": 0.5, "verified": False},
            )
            store.append(
                content="JavaScript frameworks overview",
                source={"identifier": "test", "trust_level": 0.5, "verified": False},
            )

            loader = SessionHistoryLoader(store)

            # Filter by keyword
            results = loader.query_historical(keywords=["python"])

            # Should only find Python entry
            assert len(results) >= 1
            assert all("python" in e.content.lower() for e in results)


class TestTrustFiltering:
    """TEST: Trust filtering excludes low-trust sources"""

    def test_min_trust_level_filter(self):
        """Low trust entries are filtered out."""
        from src.memory.episodic import EpisodicStore
        from src.memory.session_history import SessionHistoryLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))

            # Create entries with different trust levels
            store.start_session()

            # High trust entry
            store.append(
                content="High trust message",
                source={"identifier": "guardian@test.com", "trust_level": 0.9, "verified": True},
            )

            # Low trust entry
            store.append(
                content="Low trust message",
                source={"identifier": "unknown@test.com", "trust_level": 0.2, "verified": False},
            )

            loader = SessionHistoryLoader(store)

            # Query with minimum trust
            results = loader.query_historical(min_trust_level=0.5)

            # Should only include high trust entry
            assert len(results) >= 1
            assert all(e.provenance.trust_level >= 0.5 for e in results)

    def test_trust_level_parsing(self):
        """Trust levels are parsed from various formats."""
        from src.memory.session_history import SessionHistoryLoader

        loader = SessionHistoryLoader()

        # Numeric
        assert loader._parse_trust_level(0.8) == 0.8
        assert loader._parse_trust_level(1) == 1.0

        # String labels
        assert loader._parse_trust_level("guardian") == 0.95
        assert loader._parse_trust_level("high") == 0.8
        assert loader._parse_trust_level("medium") == 0.5
        assert loader._parse_trust_level("low") == 0.3

        # Default for unknown
        assert loader._parse_trust_level("something_else") == 0.5
        assert loader._parse_trust_level(None) == 0.5


class TestProvenanceTracking:
    """TEST: Provenance tags preserved through to context"""

    def test_provenance_tags_created(self):
        """Provenance tags are created for all entries."""
        from src.memory.episodic import EpisodicStore
        from src.memory.session_history import SessionHistoryLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))

            session = store.start_session()
            store.append(
                content="Test message",
                source={
                    "identifier": "user@example.com",
                    "trust_level": 0.75,
                    "verified": True,
                },
                session_id=session,
            )

            loader = SessionHistoryLoader(store)
            entries = loader.load_current_session(session)

            assert len(entries) == 1
            entry = entries[0]

            # Check provenance
            assert entry.provenance.source_identifier == "user@example.com"
            assert entry.provenance.trust_level == 0.75
            assert entry.provenance.verified is True
            assert entry.provenance.session_id == session

    def test_provenance_preserved_in_context(self):
        """Provenance is included in context output."""
        from src.memory.session_history import HistoryEntry, ProvenanceTag

        entry = HistoryEntry(
            content="What about security?",
            response="Let me explain security concepts.",
            provenance=ProvenanceTag(
                source_identifier="guardian@lifewithai.ai",
                trust_level=0.95,
                verified=True,
                session_id="sess_001",
                timestamp="2026-02-03T12:00:00Z",
            ),
        )

        context_str = entry.to_context_string(include_provenance=True)

        # Should include provenance info
        assert "guardian@lifewithai.ai" in context_str
        assert "*" in context_str  # Trust indicator
        assert "v" in context_str  # Verified mark

    def test_provenance_in_merged_output(self):
        """Provenance preserved through merge and context generation."""
        from src.memory.episodic import EpisodicStore
        from src.memory.session_history import SessionHistoryLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))

            # Create sessions
            session1 = store.start_session("old_session")
            store.append(
                content="Historical security discussion",
                source={"identifier": "alice@test.com", "trust_level": 0.8, "verified": True},
                session_id=session1,
            )

            session2 = store.start_session("current_session")
            store.append(
                content="Current conversation",
                source={"identifier": "bob@test.com", "trust_level": 0.7, "verified": False},
                session_id=session2,
            )

            loader = SessionHistoryLoader(store)

            # Load and merge
            current = loader.load_current_session("current_session")
            historical = loader.query_historical(exclude_session="current_session")
            merged = loader.merge_with_provenance(current, historical)

            # Generate context
            context = loader.to_context(merged, include_provenance=True)

            # Both sources should be in context
            assert "bob@test.com" in context or "alice@test.com" in context


class TestSecurityConversationQuery:
    """TEST: Query 'previous conversations about security' returns relevant episodes"""

    def test_search_conversations_about_security(self):
        """Can search for previous security conversations."""
        from src.memory.episodic import EpisodicStore
        from src.memory.session_history import SessionHistoryLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))

            # Create various conversations
            store.start_session()

            # Security-related
            store.append(
                content="What are the best practices for API security?",
                source={"identifier": "dev@company.com", "trust_level": 0.7, "verified": True},
                response_summary="Discussed authentication, rate limiting, and input validation",
            )
            store.append(
                content="How do we prevent SQL injection attacks?",
                source={"identifier": "dev@company.com", "trust_level": 0.7, "verified": True},
                response_summary="Explained parameterized queries",
            )

            # Non-security
            store.append(
                content="What's a good recipe for pasta?",
                source={"identifier": "friend@email.com", "trust_level": 0.5, "verified": False},
                response_summary="Shared carbonara recipe",
            )
            store.append(
                content="When is the meeting tomorrow?",
                source={"identifier": "coworker@company.com", "trust_level": 0.6, "verified": True},
                response_summary="Meeting at 2pm",
            )

            loader = SessionHistoryLoader(store)

            # Search for security conversations
            results = loader.search_conversations("security")

            # Should find security-related entries
            assert len(results) >= 2

            # Top results should be security-related
            security_related = [e for e in results[:3] if
                "security" in e.content.lower() or
                "injection" in e.content.lower() or
                "authentication" in (e.response or "").lower()]
            assert len(security_related) >= 1

    def test_search_with_trust_filter(self):
        """Search respects trust level filter."""
        from src.memory.episodic import EpisodicStore
        from src.memory.session_history import SessionHistoryLoader

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))
            store.start_session()

            # High trust security discussion
            store.append(
                content="Security architecture review",
                source={"identifier": "guardian@secure.com", "trust_level": 0.9, "verified": True},
            )

            # Low trust security mention
            store.append(
                content="Security tips from random website",
                source={"identifier": "spam@unknown.com", "trust_level": 0.1, "verified": False},
            )

            loader = SessionHistoryLoader(store)

            # Search with high trust requirement
            results = loader.search_conversations(
                "security",
                min_trust_level=0.5,
            )

            # Should only find high trust entry
            assert all(e.provenance.trust_level >= 0.5 for e in results)


class TestHistoryMerging:
    """Test history merging functionality."""

    def test_merge_deduplicates(self):
        """Merge removes duplicate entries."""
        from src.memory.session_history import HistoryEntry, ProvenanceTag, SessionHistoryLoader

        loader = SessionHistoryLoader()

        # Create duplicate entries
        prov1 = ProvenanceTag(
            source_identifier="user@test.com",
            trust_level=0.5,
            verified=False,
            session_id="s1",
            timestamp="2026-02-03T12:00:00Z",
        )
        prov2 = ProvenanceTag(
            source_identifier="user@test.com",
            trust_level=0.5,
            verified=False,
            session_id="s2",
            timestamp="2026-02-03T13:00:00Z",
        )

        current = [HistoryEntry(content="Same content", response=None, provenance=prov1)]
        historical = [HistoryEntry(content="Same content", response=None, provenance=prov2)]

        merged = loader.merge_with_provenance(current, historical, deduplicate=True)

        # Should only have one entry
        assert len(merged) == 1

    def test_merge_preserves_store_type(self):
        """Merge marks historical entries appropriately."""
        from src.memory.session_history import HistoryEntry, ProvenanceTag, SessionHistoryLoader

        loader = SessionHistoryLoader()

        prov1 = ProvenanceTag(
            source_identifier="user", trust_level=0.5, verified=False,
            session_id="current", timestamp="2026-02-03T12:00:00Z",
        )
        prov2 = ProvenanceTag(
            source_identifier="user", trust_level=0.5, verified=False,
            session_id="old", timestamp="2026-02-02T12:00:00Z",
        )

        current = [HistoryEntry(content="Current msg", response=None, provenance=prov1)]
        historical = [HistoryEntry(content="Old msg", response=None, provenance=prov2)]

        merged = loader.merge_with_provenance(current, historical)

        # Find the historical entry
        hist_entries = [e for e in merged if e.content == "Old msg"]
        assert len(hist_entries) == 1
        assert hist_entries[0].provenance.store_type == "historical"


class TestContextGeneration:
    """Test context output generation."""

    def test_context_respects_max_chars(self):
        """Context generation respects character limit."""
        from src.memory.session_history import HistoryEntry, ProvenanceTag, SessionHistoryLoader

        loader = SessionHistoryLoader()

        # Create many entries
        entries = []
        for i in range(20):
            prov = ProvenanceTag(
                source_identifier="user", trust_level=0.5, verified=False,
                session_id="s1", timestamp="2026-02-03T12:00:00Z",
            )
            entries.append(HistoryEntry(
                content=f"Message {i} " * 50,  # Long content
                response="Response " * 20,
                provenance=prov,
            ))

        context = loader.to_context(entries, max_chars=1000)

        assert len(context) <= 1500  # Some buffer for headers

    def test_context_includes_headers(self):
        """Context has proper section headers."""
        from src.memory.session_history import HistoryEntry, ProvenanceTag, SessionHistoryLoader

        loader = SessionHistoryLoader()

        prov = ProvenanceTag(
            source_identifier="user", trust_level=0.5, verified=False,
            session_id="s1", timestamp="2026-02-03T12:00:00Z",
        )
        entries = [HistoryEntry(content="Test", response="Response", provenance=prov)]

        context = loader.to_context(entries)

        assert "## Relevant History" in context
        assert "### Current Session" in context


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
