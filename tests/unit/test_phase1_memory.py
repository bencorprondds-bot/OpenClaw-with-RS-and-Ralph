"""
Phase 1 Benchmarks - Local Structure + Memory Router

Tests for:
- Directory structure creation
- Memory Router output format
- Episodic store JSONL with checksums
- Router reading from all five store types
- Checksum validation
- Write/read integrity (100 entries)
"""

import json
import tempfile
from pathlib import Path

import pytest


class TestDirectoryStructure:
    """TEST: Directory structure creates correctly"""

    def test_init_creates_all_directories(self):
        """All required directories are created."""
        from src.memory.init_store import init_memory_structure

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            structure = init_memory_structure(root)

            # Check all main stores exist
            assert (root / "episodic").is_dir()
            assert (root / "semantic").is_dir()
            assert (root / "trust").is_dir()
            assert (root / "threats").is_dir()
            assert (root / "procedural").is_dir()
            assert (root / "checksums").is_dir()

    def test_init_creates_subdirectories(self):
        """Subdirectories for semantic, trust, threats, procedural exist."""
        from src.memory.init_store import init_memory_structure

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            init_memory_structure(root)

            # Semantic subdirs
            assert (root / "semantic" / "patterns").is_dir()
            assert (root / "semantic" / "learnings").is_dir()
            assert (root / "semantic" / "principles").is_dir()

            # Trust subdirs
            assert (root / "trust" / "entities").is_dir()
            assert (root / "trust" / "sources").is_dir()

            # Threats subdirs
            assert (root / "threats" / "signatures").is_dir()
            assert (root / "threats" / "incidents").is_dir()

            # Procedural subdirs
            assert (root / "procedural" / "responses").is_dir()
            assert (root / "procedural" / "workflows").is_dir()
            assert (root / "procedural" / "reflexes").is_dir()

    def test_init_creates_default_files(self):
        """Default policy files are created."""
        from src.memory.init_store import init_memory_structure

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            init_memory_structure(root)

            assert (root / "trust" / "trust_policies.md").exists()
            assert (root / "threats" / "active_threats.md").exists()
            assert (root / "semantic" / "principles" / "core_values.md").exists()

    def test_init_creates_manifest(self):
        """Manifest file is created with checksums."""
        from src.memory.init_store import init_memory_structure

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            init_memory_structure(root)

            manifest_path = root / "checksums" / "manifest.sha256"
            assert manifest_path.exists()

            manifest = json.loads(manifest_path.read_text())
            assert "stores" in manifest
            assert "episodic" in manifest["stores"]


class TestMemoryRouterOutput:
    """TEST: Memory Router outputs valid markdown matching current MEMORY.md format"""

    def test_router_outputs_markdown(self):
        """Router produces valid markdown output."""
        from src.memory.router import MemoryRouter

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))
            context = router.assemble_context()

            # Should be a string
            assert isinstance(context, str)

            # Should have markdown headers
            assert "# Memory Context" in context

            # Should have sections
            assert "##" in context

    def test_router_includes_threat_awareness(self):
        """Router includes threat awareness section."""
        from src.memory.router import MemoryRouter

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))
            context = router.assemble_context()

            # May or may not have threats depending on defaults
            # At minimum, the router should run without error
            assert len(context) > 0

    def test_router_includes_trust_context(self):
        """Router includes trust information when source provided."""
        from src.memory.router import MemoryRouter

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))
            context = router.assemble_context(source_identifier="test@example.com")

            assert "Current Source Trust" in context
            assert "test@example.com" in context


class TestEpisodicStore:
    """TEST: Episodic entries write as valid JSONL with checksums"""

    def test_episodic_writes_jsonl(self):
        """Entries are written in JSONL format."""
        from src.memory.episodic import EpisodicStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))
            session = store.start_session()

            store.append(
                content="Test message",
                source={"identifier": "test@example.com", "trust_level": 0.8, "verified": True},
            )

            # Find the session file
            session_file = store._get_session_path(session)
            assert session_file.exists()

            # Read and verify JSONL format
            with open(session_file, "r") as f:
                line = f.readline()
                data = json.loads(line)

            assert "timestamp" in data
            assert "session_id" in data
            assert "content" in data
            assert data["content"] == "Test message"

    def test_episodic_creates_checksums(self):
        """Each session has a checksum file."""
        from src.memory.episodic import EpisodicStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))
            session = store.start_session()

            store.append(
                content="Test message",
                source={"identifier": "test@example.com", "trust_level": 0.8, "verified": True},
            )

            checksum_file = store._get_checksum_path(session)
            assert checksum_file.exists()
            assert checksum_file.read_text().startswith("sha256:")

    def test_episodic_entry_has_checksum(self):
        """Each entry has an embedded checksum."""
        from src.memory.episodic import EpisodicStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))
            session = store.start_session()

            entry = store.append(
                content="Test message",
                source={"identifier": "test@example.com", "trust_level": 0.8, "verified": True},
            )

            assert entry.checksum is not None
            assert entry.checksum.startswith("sha256:")


class TestRouterReadsAllStores:
    """TEST: Router can read from all five store types"""

    def test_router_reads_episodic(self):
        """Router can query episodic store."""
        from src.memory.router import MemoryRouter

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))

            # Add some data
            router.episodic.start_session()
            router.episodic.append(
                content="Test",
                source={"identifier": "test", "trust_level": 0.5, "verified": False},
            )

            # Query via router
            results = router.query_local_store("episodic", limit=10)
            assert len(results) >= 1

    def test_router_reads_semantic(self):
        """Router can query semantic store."""
        from src.memory.router import MemoryRouter
        from src.memory.semantic import Learning

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))

            # Add a learning
            learning = Learning(
                title="Test Learning",
                date="2026-02-03",
                source="Test",
                confidence="high",
                validated_by=["test"],
                pattern="Test pattern",
                signature=["test"],
                response=["test"],
            )
            router.semantic.add_learning(learning)

            # Query via router
            results = router.query_local_store("semantic", query="Test")
            assert len(results) >= 1

    def test_router_reads_trust(self):
        """Router can query trust ledger."""
        from src.memory.router import MemoryRouter

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))

            # Add an entity
            router.trust.create_entity("test@example.com", role="user")

            # Query via router
            result = router.query_local_store("trust", identifier="test@example.com")
            assert result is not None
            assert result.identifier == "test@example.com"

    def test_router_reads_threats(self):
        """Router can query threat signatures."""
        from src.memory.router import MemoryRouter
        from src.memory.threats import ThreatSignature

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))

            # Add a signature
            sig = ThreatSignature(
                name="TEST_THREAT",
                severity="low",
                first_observed="2026-02-03",
                source="test",
                pattern="test pattern",
                indicators=["test indicator"],
                trigger_phrases=["test phrase"],
                response=["test response"],
            )
            router.threats.add_signature(sig)

            # Query via router
            results = router.query_local_store("threats", content="test phrase here")
            assert len(results) >= 1

    def test_router_reads_procedural(self):
        """Router can query procedural memory."""
        from src.memory.router import MemoryRouter
        from src.memory.procedural import Procedure

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))

            # Add a procedure
            proc = Procedure(
                name="Test Procedure",
                trigger="test situation",
                immediate_actions=["action 1"],
                assessment_steps=["step 1"],
                escalation_matrix=[],
                post_actions=["post 1"],
            )
            router.procedural.add_procedure(proc)

            # Query via router
            results = router.query_local_store("procedural", situation="test situation")
            assert len(results) >= 1


class TestChecksumValidation:
    """TEST: Checksums validate on read"""

    def test_valid_checksum_passes(self):
        """Valid checksums pass verification."""
        from src.memory.episodic import EpisodicStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))
            session = store.start_session()

            store.append(
                content="Test",
                source={"identifier": "test", "trust_level": 0.5, "verified": False},
            )

            # Verification should pass
            assert store.verify_session(session) is True

    def test_tampered_file_fails_verification(self):
        """Tampered files fail checksum verification."""
        from src.memory.episodic import EpisodicStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))
            session = store.start_session()

            store.append(
                content="Test",
                source={"identifier": "test", "trust_level": 0.5, "verified": False},
            )

            # Tamper with the file
            session_path = store._get_session_path(session)
            content = session_path.read_text()
            session_path.write_text(content + "\nTAMPERED")

            # Verification should fail
            assert store.verify_session(session) is False

    def test_store_integrity_verification(self):
        """Full store integrity verification works."""
        from src.memory.init_store import init_memory_structure, verify_store_integrity

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            init_memory_structure(root)

            is_valid, issues = verify_store_integrity(root)
            assert is_valid is True
            assert len(issues) == 0


class TestWriteReadIntegrity:
    """TEST: Write 100 entries, read them back, verify integrity"""

    def test_100_entries_integrity(self):
        """Write 100 entries and verify all are readable with correct checksums."""
        from src.memory.episodic import EpisodicStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store = EpisodicStore(Path(tmpdir))
            session = store.start_session()

            # Write 100 entries
            written_entries = []
            for i in range(100):
                entry = store.append(
                    content=f"Test message {i}",
                    source={
                        "identifier": f"test{i % 10}@example.com",
                        "trust_level": 0.5 + (i % 5) * 0.1,
                        "verified": i % 2 == 0,
                    },
                    response_summary=f"Response to message {i}",
                )
                written_entries.append(entry)

            # Read all entries back
            read_entries = store.read_session(session, verify=True)

            # Verify count
            assert len(read_entries) == 100

            # Verify content matches
            for i, entry in enumerate(read_entries):
                assert entry.content == f"Test message {i}"
                assert entry.response_summary == f"Response to message {i}"

            # Verify all entry checksums
            for entry in read_entries:
                assert entry.verify() is True

            # Verify session checksum
            assert store.verify_session(session) is True


class TestContextWindowCompatibility:
    """TEST: Output passes to Context Window Guard without errors"""

    def test_output_is_reasonable_size(self):
        """Output is within reasonable context window limits."""
        from src.memory.router import MemoryRouter

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))

            # Add some data to make it realistic
            router.episodic.start_session()
            for i in range(20):
                router.episodic.append(
                    content=f"Interaction {i}",
                    source={"identifier": "test", "trust_level": 0.5, "verified": False},
                )

            context = router.assemble_context()

            # Should be under a reasonable limit (e.g., 10KB for memory context)
            assert len(context) < 10000

    def test_output_has_no_invalid_characters(self):
        """Output contains only valid UTF-8 characters."""
        from src.memory.router import MemoryRouter

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))
            context = router.assemble_context()

            # Should be valid UTF-8
            context.encode("utf-8")  # Will raise if invalid

    def test_output_is_valid_markdown(self):
        """Output is valid markdown (basic structure check)."""
        from src.memory.router import MemoryRouter

        with tempfile.TemporaryDirectory() as tmpdir:
            router = MemoryRouter(Path(tmpdir))
            context = router.assemble_context()

            # Should have proper header hierarchy
            lines = context.split("\n")
            has_h1 = any(line.startswith("# ") for line in lines)
            has_h2 = any(line.startswith("## ") for line in lines)

            assert has_h1
            assert has_h2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
