"""
Phase 6 Benchmarks - Public Record + Integrity Verification

Tests for:
- Selected entries publish to public endpoint
- Public checksums match private store checksums
- Tamper detection works (modify public record -> system flags)
- Simulate tampering, verify detection within one read cycle
"""

import tempfile
from datetime import datetime
from pathlib import Path

import pytest


class TestSelectivePublishing:
    """TEST: Selected entries publish to public endpoint"""

    def test_publish_checksums(self):
        """Can publish checksums to public record."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create some content in stores
            (path / "semantic" / "patterns").mkdir(parents=True)
            (path / "semantic" / "patterns" / "test.md").write_text("# Test Pattern")

            (path / "threats" / "signatures").mkdir(parents=True)
            (path / "threats" / "signatures" / "sig1.json").write_text('{"id": "test"}')

            record = PublicRecord(memory_root=path)
            manifest = record.publish_checksums()

            assert manifest is not None
            assert len(manifest.entries) >= 2
            assert manifest.manifest_checksum != ""

    def test_publish_creates_public_directory(self):
        """Publishing creates public directory structure."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            record = PublicRecord(memory_root=path)
            record.publish_checksums()

            assert (path / "public" / "checksums" / "manifest.json").exists()
            assert (path / "public" / "checksums" / "history").is_dir()

    def test_never_publishes_trust_ledger(self):
        """Trust ledger is never included in published checksums."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create trust store content (should be excluded)
            (path / "trust" / "entities").mkdir(parents=True)
            (path / "trust" / "entities" / "user.json").write_text('{"trust": 0.5}')

            # Create semantic content (should be included)
            (path / "semantic" / "patterns").mkdir(parents=True)
            (path / "semantic" / "patterns" / "test.md").write_text("# Test")

            record = PublicRecord(memory_root=path)
            manifest = record.publish_checksums()

            # Check no trust entries
            trust_entries = [e for e in manifest.entries if "trust" in e.path]
            assert len(trust_entries) == 0

    def test_never_publishes_episodic_logs(self):
        """Episodic logs are never included in published checksums."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create episodic content (should be excluded)
            (path / "episodic" / "2026" / "02").mkdir(parents=True)
            (path / "episodic" / "2026" / "02" / "04.jsonl").write_text('{"log": "entry"}')

            record = PublicRecord(memory_root=path)
            manifest = record.publish_checksums()

            # Check no episodic entries
            episodic_entries = [e for e in manifest.entries if "episodic" in e.path]
            assert len(episodic_entries) == 0

    def test_publish_threat_signatures(self):
        """Can publish threat signatures for community defense."""
        from src.memory.public_record import PublicRecord
        from src.memory.threats import ThreatSignatures

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create a threat signature
            threats = ThreatSignatures(path)
            threats.add_signature(
                signature_id="TEST001",
                severity="high",
                pattern="test pattern",
                description="Test threat signature",
                indicators=["indicator1", "indicator2"],
            )

            record = PublicRecord(memory_root=path)
            published = record.publish_threat_signatures()

            assert published["signature_count"] >= 1
            assert (path / "public" / "threats" / "signatures.json").exists()

    def test_publish_learnings(self):
        """Can publish selected learnings."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            record = PublicRecord(memory_root=Path(tmpdir))

            learnings = [
                {
                    "id": "learn1",
                    "category": "security",
                    "summary": "Always validate input",
                    "learned_at": "2026-02-04",
                    "source": "semantic/learnings/security.md",
                },
            ]

            published = record.publish_learnings(learnings)

            assert published["learning_count"] == 1
            assert published["learnings"][0]["category"] == "security"


class TestChecksumIntegrity:
    """TEST: Public checksums match private store checksums"""

    def test_checksums_match_on_publish(self):
        """Generated checksums match file content."""
        from src.memory.public_record import PublicRecord
        import hashlib

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create test file
            test_content = "Test content for checksum"
            (path / "semantic").mkdir()
            test_file = path / "semantic" / "test.txt"
            test_file.write_text(test_content)

            expected_checksum = hashlib.sha256(test_content.encode()).hexdigest()

            record = PublicRecord(memory_root=path)
            manifest = record.publish_checksums()

            # Find the entry
            entries = [e for e in manifest.entries if "test.txt" in e.path]
            assert len(entries) == 1
            assert entries[0].checksum == expected_checksum

    def test_manifest_has_self_checksum(self):
        """Manifest includes checksum of itself."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            record = PublicRecord(memory_root=path)
            manifest = record.publish_checksums()

            assert manifest.manifest_checksum != ""
            assert len(manifest.manifest_checksum) == 64  # SHA256 hex

    def test_verify_returns_verified_when_unchanged(self):
        """Verification returns VERIFIED when files unchanged."""
        from src.memory.public_record import PublicRecord, VerificationStatus

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("original content")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()

            # Verify without changes
            result = record.verify_integrity()

            assert result.status == VerificationStatus.VERIFIED
            assert result.tampered_count == 0
            assert result.verified_count >= 1


class TestTamperDetection:
    """TEST: Tamper detection works (modify public record -> system flags)"""

    def test_detects_modified_file(self):
        """Detects when a file has been modified."""
        from src.memory.public_record import PublicRecord, VerificationStatus

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            test_file = path / "semantic" / "test.txt"
            test_file.write_text("original content")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()

            # Modify the file (tampering)
            test_file.write_text("tampered content")

            # Verify should detect
            result = record.verify_integrity()

            assert result.status == VerificationStatus.TAMPERED
            assert result.tampered_count >= 1
            assert any("test.txt" in e for e in result.tampered_entries)

    def test_detects_deleted_file(self):
        """Detects when a file has been deleted."""
        from src.memory.public_record import PublicRecord, VerificationStatus

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            test_file = path / "semantic" / "test.txt"
            test_file.write_text("original content")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()

            # Delete the file
            test_file.unlink()

            # Verify should detect
            result = record.verify_integrity()

            assert result.status == VerificationStatus.MISSING
            assert result.missing_count >= 1

    def test_creates_alert_on_tampering(self):
        """Creates alert file when tampering detected."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            test_file = path / "semantic" / "test.txt"
            test_file.write_text("original content")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()

            # Tamper
            test_file.write_text("tampered!")

            # Verify (should create alert)
            record.verify_integrity()

            # Check for alert file
            alerts_dir = path / "public" / "verification" / "alerts"
            alerts = list(alerts_dir.glob("*.json")) if alerts_dir.exists() else []
            assert len(alerts) >= 1

    def test_alert_handler_called(self):
        """Registered alert handlers are called on tampering."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            test_file = path / "semantic" / "test.txt"
            test_file.write_text("original")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()

            # Register handler
            alerts_received = []
            record.register_alert_handler(lambda alert: alerts_received.append(alert))

            # Tamper and verify
            test_file.write_text("tampered!")
            record.verify_integrity()

            assert len(alerts_received) >= 1
            assert alerts_received[0].severity == "critical"


class TestTamperingSimulation:
    """TEST: Simulate tampering, verify detection within one read cycle"""

    def test_simulate_and_detect(self):
        """Can simulate tampering and detect it immediately."""
        from src.memory.public_record import PublicRecord, VerificationStatus

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            test_file = path / "semantic" / "target.txt"
            test_file.write_text("original content")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()

            # Simulate tampering
            success = record.simulate_tampering(test_file)
            assert success is True

            # Verify detects immediately
            result = record.verify_integrity()
            assert result.status == VerificationStatus.TAMPERED

    def test_verify_on_read_detects_tampering(self):
        """verify_on_read detects tampering during file access."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            test_file = path / "semantic" / "critical.txt"
            test_file.write_text("critical data")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()

            # Before tampering - should verify
            assert record.verify_on_read(test_file) is True

            # After tampering - should fail
            test_file.write_text("tampered data")
            assert record.verify_on_read(test_file) is False

    def test_detection_within_one_cycle(self):
        """Tampering is detected within single verification cycle."""
        from src.memory.public_record import PublicRecord, VerificationStatus

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create multiple files
            (path / "semantic" / "patterns").mkdir(parents=True)
            (path / "semantic" / "patterns" / "p1.md").write_text("Pattern 1")
            (path / "semantic" / "patterns" / "p2.md").write_text("Pattern 2")
            (path / "semantic" / "patterns" / "p3.md").write_text("Pattern 3")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()

            # Tamper with one file
            (path / "semantic" / "patterns" / "p2.md").write_text("TAMPERED!")

            # Single verification should catch it
            result = record.verify_integrity()

            assert result.status == VerificationStatus.TAMPERED
            assert result.tampered_count == 1
            assert "p2.md" in result.tampered_entries[0]
            assert result.verified_count == 2  # p1 and p3 still valid


class TestVerificationHistory:
    """Test verification history tracking."""

    def test_saves_verification_result(self):
        """Verification results are saved."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()
            record.verify_integrity()

            # Check saved result
            result_file = path / "public" / "verification" / "last_check.json"
            assert result_file.exists()

    def test_get_verification_history(self):
        """Can retrieve verification history."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()
            record.verify_integrity()

            history = record.get_verification_history()
            assert len(history) >= 1


class TestChecksumHistoryArchive:
    """Test checksum history archival."""

    def test_archives_manifest_history(self):
        """Manifests are archived to history."""
        from src.memory.public_record import PublicRecord

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            record = PublicRecord(memory_root=path)
            record.publish_checksums()

            # Check history
            history_dir = path / "public" / "checksums" / "history"
            archives = list(history_dir.glob("manifest_*.json"))
            assert len(archives) >= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
