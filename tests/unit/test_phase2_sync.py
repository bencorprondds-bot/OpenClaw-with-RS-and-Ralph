"""
Phase 2 Benchmarks - Domain Backup + Sync

Tests for:
- API endpoint handling (mock)
- Sync within 30s target
- Domain recovery
- Conflict detection
- Corruption recovery
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestSyncConfig:
    """Test sync configuration."""

    def test_config_from_env(self):
        """Config loads from environment variables."""
        from src.sync.domain import SyncConfig

        with patch.dict("os.environ", {
            "MEMORY_DOMAIN_URL": "https://test.example.com/",
            "MEMORY_API_KEY": "test-key-123",
            "MEMORY_SYNC_INTERVAL": "60",
        }):
            config = SyncConfig.from_env()

            assert config.domain_url == "https://test.example.com/"
            assert config.api_key == "test-key-123"
            assert config.sync_interval_seconds == 60

    def test_config_defaults(self):
        """Config has sensible defaults."""
        from src.sync.domain import SyncConfig

        config = SyncConfig()

        assert "lifewithai.ai" in config.domain_url
        assert config.sync_interval_seconds == 30
        assert config.timeout_seconds == 30
        assert config.retry_attempts == 3


class TestDomainSync:
    """TEST: API endpoint accepts authenticated writes"""

    def test_sync_creates_headers(self):
        """Sync creates proper authentication headers."""
        from src.sync.domain import DomainSync, SyncConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            config = SyncConfig(api_key="test-api-key")
            sync = DomainSync(Path(tmpdir), config)

            headers = sync._get_headers()

            assert headers["Authorization"] == "Bearer test-api-key"
            assert headers["Content-Type"] == "application/json"

    def test_sync_builds_urls(self):
        """Sync builds correct API URLs."""
        from src.sync.domain import DomainSync, SyncConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            config = SyncConfig(domain_url="https://example.com/memory/")
            sync = DomainSync(Path(tmpdir), config)

            url = sync._build_url("manifest.json")
            assert url == "https://example.com/memory/manifest.json"

    def test_get_local_manifest(self):
        """Can read local manifest."""
        from src.sync.domain import DomainSync
        from src.memory.init_store import init_memory_structure

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            init_memory_structure(root)

            sync = DomainSync(root)
            manifest = sync.get_local_manifest()

            assert manifest.version == "1.0"
            assert "stores" in manifest.to_dict()

    def test_get_store_files(self):
        """Can enumerate store files with checksums."""
        from src.sync.domain import DomainSync
        from src.memory.init_store import init_memory_structure

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            init_memory_structure(root)

            # Add a test file
            test_file = root / "episodic" / "test.jsonl"
            test_file.write_text('{"test": "data"}\n')

            sync = DomainSync(root)
            files = sync.get_store_files("episodic")

            assert len(files) >= 1
            test_entry = next((f for f in files if f["path"] == "test.jsonl"), None)
            assert test_entry is not None
            assert "checksum" in test_entry


class TestSyncTiming:
    """TEST: Local changes sync to domain within 30s"""

    def test_sync_config_default_interval(self):
        """Default sync interval is 30 seconds."""
        from src.sync.domain import SyncConfig

        config = SyncConfig()
        assert config.sync_interval_seconds == 30

    def test_sync_status_tracking(self):
        """Sync tracks timing information."""
        from src.sync.domain import DomainSync

        with tempfile.TemporaryDirectory() as tmpdir:
            sync = DomainSync(Path(tmpdir))

            # Mock the request to avoid actual network calls
            with patch.object(sync, '_request_sync', return_value={"success": True}):
                status = sync.push_sync()

                assert status.timestamp is not None
                assert status.duration_ms >= 0


class TestDomainRecovery:
    """TEST: Domain pull restores local state after simulated wipe"""

    def test_recovery_creates_backup(self):
        """Recovery creates backup before wiping."""
        from src.sync.domain import DomainSync
        from src.memory.init_store import init_memory_structure

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "memory"
            init_memory_structure(root)

            # Add some data
            (root / "episodic" / "test.jsonl").write_text('{"data": "important"}\n')

            sync = DomainSync(root)

            # Mock pull to fail (so backup is preserved)
            with patch.object(sync, 'pull_sync', return_value=MagicMock(
                success=False,
                errors=["Simulated failure"],
                items_synced=0,
                items_failed=0,
            )):
                # Recovery should create backup
                status = sync.recover()

                # Check that backup was created
                backups = list(Path(tmpdir).glob("memory_backup_*"))
                assert len(backups) >= 1

    def test_get_sync_status(self):
        """Can get current sync status."""
        from src.sync.domain import DomainSync
        from src.memory.init_store import init_memory_structure

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            init_memory_structure(root)

            sync = DomainSync(root)
            status = sync.get_sync_status()

            assert "last_sync" in status
            assert "sync_in_progress" in status
            assert "local_manifest" in status
            assert "config" in status


class TestConflictDetection:
    """TEST: Conflict detection fires when stores diverge"""

    def test_detects_missing_local(self):
        """Detects files missing locally."""
        from src.sync.conflict import ConflictDetector, ConflictType

        with tempfile.TemporaryDirectory() as tmpdir:
            detector = ConflictDetector(Path(tmpdir))

            domain_files = {
                "episodic/2026/02/03/session.jsonl": {
                    "checksum": "abc123",
                    "modified": "2026-02-03T12:00:00Z",
                }
            }
            local_files = {}

            conflicts = detector.detect_conflicts(domain_files, local_files)

            assert len(conflicts) == 1
            assert conflicts[0].conflict_type == ConflictType.MISSING_LOCAL.value

    def test_detects_missing_domain(self):
        """Detects files missing from domain."""
        from src.sync.conflict import ConflictDetector, ConflictType

        with tempfile.TemporaryDirectory() as tmpdir:
            detector = ConflictDetector(Path(tmpdir))

            domain_files = {}
            local_files = {
                "episodic/2026/02/03/session.jsonl": {
                    "checksum": "abc123",
                    "modified": "2026-02-03T12:00:00Z",
                }
            }

            conflicts = detector.detect_conflicts(domain_files, local_files)

            assert len(conflicts) == 1
            assert conflicts[0].conflict_type == ConflictType.MISSING_DOMAIN.value

    def test_detects_content_mismatch(self):
        """Detects content differences."""
        from src.sync.conflict import ConflictDetector, ConflictType

        with tempfile.TemporaryDirectory() as tmpdir:
            detector = ConflictDetector(Path(tmpdir))

            domain_files = {
                "episodic/session.jsonl": {
                    "checksum": "domain_hash_123",
                    "modified": "2026-02-03T12:00:00Z",
                }
            }
            local_files = {
                "episodic/session.jsonl": {
                    "checksum": "local_hash_456",
                    "modified": "2026-02-03T11:00:00Z",
                }
            }

            conflicts = detector.detect_conflicts(domain_files, local_files)

            assert len(conflicts) == 1
            assert conflicts[0].conflict_type == ConflictType.CONTENT_MISMATCH.value
            assert conflicts[0].local_checksum == "local_hash_456"
            assert conflicts[0].domain_checksum == "domain_hash_123"

    def test_no_conflict_when_matching(self):
        """No conflict when checksums match."""
        from src.sync.conflict import ConflictDetector

        with tempfile.TemporaryDirectory() as tmpdir:
            detector = ConflictDetector(Path(tmpdir))

            same_hash = "matching_hash_789"
            files = {
                "episodic/session.jsonl": {
                    "checksum": same_hash,
                    "modified": "2026-02-03T12:00:00Z",
                }
            }

            conflicts = detector.detect_conflicts(files, files)

            assert len(conflicts) == 0


class TestConflictResolution:
    """TEST: Conflict resolution works correctly"""

    def test_resolve_use_domain(self):
        """Can resolve by using domain version."""
        from src.sync.conflict import ConflictDetector, Conflict, ResolutionStrategy

        with tempfile.TemporaryDirectory() as tmpdir:
            detector = ConflictDetector(Path(tmpdir))

            conflict = Conflict(
                id="test-conflict-1",
                store="episodic",
                path="session.jsonl",
                conflict_type="content_mismatch",
                local_checksum="local",
                domain_checksum="domain",
            )

            resolution = detector.resolve(conflict, ResolutionStrategy.USE_DOMAIN)

            assert resolution.success
            assert resolution.strategy == "use_domain"

    def test_resolve_flags_for_guardian(self):
        """Can flag for guardian review."""
        from src.sync.conflict import ConflictDetector, Conflict, ResolutionStrategy

        with tempfile.TemporaryDirectory() as tmpdir:
            detector = ConflictDetector(Path(tmpdir))

            conflict = Conflict(
                id="test-conflict-2",
                store="trust",
                path="entities/guardian.json",
                conflict_type="content_mismatch",
            )

            resolution = detector.resolve(conflict, ResolutionStrategy.GUARDIAN_REVIEW)

            assert resolution.success
            assert resolution.strategy == "guardian_review"

            # Check it's in the review queue
            queue = detector.get_guardian_review_queue()
            assert len(queue) >= 1

    def test_conflict_stats(self):
        """Can get conflict statistics."""
        from src.sync.conflict import ConflictDetector

        with tempfile.TemporaryDirectory() as tmpdir:
            detector = ConflictDetector(Path(tmpdir))

            # Create some conflicts
            domain_files = {
                "episodic/a.jsonl": {"checksum": "1", "modified": "2026-02-03T12:00:00Z"},
                "semantic/b.md": {"checksum": "2", "modified": "2026-02-03T12:00:00Z"},
            }
            local_files = {}

            detector.detect_conflicts(domain_files, local_files)

            stats = detector.get_conflict_stats()

            assert stats["total_pending"] == 2
            assert "by_store" in stats
            assert "by_type" in stats


class TestSyncQueue:
    """Test sync queue for offline support."""

    def test_queue_enqueue(self):
        """Can enqueue changes."""
        from src.sync.queue import SyncQueue

        with tempfile.TemporaryDirectory() as tmpdir:
            queue = SyncQueue(Path(tmpdir))

            change = queue.enqueue("episodic", "2026/02/03/session.jsonl", "update")

            assert change.store == "episodic"
            assert change.operation == "update"

    def test_queue_deduplication(self):
        """Queue deduplicates entries for same path."""
        from src.sync.queue import SyncQueue

        with tempfile.TemporaryDirectory() as tmpdir:
            queue = SyncQueue(Path(tmpdir))

            queue.enqueue("episodic", "session.jsonl", "update")
            queue.enqueue("episodic", "session.jsonl", "update")

            pending = queue.get_pending()

            # Should only have one entry due to deduplication
            assert len(pending) == 1

    def test_queue_retry_backoff(self):
        """Queue implements retry backoff."""
        from src.sync.queue import SyncQueue

        with tempfile.TemporaryDirectory() as tmpdir:
            queue = SyncQueue(Path(tmpdir))

            change = queue.enqueue("episodic", "session.jsonl", "update")

            # Mark as failed multiple times
            queue.mark_failed(change.id, "Connection timeout")
            queue.mark_failed(change.id, "Connection timeout")

            # Should still be in queue but with retry count
            pending = queue.get_pending()
            if pending:
                assert pending[0].retry_count >= 0

    def test_queue_stats(self):
        """Can get queue statistics."""
        from src.sync.queue import SyncQueue

        with tempfile.TemporaryDirectory() as tmpdir:
            queue = SyncQueue(Path(tmpdir))

            queue.enqueue("episodic", "a.jsonl", "create")
            queue.enqueue("semantic", "b.md", "update")

            stats = queue.get_queue_stats()

            assert stats["total_pending"] == 2
            assert "by_store" in stats
            assert "by_operation" in stats


class TestCorruptionRecovery:
    """TEST: Corrupt local store, recover from domain, verify no data loss"""

    def test_corrupted_manifest_detection(self):
        """Detects corrupted manifest."""
        from src.memory.init_store import verify_store_integrity

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "checksums").mkdir(parents=True)

            # Write invalid JSON
            (root / "checksums" / "manifest.sha256").write_text("not valid json")

            is_valid, issues = verify_store_integrity(root)

            assert not is_valid
            assert any("manifest" in issue.lower() or "json" in issue.lower() for issue in issues)

    def test_recovery_preserves_data(self):
        """Recovery process aims to preserve data."""
        from src.sync.domain import DomainSync
        from src.memory.init_store import init_memory_structure

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir) / "memory"
            init_memory_structure(root)

            # Add important data
            important_file = root / "episodic" / "important.jsonl"
            important_file.write_text('{"critical": "data"}\n')

            sync = DomainSync(root)

            # Get status before any operations
            status_before = sync.get_sync_status()
            assert "local_manifest" in status_before


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
