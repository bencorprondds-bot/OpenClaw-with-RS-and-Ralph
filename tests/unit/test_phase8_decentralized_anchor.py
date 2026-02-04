"""
Phase 8 Benchmarks - Decentralized Anchoring

Tests for:
- State anchored to Nostr/IPFS on schedule
- Historical state retrievable with proof
- Prove memory state at time T from months ago
"""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path
import json
import time

import pytest


class TestStateAnchoring:
    """TEST: State anchored to Nostr/IPFS on schedule"""

    def test_create_snapshot(self):
        """Can create state snapshot."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create some state
            (path / "semantic" / "patterns").mkdir(parents=True)
            (path / "semantic" / "patterns" / "p1.md").write_text("# Pattern 1")
            (path / "threats" / "signatures").mkdir(parents=True)
            (path / "threats" / "signatures" / "s1.json").write_text('{"id": "test"}')

            anchor = DecentralizedAnchor(memory_root=path)
            snapshot = anchor.create_snapshot()

            assert snapshot.state_hash != ""
            assert snapshot.merkle_root != ""
            assert len(snapshot.store_hashes) >= 2
            assert snapshot.entry_count >= 2

    def test_anchor_to_local(self):
        """Can anchor state to local proof store."""
        from src.memory.decentralized_anchor import DecentralizedAnchor, AnchorType

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)
            proof = anchor.anchor_state(anchor_types=[AnchorType.LOCAL])

            assert "local" in proof.anchors
            assert proof.proof_id.startswith("proof-")

            # Proof file should exist
            proof_file = path / "anchors" / "proofs" / f"{proof.proof_id}.json"
            assert proof_file.exists()

    def test_anchor_to_nostr(self):
        """Can anchor state to Nostr (simulated)."""
        from src.memory.decentralized_anchor import DecentralizedAnchor, AnchorType

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)
            proof = anchor.anchor_state(anchor_types=[AnchorType.NOSTR])

            assert "nostr" in proof.anchors
            assert "event_id" in proof.anchors["nostr"]
            assert "relay" in proof.anchors["nostr"]

            # Nostr event file should exist
            event_id = proof.anchors["nostr"]["event_id"]
            nostr_file = path / "anchors" / "nostr" / f"{event_id[:16]}.json"
            assert nostr_file.exists()

    def test_anchor_to_ipfs(self):
        """Can anchor state to IPFS (simulated)."""
        from src.memory.decentralized_anchor import DecentralizedAnchor, AnchorType

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)
            proof = anchor.anchor_state(anchor_types=[AnchorType.IPFS])

            assert "ipfs" in proof.anchors
            assert "cid" in proof.anchors["ipfs"]
            assert proof.anchors["ipfs"]["cid"].startswith("Qm")

    def test_anchor_all_networks(self):
        """Can anchor to all networks at once."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)
            proof = anchor.anchor_state()  # Default: all networks

            assert "local" in proof.anchors
            assert "nostr" in proof.anchors
            assert "ipfs" in proof.anchors

    def test_schedule_configuration(self):
        """Can get schedule configuration."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            anchor = DecentralizedAnchor(memory_root=Path(tmpdir))
            schedule = anchor.schedule_anchor(interval_hours=24)

            assert schedule["interval_hours"] == 24
            assert "next_anchor" in schedule
            assert "local" in schedule["anchor_types"]


class TestHistoricalRetrieval:
    """TEST: Historical state retrievable with proof"""

    def test_get_proof_by_id(self):
        """Can retrieve proof by ID."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)
            original_proof = anchor.anchor_state()

            # Retrieve by ID
            retrieved = anchor.get_proof(original_proof.proof_id)

            assert retrieved is not None
            assert retrieved.proof_id == original_proof.proof_id
            assert retrieved.snapshot.state_hash == original_proof.snapshot.state_hash

    def test_get_proof_for_time(self):
        """Can get proof closest to a given time."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content v1")

            anchor = DecentralizedAnchor(memory_root=path)

            # Create first proof
            proof1 = anchor.anchor_state()
            time1 = proof1.timestamp

            # Modify state and create second proof
            time.sleep(0.1)  # Ensure different timestamp
            (path / "semantic" / "test.txt").write_text("content v2")
            proof2 = anchor.anchor_state()

            # Get proof for time1 should return proof1
            retrieved = anchor.get_proof_for_time(time1)
            assert retrieved is not None
            assert retrieved.proof_id == proof1.proof_id

    def test_get_state_at_time(self):
        """Can retrieve state snapshot at a given time."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("original content")

            anchor = DecentralizedAnchor(memory_root=path)
            proof = anchor.anchor_state()

            # Get state at proof time
            state = anchor.get_state_at_time(proof.timestamp)

            assert state is not None
            assert state.state_hash == proof.snapshot.state_hash

    def test_list_proofs(self):
        """Can list all proofs."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)

            # Create multiple proofs
            anchor.anchor_state()
            time.sleep(0.1)
            anchor.anchor_state()
            time.sleep(0.1)
            anchor.anchor_state()

            proofs = anchor.list_proofs()
            assert len(proofs) >= 3


class TestProofVerification:
    """TEST: Prove memory state at time T from months ago"""

    def test_verify_valid_proof(self):
        """Can verify a valid proof."""
        from src.memory.decentralized_anchor import DecentralizedAnchor, ProofStatus

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)
            proof = anchor.anchor_state()

            result = anchor.verify_proof(proof)

            assert result.status == ProofStatus.VALID
            assert "local" in result.verified_anchors

    def test_verify_state_at_time(self):
        """Can verify state exists at a given time."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)
            proof = anchor.anchor_state()

            # Verify at proof time
            is_valid = anchor.verify_state_at_time(proof.timestamp)
            assert is_valid is True

    def test_verify_nonexistent_time_fails(self):
        """Verification fails for time with no proof."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            anchor = DecentralizedAnchor(memory_root=Path(tmpdir))

            # Try to verify a time in the past with no proofs
            past_time = (datetime.utcnow() - timedelta(days=365)).isoformat() + "Z"
            is_valid = anchor.verify_state_at_time(past_time)

            assert is_valid is False

    def test_proof_includes_signature(self):
        """Proofs include cryptographic signature."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)
            proof = anchor.anchor_state()

            assert proof.signature != ""
            assert len(proof.signature) == 64  # SHA256 hex

    def test_merkle_root_calculated(self):
        """Merkle root is calculated for state."""
        from src.memory.decentralized_anchor import DecentralizedAnchor

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create multiple files
            (path / "semantic" / "patterns").mkdir(parents=True)
            (path / "semantic" / "patterns" / "p1.md").write_text("Pattern 1")
            (path / "semantic" / "patterns" / "p2.md").write_text("Pattern 2")
            (path / "threats").mkdir()
            (path / "threats" / "sig.json").write_text("{}")

            anchor = DecentralizedAnchor(memory_root=path)
            snapshot = anchor.create_snapshot()

            assert snapshot.merkle_root != ""
            assert len(snapshot.merkle_root) == 64  # SHA256 hex

    def test_simulated_historical_proof(self):
        """Can prove state from simulated historical anchor."""
        from src.memory.decentralized_anchor import DecentralizedAnchor, ProofStatus

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "important.txt").write_text("critical data")

            anchor = DecentralizedAnchor(memory_root=path)

            # Create proof (simulates anchoring "months ago")
            proof = anchor.anchor_state()

            # Verify all anchors
            result = anchor.verify_proof(proof)

            assert result.status == ProofStatus.VALID
            assert len(result.verified_anchors) >= 1
            assert result.state_hash == proof.snapshot.state_hash

            # The proof demonstrates we can prove state at time T
            print(f"Proved state at {proof.timestamp}")
            print(f"State hash: {proof.snapshot.state_hash[:16]}...")
            print(f"Verified anchors: {result.verified_anchors}")


class TestConvenienceFunctions:
    """Test convenience functions."""

    def test_anchor_memory_state(self):
        """Convenience function works."""
        from src.memory.decentralized_anchor import anchor_memory_state

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            # Monkeypatch memory root
            import src.memory.init_store as init_store
            original = init_store.get_memory_root
            init_store.get_memory_root = lambda: path

            try:
                proof = anchor_memory_state(path)
                assert proof is not None
                assert proof.proof_id.startswith("proof-")
            finally:
                init_store.get_memory_root = original


class TestNostrEventFormat:
    """Test Nostr event format compliance."""

    def test_nostr_event_has_required_fields(self):
        """Nostr event has all required NIP-01 fields."""
        from src.memory.decentralized_anchor import DecentralizedAnchor, AnchorType

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)
            proof = anchor.anchor_state(anchor_types=[AnchorType.NOSTR])

            # Load event file
            event_id = proof.anchors["nostr"]["event_id"]
            nostr_file = path / "anchors" / "nostr" / f"{event_id[:16]}.json"
            event = json.loads(nostr_file.read_text())

            # NIP-01 required fields
            assert "id" in event
            assert "pubkey" in event
            assert "created_at" in event
            assert "kind" in event
            assert "tags" in event
            assert "content" in event
            assert "sig" in event


class TestIPFSPinFormat:
    """Test IPFS pin format."""

    def test_ipfs_cid_format(self):
        """IPFS CID has correct format."""
        from src.memory.decentralized_anchor import DecentralizedAnchor, AnchorType

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            (path / "semantic").mkdir()
            (path / "semantic" / "test.txt").write_text("content")

            anchor = DecentralizedAnchor(memory_root=path)
            proof = anchor.anchor_state(anchor_types=[AnchorType.IPFS])

            cid = proof.anchors["ipfs"]["cid"]

            # CID should start with Qm (CIDv0 format)
            assert cid.startswith("Qm")
            assert len(cid) >= 40


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
