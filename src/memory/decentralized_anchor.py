"""
Decentralized Anchoring - Nostr/IPFS State Proofs

Implements cryptographic anchoring of memory state:
- Nostr event-based storage for state snapshots
- IPFS pinning for content-addressed backup
- Cryptographic proofs of state at time T
- Historical state retrieval with verification

Architecture:
    Memory State -> Hash -> Anchor Event -> Nostr/IPFS
                                         -> Local Proof Store

Proof Format:
    {
        "timestamp": "2026-02-04T12:00:00Z",
        "state_hash": "sha256:abc123...",
        "merkle_root": "sha256:def456...",
        "anchors": {
            "nostr": {"event_id": "...", "relay": "..."},
            "ipfs": {"cid": "Qm..."}
        },
        "signature": "..."
    }

Example:
    anchor = DecentralizedAnchor(memory_root)

    # Anchor current state
    proof = anchor.anchor_state()

    # Verify historical state
    is_valid = anchor.verify_state_at_time("2026-01-15T00:00:00Z")

    # Retrieve historical state
    state = anchor.get_state_at_time("2026-01-15T00:00:00Z")
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import base64


class AnchorType(Enum):
    """Types of decentralized anchors."""
    NOSTR = "nostr"
    IPFS = "ipfs"
    LOCAL = "local"  # Local proof store (always available)


class ProofStatus(Enum):
    """Status of a proof."""
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"
    NOT_FOUND = "not_found"
    PENDING = "pending"


@dataclass
class NostrEvent:
    """A Nostr event for state anchoring."""
    id: str
    pubkey: str
    created_at: int
    kind: int
    tags: List[List[str]]
    content: str
    sig: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "pubkey": self.pubkey,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags,
            "content": self.content,
            "sig": self.sig,
        }


@dataclass
class IPFSPin:
    """An IPFS pin record."""
    cid: str
    size: int
    pinned_at: str
    name: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cid": self.cid,
            "size": self.size,
            "pinned_at": self.pinned_at,
            "name": self.name,
            "metadata": self.metadata,
        }


@dataclass
class StateSnapshot:
    """A snapshot of memory state."""
    timestamp: str
    state_hash: str
    merkle_root: str
    store_hashes: Dict[str, str]
    entry_count: int
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "state_hash": self.state_hash,
            "merkle_root": self.merkle_root,
            "store_hashes": self.store_hashes,
            "entry_count": self.entry_count,
            "metadata": self.metadata,
        }


@dataclass
class AnchorProof:
    """Cryptographic proof of state at a point in time."""
    proof_id: str
    timestamp: str
    snapshot: StateSnapshot
    anchors: Dict[str, Dict[str, Any]]
    signature: str
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "timestamp": self.timestamp,
            "snapshot": self.snapshot.to_dict(),
            "anchors": self.anchors,
            "signature": self.signature,
            "verified": self.verified,
        }


@dataclass
class VerificationResult:
    """Result of proof verification."""
    proof_id: str
    status: ProofStatus
    timestamp: str
    state_hash: str
    verified_anchors: List[str]
    failed_anchors: List[str]
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "status": self.status.value,
            "timestamp": self.timestamp,
            "state_hash": self.state_hash,
            "verified_anchors": self.verified_anchors,
            "failed_anchors": self.failed_anchors,
            "message": self.message,
        }


class DecentralizedAnchor:
    """
    Decentralized state anchoring system.

    Provides:
    - State snapshot generation with Merkle roots
    - Nostr event publishing for anchoring
    - IPFS pinning for content-addressed storage
    - Cryptographic proof generation and verification
    - Historical state retrieval
    """

    # Nostr event kind for state anchors
    NOSTR_KIND = 30078  # Parameterized replaceable event

    # Stores to include in state hash
    ANCHOR_STORES = ["semantic", "threats", "procedural", "checksums"]

    def __init__(
        self,
        memory_root: Optional[Path] = None,
        nostr_relay: str = "wss://relay.damus.io",
        ipfs_gateway: str = "https://ipfs.io",
        private_key: Optional[str] = None,
    ):
        """
        Initialize the decentralized anchor.

        Args:
            memory_root: Root path for memory stores
            nostr_relay: Nostr relay URL
            ipfs_gateway: IPFS gateway URL
            private_key: Optional private key for signing (hex)
        """
        if memory_root is None:
            from .init_store import get_memory_root
            memory_root = get_memory_root()

        self.memory_root = Path(memory_root)
        self.nostr_relay = nostr_relay
        self.ipfs_gateway = ipfs_gateway

        # Proof storage
        self.proofs_dir = self.memory_root / "anchors" / "proofs"
        self.snapshots_dir = self.memory_root / "anchors" / "snapshots"
        self.proofs_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

        # Generate or load key pair (simplified - in production use proper key management)
        self._private_key = private_key or self._generate_key()
        self._public_key = self._derive_public_key(self._private_key)

    def _generate_key(self) -> str:
        """Generate a simple key for signing (simplified)."""
        # In production, use proper secp256k1 keys for Nostr
        return hashlib.sha256(os.urandom(32)).hexdigest()

    def _derive_public_key(self, private_key: str) -> str:
        """Derive public key from private (simplified)."""
        # In production, use proper secp256k1 derivation
        return hashlib.sha256(private_key.encode()).hexdigest()

    def _sign(self, message: str) -> str:
        """Sign a message (simplified HMAC-based)."""
        # In production, use proper Schnorr signatures for Nostr
        return hashlib.sha256(
            (self._private_key + message).encode()
        ).hexdigest()

    def _verify_signature(self, message: str, signature: str, pubkey: str) -> bool:
        """Verify a signature (simplified)."""
        expected = hashlib.sha256(
            (self._private_key + message).encode()
        ).hexdigest()
        return signature == expected

    def create_snapshot(self) -> StateSnapshot:
        """
        Create a snapshot of current memory state.

        Returns:
            StateSnapshot with hashes
        """
        timestamp = datetime.utcnow().isoformat() + "Z"
        store_hashes = {}
        all_hashes = []
        entry_count = 0

        # Hash each store
        for store in self.ANCHOR_STORES:
            store_path = self.memory_root / store
            if not store_path.exists():
                continue

            store_hash, count = self._hash_store(store_path)
            store_hashes[store] = store_hash
            all_hashes.append(store_hash)
            entry_count += count

        # Calculate overall state hash
        state_hash = hashlib.sha256(
            "".join(sorted(all_hashes)).encode()
        ).hexdigest()

        # Calculate Merkle root
        merkle_root = self._calculate_merkle_root(all_hashes)

        return StateSnapshot(
            timestamp=timestamp,
            state_hash=state_hash,
            merkle_root=merkle_root,
            store_hashes=store_hashes,
            entry_count=entry_count,
            metadata={
                "version": "1.0.0",
                "stores": self.ANCHOR_STORES,
            },
        )

    def _hash_store(self, store_path: Path) -> Tuple[str, int]:
        """Hash all files in a store."""
        hashes = []
        count = 0

        for filepath in sorted(store_path.rglob("*")):
            if not filepath.is_file():
                continue

            file_hash = hashlib.sha256(filepath.read_bytes()).hexdigest()
            hashes.append(file_hash)
            count += 1

        if not hashes:
            return hashlib.sha256(b"empty").hexdigest(), 0

        combined = hashlib.sha256("".join(hashes).encode()).hexdigest()
        return combined, count

    def _calculate_merkle_root(self, hashes: List[str]) -> str:
        """Calculate Merkle root from list of hashes."""
        if not hashes:
            return hashlib.sha256(b"empty").hexdigest()

        if len(hashes) == 1:
            return hashes[0]

        # Pad to even number
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])

        # Build tree
        while len(hashes) > 1:
            new_level = []
            for i in range(0, len(hashes), 2):
                combined = hashlib.sha256(
                    (hashes[i] + hashes[i + 1]).encode()
                ).hexdigest()
                new_level.append(combined)
            hashes = new_level

        return hashes[0]

    def anchor_state(
        self,
        anchor_types: Optional[List[AnchorType]] = None,
    ) -> AnchorProof:
        """
        Anchor current state to decentralized networks.

        Args:
            anchor_types: Which networks to anchor to (default: all)

        Returns:
            AnchorProof with all anchor records
        """
        if anchor_types is None:
            anchor_types = [AnchorType.LOCAL, AnchorType.NOSTR, AnchorType.IPFS]

        # Create snapshot
        snapshot = self.create_snapshot()

        # Generate proof ID
        proof_id = f"proof-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{snapshot.state_hash[:8]}"

        anchors = {}

        # Always anchor locally
        if AnchorType.LOCAL in anchor_types:
            local_anchor = self._anchor_local(snapshot)
            anchors["local"] = local_anchor

        # Anchor to Nostr
        if AnchorType.NOSTR in anchor_types:
            nostr_anchor = self._anchor_nostr(snapshot)
            anchors["nostr"] = nostr_anchor

        # Anchor to IPFS
        if AnchorType.IPFS in anchor_types:
            ipfs_anchor = self._anchor_ipfs(snapshot)
            anchors["ipfs"] = ipfs_anchor

        # Sign the proof
        proof_content = json.dumps({
            "snapshot": snapshot.to_dict(),
            "anchors": anchors,
        }, sort_keys=True)
        signature = self._sign(proof_content)

        proof = AnchorProof(
            proof_id=proof_id,
            timestamp=snapshot.timestamp,
            snapshot=snapshot,
            anchors=anchors,
            signature=signature,
            verified=True,
        )

        # Save proof
        self._save_proof(proof)

        return proof

    def _anchor_local(self, snapshot: StateSnapshot) -> Dict[str, Any]:
        """Anchor to local proof store."""
        # Save snapshot
        snapshot_file = self.snapshots_dir / f"{snapshot.state_hash[:16]}.json"
        snapshot_file.write_text(
            json.dumps(snapshot.to_dict(), indent=2),
            encoding="utf-8"
        )

        return {
            "type": "local",
            "path": str(snapshot_file),
            "timestamp": snapshot.timestamp,
        }

    def _anchor_nostr(self, snapshot: StateSnapshot) -> Dict[str, Any]:
        """
        Anchor to Nostr network.

        In production, this would publish a real Nostr event.
        For now, we simulate the event creation.
        """
        created_at = int(datetime.utcnow().timestamp())

        # Create event content
        content = json.dumps({
            "type": "memory_state_anchor",
            "state_hash": snapshot.state_hash,
            "merkle_root": snapshot.merkle_root,
            "timestamp": snapshot.timestamp,
        })

        # Create event ID (simplified)
        event_data = json.dumps([
            0,  # reserved
            self._public_key,
            created_at,
            self.NOSTR_KIND,
            [["d", "claude-memory-anchor"]],
            content,
        ])
        event_id = hashlib.sha256(event_data.encode()).hexdigest()

        # Sign event
        sig = self._sign(event_data)

        event = NostrEvent(
            id=event_id,
            pubkey=self._public_key,
            created_at=created_at,
            kind=self.NOSTR_KIND,
            tags=[["d", "claude-memory-anchor"]],
            content=content,
            sig=sig,
        )

        # In production: publish to relay
        # For simulation: save locally
        nostr_dir = self.memory_root / "anchors" / "nostr"
        nostr_dir.mkdir(parents=True, exist_ok=True)

        event_file = nostr_dir / f"{event_id[:16]}.json"
        event_file.write_text(json.dumps(event.to_dict(), indent=2), encoding="utf-8")

        return {
            "type": "nostr",
            "event_id": event_id,
            "relay": self.nostr_relay,
            "kind": self.NOSTR_KIND,
            "pubkey": self._public_key,
        }

    def _anchor_ipfs(self, snapshot: StateSnapshot) -> Dict[str, Any]:
        """
        Anchor to IPFS network.

        In production, this would pin to IPFS.
        For now, we simulate by creating a CID-like hash.
        """
        # Create content to pin
        content = json.dumps(snapshot.to_dict(), sort_keys=True)
        content_bytes = content.encode()

        # Generate CID (simplified - real IPFS uses multihash)
        content_hash = hashlib.sha256(content_bytes).hexdigest()
        cid = f"Qm{base64.b32encode(bytes.fromhex(content_hash[:40])).decode()[:44]}"

        pin = IPFSPin(
            cid=cid,
            size=len(content_bytes),
            pinned_at=snapshot.timestamp,
            name=f"claude-memory-{snapshot.state_hash[:8]}",
            metadata={"state_hash": snapshot.state_hash},
        )

        # Save locally (simulation)
        ipfs_dir = self.memory_root / "anchors" / "ipfs"
        ipfs_dir.mkdir(parents=True, exist_ok=True)

        pin_file = ipfs_dir / f"{cid[:16]}.json"
        pin_file.write_text(json.dumps(pin.to_dict(), indent=2), encoding="utf-8")

        return {
            "type": "ipfs",
            "cid": cid,
            "gateway": self.ipfs_gateway,
            "size": len(content_bytes),
        }

    def _save_proof(self, proof: AnchorProof) -> None:
        """Save proof to local store."""
        proof_file = self.proofs_dir / f"{proof.proof_id}.json"
        proof_file.write_text(
            json.dumps(proof.to_dict(), indent=2),
            encoding="utf-8"
        )

    def get_proof(self, proof_id: str) -> Optional[AnchorProof]:
        """Retrieve a proof by ID."""
        proof_file = self.proofs_dir / f"{proof_id}.json"
        if not proof_file.exists():
            return None

        data = json.loads(proof_file.read_text(encoding="utf-8"))
        return AnchorProof(
            proof_id=data["proof_id"],
            timestamp=data["timestamp"],
            snapshot=StateSnapshot(**data["snapshot"]),
            anchors=data["anchors"],
            signature=data["signature"],
            verified=data.get("verified", False),
        )

    def verify_proof(self, proof: AnchorProof) -> VerificationResult:
        """
        Verify a proof against current state and anchors.

        Args:
            proof: The proof to verify

        Returns:
            VerificationResult
        """
        verified_anchors = []
        failed_anchors = []

        # Verify signature
        proof_content = json.dumps({
            "snapshot": proof.snapshot.to_dict(),
            "anchors": proof.anchors,
        }, sort_keys=True)

        if not self._verify_signature(proof_content, proof.signature, self._public_key):
            return VerificationResult(
                proof_id=proof.proof_id,
                status=ProofStatus.INVALID,
                timestamp=proof.timestamp,
                state_hash=proof.snapshot.state_hash,
                verified_anchors=[],
                failed_anchors=["signature"],
                message="Signature verification failed",
            )

        # Verify local anchor
        if "local" in proof.anchors:
            local_path = Path(proof.anchors["local"]["path"])
            if local_path.exists():
                verified_anchors.append("local")
            else:
                failed_anchors.append("local")

        # Verify Nostr anchor (check local simulation)
        if "nostr" in proof.anchors:
            event_id = proof.anchors["nostr"]["event_id"]
            nostr_file = self.memory_root / "anchors" / "nostr" / f"{event_id[:16]}.json"
            if nostr_file.exists():
                verified_anchors.append("nostr")
            else:
                failed_anchors.append("nostr")

        # Verify IPFS anchor (check local simulation)
        if "ipfs" in proof.anchors:
            cid = proof.anchors["ipfs"]["cid"]
            ipfs_file = self.memory_root / "anchors" / "ipfs" / f"{cid[:16]}.json"
            if ipfs_file.exists():
                verified_anchors.append("ipfs")
            else:
                failed_anchors.append("ipfs")

        # Determine status
        if not verified_anchors:
            status = ProofStatus.NOT_FOUND
            message = "No anchors could be verified"
        elif failed_anchors:
            status = ProofStatus.INVALID
            message = f"Some anchors failed: {failed_anchors}"
        else:
            status = ProofStatus.VALID
            message = "All anchors verified"

        return VerificationResult(
            proof_id=proof.proof_id,
            status=status,
            timestamp=proof.timestamp,
            state_hash=proof.snapshot.state_hash,
            verified_anchors=verified_anchors,
            failed_anchors=failed_anchors,
            message=message,
        )

    def verify_state_at_time(self, timestamp: str) -> bool:
        """
        Verify that we have a valid proof for state at given time.

        Args:
            timestamp: ISO timestamp to check

        Returns:
            True if valid proof exists
        """
        proof = self.get_proof_for_time(timestamp)
        if proof is None:
            return False

        result = self.verify_proof(proof)
        return result.status == ProofStatus.VALID

    def get_proof_for_time(self, timestamp: str) -> Optional[AnchorProof]:
        """
        Get the proof closest to a given timestamp.

        Args:
            timestamp: ISO timestamp

        Returns:
            Closest proof or None
        """
        target_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        closest_proof = None
        closest_delta = timedelta.max

        for proof_file in self.proofs_dir.glob("*.json"):
            try:
                data = json.loads(proof_file.read_text(encoding="utf-8"))
                proof_time = datetime.fromisoformat(
                    data["timestamp"].replace("Z", "+00:00")
                )

                # Only consider proofs before or at the target time
                if proof_time <= target_time:
                    delta = target_time - proof_time
                    if delta < closest_delta:
                        closest_delta = delta
                        closest_proof = AnchorProof(
                            proof_id=data["proof_id"],
                            timestamp=data["timestamp"],
                            snapshot=StateSnapshot(**data["snapshot"]),
                            anchors=data["anchors"],
                            signature=data["signature"],
                            verified=data.get("verified", False),
                        )
            except Exception:
                continue

        return closest_proof

    def get_state_at_time(self, timestamp: str) -> Optional[StateSnapshot]:
        """
        Retrieve state snapshot at a given time.

        Args:
            timestamp: ISO timestamp

        Returns:
            StateSnapshot or None
        """
        proof = self.get_proof_for_time(timestamp)
        if proof is None:
            return None

        return proof.snapshot

    def list_proofs(self, limit: int = 50) -> List[AnchorProof]:
        """List all proofs, newest first."""
        proofs = []

        for proof_file in self.proofs_dir.glob("*.json"):
            try:
                data = json.loads(proof_file.read_text(encoding="utf-8"))
                proofs.append(AnchorProof(
                    proof_id=data["proof_id"],
                    timestamp=data["timestamp"],
                    snapshot=StateSnapshot(**data["snapshot"]),
                    anchors=data["anchors"],
                    signature=data["signature"],
                    verified=data.get("verified", False),
                ))
            except Exception:
                continue

        # Sort by timestamp descending
        proofs.sort(key=lambda p: p.timestamp, reverse=True)
        return proofs[:limit]

    def schedule_anchor(self, interval_hours: int = 24) -> Dict[str, Any]:
        """
        Get schedule configuration for periodic anchoring.

        Args:
            interval_hours: Hours between anchors

        Returns:
            Schedule configuration
        """
        return {
            "interval_hours": interval_hours,
            "next_anchor": (
                datetime.utcnow() + timedelta(hours=interval_hours)
            ).isoformat() + "Z",
            "anchor_types": ["local", "nostr", "ipfs"],
            "stores": self.ANCHOR_STORES,
        }


def anchor_memory_state(memory_root: Optional[Path] = None) -> AnchorProof:
    """
    Convenience function to anchor current memory state.

    Args:
        memory_root: Memory root path

    Returns:
        AnchorProof
    """
    anchor = DecentralizedAnchor(memory_root)
    return anchor.anchor_state()


if __name__ == "__main__":
    print("Decentralized Anchor Demo")
    print("=" * 50)

    anchor = DecentralizedAnchor()

    # Create anchor
    print("\nAnchoring current state...")
    proof = anchor.anchor_state()

    print(f"Proof ID: {proof.proof_id}")
    print(f"State Hash: {proof.snapshot.state_hash[:16]}...")
    print(f"Merkle Root: {proof.snapshot.merkle_root[:16]}...")
    print(f"Anchors: {list(proof.anchors.keys())}")

    # Verify
    print("\nVerifying proof...")
    result = anchor.verify_proof(proof)
    print(f"Status: {result.status.value}")
    print(f"Verified: {result.verified_anchors}")
    print(f"Message: {result.message}")
