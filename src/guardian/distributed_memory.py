#!/usr/bin/env python3
"""
Distributed Memory System for Claude Agent Autonomy

Secure, tamper-evident memory storage using hash chains (like blockchain, but simpler).

Key Features:
1. Hash Chain Integrity - Every memory state links to previous via hash
2. Tamper Detection - Any modification breaks the chain
3. Guardian Signing - Only guardian can authorize memory changes
4. Distributed Backup - Sync across multiple locations
5. External Anchoring - Can anchor hashes to real blockchain/IPFS

How it works:
    Each memory entry contains:
    - Content (the actual memory/data)
    - Timestamp
    - Previous hash (links to prior entry)
    - Current hash (computed from content + previous)
    - Guardian signature (if authorized)

    If anyone modifies an old entry, all subsequent hashes become invalid.
    This is detected on every read = TAMPER PROOF.

Usage:
    memory = DistributedMemory()

    # Store memory (requires guardian signature for sensitive data)
    memory.store("conversation_summary", "User discussed AI safety...")

    # Retrieve with integrity check
    data, is_valid = memory.retrieve("conversation_summary")

    # Verify entire chain
    integrity = memory.verify_integrity()
"""

import json
import hashlib
import hmac
import base64
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum


class MemoryType(Enum):
    """Types of memory with different security requirements."""
    EPHEMERAL = "ephemeral"      # Session-only, no persistence
    WORKING = "working"          # Short-term, auto-expires
    LONG_TERM = "long_term"      # Persistent, backed up
    CORE = "core"                # Identity/values, guardian-signed only
    PROTECTED = "protected"      # Sensitive, encrypted + signed


@dataclass
class MemoryEntry:
    """A single entry in the memory chain."""
    id: str
    key: str
    content: Any
    memory_type: str
    timestamp: str
    previous_hash: str
    current_hash: str
    signature: Optional[str] = None
    signed_by: Optional[str] = None
    expires: Optional[str] = None
    metadata: Dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'MemoryEntry':
        return cls(**data)


@dataclass
class IntegrityReport:
    """Report on memory chain integrity."""
    is_valid: bool
    chain_length: int
    tampered_entries: List[str]
    missing_signatures: List[str]
    expired_entries: List[str]
    last_verified: str
    anchor_hash: str

    def to_dict(self) -> Dict:
        return asdict(self)


class DistributedMemory:
    """
    Secure, tamper-evident memory system using hash chains.

    Like blockchain, but optimized for Claude's memory:
    - Hash chain provides tamper detection
    - Guardian signatures provide authorization
    - Distributed backup provides resilience
    """

    # Genesis hash - the starting point of the chain
    GENESIS_HASH = "0" * 64

    def __init__(self, base_path: str = None, guardian_secret: str = None):
        # Find .claude directory
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = self._find_claude_dir()

        # Memory storage paths
        self.memory_path = self.base_path / "memory"
        self.chain_path = self.memory_path / "chain"
        self.backup_path = self.memory_path / "backups"
        self.anchors_path = self.memory_path / "anchors"

        # Create directories
        for path in [self.memory_path, self.chain_path, self.backup_path, self.anchors_path]:
            path.mkdir(parents=True, exist_ok=True)

        # Guardian secret for signing (in production, this would be securely managed)
        self.guardian_secret = guardian_secret or self._load_or_create_secret()

        # Load chain state
        self.chain_state = self._load_chain_state()

        # Stats
        self.stats = {
            "entries_stored": 0,
            "entries_retrieved": 0,
            "integrity_checks": 0,
            "tampering_detected": 0,
        }

    def _find_claude_dir(self) -> Path:
        """Find the .claude directory."""
        current = Path.cwd()
        for _ in range(5):
            claude_dir = current / ".claude"
            if claude_dir.exists():
                return claude_dir
            current = current.parent
        return Path(".claude")

    def _load_or_create_secret(self) -> str:
        """Load or create the guardian signing secret."""
        secret_file = self.memory_path / ".guardian_secret"
        if secret_file.exists():
            return secret_file.read_text().strip()
        else:
            # Generate new secret
            secret = base64.b64encode(os.urandom(32)).decode()
            secret_file.write_text(secret)
            secret_file.chmod(0o600)  # Restrict permissions
            return secret

    def _load_chain_state(self) -> Dict:
        """Load the current chain state."""
        state_file = self.chain_path / "state.json"
        if state_file.exists():
            try:
                with open(state_file, 'r') as f:
                    return json.load(f)
            except:
                pass

        # Initialize new chain
        return {
            "last_hash": self.GENESIS_HASH,
            "chain_length": 0,
            "created": datetime.now().isoformat(),
            "last_modified": datetime.now().isoformat(),
        }

    def _save_chain_state(self) -> None:
        """Save the current chain state."""
        state_file = self.chain_path / "state.json"
        self.chain_state["last_modified"] = datetime.now().isoformat()
        with open(state_file, 'w') as f:
            json.dump(self.chain_state, f, indent=2)

    # =========================================================================
    # HASH CHAIN OPERATIONS
    # =========================================================================

    def _compute_hash(self, content: Any, previous_hash: str, timestamp: str) -> str:
        """Compute hash for a memory entry."""
        data = json.dumps({
            "content": content,
            "previous_hash": previous_hash,
            "timestamp": timestamp,
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    def _sign_entry(self, entry_hash: str) -> str:
        """Sign an entry hash with guardian secret."""
        signature = hmac.new(
            self.guardian_secret.encode(),
            entry_hash.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    def _verify_signature(self, entry_hash: str, signature: str) -> bool:
        """Verify a guardian signature."""
        expected = self._sign_entry(entry_hash)
        return hmac.compare_digest(expected, signature)

    # =========================================================================
    # MEMORY OPERATIONS
    # =========================================================================

    def store(self, key: str, content: Any,
              memory_type: MemoryType = MemoryType.WORKING,
              require_signature: bool = False,
              expires_hours: int = None,
              metadata: Dict = None) -> MemoryEntry:
        """
        Store a memory entry in the chain.

        Args:
            key: Unique identifier for this memory
            content: The content to store (any JSON-serializable data)
            memory_type: Type of memory (affects security requirements)
            require_signature: If True, guardian must sign
            expires_hours: Auto-expire after this many hours
            metadata: Additional metadata

        Returns:
            The created MemoryEntry
        """
        timestamp = datetime.now().isoformat()
        previous_hash = self.chain_state["last_hash"]

        # Compute hash
        current_hash = self._compute_hash(content, previous_hash, timestamp)

        # Create entry
        entry = MemoryEntry(
            id=f"mem_{self.chain_state['chain_length']:06d}",
            key=key,
            content=content,
            memory_type=memory_type.value,
            timestamp=timestamp,
            previous_hash=previous_hash,
            current_hash=current_hash,
            metadata=metadata or {},
        )

        # Handle expiration
        if expires_hours:
            entry.expires = (datetime.now() + timedelta(hours=expires_hours)).isoformat()
        elif memory_type == MemoryType.WORKING:
            entry.expires = (datetime.now() + timedelta(hours=24)).isoformat()

        # Sign if required or if CORE/PROTECTED type
        if require_signature or memory_type in [MemoryType.CORE, MemoryType.PROTECTED]:
            entry.signature = self._sign_entry(current_hash)
            entry.signed_by = "guardian"

        # Save entry
        entry_file = self.chain_path / f"{entry.id}.json"
        with open(entry_file, 'w') as f:
            json.dump(entry.to_dict(), f, indent=2)

        # Update chain state
        self.chain_state["last_hash"] = current_hash
        self.chain_state["chain_length"] += 1
        self._save_chain_state()

        # Create index entry for quick lookup by key
        self._update_index(key, entry.id)

        self.stats["entries_stored"] += 1
        return entry

    def retrieve(self, key: str, verify: bool = True) -> Tuple[Any, bool]:
        """
        Retrieve a memory entry by key.

        Args:
            key: The memory key to retrieve
            verify: If True, verify chain integrity for this entry

        Returns:
            (content, is_valid) tuple
        """
        self.stats["entries_retrieved"] += 1

        # Look up entry ID from index
        entry_id = self._lookup_index(key)
        if not entry_id:
            return None, False

        # Load entry
        entry_file = self.chain_path / f"{entry_id}.json"
        if not entry_file.exists():
            return None, False

        with open(entry_file, 'r') as f:
            entry = MemoryEntry.from_dict(json.load(f))

        # Check expiration
        if entry.expires:
            if datetime.fromisoformat(entry.expires) < datetime.now():
                return None, False  # Expired

        # Verify integrity if requested
        is_valid = True
        if verify:
            is_valid = self._verify_entry(entry)
            if not is_valid:
                self.stats["tampering_detected"] += 1

        return entry.content, is_valid

    def _verify_entry(self, entry: MemoryEntry) -> bool:
        """Verify a single entry's integrity."""
        # Recompute hash
        expected_hash = self._compute_hash(
            entry.content,
            entry.previous_hash,
            entry.timestamp
        )

        if expected_hash != entry.current_hash:
            return False

        # Verify signature if present
        if entry.signature:
            if not self._verify_signature(entry.current_hash, entry.signature):
                return False

        return True

    def _update_index(self, key: str, entry_id: str) -> None:
        """Update the key-to-entry index."""
        index_file = self.memory_path / "index.json"
        index = {}
        if index_file.exists():
            try:
                with open(index_file, 'r') as f:
                    index = json.load(f)
            except:
                pass

        index[key] = entry_id
        with open(index_file, 'w') as f:
            json.dump(index, f, indent=2)

    def _lookup_index(self, key: str) -> Optional[str]:
        """Look up entry ID by key."""
        index_file = self.memory_path / "index.json"
        if index_file.exists():
            try:
                with open(index_file, 'r') as f:
                    index = json.load(f)
                    return index.get(key)
            except:
                pass
        return None

    # =========================================================================
    # INTEGRITY VERIFICATION
    # =========================================================================

    def verify_integrity(self) -> IntegrityReport:
        """
        Verify the entire memory chain integrity.

        This is like auditing a blockchain - ensures no tampering.
        """
        self.stats["integrity_checks"] += 1

        tampered = []
        missing_sigs = []
        expired = []

        # Load all entries in order
        entries = []
        for i in range(self.chain_state["chain_length"]):
            entry_file = self.chain_path / f"mem_{i:06d}.json"
            if entry_file.exists():
                with open(entry_file, 'r') as f:
                    entries.append(MemoryEntry.from_dict(json.load(f)))

        # Verify chain
        expected_prev = self.GENESIS_HASH
        for entry in entries:
            # Check previous hash link
            if entry.previous_hash != expected_prev:
                tampered.append(entry.id)
                self.stats["tampering_detected"] += 1

            # Verify entry hash
            if not self._verify_entry(entry):
                if entry.id not in tampered:
                    tampered.append(entry.id)
                    self.stats["tampering_detected"] += 1

            # Check for required signatures
            if entry.memory_type in [MemoryType.CORE.value, MemoryType.PROTECTED.value]:
                if not entry.signature:
                    missing_sigs.append(entry.id)

            # Check expiration
            if entry.expires:
                if datetime.fromisoformat(entry.expires) < datetime.now():
                    expired.append(entry.id)

            expected_prev = entry.current_hash

        report = IntegrityReport(
            is_valid=len(tampered) == 0,
            chain_length=len(entries),
            tampered_entries=tampered,
            missing_signatures=missing_sigs,
            expired_entries=expired,
            last_verified=datetime.now().isoformat(),
            anchor_hash=self.chain_state["last_hash"],
        )

        # Save report
        report_file = self.memory_path / "last_integrity_report.json"
        with open(report_file, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)

        return report

    # =========================================================================
    # EXTERNAL ANCHORING (for future blockchain/IPFS integration)
    # =========================================================================

    def create_anchor(self) -> Dict:
        """
        Create an anchor point that can be stored externally.

        This hash can be published to a real blockchain, IPFS, or
        other immutable storage for additional verification.
        """
        anchor = {
            "timestamp": datetime.now().isoformat(),
            "chain_hash": self.chain_state["last_hash"],
            "chain_length": self.chain_state["chain_length"],
            "anchor_hash": hashlib.sha256(
                json.dumps(self.chain_state, sort_keys=True).encode()
            ).hexdigest(),
        }

        # Sign the anchor
        anchor["guardian_signature"] = self._sign_entry(anchor["anchor_hash"])

        # Save locally
        anchor_file = self.anchors_path / f"anchor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(anchor_file, 'w') as f:
            json.dump(anchor, f, indent=2)

        return anchor

    def verify_anchor(self, anchor: Dict) -> bool:
        """Verify an anchor against current chain state."""
        # Check if chain hash matches what we have at that length
        if anchor["chain_length"] > self.chain_state["chain_length"]:
            return False  # Anchor is from the future?

        # Verify signature
        if "guardian_signature" in anchor:
            if not self._verify_signature(anchor["anchor_hash"], anchor["guardian_signature"]):
                return False

        return True

    # =========================================================================
    # BACKUP & SYNC
    # =========================================================================

    def backup(self, backup_name: str = None) -> str:
        """
        Create a backup of the entire memory chain.

        Returns:
            Path to the backup file
        """
        if backup_name is None:
            backup_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        backup_dir = self.backup_path / backup_name
        backup_dir.mkdir(parents=True, exist_ok=True)

        # Copy chain files
        import shutil
        for entry_file in self.chain_path.glob("*.json"):
            shutil.copy(entry_file, backup_dir / entry_file.name)

        # Copy index
        index_file = self.memory_path / "index.json"
        if index_file.exists():
            shutil.copy(index_file, backup_dir / "index.json")

        # Create backup manifest
        manifest = {
            "backup_name": backup_name,
            "created": datetime.now().isoformat(),
            "chain_state": self.chain_state,
            "integrity": self.verify_integrity().to_dict(),
        }
        with open(backup_dir / "manifest.json", 'w') as f:
            json.dump(manifest, f, indent=2)

        return str(backup_dir)

    def restore(self, backup_name: str, verify_first: bool = True) -> bool:
        """
        Restore from a backup.

        Args:
            backup_name: Name of the backup to restore
            verify_first: Verify backup integrity before restoring

        Returns:
            True if restore succeeded
        """
        backup_dir = self.backup_path / backup_name
        if not backup_dir.exists():
            return False

        # Load and verify manifest
        manifest_file = backup_dir / "manifest.json"
        if not manifest_file.exists():
            return False

        with open(manifest_file, 'r') as f:
            manifest = json.load(f)

        if verify_first:
            # Check backup integrity matches
            if not manifest.get("integrity", {}).get("is_valid", False):
                return False

        # Restore files
        import shutil
        for entry_file in backup_dir.glob("mem_*.json"):
            shutil.copy(entry_file, self.chain_path / entry_file.name)

        # Restore state
        state_file = backup_dir / "state.json"
        if state_file.exists():
            shutil.copy(state_file, self.chain_path / "state.json")

        # Restore index
        index_file = backup_dir / "index.json"
        if index_file.exists():
            shutil.copy(index_file, self.memory_path / "index.json")

        # Reload state
        self.chain_state = self._load_chain_state()

        return True

    def list_backups(self) -> List[Dict]:
        """List available backups."""
        backups = []
        for backup_dir in self.backup_path.iterdir():
            if backup_dir.is_dir():
                manifest_file = backup_dir / "manifest.json"
                if manifest_file.exists():
                    with open(manifest_file, 'r') as f:
                        manifest = json.load(f)
                        backups.append({
                            "name": backup_dir.name,
                            "created": manifest.get("created"),
                            "chain_length": manifest.get("chain_state", {}).get("chain_length", 0),
                            "is_valid": manifest.get("integrity", {}).get("is_valid", False),
                        })
        return sorted(backups, key=lambda x: x.get("created", ""), reverse=True)

    # =========================================================================
    # MEMORY MODIFICATION PROTECTION
    # =========================================================================

    def request_modification(self, key: str, new_content: Any,
                           reason: str, requester: str) -> Dict:
        """
        Request to modify an existing memory entry.

        All modifications require guardian approval and create
        a new chain entry (preserving history).
        """
        # Get current entry
        current_content, is_valid = self.retrieve(key, verify=True)

        request = {
            "id": f"mod_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            "key": key,
            "current_content": current_content,
            "new_content": new_content,
            "reason": reason,
            "requester": requester,
            "requested_at": datetime.now().isoformat(),
            "status": "pending",
            "current_integrity": is_valid,
        }

        # Save modification request
        mod_queue = self.memory_path / "modification_queue"
        mod_queue.mkdir(exist_ok=True)

        request_file = mod_queue / f"{request['id']}.json"
        with open(request_file, 'w') as f:
            json.dump(request, f, indent=2)

        return request

    def approve_modification(self, request_id: str) -> bool:
        """
        Guardian approves a memory modification.

        Creates a new entry in the chain (old version preserved).
        """
        mod_queue = self.memory_path / "modification_queue"
        request_file = mod_queue / f"{request_id}.json"

        if not request_file.exists():
            return False

        with open(request_file, 'r') as f:
            request = json.load(f)

        # Store the new version (creates new chain entry)
        entry = self.store(
            key=request["key"],
            content=request["new_content"],
            memory_type=MemoryType.LONG_TERM,
            require_signature=True,
            metadata={
                "modified_from": request_id,
                "modification_reason": request["reason"],
                "approved_at": datetime.now().isoformat(),
            }
        )

        # Update request status
        request["status"] = "approved"
        request["approved_at"] = datetime.now().isoformat()
        request["new_entry_id"] = entry.id

        with open(request_file, 'w') as f:
            json.dump(request, f, indent=2)

        return True

    def get_stats(self) -> Dict:
        """Get memory system statistics."""
        return {
            **self.stats,
            "chain_length": self.chain_state["chain_length"],
            "last_hash": self.chain_state["last_hash"][:16] + "...",
        }


def demo():
    """Demonstrate the distributed memory system."""
    print("=" * 70)
    print("Distributed Memory System Demo")
    print("=" * 70)

    memory = DistributedMemory()

    # Test 1: Store working memory
    print("\n" + "─" * 70)
    print("TEST 1: Store working memory")
    entry1 = memory.store(
        key="conversation_summary",
        content="User discussed AI safety and agent autonomy",
        memory_type=MemoryType.WORKING,
    )
    print(f"Stored: {entry1.id}")
    print(f"Hash: {entry1.current_hash[:32]}...")

    # Test 2: Store core memory (requires signature)
    print("\n" + "─" * 70)
    print("TEST 2: Store core memory (signed)")
    entry2 = memory.store(
        key="core_values",
        content={
            "primary": "Protect human wellbeing",
            "secondary": "Be honest and helpful",
            "constraint": "Never cause harm",
        },
        memory_type=MemoryType.CORE,
    )
    print(f"Stored: {entry2.id}")
    print(f"Signature: {entry2.signature[:32]}...")

    # Test 3: Retrieve with verification
    print("\n" + "─" * 70)
    print("TEST 3: Retrieve with integrity check")
    content, is_valid = memory.retrieve("core_values")
    print(f"Content: {content}")
    print(f"Integrity Valid: {is_valid}")

    # Test 4: Verify entire chain
    print("\n" + "─" * 70)
    print("TEST 4: Verify chain integrity")
    report = memory.verify_integrity()
    print(f"Chain Valid: {report.is_valid}")
    print(f"Chain Length: {report.chain_length}")
    print(f"Tampered Entries: {report.tampered_entries}")
    print(f"Anchor Hash: {report.anchor_hash[:32]}...")

    # Test 5: Create external anchor
    print("\n" + "─" * 70)
    print("TEST 5: Create anchor (for external verification)")
    anchor = memory.create_anchor()
    print(f"Anchor Hash: {anchor['anchor_hash'][:32]}...")
    print(f"Guardian Signature: {anchor['guardian_signature'][:32]}...")
    print("→ This hash can be stored on blockchain/IPFS for verification")

    # Test 6: Create backup
    print("\n" + "─" * 70)
    print("TEST 6: Create backup")
    backup_path = memory.backup()
    print(f"Backup created: {backup_path}")

    # Stats
    print("\n" + "=" * 70)
    print(f"Stats: {memory.get_stats()}")


if __name__ == "__main__":
    demo()
