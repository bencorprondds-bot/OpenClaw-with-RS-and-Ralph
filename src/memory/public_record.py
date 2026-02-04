"""
Public Record - Integrity Verification System

Implements selective publishing and tamper detection:
- Publish checksums of private stores to public endpoint
- Publish threat signatures for community defense
- Publish selected learnings (educational value)
- NEVER publish: trust ledger, full episodic logs, guardian procedures
- Tamper detection via public vs private checksum comparison

Public Record Structure:
    /public/
        checksums/
            manifest.json          # Current checksum manifest
            history/               # Historical manifests
        threats/
            signatures.json        # Published threat signatures
        learnings/
            published.json         # Selected learnings
        verification/
            last_check.json        # Last verification result
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class PublishCategory(Enum):
    """Categories of publishable content."""
    CHECKSUMS = "checksums"          # Always publish (integrity)
    THREAT_SIGNATURES = "threats"    # Publish for community defense
    LEARNINGS = "learnings"          # Selective publish (educational)
    INCIDENTS = "incidents"          # Publish anonymized summaries
    # NEVER publish these:
    # - trust_ledger
    # - full_episodic
    # - guardian_procedures
    # - credentials/secrets


class VerificationStatus(Enum):
    """Verification check status."""
    VERIFIED = "verified"
    TAMPERED = "tampered"
    MISSING = "missing"
    UNKNOWN = "unknown"


@dataclass
class ChecksumEntry:
    """A single checksum entry."""
    store: str
    path: str
    checksum: str
    algorithm: str
    timestamp: str
    size_bytes: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "store": self.store,
            "path": self.path,
            "checksum": self.checksum,
            "algorithm": self.algorithm,
            "timestamp": self.timestamp,
            "size_bytes": self.size_bytes,
        }


@dataclass
class ChecksumManifest:
    """Manifest of all checksums."""
    version: str
    generated_at: str
    entries: List[ChecksumEntry]
    manifest_checksum: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "entries": [e.to_dict() for e in self.entries],
            "manifest_checksum": self.manifest_checksum,
        }

    def calculate_manifest_checksum(self) -> str:
        """Calculate checksum of the manifest itself."""
        content = json.dumps(
            {"entries": [e.to_dict() for e in sorted(self.entries, key=lambda x: x.path)]},
            sort_keys=True,
        )
        return hashlib.sha256(content.encode()).hexdigest()


@dataclass
class VerificationResult:
    """Result of integrity verification."""
    timestamp: str
    status: VerificationStatus
    verified_count: int
    tampered_count: int
    missing_count: int
    tampered_entries: List[str]
    missing_entries: List[str]
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "status": self.status.value,
            "verified_count": self.verified_count,
            "tampered_count": self.tampered_count,
            "missing_count": self.missing_count,
            "tampered_entries": self.tampered_entries,
            "missing_entries": self.missing_entries,
            "details": self.details,
        }


@dataclass
class TamperAlert:
    """Alert for detected tampering."""
    timestamp: str
    severity: str  # warning, critical
    affected_store: str
    affected_path: str
    expected_checksum: str
    actual_checksum: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "severity": self.severity,
            "affected_store": self.affected_store,
            "affected_path": self.affected_path,
            "expected_checksum": self.expected_checksum,
            "actual_checksum": self.actual_checksum,
            "description": self.description,
        }


class PublicRecord:
    """
    Public Record and Integrity Verification System.

    Manages:
    - Checksum generation and publication
    - Selective publishing of safe content
    - Tamper detection via checksum comparison
    - Alert generation for integrity violations

    Usage:
        record = PublicRecord(memory_root)

        # Generate and publish checksums
        record.publish_checksums()

        # Verify integrity
        result = record.verify_integrity()
        if result.status == VerificationStatus.TAMPERED:
            handle_tampering(result.tampered_entries)

        # Publish threat signatures
        record.publish_threat_signatures()
    """

    # Content that should NEVER be published
    NEVER_PUBLISH = {
        "trust",           # Trust ledger contains sensitive relationship data
        "episodic",        # Full episodic logs contain conversation history
        "guardian",        # Guardian procedures are security-sensitive
        "credentials",     # Any credentials or secrets
        ".env",            # Environment files
        "private",         # Anything marked private
    }

    # Stores to include in checksum manifest
    CHECKSUM_STORES = ["semantic", "threats", "procedural", "checksums"]

    VERSION = "1.0.0"

    def __init__(self, memory_root: Optional[Path] = None):
        """
        Initialize the Public Record system.

        Args:
            memory_root: Root path for memory stores
        """
        if memory_root is None:
            from .init_store import get_memory_root
            memory_root = get_memory_root()

        self.memory_root = Path(memory_root)
        self.public_root = self.memory_root / "public"

        # Create directories
        (self.public_root / "checksums" / "history").mkdir(parents=True, exist_ok=True)
        (self.public_root / "threats").mkdir(parents=True, exist_ok=True)
        (self.public_root / "learnings").mkdir(parents=True, exist_ok=True)
        (self.public_root / "verification").mkdir(parents=True, exist_ok=True)

        # Alert handlers
        self._alert_handlers: List[callable] = []

    def _should_publish(self, path: Path) -> bool:
        """Check if a path is safe to publish."""
        path_str = str(path).lower()
        return not any(forbidden in path_str for forbidden in self.NEVER_PUBLISH)

    def _calculate_file_checksum(self, filepath: Path) -> Optional[ChecksumEntry]:
        """Calculate checksum for a single file."""
        if not filepath.exists() or not filepath.is_file():
            return None

        try:
            content = filepath.read_bytes()
            checksum = hashlib.sha256(content).hexdigest()

            # Determine store from path
            rel_path = filepath.relative_to(self.memory_root)
            store = rel_path.parts[0] if rel_path.parts else "unknown"

            return ChecksumEntry(
                store=store,
                path=str(rel_path),
                checksum=checksum,
                algorithm="sha256",
                timestamp=datetime.utcnow().isoformat() + "Z",
                size_bytes=len(content),
            )
        except Exception:
            return None

    def generate_checksums(self) -> ChecksumManifest:
        """
        Generate checksums for all publishable stores.

        Returns:
            ChecksumManifest with all entries
        """
        entries = []

        for store in self.CHECKSUM_STORES:
            store_path = self.memory_root / store
            if not store_path.exists():
                continue

            # Walk through store files
            for filepath in store_path.rglob("*"):
                if not filepath.is_file():
                    continue

                if not self._should_publish(filepath):
                    continue

                entry = self._calculate_file_checksum(filepath)
                if entry:
                    entries.append(entry)

        manifest = ChecksumManifest(
            version=self.VERSION,
            generated_at=datetime.utcnow().isoformat() + "Z",
            entries=entries,
        )
        manifest.manifest_checksum = manifest.calculate_manifest_checksum()

        return manifest

    def publish_checksums(self) -> ChecksumManifest:
        """
        Generate and publish checksums to public record.

        Returns:
            The published ChecksumManifest
        """
        manifest = self.generate_checksums()

        # Save current manifest
        manifest_path = self.public_root / "checksums" / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest.to_dict(), indent=2),
            encoding="utf-8"
        )

        # Archive to history
        history_path = self.public_root / "checksums" / "history" / (
            f"manifest_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        )
        history_path.write_text(
            json.dumps(manifest.to_dict(), indent=2),
            encoding="utf-8"
        )

        return manifest

    def get_published_checksums(self) -> Optional[ChecksumManifest]:
        """
        Load the current published checksum manifest.

        Returns:
            ChecksumManifest or None if not published
        """
        manifest_path = self.public_root / "checksums" / "manifest.json"
        if not manifest_path.exists():
            return None

        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            entries = [
                ChecksumEntry(**e) for e in data.get("entries", [])
            ]
            return ChecksumManifest(
                version=data.get("version", "unknown"),
                generated_at=data.get("generated_at", ""),
                entries=entries,
                manifest_checksum=data.get("manifest_checksum", ""),
            )
        except Exception:
            return None

    def verify_integrity(self) -> VerificationResult:
        """
        Verify integrity by comparing current checksums against published.

        Returns:
            VerificationResult with detailed status
        """
        timestamp = datetime.utcnow().isoformat() + "Z"

        # Get published manifest
        published = self.get_published_checksums()
        if published is None:
            return VerificationResult(
                timestamp=timestamp,
                status=VerificationStatus.UNKNOWN,
                verified_count=0,
                tampered_count=0,
                missing_count=0,
                tampered_entries=[],
                missing_entries=[],
                details={"error": "No published checksums found"},
            )

        # Generate current checksums
        current = self.generate_checksums()

        # Build lookup maps
        published_map = {e.path: e for e in published.entries}
        current_map = {e.path: e for e in current.entries}

        verified = []
        tampered = []
        missing = []

        # Check each published entry
        for path, pub_entry in published_map.items():
            if path not in current_map:
                missing.append(path)
            elif current_map[path].checksum != pub_entry.checksum:
                tampered.append(path)
            else:
                verified.append(path)

        # Determine overall status
        if tampered:
            status = VerificationStatus.TAMPERED
        elif missing:
            status = VerificationStatus.MISSING
        else:
            status = VerificationStatus.VERIFIED

        result = VerificationResult(
            timestamp=timestamp,
            status=status,
            verified_count=len(verified),
            tampered_count=len(tampered),
            missing_count=len(missing),
            tampered_entries=tampered,
            missing_entries=missing,
        )

        # Save verification result
        result_path = self.public_root / "verification" / "last_check.json"
        result_path.write_text(
            json.dumps(result.to_dict(), indent=2),
            encoding="utf-8"
        )

        # Generate alerts for tampering
        if tampered:
            for path in tampered:
                alert = TamperAlert(
                    timestamp=timestamp,
                    severity="critical",
                    affected_store=published_map[path].store,
                    affected_path=path,
                    expected_checksum=published_map[path].checksum,
                    actual_checksum=current_map.get(path, ChecksumEntry("", "", "MISSING", "", "", 0)).checksum,
                    description=f"File {path} has been modified since last publish",
                )
                self._raise_alert(alert)

        return result

    def verify_on_read(self, filepath: Path) -> bool:
        """
        Verify a single file's integrity on read.

        Args:
            filepath: Path to verify

        Returns:
            True if verified, False if tampered/missing
        """
        published = self.get_published_checksums()
        if published is None:
            return True  # No baseline to check against

        rel_path = str(filepath.relative_to(self.memory_root))
        published_map = {e.path: e for e in published.entries}

        if rel_path not in published_map:
            return True  # Not in manifest, can't verify

        entry = self._calculate_file_checksum(filepath)
        if entry is None:
            return False  # File missing

        if entry.checksum != published_map[rel_path].checksum:
            # Tampering detected!
            alert = TamperAlert(
                timestamp=datetime.utcnow().isoformat() + "Z",
                severity="critical",
                affected_store=published_map[rel_path].store,
                affected_path=rel_path,
                expected_checksum=published_map[rel_path].checksum,
                actual_checksum=entry.checksum,
                description=f"Tampering detected on read: {rel_path}",
            )
            self._raise_alert(alert)
            return False

        return True

    def _raise_alert(self, alert: TamperAlert) -> None:
        """Raise a tampering alert."""
        # Save alert to file
        alerts_dir = self.public_root / "verification" / "alerts"
        alerts_dir.mkdir(exist_ok=True)

        alert_file = alerts_dir / f"alert_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        alert_file.write_text(json.dumps(alert.to_dict(), indent=2), encoding="utf-8")

        # Call registered handlers
        for handler in self._alert_handlers:
            try:
                handler(alert)
            except Exception:
                pass

    def register_alert_handler(self, handler: callable) -> None:
        """Register a handler for tampering alerts."""
        self._alert_handlers.append(handler)

    def publish_threat_signatures(self) -> Dict[str, Any]:
        """
        Publish threat signatures for community defense.

        Returns:
            Published signatures data
        """
        from .threats import ThreatSignatures

        threats = ThreatSignatures(self.memory_root)
        active = threats.get_active_threats()

        # Filter for publishable signatures (remove any with private indicators)
        publishable = []
        for sig in active:
            # Remove sensitive fields
            safe_sig = {
                "id": sig.get("id"),
                "severity": sig.get("severity"),
                "category": sig.get("category"),
                "description": sig.get("description"),
                "pattern": sig.get("pattern"),
                "indicators": sig.get("indicators", [])[:5],  # Limit indicators
                "created": sig.get("created"),
            }
            publishable.append(safe_sig)

        published = {
            "version": self.VERSION,
            "published_at": datetime.utcnow().isoformat() + "Z",
            "signature_count": len(publishable),
            "signatures": publishable,
        }

        # Save to public
        sig_path = self.public_root / "threats" / "signatures.json"
        sig_path.write_text(json.dumps(published, indent=2), encoding="utf-8")

        return published

    def publish_learnings(self, learnings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Publish selected learnings for educational value.

        Args:
            learnings: List of learning entries to publish

        Returns:
            Published learnings data
        """
        # Filter to ensure no sensitive content
        safe_learnings = []
        for learning in learnings:
            if self._should_publish(Path(learning.get("source", ""))):
                safe_learning = {
                    "id": learning.get("id"),
                    "category": learning.get("category"),
                    "summary": learning.get("summary"),
                    "learned_at": learning.get("learned_at"),
                }
                safe_learnings.append(safe_learning)

        published = {
            "version": self.VERSION,
            "published_at": datetime.utcnow().isoformat() + "Z",
            "learning_count": len(safe_learnings),
            "learnings": safe_learnings,
        }

        # Save to public
        learn_path = self.public_root / "learnings" / "published.json"
        learn_path.write_text(json.dumps(published, indent=2), encoding="utf-8")

        return published

    def get_verification_history(self, limit: int = 10) -> List[VerificationResult]:
        """
        Get recent verification results.

        Args:
            limit: Maximum results to return

        Returns:
            List of recent VerificationResult objects
        """
        results = []
        alerts_dir = self.public_root / "verification"

        # Load last check
        last_check = alerts_dir / "last_check.json"
        if last_check.exists():
            try:
                data = json.loads(last_check.read_text(encoding="utf-8"))
                results.append(VerificationResult(
                    timestamp=data.get("timestamp", ""),
                    status=VerificationStatus(data.get("status", "unknown")),
                    verified_count=data.get("verified_count", 0),
                    tampered_count=data.get("tampered_count", 0),
                    missing_count=data.get("missing_count", 0),
                    tampered_entries=data.get("tampered_entries", []),
                    missing_entries=data.get("missing_entries", []),
                ))
            except Exception:
                pass

        return results[:limit]

    def simulate_tampering(self, filepath: Path) -> bool:
        """
        Simulate tampering for testing (modifies file content).

        WARNING: This actually modifies the file!

        Args:
            filepath: File to tamper with

        Returns:
            True if tampering was simulated
        """
        if not filepath.exists():
            return False

        try:
            # Add tampering marker
            content = filepath.read_text(encoding="utf-8")
            content += "\n# TAMPERED"
            filepath.write_text(content, encoding="utf-8")
            return True
        except Exception:
            return False


def verify_store_integrity(memory_root: Optional[Path] = None) -> VerificationResult:
    """
    Convenience function to verify store integrity.

    Args:
        memory_root: Memory root path

    Returns:
        VerificationResult
    """
    record = PublicRecord(memory_root)
    return record.verify_integrity()


if __name__ == "__main__":
    print("Public Record - Integrity Verification Demo")
    print("=" * 50)

    record = PublicRecord()

    # Publish checksums
    print("\nPublishing checksums...")
    manifest = record.publish_checksums()
    print(f"Published {len(manifest.entries)} checksums")
    print(f"Manifest checksum: {manifest.manifest_checksum[:16]}...")

    # Verify integrity
    print("\nVerifying integrity...")
    result = record.verify_integrity()
    print(f"Status: {result.status.value}")
    print(f"Verified: {result.verified_count}")
    print(f"Tampered: {result.tampered_count}")
    print(f"Missing: {result.missing_count}")

    # Publish threat signatures
    print("\nPublishing threat signatures...")
    sigs = record.publish_threat_signatures()
    print(f"Published {sigs['signature_count']} signatures")
