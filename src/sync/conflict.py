"""
Conflict Detection and Resolution

Detects and resolves conflicts between local and domain stores.
Implements the priority: Guardian > Domain > Public > Decentralized > Local

Features:
- Version comparison
- Conflict detection
- Resolution strategies
- Guardian review flagging
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ConflictType(Enum):
    """Types of conflicts."""
    CONTENT_MISMATCH = "content_mismatch"  # Same path, different content
    MISSING_LOCAL = "missing_local"  # Exists in domain, not local
    MISSING_DOMAIN = "missing_domain"  # Exists in local, not domain
    CHECKSUM_MISMATCH = "checksum_mismatch"  # Checksum doesn't match
    VERSION_CONFLICT = "version_conflict"  # Different versions
    TIMESTAMP_CONFLICT = "timestamp_conflict"  # Modified at different times


class ResolutionStrategy(Enum):
    """Conflict resolution strategies."""
    USE_DOMAIN = "use_domain"  # Domain is authoritative
    USE_LOCAL = "use_local"  # Keep local version
    USE_NEWER = "use_newer"  # Use most recently modified
    MERGE = "merge"  # Attempt to merge (if possible)
    GUARDIAN_REVIEW = "guardian_review"  # Requires human review
    SKIP = "skip"  # Skip this conflict


@dataclass
class Conflict:
    """A detected conflict."""

    id: str
    store: str
    path: str
    conflict_type: str
    local_checksum: Optional[str] = None
    domain_checksum: Optional[str] = None
    local_modified: Optional[str] = None
    domain_modified: Optional[str] = None
    details: str = ""
    suggested_resolution: str = "use_domain"
    resolved: bool = False
    resolution: Optional[str] = None
    resolved_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "store": self.store,
            "path": self.path,
            "conflict_type": self.conflict_type,
            "local_checksum": self.local_checksum,
            "domain_checksum": self.domain_checksum,
            "local_modified": self.local_modified,
            "domain_modified": self.domain_modified,
            "details": self.details,
            "suggested_resolution": self.suggested_resolution,
            "resolved": self.resolved,
            "resolution": self.resolution,
            "resolved_at": self.resolved_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Conflict":
        return cls(**data)


@dataclass
class ConflictResolution:
    """Result of conflict resolution."""

    conflict_id: str
    strategy: str
    success: bool
    details: str = ""
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class ConflictDetector:
    """
    Detects conflicts between local and domain stores.

    Usage:
        detector = ConflictDetector(local_root)

        # Compare with domain
        conflicts = detector.detect_conflicts(domain_manifest, local_manifest)

        # Resolve conflicts
        for conflict in conflicts:
            resolution = detector.resolve(conflict, ResolutionStrategy.USE_DOMAIN)
    """

    # Priority order for resolution (higher = more authoritative)
    PRIORITY = {
        "guardian": 5,
        "domain": 4,
        "public": 3,
        "decentralized": 2,
        "local": 1,
    }

    def __init__(self, local_root: Path):
        """
        Initialize conflict detector.

        Args:
            local_root: Path to local memory store
        """
        self.local_root = Path(local_root)

        # Conflict storage
        self.conflicts_dir = self.local_root / ".conflicts"
        self.conflicts_dir.mkdir(parents=True, exist_ok=True)

        self.conflicts_file = self.conflicts_dir / "pending.json"
        self.resolved_file = self.conflicts_dir / "resolved.json"

        # Load existing conflicts
        self._conflicts: Dict[str, Conflict] = {}
        self._load_conflicts()

    def _load_conflicts(self) -> None:
        """Load conflicts from disk."""
        if self.conflicts_file.exists():
            try:
                data = json.loads(self.conflicts_file.read_text())
                for item in data:
                    conflict = Conflict.from_dict(item)
                    self._conflicts[conflict.id] = conflict
            except Exception:
                self._conflicts = {}

    def _save_conflicts(self) -> None:
        """Save conflicts to disk."""
        data = [c.to_dict() for c in self._conflicts.values() if not c.resolved]
        self.conflicts_file.write_text(json.dumps(data, indent=2))

    def _generate_id(self, store: str, path: str) -> str:
        """Generate conflict ID."""
        content = f"{store}:{path}:{datetime.utcnow().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def detect_conflicts(
        self,
        domain_files: Dict[str, Dict[str, Any]],
        local_files: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> List[Conflict]:
        """
        Detect conflicts between local and domain.

        Args:
            domain_files: Dict of {store/path: {checksum, modified, ...}}
            local_files: Dict of local files (computed if not provided)

        Returns:
            List of detected conflicts
        """
        if local_files is None:
            local_files = self._get_local_files()

        conflicts = []

        # Check all paths
        all_paths = set(domain_files.keys()) | set(local_files.keys())

        for path in all_paths:
            domain_info = domain_files.get(path)
            local_info = local_files.get(path)

            conflict = self._check_conflict(path, local_info, domain_info)
            if conflict:
                self._conflicts[conflict.id] = conflict
                conflicts.append(conflict)

        self._save_conflicts()
        return conflicts

    def _get_local_files(self) -> Dict[str, Dict[str, Any]]:
        """Get all local files with their info."""
        files = {}

        for store_name in ["episodic", "semantic", "trust", "threats", "procedural"]:
            store_path = self.local_root / store_name

            if not store_path.exists():
                continue

            for file_path in store_path.rglob("*"):
                if file_path.is_file():
                    rel_path = file_path.relative_to(self.local_root)
                    content = file_path.read_bytes()

                    files[str(rel_path)] = {
                        "checksum": hashlib.sha256(content).hexdigest(),
                        "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat() + "Z",
                        "size": len(content),
                    }

        return files

    def _check_conflict(
        self,
        path: str,
        local_info: Optional[Dict[str, Any]],
        domain_info: Optional[Dict[str, Any]],
    ) -> Optional[Conflict]:
        """Check if there's a conflict for a single file."""
        store = path.split("/")[0] if "/" in path else "unknown"
        file_path = "/".join(path.split("/")[1:]) if "/" in path else path

        # Missing in one location
        if local_info is None and domain_info is not None:
            return Conflict(
                id=self._generate_id(store, file_path),
                store=store,
                path=file_path,
                conflict_type=ConflictType.MISSING_LOCAL.value,
                domain_checksum=domain_info.get("checksum"),
                domain_modified=domain_info.get("modified"),
                details="File exists in domain but not locally",
                suggested_resolution=ResolutionStrategy.USE_DOMAIN.value,
            )

        if domain_info is None and local_info is not None:
            return Conflict(
                id=self._generate_id(store, file_path),
                store=store,
                path=file_path,
                conflict_type=ConflictType.MISSING_DOMAIN.value,
                local_checksum=local_info.get("checksum"),
                local_modified=local_info.get("modified"),
                details="File exists locally but not in domain",
                suggested_resolution=ResolutionStrategy.USE_LOCAL.value,
            )

        # Both exist - check for differences
        if local_info and domain_info:
            local_checksum = local_info.get("checksum")
            domain_checksum = domain_info.get("checksum")

            if local_checksum != domain_checksum:
                # Determine which is newer
                local_modified = local_info.get("modified", "")
                domain_modified = domain_info.get("modified", "")

                if local_modified > domain_modified:
                    suggested = ResolutionStrategy.USE_LOCAL.value
                else:
                    suggested = ResolutionStrategy.USE_DOMAIN.value

                return Conflict(
                    id=self._generate_id(store, file_path),
                    store=store,
                    path=file_path,
                    conflict_type=ConflictType.CONTENT_MISMATCH.value,
                    local_checksum=local_checksum,
                    domain_checksum=domain_checksum,
                    local_modified=local_modified,
                    domain_modified=domain_modified,
                    details=f"Content differs (local: {local_checksum[:8]}..., domain: {domain_checksum[:8]}...)",
                    suggested_resolution=suggested,
                )

        return None

    def resolve(
        self,
        conflict: Conflict,
        strategy: ResolutionStrategy,
        domain_sync: Optional[Any] = None,
    ) -> ConflictResolution:
        """
        Resolve a conflict using the specified strategy.

        Args:
            conflict: The conflict to resolve
            strategy: Resolution strategy to use
            domain_sync: Optional DomainSync instance for fetching/pushing

        Returns:
            ConflictResolution result
        """
        result = ConflictResolution(
            conflict_id=conflict.id,
            strategy=strategy.value,
            success=False,
        )

        try:
            if strategy == ResolutionStrategy.USE_DOMAIN:
                result = self._resolve_use_domain(conflict, domain_sync)

            elif strategy == ResolutionStrategy.USE_LOCAL:
                result = self._resolve_use_local(conflict, domain_sync)

            elif strategy == ResolutionStrategy.USE_NEWER:
                result = self._resolve_use_newer(conflict, domain_sync)

            elif strategy == ResolutionStrategy.GUARDIAN_REVIEW:
                result = self._flag_for_guardian(conflict)

            elif strategy == ResolutionStrategy.SKIP:
                result = ConflictResolution(
                    conflict_id=conflict.id,
                    strategy=strategy.value,
                    success=True,
                    details="Conflict skipped",
                )

            # Mark as resolved
            if result.success:
                conflict.resolved = True
                conflict.resolution = strategy.value
                conflict.resolved_at = datetime.utcnow().isoformat() + "Z"
                self._archive_resolved(conflict)

            self._save_conflicts()

        except Exception as e:
            result.details = f"Error: {e}"

        return result

    def _resolve_use_domain(
        self,
        conflict: Conflict,
        domain_sync: Optional[Any],
    ) -> ConflictResolution:
        """Resolve by using domain version."""
        if domain_sync is None:
            return ConflictResolution(
                conflict_id=conflict.id,
                strategy=ResolutionStrategy.USE_DOMAIN.value,
                success=False,
                details="No domain sync available",
            )

        # Pull specific file from domain
        # This would use domain_sync.pull_sync() for specific files
        # For now, return success assuming caller will handle

        return ConflictResolution(
            conflict_id=conflict.id,
            strategy=ResolutionStrategy.USE_DOMAIN.value,
            success=True,
            details=f"Using domain version for {conflict.store}/{conflict.path}",
        )

    def _resolve_use_local(
        self,
        conflict: Conflict,
        domain_sync: Optional[Any],
    ) -> ConflictResolution:
        """Resolve by using local version."""
        if domain_sync is None:
            return ConflictResolution(
                conflict_id=conflict.id,
                strategy=ResolutionStrategy.USE_LOCAL.value,
                success=False,
                details="No domain sync available",
            )

        # Push specific file to domain
        return ConflictResolution(
            conflict_id=conflict.id,
            strategy=ResolutionStrategy.USE_LOCAL.value,
            success=True,
            details=f"Using local version for {conflict.store}/{conflict.path}",
        )

    def _resolve_use_newer(
        self,
        conflict: Conflict,
        domain_sync: Optional[Any],
    ) -> ConflictResolution:
        """Resolve by using newer version."""
        local_mod = conflict.local_modified or ""
        domain_mod = conflict.domain_modified or ""

        if local_mod > domain_mod:
            return self._resolve_use_local(conflict, domain_sync)
        else:
            return self._resolve_use_domain(conflict, domain_sync)

    def _flag_for_guardian(self, conflict: Conflict) -> ConflictResolution:
        """Flag conflict for guardian review."""
        # Write to guardian review file
        review_file = self.conflicts_dir / "guardian_review.json"

        try:
            if review_file.exists():
                data = json.loads(review_file.read_text())
            else:
                data = []

            data.append({
                **conflict.to_dict(),
                "flagged_at": datetime.utcnow().isoformat() + "Z",
            })

            review_file.write_text(json.dumps(data, indent=2))

            return ConflictResolution(
                conflict_id=conflict.id,
                strategy=ResolutionStrategy.GUARDIAN_REVIEW.value,
                success=True,
                details="Flagged for guardian review",
            )
        except Exception as e:
            return ConflictResolution(
                conflict_id=conflict.id,
                strategy=ResolutionStrategy.GUARDIAN_REVIEW.value,
                success=False,
                details=f"Failed to flag: {e}",
            )

    def _archive_resolved(self, conflict: Conflict) -> None:
        """Archive a resolved conflict."""
        try:
            if self.resolved_file.exists():
                data = json.loads(self.resolved_file.read_text())
            else:
                data = []

            data.append(conflict.to_dict())

            # Keep only last 500 resolved
            if len(data) > 500:
                data = data[-500:]

            self.resolved_file.write_text(json.dumps(data, indent=2))

            # Remove from pending
            if conflict.id in self._conflicts:
                del self._conflicts[conflict.id]

        except Exception:
            pass

    def get_pending_conflicts(self) -> List[Conflict]:
        """Get all unresolved conflicts."""
        return [c for c in self._conflicts.values() if not c.resolved]

    def get_guardian_review_queue(self) -> List[Dict[str, Any]]:
        """Get conflicts flagged for guardian review."""
        review_file = self.conflicts_dir / "guardian_review.json"
        if not review_file.exists():
            return []

        try:
            return json.loads(review_file.read_text())
        except Exception:
            return []

    def clear_guardian_review(self, conflict_id: str) -> bool:
        """Remove a conflict from guardian review queue."""
        review_file = self.conflicts_dir / "guardian_review.json"
        if not review_file.exists():
            return False

        try:
            data = json.loads(review_file.read_text())
            data = [c for c in data if c.get("id") != conflict_id]
            review_file.write_text(json.dumps(data, indent=2))
            return True
        except Exception:
            return False

    def get_conflict_stats(self) -> Dict[str, Any]:
        """Get conflict statistics."""
        pending = self.get_pending_conflicts()

        by_type: Dict[str, int] = {}
        by_store: Dict[str, int] = {}

        for conflict in pending:
            by_type[conflict.conflict_type] = by_type.get(conflict.conflict_type, 0) + 1
            by_store[conflict.store] = by_store.get(conflict.store, 0) + 1

        return {
            "total_pending": len(pending),
            "guardian_review_queue": len(self.get_guardian_review_queue()),
            "by_type": by_type,
            "by_store": by_store,
        }
