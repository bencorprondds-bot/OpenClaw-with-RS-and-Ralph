"""
Sync Queue - Offline and Retry Support

Manages a persistent queue of changes that need to be synced to the domain.
Handles offline scenarios and automatic retry with backoff.

Features:
- Persistent queue storage
- Automatic retry with exponential backoff
- Batch processing
- Deduplication
"""

import json
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from enum import Enum


class SyncOperation(Enum):
    """Types of sync operations."""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"


@dataclass
class QueuedChange:
    """A queued change waiting to be synced."""

    id: str
    store: str
    path: str
    operation: str
    timestamp: str
    content_hash: Optional[str] = None
    retry_count: int = 0
    last_attempt: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "QueuedChange":
        return cls(**data)


class SyncQueue:
    """
    Persistent queue for sync operations.

    Usage:
        queue = SyncQueue(local_root)

        # Add change to queue
        queue.enqueue("episodic", "2026/02/03/session_001.jsonl", "update")

        # Process queue
        pending = queue.get_pending()
        for change in pending:
            success = sync_to_domain(change)
            if success:
                queue.mark_complete(change.id)
            else:
                queue.mark_failed(change.id, "Connection timeout")
    """

    def __init__(self, local_root: Path, max_retries: int = 5):
        """
        Initialize sync queue.

        Args:
            local_root: Path to local memory store
            max_retries: Maximum retry attempts before giving up
        """
        self.local_root = Path(local_root)
        self.max_retries = max_retries

        # Queue storage
        self.queue_dir = self.local_root / ".sync_queue"
        self.queue_dir.mkdir(parents=True, exist_ok=True)

        self.queue_file = self.queue_dir / "pending.json"
        self.failed_file = self.queue_dir / "failed.json"
        self.completed_file = self.queue_dir / "completed.json"

        # In-memory cache
        self._queue: Dict[str, QueuedChange] = {}
        self._load_queue()

    def _load_queue(self) -> None:
        """Load queue from disk."""
        if self.queue_file.exists():
            try:
                data = json.loads(self.queue_file.read_text())
                for item in data:
                    change = QueuedChange.from_dict(item)
                    self._queue[change.id] = change
            except Exception:
                self._queue = {}

    def _save_queue(self) -> None:
        """Save queue to disk."""
        data = [change.to_dict() for change in self._queue.values()]
        self.queue_file.write_text(json.dumps(data, indent=2))

    def _generate_id(self, store: str, path: str) -> str:
        """Generate unique ID for a change."""
        import hashlib
        content = f"{store}:{path}:{datetime.utcnow().isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def enqueue(
        self,
        store: str,
        path: str,
        operation: str = "update",
        content_hash: Optional[str] = None,
        deduplicate: bool = True,
    ) -> QueuedChange:
        """
        Add a change to the sync queue.

        Args:
            store: Store name (episodic, semantic, etc.)
            path: Path within store
            operation: Operation type (create, update, delete)
            content_hash: Optional hash of content for deduplication
            deduplicate: Whether to deduplicate existing entries

        Returns:
            The queued change
        """
        # Check for duplicate
        if deduplicate:
            for change in self._queue.values():
                if change.store == store and change.path == path:
                    # Update existing entry
                    change.timestamp = datetime.utcnow().isoformat() + "Z"
                    change.content_hash = content_hash
                    change.operation = operation
                    self._save_queue()
                    return change

        # Create new entry
        change = QueuedChange(
            id=self._generate_id(store, path),
            store=store,
            path=path,
            operation=operation,
            timestamp=datetime.utcnow().isoformat() + "Z",
            content_hash=content_hash,
        )

        self._queue[change.id] = change
        self._save_queue()

        return change

    def get_pending(self, limit: int = 100) -> List[QueuedChange]:
        """
        Get pending changes ready for sync.

        Args:
            limit: Maximum number of changes to return

        Returns:
            List of changes ready to sync
        """
        now = datetime.utcnow()
        pending = []

        for change in self._queue.values():
            if change.retry_count >= self.max_retries:
                continue

            # Check backoff period
            if change.last_attempt:
                try:
                    last = datetime.fromisoformat(change.last_attempt.replace("Z", "+00:00"))
                    backoff_seconds = min(300, 2 ** change.retry_count * 5)  # Max 5 minutes
                    if (now.replace(tzinfo=last.tzinfo) - last).total_seconds() < backoff_seconds:
                        continue
                except ValueError:
                    pass

            pending.append(change)

            if len(pending) >= limit:
                break

        # Sort by timestamp (oldest first)
        return sorted(pending, key=lambda c: c.timestamp)

    def mark_complete(self, change_id: str) -> None:
        """Mark a change as successfully synced."""
        if change_id not in self._queue:
            return

        change = self._queue.pop(change_id)

        # Log to completed file
        self._append_to_log(self.completed_file, change)

        self._save_queue()

    def mark_failed(self, change_id: str, error: str) -> None:
        """Mark a change as failed (will retry)."""
        if change_id not in self._queue:
            return

        change = self._queue[change_id]
        change.retry_count += 1
        change.last_attempt = datetime.utcnow().isoformat() + "Z"
        change.error = error

        # Move to failed if max retries exceeded
        if change.retry_count >= self.max_retries:
            self._queue.pop(change_id)
            self._append_to_log(self.failed_file, change)

        self._save_queue()

    def _append_to_log(self, log_file: Path, change: QueuedChange) -> None:
        """Append change to a log file."""
        try:
            if log_file.exists():
                data = json.loads(log_file.read_text())
            else:
                data = []

            data.append(change.to_dict())

            # Keep only last 1000 entries
            if len(data) > 1000:
                data = data[-1000:]

            log_file.write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        pending = [c for c in self._queue.values() if c.retry_count < self.max_retries]
        retrying = [c for c in self._queue.values() if c.retry_count > 0 and c.retry_count < self.max_retries]

        return {
            "total_pending": len(pending),
            "retrying": len(retrying),
            "by_store": self._count_by_store(),
            "by_operation": self._count_by_operation(),
            "oldest_pending": min((c.timestamp for c in pending), default=None),
        }

    def _count_by_store(self) -> Dict[str, int]:
        """Count pending changes by store."""
        counts: Dict[str, int] = {}
        for change in self._queue.values():
            counts[change.store] = counts.get(change.store, 0) + 1
        return counts

    def _count_by_operation(self) -> Dict[str, int]:
        """Count pending changes by operation."""
        counts: Dict[str, int] = {}
        for change in self._queue.values():
            counts[change.operation] = counts.get(change.operation, 0) + 1
        return counts

    def clear_completed(self, older_than_days: int = 7) -> int:
        """Clear old completed entries."""
        if not self.completed_file.exists():
            return 0

        try:
            data = json.loads(self.completed_file.read_text())
            cutoff = datetime.utcnow().isoformat()[:10]  # Simple date comparison

            original_count = len(data)
            data = [
                item for item in data
                if item.get("timestamp", "")[:10] >= cutoff
            ]

            self.completed_file.write_text(json.dumps(data, indent=2))
            return original_count - len(data)
        except Exception:
            return 0

    def clear_all(self) -> None:
        """Clear entire queue (use with caution)."""
        self._queue.clear()
        self._save_queue()

    def retry_failed(self) -> int:
        """Move failed items back to pending queue."""
        if not self.failed_file.exists():
            return 0

        try:
            data = json.loads(self.failed_file.read_text())
            count = 0

            for item in data:
                change = QueuedChange.from_dict(item)
                change.retry_count = 0
                change.last_attempt = None
                change.error = None
                self._queue[change.id] = change
                count += 1

            # Clear failed file
            self.failed_file.write_text("[]")

            self._save_queue()
            return count
        except Exception:
            return 0
