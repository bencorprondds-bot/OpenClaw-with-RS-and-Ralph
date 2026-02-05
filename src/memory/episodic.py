"""
Episodic Store - Raw Audit Trail

Stores interaction logs as append-only JSONL files with checksums.
This is the ground truth - what actually happened.

Structure:
    /episodic/
      /YYYY/
        /MM/
          /DD/
            session_001.jsonl
            session_001.sha256
"""

import hashlib
import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


@dataclass
class EpisodicEntry:
    """A single episodic memory entry."""

    timestamp: str
    session_id: str
    type: str  # interaction, system, error, etc.
    source: Dict[str, Any]  # identifier, trust_level, verified
    content: str
    response_summary: Optional[str] = None
    flags: List[str] = None
    checksum: Optional[str] = None

    def __post_init__(self):
        if self.flags is None:
            self.flags = []
        if self.checksum is None:
            self.checksum = self._compute_checksum()

    def _compute_checksum(self) -> str:
        """Compute SHA256 checksum of entry content."""
        data = {
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "type": self.type,
            "source": self.source,
            "content": self.content,
            "response_summary": self.response_summary,
            "flags": self.flags,
        }
        content = json.dumps(data, sort_keys=True)
        return f"sha256:{hashlib.sha256(content.encode()).hexdigest()}"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EpisodicEntry":
        """Create from dictionary."""
        return cls(**data)

    def verify(self) -> bool:
        """Verify the entry's checksum."""
        expected = self._compute_checksum()
        return self.checksum == expected


class EpisodicStore:
    """
    Manages episodic memory storage.

    Features:
    - Append-only JSONL files
    - Date-based directory hierarchy
    - Per-entry checksums
    - Session-based file organization
    """

    def __init__(self, root: Optional[Path] = None):
        """Initialize the episodic store."""
        if root is None:
            from .init_store import get_memory_root
            root = get_memory_root()
        self.root = Path(root) / "episodic"
        self.root.mkdir(parents=True, exist_ok=True)
        self._current_session_id: Optional[str] = None
        self._session_sequence: int = 0

    def _get_date_path(self, dt: Optional[datetime] = None) -> Path:
        """Get the path for a specific date."""
        if dt is None:
            dt = datetime.utcnow()
        return self.root / dt.strftime("%Y") / dt.strftime("%m") / dt.strftime("%d")

    def _get_session_path(self, session_id: str, dt: Optional[datetime] = None) -> Path:
        """Get the JSONL file path for a session."""
        date_path = self._get_date_path(dt)
        date_path.mkdir(parents=True, exist_ok=True)
        return date_path / f"{session_id}.jsonl"

    def _get_checksum_path(self, session_id: str, dt: Optional[datetime] = None) -> Path:
        """Get the checksum file path for a session."""
        date_path = self._get_date_path(dt)
        return date_path / f"{session_id}.sha256"

    def start_session(self, session_id: Optional[str] = None) -> str:
        """Start a new session or resume an existing one."""
        if session_id is None:
            session_id = f"session_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{os.getpid()}"
        self._current_session_id = session_id
        self._session_sequence = self._get_last_sequence(session_id)
        return session_id

    def _get_last_sequence(self, session_id: str) -> int:
        """Get the last sequence number for a session."""
        session_path = self._get_session_path(session_id)
        if not session_path.exists():
            return 0
        count = 0
        with open(session_path, "r", encoding="utf-8") as f:
            for _ in f:
                count += 1
        return count

    def append(
        self,
        content: str,
        source: Dict[str, Any],
        entry_type: str = "interaction",
        response_summary: Optional[str] = None,
        flags: Optional[List[str]] = None,
        session_id: Optional[str] = None,
    ) -> EpisodicEntry:
        """
        Append a new entry to the episodic store.

        Args:
            content: The interaction content
            source: Source information (identifier, trust_level, verified)
            entry_type: Type of entry (interaction, system, error, etc.)
            response_summary: Optional summary of the response
            flags: Optional list of flags
            session_id: Session ID (uses current session if not provided)

        Returns:
            The created EpisodicEntry
        """
        if session_id is None:
            session_id = self._current_session_id
        if session_id is None:
            session_id = self.start_session()

        self._session_sequence += 1

        entry = EpisodicEntry(
            timestamp=datetime.utcnow().isoformat() + "Z",
            session_id=session_id,
            type=entry_type,
            source=source,
            content=content,
            response_summary=response_summary,
            flags=flags or [],
        )

        # Write to JSONL file (append-only)
        session_path = self._get_session_path(session_id)
        with open(session_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry.to_dict()) + "\n")

        # Update session checksum
        self._update_session_checksum(session_id)

        return entry

    def _update_session_checksum(self, session_id: str, dt: Optional[datetime] = None) -> None:
        """Update the checksum file for a session."""
        session_path = self._get_session_path(session_id, dt)
        checksum_path = self._get_checksum_path(session_id, dt)

        if session_path.exists():
            content = session_path.read_bytes()
            checksum = hashlib.sha256(content).hexdigest()
            checksum_path.write_text(f"sha256:{checksum}")

    def read_session(
        self, session_id: str, dt: Optional[datetime] = None, verify: bool = True
    ) -> List[EpisodicEntry]:
        """
        Read all entries from a session.

        Args:
            session_id: The session ID to read
            dt: Optional date (defaults to today)
            verify: Whether to verify checksums

        Returns:
            List of EpisodicEntry objects
        """
        session_path = self._get_session_path(session_id, dt)

        if not session_path.exists():
            return []

        if verify:
            if not self.verify_session(session_id, dt):
                raise ValueError(f"Session {session_id} failed checksum verification")

        entries = []
        with open(session_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    entry = EpisodicEntry.from_dict(data)
                    entries.append(entry)

        return entries

    def verify_session(self, session_id: str, dt: Optional[datetime] = None) -> bool:
        """Verify the checksum of a session file."""
        session_path = self._get_session_path(session_id, dt)
        checksum_path = self._get_checksum_path(session_id, dt)

        if not session_path.exists():
            return True  # Empty session is valid

        if not checksum_path.exists():
            return False  # Missing checksum is invalid

        content = session_path.read_bytes()
        actual = f"sha256:{hashlib.sha256(content).hexdigest()}"
        expected = checksum_path.read_text().strip()

        return actual == expected

    def query(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        source_identifier: Optional[str] = None,
        entry_type: Optional[str] = None,
        min_trust_level: Optional[float] = None,
        flags: Optional[List[str]] = None,
        limit: int = 100,
    ) -> Iterator[EpisodicEntry]:
        """
        Query entries across sessions.

        Args:
            start_date: Start of date range
            end_date: End of date range
            source_identifier: Filter by source identifier
            entry_type: Filter by entry type
            min_trust_level: Minimum trust level
            flags: Required flags
            limit: Maximum entries to return

        Yields:
            Matching EpisodicEntry objects
        """
        if end_date is None:
            end_date = datetime.utcnow()
        if start_date is None:
            start_date = datetime(end_date.year, end_date.month, 1)

        count = 0
        current = end_date

        while current >= start_date and count < limit:
            date_path = self._get_date_path(current)

            if date_path.exists():
                for session_file in sorted(date_path.glob("*.jsonl"), reverse=True):
                    session_id = session_file.stem

                    try:
                        entries = self.read_session(session_id, current, verify=False)
                    except Exception:
                        continue

                    for entry in reversed(entries):
                        if count >= limit:
                            return

                        # Apply filters
                        if source_identifier and entry.source.get("identifier") != source_identifier:
                            continue
                        if entry_type and entry.type != entry_type:
                            continue
                        if min_trust_level is not None:
                            trust = entry.source.get("trust_level", 0)
                            if isinstance(trust, str):
                                # Convert trust level strings to numbers
                                trust_map = {"guardian": 0.95, "high": 0.8, "medium": 0.5, "low": 0.3}
                                trust = trust_map.get(trust.lower(), 0.5)
                            if trust < min_trust_level:
                                continue
                        if flags:
                            if not all(f in entry.flags for f in flags):
                                continue

                        yield entry
                        count += 1

            # Move to previous day
            current = datetime(current.year, current.month, current.day)
            current = datetime.fromordinal(current.toordinal() - 1)

    def detect_gaps(self, session_id: str, dt: Optional[datetime] = None) -> List[int]:
        """
        Detect sequence gaps in a session (potential tampering indicator).

        Returns:
            List of missing sequence numbers
        """
        entries = self.read_session(session_id, dt, verify=False)

        if not entries:
            return []

        # Parse timestamps to check for gaps
        timestamps = []
        for entry in entries:
            try:
                ts = datetime.fromisoformat(entry.timestamp.replace("Z", "+00:00"))
                timestamps.append(ts)
            except ValueError:
                continue

        # Check for time reversals (entries out of order)
        gaps = []
        for i in range(1, len(timestamps)):
            if timestamps[i] < timestamps[i - 1]:
                gaps.append(i)

        return gaps

    def list_sessions(self, dt: Optional[datetime] = None) -> List[str]:
        """List all sessions for a given date."""
        date_path = self._get_date_path(dt)
        if not date_path.exists():
            return []
        return [f.stem for f in date_path.glob("*.jsonl")]


if __name__ == "__main__":
    # Quick test
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        store = EpisodicStore(Path(tmpdir))
        session = store.start_session()

        # Write some entries
        for i in range(5):
            store.append(
                content=f"Test message {i}",
                source={"identifier": "test@example.com", "trust_level": 0.8, "verified": True},
                response_summary=f"Response to message {i}",
            )

        # Read back
        entries = store.read_session(session)
        print(f"Wrote and read {len(entries)} entries")

        # Verify
        assert store.verify_session(session), "Verification failed!"
        print("Checksum verification passed")

        # Query
        results = list(store.query(min_trust_level=0.5, limit=3))
        print(f"Query returned {len(results)} entries")
