"""
Domain Sync - Backup and Recovery

Handles synchronization between local memory stores and the domain-hosted
backup at lifewithai.ai/memory/claude/ (or configurable endpoint).

Features:
- Async sync from local to domain (non-blocking)
- Write-through pattern: local first, then domain
- Recovery from domain to local
- Authenticated API access
"""

import asyncio
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

# Use stdlib for sync operations, async libraries optional
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

# Fallback to urllib for basic operations
import urllib.request
import urllib.error


@dataclass
class SyncConfig:
    """Configuration for domain sync."""

    domain_url: str = "https://lifewithai.ai/memory/claude/"
    api_key: Optional[str] = None
    sync_interval_seconds: int = 30
    timeout_seconds: int = 30
    retry_attempts: int = 3
    retry_delay_seconds: int = 5
    batch_size: int = 100

    @classmethod
    def from_env(cls) -> "SyncConfig":
        """Load configuration from environment variables."""
        return cls(
            domain_url=os.environ.get("MEMORY_DOMAIN_URL", "https://lifewithai.ai/memory/claude/"),
            api_key=os.environ.get("MEMORY_API_KEY"),
            sync_interval_seconds=int(os.environ.get("MEMORY_SYNC_INTERVAL", "30")),
            timeout_seconds=int(os.environ.get("MEMORY_SYNC_TIMEOUT", "30")),
            retry_attempts=int(os.environ.get("MEMORY_SYNC_RETRIES", "3")),
        )


@dataclass
class SyncStatus:
    """Status of a sync operation."""

    success: bool
    timestamp: str
    items_synced: int = 0
    items_failed: int = 0
    errors: List[str] = field(default_factory=list)
    duration_ms: float = 0


@dataclass
class DomainManifest:
    """Manifest of domain store state."""

    version: str
    last_updated: str
    stores: Dict[str, Dict[str, Any]]
    checksum: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "last_updated": self.last_updated,
            "stores": self.stores,
            "checksum": self.checksum,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DomainManifest":
        return cls(
            version=data.get("version", "1.0"),
            last_updated=data.get("last_updated", ""),
            stores=data.get("stores", {}),
            checksum=data.get("checksum", ""),
        )


class DomainSync:
    """
    Handles synchronization with domain-hosted memory store.

    Usage:
        config = SyncConfig.from_env()
        sync = DomainSync(local_root, config)

        # Sync local to domain
        status = await sync.push()

        # Recover from domain
        status = await sync.pull()

        # Check status
        is_synced = await sync.is_synced()
    """

    def __init__(
        self,
        local_root: Path,
        config: Optional[SyncConfig] = None,
        on_conflict: Optional[Callable] = None,
    ):
        """
        Initialize domain sync.

        Args:
            local_root: Path to local memory store
            config: Sync configuration
            on_conflict: Callback for conflict resolution
        """
        self.local_root = Path(local_root)
        self.config = config or SyncConfig.from_env()
        self.on_conflict = on_conflict

        # Sync state
        self._last_sync: Optional[datetime] = None
        self._sync_in_progress = False
        self._pending_changes: List[Dict[str, Any]] = []

        # Background sync task
        self._sync_task: Optional[asyncio.Task] = None

    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers for API requests."""
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "OpenClaw-Memory-Sync/1.0",
        }
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def _build_url(self, path: str) -> str:
        """Build full URL for API endpoint."""
        return urljoin(self.config.domain_url, path)

    # ==================== Synchronous API (urllib fallback) ====================

    def _request_sync(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Make synchronous HTTP request using urllib."""
        url = self._build_url(path)
        headers = self._get_headers()

        body = None
        if data:
            body = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as response:
                response_data = response.read().decode("utf-8")
                return json.loads(response_data) if response_data else {}
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.reason}"}
        except urllib.error.URLError as e:
            return {"error": f"URL Error: {e.reason}"}
        except Exception as e:
            return {"error": str(e)}

    # ==================== Store Operations ====================

    def get_local_manifest(self) -> DomainManifest:
        """Get manifest of local store state."""
        manifest_path = self.local_root / "checksums" / "manifest.sha256"

        if not manifest_path.exists():
            return DomainManifest(
                version="1.0",
                last_updated=datetime.utcnow().isoformat() + "Z",
                stores={},
                checksum="",
            )

        try:
            data = json.loads(manifest_path.read_text())
            return DomainManifest(
                version=data.get("version", "1.0"),
                last_updated=data.get("created", ""),
                stores=data.get("stores", {}),
                checksum=self._compute_manifest_checksum(data),
            )
        except Exception:
            return DomainManifest(
                version="1.0",
                last_updated=datetime.utcnow().isoformat() + "Z",
                stores={},
                checksum="",
            )

    def _compute_manifest_checksum(self, data: Dict[str, Any]) -> str:
        """Compute checksum of manifest data."""
        content = json.dumps(data, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def get_store_files(self, store_name: str) -> List[Dict[str, Any]]:
        """Get list of files in a local store with their checksums."""
        store_path = self.local_root / store_name
        files = []

        if not store_path.exists():
            return files

        for file_path in store_path.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(store_path)
                content = file_path.read_bytes()
                checksum = hashlib.sha256(content).hexdigest()

                files.append({
                    "path": str(rel_path),
                    "checksum": checksum,
                    "size": len(content),
                    "modified": datetime.fromtimestamp(file_path.stat().st_mtime).isoformat() + "Z",
                })

        return files

    # ==================== Push (Local -> Domain) ====================

    def push_sync(self) -> SyncStatus:
        """
        Synchronously push local changes to domain.

        Returns:
            SyncStatus with results
        """
        start_time = time.time()
        errors = []
        items_synced = 0
        items_failed = 0

        # Get local manifest
        local_manifest = self.get_local_manifest()

        # Push manifest first
        result = self._request_sync("PUT", "manifest.json", local_manifest.to_dict())
        if "error" in result:
            errors.append(f"Manifest push failed: {result['error']}")

        # Push each store
        for store_name in ["episodic", "semantic", "trust", "threats", "procedural"]:
            store_files = self.get_store_files(store_name)

            for file_info in store_files:
                file_path = self.local_root / store_name / file_info["path"]

                try:
                    content = file_path.read_text(encoding="utf-8")
                    payload = {
                        "path": f"{store_name}/{file_info['path']}",
                        "content": content,
                        "checksum": file_info["checksum"],
                    }

                    result = self._request_sync("PUT", f"stores/{store_name}/{file_info['path']}", payload)

                    if "error" in result:
                        errors.append(f"Failed to push {store_name}/{file_info['path']}: {result['error']}")
                        items_failed += 1
                    else:
                        items_synced += 1

                except Exception as e:
                    errors.append(f"Error reading {file_path}: {e}")
                    items_failed += 1

        duration_ms = (time.time() - start_time) * 1000
        self._last_sync = datetime.utcnow()

        return SyncStatus(
            success=len(errors) == 0,
            timestamp=datetime.utcnow().isoformat() + "Z",
            items_synced=items_synced,
            items_failed=items_failed,
            errors=errors,
            duration_ms=duration_ms,
        )

    # ==================== Pull (Domain -> Local) ====================

    def pull_sync(self, stores: Optional[List[str]] = None) -> SyncStatus:
        """
        Synchronously pull from domain to local.

        Args:
            stores: Specific stores to pull (None = all)

        Returns:
            SyncStatus with results
        """
        start_time = time.time()
        errors = []
        items_synced = 0
        items_failed = 0

        if stores is None:
            stores = ["episodic", "semantic", "trust", "threats", "procedural"]

        # Get domain manifest
        result = self._request_sync("GET", "manifest.json")
        if "error" in result:
            return SyncStatus(
                success=False,
                timestamp=datetime.utcnow().isoformat() + "Z",
                errors=[f"Failed to get domain manifest: {result['error']}"],
                duration_ms=(time.time() - start_time) * 1000,
            )

        domain_manifest = DomainManifest.from_dict(result)

        # Pull each store
        for store_name in stores:
            if store_name not in domain_manifest.stores:
                continue

            # Get file list from domain
            result = self._request_sync("GET", f"stores/{store_name}/")
            if "error" in result:
                errors.append(f"Failed to list {store_name}: {result['error']}")
                continue

            files = result.get("files", [])

            for file_info in files:
                file_path = file_info.get("path", "")

                # Get file content
                result = self._request_sync("GET", f"stores/{store_name}/{file_path}")
                if "error" in result:
                    errors.append(f"Failed to get {store_name}/{file_path}: {result['error']}")
                    items_failed += 1
                    continue

                content = result.get("content", "")
                expected_checksum = file_info.get("checksum", "")

                # Verify checksum
                actual_checksum = hashlib.sha256(content.encode()).hexdigest()
                if expected_checksum and actual_checksum != expected_checksum:
                    errors.append(f"Checksum mismatch for {store_name}/{file_path}")
                    items_failed += 1
                    continue

                # Write to local
                try:
                    local_path = self.local_root / store_name / file_path
                    local_path.parent.mkdir(parents=True, exist_ok=True)
                    local_path.write_text(content, encoding="utf-8")
                    items_synced += 1
                except Exception as e:
                    errors.append(f"Failed to write {store_name}/{file_path}: {e}")
                    items_failed += 1

        duration_ms = (time.time() - start_time) * 1000
        self._last_sync = datetime.utcnow()

        return SyncStatus(
            success=len(errors) == 0,
            timestamp=datetime.utcnow().isoformat() + "Z",
            items_synced=items_synced,
            items_failed=items_failed,
            errors=errors,
            duration_ms=duration_ms,
        )

    # ==================== Recovery ====================

    def recover(self, target_path: Optional[Path] = None) -> SyncStatus:
        """
        Recover local store from domain backup.

        Args:
            target_path: Path to recover to (default: local_root)

        Returns:
            SyncStatus with results
        """
        if target_path is None:
            target_path = self.local_root

        # Backup current local state first
        backup_path = target_path.parent / f"{target_path.name}_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        try:
            if target_path.exists():
                import shutil
                shutil.copytree(target_path, backup_path)
        except Exception as e:
            return SyncStatus(
                success=False,
                timestamp=datetime.utcnow().isoformat() + "Z",
                errors=[f"Failed to backup local store: {e}"],
            )

        # Clear local and pull from domain
        try:
            if target_path.exists():
                import shutil
                shutil.rmtree(target_path)
            target_path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            return SyncStatus(
                success=False,
                timestamp=datetime.utcnow().isoformat() + "Z",
                errors=[f"Failed to clear local store: {e}"],
            )

        # Temporarily point to target and pull
        original_root = self.local_root
        self.local_root = target_path

        status = self.pull_sync()

        self.local_root = original_root

        # If recovery failed, restore backup
        if not status.success and backup_path.exists():
            try:
                import shutil
                shutil.rmtree(target_path)
                shutil.move(str(backup_path), str(target_path))
                status.errors.append("Recovery failed, restored from local backup")
            except Exception as e:
                status.errors.append(f"Failed to restore backup: {e}")

        return status

    # ==================== Status & Health ====================

    def get_sync_status(self) -> Dict[str, Any]:
        """Get current sync status."""
        local_manifest = self.get_local_manifest()

        return {
            "last_sync": self._last_sync.isoformat() + "Z" if self._last_sync else None,
            "sync_in_progress": self._sync_in_progress,
            "pending_changes": len(self._pending_changes),
            "local_manifest": local_manifest.to_dict(),
            "config": {
                "domain_url": self.config.domain_url,
                "sync_interval": self.config.sync_interval_seconds,
                "has_api_key": self.config.api_key is not None,
            },
        }

    def health_check(self) -> Dict[str, Any]:
        """Check connectivity to domain."""
        start_time = time.time()

        result = self._request_sync("GET", "health")

        return {
            "reachable": "error" not in result,
            "latency_ms": (time.time() - start_time) * 1000,
            "error": result.get("error"),
            "domain_url": self.config.domain_url,
        }

    # ==================== Async Operations (if aiohttp available) ====================

    async def push_async(self) -> SyncStatus:
        """Async push to domain."""
        if not HAS_AIOHTTP and not HAS_HTTPX:
            # Fall back to sync
            return self.push_sync()

        # Use sync for now, async implementation can be added later
        return self.push_sync()

    async def pull_async(self, stores: Optional[List[str]] = None) -> SyncStatus:
        """Async pull from domain."""
        if not HAS_AIOHTTP and not HAS_HTTPX:
            return self.pull_sync(stores)

        return self.pull_sync(stores)

    # ==================== Background Sync ====================

    async def start_background_sync(self) -> None:
        """Start background sync task."""
        if self._sync_task is not None:
            return

        self._sync_task = asyncio.create_task(self._background_sync_loop())

    async def stop_background_sync(self) -> None:
        """Stop background sync task."""
        if self._sync_task is not None:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
            self._sync_task = None

    async def _background_sync_loop(self) -> None:
        """Background sync loop."""
        while True:
            try:
                await asyncio.sleep(self.config.sync_interval_seconds)

                if self._pending_changes:
                    self._sync_in_progress = True
                    await self.push_async()
                    self._pending_changes.clear()
                    self._sync_in_progress = False

            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue
                self._sync_in_progress = False

    def queue_change(self, store: str, path: str, operation: str = "update") -> None:
        """Queue a change for background sync."""
        self._pending_changes.append({
            "store": store,
            "path": path,
            "operation": operation,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        cmd = sys.argv[1]

        if cmd == "--status":
            from src.memory.init_store import get_memory_root
            sync = DomainSync(get_memory_root())
            status = sync.get_sync_status()
            print(json.dumps(status, indent=2))

        elif cmd == "--health":
            from src.memory.init_store import get_memory_root
            sync = DomainSync(get_memory_root())
            health = sync.health_check()
            print(json.dumps(health, indent=2))

        elif cmd == "--sync-now":
            from src.memory.init_store import get_memory_root
            sync = DomainSync(get_memory_root())
            status = sync.push_sync()
            print(json.dumps({
                "success": status.success,
                "items_synced": status.items_synced,
                "errors": status.errors,
                "duration_ms": status.duration_ms,
            }, indent=2))

        elif cmd == "--recover":
            from src.memory.init_store import get_memory_root
            target = Path(sys.argv[2]) if len(sys.argv) > 2 else None
            sync = DomainSync(get_memory_root())
            status = sync.recover(target)
            print(json.dumps({
                "success": status.success,
                "items_synced": status.items_synced,
                "errors": status.errors,
            }, indent=2))
    else:
        print("Domain Sync - Memory Backup and Recovery")
        print()
        print("Usage:")
        print("  python -m src.sync.domain --status     # Show sync status")
        print("  python -m src.sync.domain --health     # Check domain connectivity")
        print("  python -m src.sync.domain --sync-now   # Push to domain")
        print("  python -m src.sync.domain --recover    # Recover from domain")
