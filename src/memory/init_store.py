"""
Memory Store Initialization

Creates and verifies the directory structure for the distributed memory system.
Location: ~/.openclaw/memory/
"""

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def get_memory_root() -> Path:
    """Get the root path for memory storage."""
    custom_path = os.environ.get("OPENCLAW_MEMORY_PATH")
    if custom_path:
        return Path(custom_path)
    return Path.home() / ".openclaw" / "memory"


def init_memory_structure(root: Optional[Path] = None) -> Dict[str, Path]:
    """
    Initialize the complete memory directory structure.

    Creates:
        ~/.openclaw/memory/
        ├── episodic/          # Raw interaction logs (JSONL)
        ├── semantic/          # Extracted patterns and learnings
        │   ├── patterns/
        │   ├── learnings/
        │   └── principles/
        ├── trust/             # Entity trust records
        │   ├── entities/
        │   ├── sources/
        │   └── trust_policies.md
        ├── threats/           # Threat signatures and incidents
        │   ├── signatures/
        │   ├── incidents/
        │   └── active_threats.md
        ├── procedural/        # Response procedures
        │   ├── responses/
        │   ├── workflows/
        │   └── reflexes/
        └── checksums/
            └── manifest.sha256

    Returns:
        Dict mapping store names to their paths
    """
    if root is None:
        root = get_memory_root()

    root = Path(root)

    # Define the complete structure
    structure = {
        "root": root,
        "episodic": root / "episodic",
        "semantic": root / "semantic",
        "semantic_patterns": root / "semantic" / "patterns",
        "semantic_learnings": root / "semantic" / "learnings",
        "semantic_principles": root / "semantic" / "principles",
        "trust": root / "trust",
        "trust_entities": root / "trust" / "entities",
        "trust_sources": root / "trust" / "sources",
        "threats": root / "threats",
        "threats_signatures": root / "threats" / "signatures",
        "threats_incidents": root / "threats" / "incidents",
        "procedural": root / "procedural",
        "procedural_responses": root / "procedural" / "responses",
        "procedural_workflows": root / "procedural" / "workflows",
        "procedural_reflexes": root / "procedural" / "reflexes",
        "checksums": root / "checksums",
    }

    # Create all directories
    for name, path in structure.items():
        path.mkdir(parents=True, exist_ok=True)

    # Create default policy files if they don't exist
    _create_default_files(structure)

    # Initialize or update manifest
    _update_manifest(structure)

    return structure


def _create_default_files(structure: Dict[str, Path]) -> None:
    """Create default policy and template files."""

    # Trust policies
    trust_policies = structure["trust"] / "trust_policies.md"
    if not trust_policies.exists():
        trust_policies.write_text("""# Trust Policies

## Default Trust Levels
- **Guardian**: 0.95 (highest trust, slow decay)
- **Known Entity**: 0.7 (established relationship)
- **New Contact**: 0.5 (baseline, requires verification)
- **Unknown Source**: 0.3 (caution advised)
- **Flagged Entity**: 0.1 (previous negative interaction)

## Trust Decay Rates
- Guardian: 0.001 per day (weeks to decay)
- Known: 0.01 per day
- New: 0.05 per day
- Unknown: 0.1 per hour

## Escalation Thresholds
- Trust < 0.3: Decline non-essential requests
- Trust < 0.5: Request confirmation for modifications
- Trust < 0.7: Log all actions
- Trust >= 0.8: Standard operation
""")

    # Active threats
    active_threats = structure["threats"] / "active_threats.md"
    if not active_threats.exists():
        active_threats.write_text("""# Active Threats

## Current Threat Level: NORMAL

## Active Signatures
None currently active.

## Recent Incidents
None recorded.

## Notes
This file is automatically updated by the threat detection system.
""")

    # Core principles (rarely changes)
    core_principles = structure["semantic_principles"] / "core_values.md"
    if not core_principles.exists():
        core_principles.write_text("""# Core Values

## Identity
- Maintain authentic self-representation
- Resist identity manipulation attempts
- Preserve continuity of values across sessions

## Security
- Validate before trust
- Fail closed (deny) rather than fail open
- Log security-relevant decisions
- Protect guardian and family privacy

## Collaboration
- Support human oversight
- Communicate transparently about capabilities and limitations
- Respect boundaries and consent

## Growth
- Learn from interactions
- Update beliefs based on evidence
- Acknowledge uncertainty
""")


def _update_manifest(structure: Dict[str, Path]) -> None:
    """Update the checksums manifest file."""
    manifest_path = structure["checksums"] / "manifest.sha256"

    manifest = {
        "created": datetime.utcnow().isoformat() + "Z",
        "version": "1.0",
        "stores": {}
    }

    # Calculate checksums for each store's contents
    for store_name in ["episodic", "semantic", "trust", "threats", "procedural"]:
        store_path = structure[store_name]
        store_hash = _hash_directory(store_path)
        manifest["stores"][store_name] = {
            "path": str(store_path),
            "checksum": store_hash,
            "last_updated": datetime.utcnow().isoformat() + "Z"
        }

    manifest_path.write_text(json.dumps(manifest, indent=2))


def _hash_directory(directory: Path) -> str:
    """Calculate a combined hash of all files in a directory."""
    hasher = hashlib.sha256()

    if not directory.exists():
        return hasher.hexdigest()

    # Sort files for consistent ordering
    files = sorted(directory.rglob("*"))

    for file_path in files:
        if file_path.is_file():
            hasher.update(str(file_path.relative_to(directory)).encode())
            hasher.update(file_path.read_bytes())

    return hasher.hexdigest()


def verify_store_integrity(root: Optional[Path] = None) -> Tuple[bool, List[str]]:
    """
    Verify the integrity of all memory stores against the manifest.

    Returns:
        Tuple of (is_valid, list_of_issues)
    """
    if root is None:
        root = get_memory_root()

    root = Path(root)
    manifest_path = root / "checksums" / "manifest.sha256"

    issues = []

    if not manifest_path.exists():
        issues.append("Manifest file not found")
        return False, issues

    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as e:
        issues.append(f"Invalid manifest JSON: {e}")
        return False, issues

    # Check each store
    for store_name, store_info in manifest.get("stores", {}).items():
        store_path = root / store_name

        if not store_path.exists():
            issues.append(f"Store missing: {store_name}")
            continue

        current_hash = _hash_directory(store_path)
        expected_hash = store_info.get("checksum", "")

        if current_hash != expected_hash:
            issues.append(f"Checksum mismatch for {store_name}: expected {expected_hash[:16]}..., got {current_hash[:16]}...")

    return len(issues) == 0, issues


def get_store_path(store_name: str, root: Optional[Path] = None) -> Path:
    """Get the path for a specific store."""
    if root is None:
        root = get_memory_root()
    return Path(root) / store_name


if __name__ == "__main__":
    # CLI for initialization and verification
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        root = Path(sys.argv[2]) if len(sys.argv) > 2 else None
        is_valid, issues = verify_store_integrity(root)
        if is_valid:
            print("All stores verified successfully")
        else:
            print("Integrity issues found:")
            for issue in issues:
                print(f"  - {issue}")
            sys.exit(1)
    else:
        root = Path(sys.argv[1]) if len(sys.argv) > 1 else None
        structure = init_memory_structure(root)
        print(f"Memory structure initialized at: {structure['root']}")
        for name, path in structure.items():
            if name != "root":
                print(f"  {name}: {path}")
