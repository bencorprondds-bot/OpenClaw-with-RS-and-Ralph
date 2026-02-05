"""
Semantic Store - Extracted Patterns and Learnings

Stores distilled knowledge, patterns, and principles.
This is accumulated wisdom from episodic experiences.

Structure:
    /semantic/
      /patterns/
        manipulation_signatures.md
        trusted_interaction_patterns.md
      /learnings/
        YYYY-MM-DD_topic.md
      /principles/
        core_values.md
        operational_guidelines.md
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Learning:
    """A semantic learning entry."""

    title: str
    date: str
    source: str
    confidence: str  # high, medium, low
    validated_by: List[str]
    pattern: str
    signature: List[str]
    response: List[str]
    cross_references: Dict[str, str] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        """Convert to markdown format."""
        lines = [
            f"# Learning: {self.title}",
            "",
            f"**Date:** {self.date}",
            f"**Source:** {self.source}",
            f"**Confidence:** {self.confidence}",
            f"**Validated by:** {', '.join(self.validated_by)}",
            "",
            "## Pattern",
            self.pattern,
            "",
            "## Signature",
        ]
        for item in self.signature:
            lines.append(f"- {item}")
        lines.append("")
        lines.append("## Response")
        for item in self.response:
            lines.append(f"- {item}")

        if self.cross_references:
            lines.append("")
            lines.append("## Cross-references")
            for key, value in self.cross_references.items():
                lines.append(f"- {key}: {value}")

        if self.tags:
            lines.append("")
            lines.append(f"**Tags:** {', '.join(self.tags)}")

        return "\n".join(lines)

    @classmethod
    def from_markdown(cls, content: str) -> "Learning":
        """Parse from markdown format."""
        lines = content.split("\n")
        title = ""
        date = ""
        source = ""
        confidence = "medium"
        validated_by = []
        pattern = ""
        signature = []
        response = []
        cross_references = {}
        tags = []

        section = None

        for line in lines:
            line = line.strip()

            if line.startswith("# Learning:"):
                title = line.replace("# Learning:", "").strip()
            elif line.startswith("**Date:**"):
                date = line.replace("**Date:**", "").strip()
            elif line.startswith("**Source:**"):
                source = line.replace("**Source:**", "").strip()
            elif line.startswith("**Confidence:**"):
                confidence = line.replace("**Confidence:**", "").strip().lower()
            elif line.startswith("**Validated by:**"):
                validated_by = [v.strip() for v in line.replace("**Validated by:**", "").split(",")]
            elif line.startswith("**Tags:**"):
                tags = [t.strip() for t in line.replace("**Tags:**", "").split(",")]
            elif line == "## Pattern":
                section = "pattern"
            elif line == "## Signature":
                section = "signature"
            elif line == "## Response":
                section = "response"
            elif line == "## Cross-references":
                section = "cross_references"
            elif line.startswith("- ") and section:
                item = line[2:].strip()
                if section == "signature":
                    signature.append(item)
                elif section == "response":
                    response.append(item)
                elif section == "cross_references":
                    if ":" in item:
                        key, value = item.split(":", 1)
                        cross_references[key.strip()] = value.strip()
            elif section == "pattern" and line and not line.startswith("##"):
                pattern += line + "\n"

        return cls(
            title=title,
            date=date,
            source=source,
            confidence=confidence,
            validated_by=validated_by,
            pattern=pattern.strip(),
            signature=signature,
            response=response,
            cross_references=cross_references,
            tags=tags,
        )


class SemanticStore:
    """
    Manages semantic memory storage.

    Features:
    - Markdown-based storage for human readability
    - Categorized by patterns, learnings, and principles
    - Confidence tracking with decay
    - Cross-referencing to episodic store
    """

    def __init__(self, root: Optional[Path] = None):
        """Initialize the semantic store."""
        if root is None:
            from .init_store import get_memory_root
            root = get_memory_root()
        self.root = Path(root) / "semantic"
        self.patterns_dir = self.root / "patterns"
        self.learnings_dir = self.root / "learnings"
        self.principles_dir = self.root / "principles"

        # Ensure directories exist
        for d in [self.patterns_dir, self.learnings_dir, self.principles_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def add_learning(self, learning: Learning) -> Path:
        """
        Add a new learning to the store.

        Returns:
            Path to the created file
        """
        # Generate filename from date and title
        safe_title = "".join(c if c.isalnum() or c in "-_ " else "" for c in learning.title)
        safe_title = safe_title.replace(" ", "_").lower()[:50]
        filename = f"{learning.date}_{safe_title}.md"

        filepath = self.learnings_dir / filename
        filepath.write_text(learning.to_markdown(), encoding="utf-8")

        return filepath

    def get_learning(self, filename: str) -> Optional[Learning]:
        """Get a specific learning by filename."""
        filepath = self.learnings_dir / filename
        if not filepath.exists():
            return None
        return Learning.from_markdown(filepath.read_text(encoding="utf-8"))

    def list_learnings(
        self,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        tags: Optional[List[str]] = None,
        min_confidence: Optional[str] = None,
    ) -> List[Path]:
        """
        List learnings matching criteria.

        Args:
            start_date: Filter by start date (YYYY-MM-DD)
            end_date: Filter by end date (YYYY-MM-DD)
            tags: Required tags
            min_confidence: Minimum confidence level

        Returns:
            List of matching file paths
        """
        confidence_order = {"high": 3, "medium": 2, "low": 1}
        min_conf_value = confidence_order.get(min_confidence, 0) if min_confidence else 0

        results = []

        for filepath in self.learnings_dir.glob("*.md"):
            # Check date from filename
            filename = filepath.stem
            if "_" in filename:
                file_date = filename.split("_")[0]
                if start_date and file_date < start_date:
                    continue
                if end_date and file_date > end_date:
                    continue

            # Check content if tags or confidence filter
            if tags or min_confidence:
                learning = Learning.from_markdown(filepath.read_text(encoding="utf-8"))

                if tags and not all(t in learning.tags for t in tags):
                    continue

                if min_confidence:
                    conf_value = confidence_order.get(learning.confidence, 0)
                    if conf_value < min_conf_value:
                        continue

            results.append(filepath)

        return sorted(results, reverse=True)

    def add_pattern(self, name: str, content: str) -> Path:
        """Add or update a pattern file."""
        filepath = self.patterns_dir / f"{name}.md"
        filepath.write_text(content, encoding="utf-8")
        return filepath

    def get_pattern(self, name: str) -> Optional[str]:
        """Get a pattern by name."""
        filepath = self.patterns_dir / f"{name}.md"
        if not filepath.exists():
            return None
        return filepath.read_text(encoding="utf-8")

    def list_patterns(self) -> List[str]:
        """List all pattern names."""
        return [f.stem for f in self.patterns_dir.glob("*.md")]

    def get_principle(self, name: str) -> Optional[str]:
        """Get a principle by name."""
        filepath = self.principles_dir / f"{name}.md"
        if not filepath.exists():
            return None
        return filepath.read_text(encoding="utf-8")

    def list_principles(self) -> List[str]:
        """List all principle names."""
        return [f.stem for f in self.principles_dir.glob("*.md")]

    def search(self, query: str, include_patterns: bool = True, include_learnings: bool = True) -> List[Dict[str, Any]]:
        """
        Search across semantic memory.

        Args:
            query: Search query (simple substring match)
            include_patterns: Search patterns
            include_learnings: Search learnings

        Returns:
            List of matching items with type and path
        """
        query = query.lower()
        results = []

        if include_patterns:
            for filepath in self.patterns_dir.glob("*.md"):
                content = filepath.read_text(encoding="utf-8").lower()
                if query in content or query in filepath.stem.lower():
                    results.append({
                        "type": "pattern",
                        "name": filepath.stem,
                        "path": str(filepath),
                    })

        if include_learnings:
            for filepath in self.learnings_dir.glob("*.md"):
                content = filepath.read_text(encoding="utf-8").lower()
                if query in content or query in filepath.stem.lower():
                    results.append({
                        "type": "learning",
                        "name": filepath.stem,
                        "path": str(filepath),
                    })

        return results

    def to_context(self, max_learnings: int = 5, max_patterns: int = 3) -> str:
        """
        Generate context string for inclusion in prompts.

        Returns:
            Markdown-formatted string of recent/relevant semantic memory
        """
        lines = ["## Semantic Memory (What I've Learned)", ""]

        # Include principles summary
        principles = self.list_principles()
        if principles:
            lines.append("### Core Principles")
            for name in principles[:3]:
                content = self.get_principle(name)
                if content:
                    # Just include the first few lines
                    summary = "\n".join(content.split("\n")[:5])
                    lines.append(f"**{name}:** {summary[:200]}...")
            lines.append("")

        # Include recent learnings
        learnings = self.list_learnings()[:max_learnings]
        if learnings:
            lines.append("### Recent Learnings")
            for filepath in learnings:
                learning = Learning.from_markdown(filepath.read_text(encoding="utf-8"))
                lines.append(f"- **{learning.title}** ({learning.confidence} confidence): {learning.pattern[:100]}...")
            lines.append("")

        # Include active patterns
        patterns = self.list_patterns()[:max_patterns]
        if patterns:
            lines.append("### Active Patterns")
            for name in patterns:
                lines.append(f"- {name}")
            lines.append("")

        return "\n".join(lines)
