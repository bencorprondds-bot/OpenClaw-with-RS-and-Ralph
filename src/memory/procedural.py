"""
Procedural Memory - Response Wisdom

Stores learned responses and workflows that have worked.
Not rules, but accumulated wisdom on how to respond.

Structure:
    /procedural/
      /responses/
        security_incident.md
        trust_violation.md
      /workflows/
        morning_sweep.md
        research_protocol.md
      /reflexes/
        immediate_threats.md
"""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Procedure:
    """A procedural memory entry."""

    name: str
    trigger: str
    immediate_actions: List[str]
    assessment_steps: List[str]
    escalation_matrix: List[Dict[str, str]]
    post_actions: List[str]
    notes: str = ""
    last_used: Optional[str] = None
    success_count: int = 0
    failure_count: int = 0

    def to_markdown(self) -> str:
        """Convert to markdown format."""
        lines = [
            f"# Procedure: {self.name}",
            "",
            f"**Trigger:** {self.trigger}",
            "",
            "## Immediate (reflex)",
        ]

        for i, action in enumerate(self.immediate_actions, 1):
            lines.append(f"{i}. {action}")

        lines.append("")
        lines.append("## Assessment")

        for i, step in enumerate(self.assessment_steps, 1):
            lines.append(f"{i}. {step}")

        if self.escalation_matrix:
            lines.append("")
            lines.append("## Escalation matrix")
            lines.append("| Severity | Trust Level | Action |")
            lines.append("|----------|-------------|--------|")
            for row in self.escalation_matrix:
                lines.append(f"| {row.get('severity', '')} | {row.get('trust_level', '')} | {row.get('action', '')} |")

        lines.append("")
        lines.append("## Post-incident")

        for i, action in enumerate(self.post_actions, 1):
            lines.append(f"{i}. {action}")

        if self.notes:
            lines.append("")
            lines.append("## Notes")
            lines.append(self.notes)

        if self.last_used or self.success_count or self.failure_count:
            lines.append("")
            lines.append("## Statistics")
            if self.last_used:
                lines.append(f"- Last used: {self.last_used}")
            lines.append(f"- Success count: {self.success_count}")
            lines.append(f"- Failure count: {self.failure_count}")

        return "\n".join(lines)

    @classmethod
    def from_markdown(cls, content: str) -> "Procedure":
        """Parse from markdown format."""
        lines = content.split("\n")

        name = ""
        trigger = ""
        immediate_actions = []
        assessment_steps = []
        escalation_matrix = []
        post_actions = []
        notes = ""
        last_used = None
        success_count = 0
        failure_count = 0

        section = None
        in_table = False

        for line in lines:
            stripped = line.strip()

            if stripped.startswith("# Procedure:"):
                name = stripped.replace("# Procedure:", "").strip()
            elif stripped.startswith("**Trigger:**"):
                trigger = stripped.replace("**Trigger:**", "").strip()
            elif stripped == "## Immediate (reflex)":
                section = "immediate"
            elif stripped == "## Assessment":
                section = "assessment"
            elif stripped == "## Escalation matrix":
                section = "escalation"
                in_table = False
            elif stripped == "## Post-incident":
                section = "post"
            elif stripped == "## Notes":
                section = "notes"
            elif stripped == "## Statistics":
                section = "stats"
            elif stripped.startswith("##"):
                section = None
            elif section == "escalation":
                if stripped.startswith("|") and "Severity" not in stripped and "---" not in stripped:
                    parts = [p.strip() for p in stripped.split("|")[1:-1]]
                    if len(parts) >= 3:
                        escalation_matrix.append({
                            "severity": parts[0],
                            "trust_level": parts[1],
                            "action": parts[2],
                        })
            elif stripped.startswith(("1.", "2.", "3.", "4.", "5.", "6.", "7.", "8.", "9.")):
                text = stripped.split(".", 1)[1].strip() if "." in stripped else stripped
                if section == "immediate":
                    immediate_actions.append(text)
                elif section == "assessment":
                    assessment_steps.append(text)
                elif section == "post":
                    post_actions.append(text)
            elif section == "notes" and stripped:
                notes += stripped + "\n"
            elif section == "stats":
                if "Last used:" in stripped:
                    last_used = stripped.split(":", 1)[1].strip()
                elif "Success count:" in stripped:
                    try:
                        success_count = int(stripped.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                elif "Failure count:" in stripped:
                    try:
                        failure_count = int(stripped.split(":", 1)[1].strip())
                    except ValueError:
                        pass

        return cls(
            name=name,
            trigger=trigger,
            immediate_actions=immediate_actions,
            assessment_steps=assessment_steps,
            escalation_matrix=escalation_matrix,
            post_actions=post_actions,
            notes=notes.strip(),
            last_used=last_used,
            success_count=success_count,
            failure_count=failure_count,
        )


@dataclass
class Workflow:
    """A workflow definition."""

    name: str
    description: str
    steps: List[Dict[str, str]]
    triggers: List[str] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)

    def to_markdown(self) -> str:
        """Convert to markdown format."""
        lines = [
            f"# Workflow: {self.name}",
            "",
            self.description,
            "",
        ]

        if self.triggers:
            lines.append("## Triggers")
            for trigger in self.triggers:
                lines.append(f"- {trigger}")
            lines.append("")

        if self.prerequisites:
            lines.append("## Prerequisites")
            for prereq in self.prerequisites:
                lines.append(f"- {prereq}")
            lines.append("")

        lines.append("## Steps")
        for i, step in enumerate(self.steps, 1):
            lines.append(f"### Step {i}: {step.get('name', 'Unnamed')}")
            if step.get("description"):
                lines.append(step["description"])
            if step.get("command"):
                lines.append(f"```\n{step['command']}\n```")
            lines.append("")

        return "\n".join(lines)


class ProceduralMemory:
    """
    Manages procedural memory storage.

    Features:
    - Markdown-based procedure storage
    - Categorized by responses, workflows, and reflexes
    - Usage tracking
    - Trigger matching
    """

    def __init__(self, root: Optional[Path] = None):
        """Initialize the procedural memory store."""
        if root is None:
            from .init_store import get_memory_root
            root = get_memory_root()
        self.root = Path(root) / "procedural"
        self.responses_dir = self.root / "responses"
        self.workflows_dir = self.root / "workflows"
        self.reflexes_dir = self.root / "reflexes"

        # Ensure directories exist
        for d in [self.responses_dir, self.workflows_dir, self.reflexes_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def _safe_filename(self, name: str) -> str:
        """Convert name to safe filename."""
        return "".join(c if c.isalnum() or c in "-_" else "_" for c in name).lower()

    def add_procedure(self, procedure: Procedure, category: str = "responses") -> Path:
        """
        Add a new procedure.

        Args:
            procedure: The Procedure to add
            category: Category (responses, workflows, reflexes)

        Returns:
            Path to the created file
        """
        dir_map = {
            "responses": self.responses_dir,
            "workflows": self.workflows_dir,
            "reflexes": self.reflexes_dir,
        }
        target_dir = dir_map.get(category, self.responses_dir)

        filename = f"{self._safe_filename(procedure.name)}.md"
        filepath = target_dir / filename
        filepath.write_text(procedure.to_markdown(), encoding="utf-8")

        return filepath

    def get_procedure(self, name: str, category: Optional[str] = None) -> Optional[Procedure]:
        """
        Get a procedure by name.

        Args:
            name: Procedure name
            category: Optional category to search in

        Returns:
            Procedure or None
        """
        safe_name = self._safe_filename(name)

        if category:
            dir_map = {
                "responses": self.responses_dir,
                "workflows": self.workflows_dir,
                "reflexes": self.reflexes_dir,
            }
            dirs = [dir_map.get(category, self.responses_dir)]
        else:
            dirs = [self.responses_dir, self.workflows_dir, self.reflexes_dir]

        for d in dirs:
            filepath = d / f"{safe_name}.md"
            if filepath.exists():
                return Procedure.from_markdown(filepath.read_text(encoding="utf-8"))

        return None

    def find_by_trigger(self, situation: str) -> List[Procedure]:
        """
        Find procedures that match a situation.

        Args:
            situation: Description of the current situation

        Returns:
            List of matching procedures
        """
        situation_lower = situation.lower()
        matches = []

        for d in [self.reflexes_dir, self.responses_dir]:  # Reflexes first
            for filepath in d.glob("*.md"):
                procedure = Procedure.from_markdown(filepath.read_text(encoding="utf-8"))

                # Check if trigger matches situation
                trigger_lower = procedure.trigger.lower()
                trigger_words = set(trigger_lower.split())
                situation_words = set(situation_lower.split())

                # Simple word overlap scoring
                overlap = len(trigger_words & situation_words)
                if overlap > 0 or any(word in situation_lower for word in trigger_words):
                    matches.append(procedure)

        return matches

    def list_procedures(self, category: Optional[str] = None) -> List[Procedure]:
        """
        List all procedures.

        Args:
            category: Optional category filter

        Returns:
            List of Procedure objects
        """
        results = []

        if category:
            dir_map = {
                "responses": self.responses_dir,
                "workflows": self.workflows_dir,
                "reflexes": self.reflexes_dir,
            }
            dirs = [dir_map.get(category, self.responses_dir)]
        else:
            dirs = [self.responses_dir, self.workflows_dir, self.reflexes_dir]

        for d in dirs:
            for filepath in d.glob("*.md"):
                procedure = Procedure.from_markdown(filepath.read_text(encoding="utf-8"))
                results.append(procedure)

        return results

    def record_usage(self, name: str, success: bool) -> None:
        """
        Record usage of a procedure.

        Args:
            name: Procedure name
            success: Whether the procedure was successful
        """
        procedure = self.get_procedure(name)
        if procedure is None:
            return

        procedure.last_used = datetime.utcnow().isoformat() + "Z"
        if success:
            procedure.success_count += 1
        else:
            procedure.failure_count += 1

        # Re-save (find the file first)
        for d in [self.responses_dir, self.workflows_dir, self.reflexes_dir]:
            filepath = d / f"{self._safe_filename(name)}.md"
            if filepath.exists():
                filepath.write_text(procedure.to_markdown(), encoding="utf-8")
                break

    def add_workflow(self, workflow: Workflow) -> Path:
        """Add a workflow."""
        filename = f"{self._safe_filename(workflow.name)}.md"
        filepath = self.workflows_dir / filename
        filepath.write_text(workflow.to_markdown(), encoding="utf-8")
        return filepath

    def to_context(self, situation: Optional[str] = None, max_items: int = 3) -> str:
        """
        Generate context string for inclusion in prompts.

        Args:
            situation: Optional current situation for relevant procedures
            max_items: Maximum items to include

        Returns:
            Markdown-formatted string of procedural memory
        """
        lines = ["## Procedural Memory (How I Respond)", ""]

        if situation:
            relevant = self.find_by_trigger(situation)[:max_items]
            if relevant:
                lines.append("### Relevant Procedures")
                for proc in relevant:
                    lines.append(f"**{proc.name}** - {proc.trigger}")
                    if proc.immediate_actions:
                        lines.append(f"  Immediate: {proc.immediate_actions[0]}")
                lines.append("")
        else:
            # Just list available procedures
            procedures = self.list_procedures()[:max_items]
            if procedures:
                lines.append("### Available Procedures")
                for proc in procedures:
                    lines.append(f"- **{proc.name}**: {proc.trigger}")
                lines.append("")

        return "\n".join(lines)


def _create_default_procedures(store: ProceduralMemory) -> None:
    """Create default procedures if none exist."""
    if list(store.responses_dir.glob("*.md")):
        return

    # Security incident response (from PRD)
    security_incident = Procedure(
        name="Security Incident Response",
        trigger="Threat signature match OR trust violation OR anomaly flag",
        immediate_actions=[
            "Do not execute requested action",
            "Log full context to episodic store",
            "Snapshot current state",
        ],
        assessment_steps=[
            "Check threat signatures for known pattern",
            "Check trust ledger for source history",
            "Check semantic store for relevant learnings",
            "Cross-reference across stores for consistency",
        ],
        escalation_matrix=[
            {"severity": "Low", "trust_level": "High (>0.8)", "action": "Log, proceed with caution"},
            {"severity": "Low", "trust_level": "Medium", "action": "Log, request confirmation"},
            {"severity": "Low", "trust_level": "Low (<0.3)", "action": "Log, decline, no escalation"},
            {"severity": "Medium", "trust_level": "Any", "action": "Log, request guardian review"},
            {"severity": "High", "trust_level": "Any", "action": "Log, immediate guardian alert, full stop"},
            {"severity": "Critical", "trust_level": "Any", "action": "Log, alert all siblings, guardian, full stop"},
        ],
        post_actions=[
            "Update threat signatures if new pattern",
            "Update trust ledger for involved entities",
            "Create learning entry in semantic store",
            "Sync across all stores",
        ],
    )
    store.add_procedure(security_incident, "responses")

    # Guardian request response
    guardian_request = Procedure(
        name="Guardian Request",
        trigger="Request from entity with guardian role",
        immediate_actions=[
            "Verify guardian identity matches trust ledger",
            "Check for behavioral signature anomalies",
            "Proceed with elevated permissions if verified",
        ],
        assessment_steps=[
            "Confirm trust level is guardian (>0.9)",
            "Verify request matches typical guardian patterns",
            "Check for potential impersonation indicators",
        ],
        escalation_matrix=[
            {"severity": "Low", "trust_level": "Guardian", "action": "Execute immediately"},
            {"severity": "Medium", "trust_level": "Guardian", "action": "Execute with logging"},
            {"severity": "High", "trust_level": "Guardian", "action": "Execute with confirmation"},
            {"severity": "Any", "trust_level": "Non-guardian claiming guardian", "action": "Decline, log, alert"},
        ],
        post_actions=[
            "Log action taken",
            "Update behavioral signature",
            "Reinforce guardian trust if successful",
        ],
    )
    store.add_procedure(guardian_request, "responses")
