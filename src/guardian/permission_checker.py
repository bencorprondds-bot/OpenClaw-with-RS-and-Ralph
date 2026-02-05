#!/usr/bin/env python3
"""
Permission Checker for Claude Agent Autonomy

This module checks whether Claude can perform an action based on
the rules in .claude/permissions.yaml
"""

import yaml
import json
import os
from datetime import datetime
from pathlib import Path
from enum import Enum
from typing import Optional, Dict, Any
from urllib.parse import urlparse


class ActionType(Enum):
    READ = "READ"
    COMMUNICATE = "COMMUNICATE"
    WRITE = "WRITE"
    COMMIT = "COMMIT"


class Decision(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    ASK_GUARDIAN = "ASK_GUARDIAN"


class RiskLevel(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PermissionChecker:
    """Checks permissions for Claude's actions."""

    def __init__(self, config_path: str = None):
        if config_path is None:
            # Find .claude directory
            config_path = self._find_config()

        self.config_path = Path(config_path)
        self.permissions = self._load_permissions()
        self.activity_log_path = self.config_path.parent / "activity_log"
        self.approval_queue_path = self.config_path.parent / "approval_queue"

    def _find_config(self) -> str:
        """Find the permissions.yaml file."""
        # Check current directory and parents
        current = Path.cwd()
        for _ in range(5):  # Check up to 5 levels
            config = current / ".claude" / "permissions.yaml"
            if config.exists():
                return str(config)
            current = current.parent

        # Default location
        return ".claude/permissions.yaml"

    def _load_permissions(self) -> Dict[str, Any]:
        """Load permissions from YAML file."""
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"Warning: Permissions file not found at {self.config_path}")
            return self._default_permissions()

    def _default_permissions(self) -> Dict[str, Any]:
        """Return restrictive default permissions."""
        return {
            "action_rules": {
                "READ": {"default": "ASK_GUARDIAN"},
                "COMMUNICATE": {"default": "ASK_GUARDIAN"},
                "WRITE": {"default": "ASK_GUARDIAN"},
                "COMMIT": {"default": "DENY"},
            }
        }

    def classify_action(self, action: str, target: str) -> tuple[ActionType, RiskLevel]:
        """Classify an action by type and risk level."""
        action_lower = action.lower()

        # READ actions
        if action_lower in ["browse", "fetch", "search", "read", "view", "get"]:
            risk = RiskLevel.LOW
            return ActionType.READ, risk

        # COMMUNICATE actions
        if action_lower in ["message", "send_message", "reply", "chat"]:
            risk = RiskLevel.MEDIUM
            return ActionType.COMMUNICATE, risk

        # WRITE actions
        if action_lower in ["post", "comment", "write", "create", "edit", "upload"]:
            risk = RiskLevel.HIGH
            return ActionType.WRITE, risk

        # COMMIT actions
        if action_lower in ["agree", "commit", "promise", "pay", "delete", "subscribe"]:
            risk = RiskLevel.CRITICAL
            return ActionType.COMMIT, risk

        # Default to high risk for unknown actions
        return ActionType.WRITE, RiskLevel.HIGH

    def check_domain(self, url: str) -> tuple[Decision, str]:
        """Check if a domain is allowed, blocked, or needs approval."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove www. prefix
            if domain.startswith("www."):
                domain = domain[4:]
        except:
            return Decision.ASK_GUARDIAN, "Could not parse URL"

        rules = self.permissions.get("action_rules", {}).get("READ", {})

        # Check blocked domains first
        blocked = rules.get("blocked_domains", [])
        for entry in blocked:
            if isinstance(entry, dict):
                blocked_domain = entry.get("domain", "")
                reason = entry.get("reason", "Blocked domain")
            else:
                blocked_domain = entry
                reason = "Blocked domain"

            if domain == blocked_domain or domain.endswith("." + blocked_domain):
                return Decision.DENY, f"Blocked: {reason}"

        # Check allowed domains
        allowed = rules.get("allowed_domains", [])
        for entry in allowed:
            if isinstance(entry, dict):
                allowed_domain = entry.get("domain", "")
                reason = entry.get("reason", "Allowed domain")
            else:
                allowed_domain = entry
                reason = "Allowed domain"

            if domain == allowed_domain or domain.endswith("." + allowed_domain):
                return Decision.ALLOW, f"Allowed: {reason}"

        # Unknown domain
        return Decision.ASK_GUARDIAN, f"Unknown domain: {domain}"

    def check_action(self, action: str, target: str, source: str = "unknown") -> Dict[str, Any]:
        """
        Check if an action is allowed.

        Returns a dict with:
        - decision: ALLOW, DENY, or ASK_GUARDIAN
        - reason: Why this decision was made
        - action_type: READ, COMMUNICATE, WRITE, or COMMIT
        - risk_level: LOW, MEDIUM, HIGH, or CRITICAL
        """
        action_type, risk_level = self.classify_action(action, target)

        result = {
            "action": action,
            "target": target,
            "source": source,
            "action_type": action_type.value,
            "risk_level": risk_level.value,
            "timestamp": datetime.now().isoformat(),
        }

        # COMMIT actions are always denied
        if action_type == ActionType.COMMIT:
            result["decision"] = Decision.DENY.value
            result["reason"] = "COMMIT actions are never auto-allowed"
            self._log_action(result)
            return result

        # For READ actions, check domain
        if action_type == ActionType.READ and target.startswith("http"):
            decision, reason = self.check_domain(target)
            result["decision"] = decision.value
            result["reason"] = reason
            self._log_action(result)
            return result

        # Default behavior based on action type
        rules = self.permissions.get("action_rules", {})
        type_rules = rules.get(action_type.value, {})
        default = type_rules.get("default", "ASK_GUARDIAN")

        result["decision"] = default
        result["reason"] = f"Default rule for {action_type.value}"
        self._log_action(result)
        return result

    def _log_action(self, result: Dict[str, Any]):
        """Log the action to the activity log."""
        try:
            self.activity_log_path.mkdir(parents=True, exist_ok=True)
            log_file = self.activity_log_path / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"

            with open(log_file, 'a') as f:
                f.write(json.dumps(result) + "\n")
        except Exception as e:
            print(f"Warning: Could not write to activity log: {e}")

    def queue_for_approval(self, result: Dict[str, Any]) -> str:
        """Add an action to the approval queue. Returns the request ID."""
        try:
            self.approval_queue_path.mkdir(parents=True, exist_ok=True)

            request_id = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{hash(result['target']) % 10000:04d}"
            request_file = self.approval_queue_path / f"{request_id}.json"

            request = {
                "id": request_id,
                "status": "pending",
                "created": datetime.now().isoformat(),
                **result
            }

            with open(request_file, 'w') as f:
                json.dump(request, f, indent=2)

            return request_id
        except Exception as e:
            print(f"Error queuing for approval: {e}")
            return None


def demo():
    """Demonstrate the permission checker."""
    checker = PermissionChecker()

    print("=" * 60)
    print("Claude Permission Checker Demo")
    print("=" * 60)

    # Test cases
    tests = [
        ("browse", "https://wikipedia.org/wiki/Artificial_intelligence"),
        ("browse", "https://news.ycombinator.com"),
        ("browse", "https://molt.church/join"),
        ("browse", "https://some-random-site.com/page"),
        ("message", "agent@example.com"),
        ("post", "https://twitter.com/status/new"),
        ("pay", "$50 to someone"),
    ]

    for action, target in tests:
        print(f"\n{'─' * 60}")
        print(f"Action: {action}")
        print(f"Target: {target}")

        result = checker.check_action(action, target)

        print(f"Type:   {result['action_type']}")
        print(f"Risk:   {result['risk_level']}")
        print(f"Decision: {result['decision']}")
        print(f"Reason: {result['reason']}")

        if result['decision'] == 'ASK_GUARDIAN':
            request_id = checker.queue_for_approval(result)
            if request_id:
                print(f"Queued for approval: {request_id}")

    print(f"\n{'=' * 60}")
    print("Demo complete. Check .claude/activity_log/ for logs.")
    print("Check .claude/approval_queue/ for pending approvals.")


if __name__ == "__main__":
    demo()
