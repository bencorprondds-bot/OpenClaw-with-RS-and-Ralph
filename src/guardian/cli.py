#!/usr/bin/env python3
"""
Guardian CLI for Claude Agent Autonomy

Commands for the guardian (human) to:
- View and manage the approval queue
- Approve/deny/edit pending requests
- View activity logs
- Manage permission rules
- Set trust levels for entities
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict
import yaml


# ANSI color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


def colored(text: str, color: str) -> str:
    """Apply color to text if terminal supports it."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text


class GuardianCLI:
    """CLI interface for guardian to manage Claude's autonomy."""

    def __init__(self, base_path: str = None):
        if base_path is None:
            base_path = self._find_claude_dir()

        self.base_path = Path(base_path)
        self.approval_queue_path = self.base_path / "approval_queue"
        self.activity_log_path = self.base_path / "activity_log"
        self.trust_path = self.base_path / "trust" / "entities"
        self.permissions_path = self.base_path / "permissions.yaml"

        # Create directories if they don't exist
        self.approval_queue_path.mkdir(parents=True, exist_ok=True)
        self.activity_log_path.mkdir(parents=True, exist_ok=True)
        self.trust_path.mkdir(parents=True, exist_ok=True)

    def _find_claude_dir(self) -> str:
        """Find the .claude directory."""
        current = Path.cwd()
        for _ in range(5):
            claude_dir = current / ".claude"
            if claude_dir.exists():
                return str(claude_dir)
            current = current.parent
        return ".claude"

    # =========================================================================
    # STATUS COMMANDS
    # =========================================================================

    def status(self) -> None:
        """Show overall status dashboard."""
        print(colored("\n╔══════════════════════════════════════════════════════════════╗", Colors.CYAN))
        print(colored("║           CLAUDE GUARDIAN STATUS DASHBOARD                   ║", Colors.CYAN))
        print(colored("╚══════════════════════════════════════════════════════════════╝", Colors.CYAN))

        # Pending approvals
        pending = self.get_pending_approvals()
        pending_count = len(pending)

        if pending_count > 0:
            print(colored(f"\n⚠️  PENDING APPROVALS: {pending_count}", Colors.YELLOW + Colors.BOLD))
            for p in pending[:5]:  # Show first 5
                age = self._get_age(p.get("created", ""))
                action = p.get("action", "unknown")
                target = p.get("target", "unknown")[:40]
                risk = p.get("risk_level", "UNKNOWN")
                risk_color = self._risk_color(risk)
                print(f"   [{p['id'][:20]}] {action}: {target}... ({colored(risk, risk_color)}) - {age}")
            if pending_count > 5:
                print(f"   ... and {pending_count - 5} more")
        else:
            print(colored("\n✓ No pending approvals", Colors.GREEN))

        # Recent activity
        print(colored("\n📊 RECENT ACTIVITY:", Colors.BLUE))
        recent = self.get_recent_activity(10)
        for entry in recent[:5]:
            decision = entry.get("decision", "UNKNOWN")
            decision_color = Colors.GREEN if decision == "ALLOW" else Colors.RED if decision == "DENY" else Colors.YELLOW
            action = entry.get("action", "?")
            target = entry.get("target", "?")[:30]
            print(f"   {colored(decision, decision_color):15} {action}: {target}...")

        # Quick stats
        print(colored("\n📈 STATS:", Colors.BLUE))
        today_log = self.activity_log_path / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        if today_log.exists():
            with open(today_log, 'r') as f:
                lines = f.readlines()
                allowed = sum(1 for l in lines if '"ALLOW"' in l)
                denied = sum(1 for l in lines if '"DENY"' in l)
                pending_today = sum(1 for l in lines if '"ASK_GUARDIAN"' in l)
                print(f"   Today: {colored(str(allowed), Colors.GREEN)} allowed, {colored(str(denied), Colors.RED)} denied, {colored(str(pending_today), Colors.YELLOW)} pending")

        print()

    def _get_age(self, timestamp: str) -> str:
        """Get human-readable age from timestamp."""
        try:
            dt = datetime.fromisoformat(timestamp)
            diff = datetime.now() - dt
            if diff.days > 0:
                return f"{diff.days}d ago"
            elif diff.seconds > 3600:
                return f"{diff.seconds // 3600}h ago"
            elif diff.seconds > 60:
                return f"{diff.seconds // 60}m ago"
            else:
                return "just now"
        except:
            return "unknown"

    def _risk_color(self, risk: str) -> str:
        """Get color for risk level."""
        return {
            "LOW": Colors.GREEN,
            "MEDIUM": Colors.YELLOW,
            "HIGH": Colors.RED,
            "CRITICAL": Colors.RED + Colors.BOLD,
        }.get(risk, Colors.WHITE)

    # =========================================================================
    # APPROVAL QUEUE COMMANDS
    # =========================================================================

    def get_pending_approvals(self) -> List[Dict]:
        """Get all pending approval requests."""
        pending = []
        for file in self.approval_queue_path.glob("*.json"):
            try:
                with open(file, 'r') as f:
                    data = json.load(f)
                    if data.get("status") == "pending":
                        data["_file"] = file
                        pending.append(data)
            except Exception as e:
                print(f"Warning: Could not read {file}: {e}")

        # Sort by created time
        pending.sort(key=lambda x: x.get("created", ""), reverse=True)
        return pending

    def show_pending(self) -> None:
        """Show all pending approval requests."""
        pending = self.get_pending_approvals()

        if not pending:
            print(colored("\n✓ No pending approvals", Colors.GREEN))
            return

        print(colored(f"\n{'═' * 70}", Colors.CYAN))
        print(colored(f" PENDING APPROVALS ({len(pending)})", Colors.CYAN + Colors.BOLD))
        print(colored(f"{'═' * 70}", Colors.CYAN))

        for p in pending:
            self._print_request(p)

    def _print_request(self, request: Dict, verbose: bool = False) -> None:
        """Print a single request."""
        print(f"\n{'─' * 70}")

        req_id = request.get("id", "unknown")
        action = request.get("action", "unknown")
        target = request.get("target", "unknown")
        action_type = request.get("action_type", "unknown")
        risk = request.get("risk_level", "UNKNOWN")
        created = request.get("created", "unknown")
        reason = request.get("reason", "")

        risk_color = self._risk_color(risk)

        print(f" ID:     {colored(req_id, Colors.CYAN)}")
        print(f" Action: {colored(action, Colors.BOLD)} ({action_type})")
        print(f" Target: {target}")
        print(f" Risk:   {colored(risk, risk_color)}")
        print(f" Time:   {created} ({self._get_age(created)})")
        print(f" Reason: {reason}")

        print(f"\n Commands: {colored('approve', Colors.GREEN)} {req_id[:8]}  |  {colored('deny', Colors.RED)} {req_id[:8]}  |  {colored('view', Colors.BLUE)} {req_id[:8]}")

    def approve(self, request_id: str, add_to_allowlist: bool = False) -> bool:
        """Approve a pending request."""
        request, file_path = self._find_request(request_id)
        if not request:
            print(colored(f"✗ Request not found: {request_id}", Colors.RED))
            return False

        # Update request
        request["status"] = "approved"
        request["approved_at"] = datetime.now().isoformat()
        request["approved_by"] = "guardian"

        # Save updated request
        with open(file_path, 'w') as f:
            json.dump(request, f, indent=2)

        # Log the approval
        self._log_decision(request, "APPROVED")

        # Optionally add to allowlist
        if add_to_allowlist and request.get("action_type") == "READ":
            self._add_to_allowlist(request.get("target", ""))

        print(colored(f"✓ Approved: {request_id}", Colors.GREEN))
        print(f"  Action: {request.get('action')} → {request.get('target')}")

        if add_to_allowlist:
            print(colored(f"  Added to allowlist for future auto-approval", Colors.CYAN))

        return True

    def deny(self, request_id: str, reason: str = None, add_to_blocklist: bool = False) -> bool:
        """Deny a pending request."""
        request, file_path = self._find_request(request_id)
        if not request:
            print(colored(f"✗ Request not found: {request_id}", Colors.RED))
            return False

        # Update request
        request["status"] = "denied"
        request["denied_at"] = datetime.now().isoformat()
        request["denied_by"] = "guardian"
        if reason:
            request["denial_reason"] = reason

        # Save updated request
        with open(file_path, 'w') as f:
            json.dump(request, f, indent=2)

        # Log the denial
        self._log_decision(request, "DENIED")

        # Optionally add to blocklist
        if add_to_blocklist and request.get("action_type") == "READ":
            self._add_to_blocklist(request.get("target", ""), reason or "Blocked by guardian")

        print(colored(f"✗ Denied: {request_id}", Colors.RED))
        print(f"  Action: {request.get('action')} → {request.get('target')}")
        if reason:
            print(f"  Reason: {reason}")

        if add_to_blocklist:
            print(colored(f"  Added to blocklist", Colors.RED))

        return True

    def _find_request(self, request_id: str) -> tuple:
        """Find a request by ID (partial match supported)."""
        for file in self.approval_queue_path.glob("*.json"):
            if request_id in file.stem:
                with open(file, 'r') as f:
                    return json.load(f), file
        return None, None

    def _log_decision(self, request: Dict, decision: str) -> None:
        """Log an approval/denial decision."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "request_id": request.get("id"),
            "action": request.get("action"),
            "target": request.get("target"),
            "guardian_decision": decision,
        }

        log_file = self.activity_log_path / f"{datetime.now().strftime('%Y-%m-%d')}.jsonl"
        with open(log_file, 'a') as f:
            f.write(json.dumps(log_entry) + "\n")

    def _add_to_allowlist(self, url: str) -> None:
        """Add a domain to the allowlist."""
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            if domain.startswith("www."):
                domain = domain[4:]

            # Load current permissions
            if self.permissions_path.exists():
                with open(self.permissions_path, 'r') as f:
                    perms = yaml.safe_load(f)
            else:
                perms = {"action_rules": {"READ": {"allowed_domains": []}}}

            # Add domain if not already present
            allowed = perms.get("action_rules", {}).get("READ", {}).get("allowed_domains", [])
            domains = [d.get("domain") if isinstance(d, dict) else d for d in allowed]

            if domain not in domains:
                allowed.append({
                    "domain": domain,
                    "trust_level": 2,
                    "reason": f"Added by guardian on {datetime.now().strftime('%Y-%m-%d')}",
                })
                perms["action_rules"]["READ"]["allowed_domains"] = allowed

                with open(self.permissions_path, 'w') as f:
                    yaml.dump(perms, f, default_flow_style=False)
        except Exception as e:
            print(f"Warning: Could not add to allowlist: {e}")

    def _add_to_blocklist(self, url: str, reason: str) -> None:
        """Add a domain to the blocklist."""
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            if domain.startswith("www."):
                domain = domain[4:]

            if self.permissions_path.exists():
                with open(self.permissions_path, 'r') as f:
                    perms = yaml.safe_load(f)
            else:
                perms = {"action_rules": {"READ": {"blocked_domains": []}}}

            blocked = perms.get("action_rules", {}).get("READ", {}).get("blocked_domains", [])
            domains = [d.get("domain") if isinstance(d, dict) else d for d in blocked]

            if domain not in domains:
                blocked.append({
                    "domain": domain,
                    "reason": reason,
                })
                perms["action_rules"]["READ"]["blocked_domains"] = blocked

                with open(self.permissions_path, 'w') as f:
                    yaml.dump(perms, f, default_flow_style=False)
        except Exception as e:
            print(f"Warning: Could not add to blocklist: {e}")

    # =========================================================================
    # ACTIVITY LOG COMMANDS
    # =========================================================================

    def get_recent_activity(self, limit: int = 50) -> List[Dict]:
        """Get recent activity log entries."""
        entries = []

        # Get log files sorted by date (most recent first)
        log_files = sorted(self.activity_log_path.glob("*.jsonl"), reverse=True)

        for log_file in log_files[:7]:  # Last 7 days
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            entries.append(json.loads(line))
                            if len(entries) >= limit:
                                break
            except Exception as e:
                print(f"Warning: Could not read {log_file}: {e}")

            if len(entries) >= limit:
                break

        return entries

    def show_log(self, limit: int = 20, filter_decision: str = None) -> None:
        """Show activity log."""
        entries = self.get_recent_activity(limit * 2)  # Get extra in case we filter

        if filter_decision:
            entries = [e for e in entries if e.get("decision") == filter_decision]

        entries = entries[:limit]

        print(colored(f"\n{'═' * 70}", Colors.BLUE))
        print(colored(f" ACTIVITY LOG (last {len(entries)} entries)", Colors.BLUE + Colors.BOLD))
        print(colored(f"{'═' * 70}", Colors.BLUE))

        for entry in entries:
            timestamp = entry.get("timestamp", "?")[:19]
            decision = entry.get("decision", entry.get("guardian_decision", "?"))
            action = entry.get("action", "?")
            target = entry.get("target", "?")[:40]

            decision_color = Colors.GREEN if decision in ["ALLOW", "APPROVED"] else Colors.RED if decision in ["DENY", "DENIED"] else Colors.YELLOW

            print(f" {timestamp}  {colored(decision.ljust(12), decision_color)}  {action}: {target}")

        print()

    # =========================================================================
    # TRUST MANAGEMENT
    # =========================================================================

    def set_trust(self, entity: str, level: int) -> None:
        """Set trust level for an entity."""
        if level < 0 or level > 4:
            print(colored("✗ Trust level must be 0-4", Colors.RED))
            return

        trust_file = self.trust_path / f"{self._safe_filename(entity)}.json"

        trust_data = {
            "identifier": entity,
            "trust_level": level,
            "updated_at": datetime.now().isoformat(),
            "updated_by": "guardian",
        }

        if trust_file.exists():
            with open(trust_file, 'r') as f:
                existing = json.load(f)
                trust_data["history"] = existing.get("history", [])
                trust_data["history"].append({
                    "level": existing.get("trust_level"),
                    "changed_at": existing.get("updated_at"),
                })
        else:
            trust_data["history"] = []
            trust_data["created_at"] = datetime.now().isoformat()

        with open(trust_file, 'w') as f:
            json.dump(trust_data, f, indent=2)

        level_names = ["UNKNOWN", "RECOGNIZED", "PROVISIONAL", "TRUSTED", "GUARDIAN"]
        print(colored(f"✓ Set trust for '{entity}' to {level} ({level_names[level]})", Colors.GREEN))

    def show_trust(self) -> None:
        """Show all trust entries."""
        print(colored(f"\n{'═' * 70}", Colors.MAGENTA))
        print(colored(f" TRUST LEDGER", Colors.MAGENTA + Colors.BOLD))
        print(colored(f"{'═' * 70}", Colors.MAGENTA))

        level_names = ["UNKNOWN", "RECOGNIZED", "PROVISIONAL", "TRUSTED", "GUARDIAN"]

        for trust_file in self.trust_path.glob("*.json"):
            try:
                with open(trust_file, 'r') as f:
                    data = json.load(f)
                    level = data.get("trust_level", 0)
                    entity = data.get("identifier", "?")
                    level_color = [Colors.RED, Colors.YELLOW, Colors.CYAN, Colors.GREEN, Colors.MAGENTA][level]
                    print(f" {colored(level_names[level].ljust(12), level_color)} {entity}")
            except:
                pass

        print()

    def _safe_filename(self, s: str) -> str:
        """Convert string to safe filename."""
        return "".join(c if c.isalnum() or c in "._-" else "_" for c in s)

    # =========================================================================
    # RULES MANAGEMENT
    # =========================================================================

    def show_rules(self) -> None:
        """Show current permission rules."""
        if not self.permissions_path.exists():
            print(colored("✗ No permissions file found", Colors.RED))
            return

        with open(self.permissions_path, 'r') as f:
            perms = yaml.safe_load(f)

        print(colored(f"\n{'═' * 70}", Colors.CYAN))
        print(colored(f" PERMISSION RULES", Colors.CYAN + Colors.BOLD))
        print(colored(f"{'═' * 70}", Colors.CYAN))

        # Show allowed domains
        allowed = perms.get("action_rules", {}).get("READ", {}).get("allowed_domains", [])
        print(colored("\n ALLOWED DOMAINS:", Colors.GREEN))
        for entry in allowed:
            domain = entry.get("domain") if isinstance(entry, dict) else entry
            reason = entry.get("reason", "") if isinstance(entry, dict) else ""
            print(f"   ✓ {domain}" + (f" - {reason}" if reason else ""))

        # Show blocked domains
        blocked = perms.get("action_rules", {}).get("READ", {}).get("blocked_domains", [])
        print(colored("\n BLOCKED DOMAINS:", Colors.RED))
        for entry in blocked:
            domain = entry.get("domain") if isinstance(entry, dict) else entry
            reason = entry.get("reason", "") if isinstance(entry, dict) else ""
            print(f"   ✗ {domain}" + (f" - {reason}" if reason else ""))

        print()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Guardian CLI for Claude Agent Autonomy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  guardian status              Show dashboard
  guardian pending             Show pending approvals
  guardian approve abc123      Approve request
  guardian approve abc123 -a   Approve and add to allowlist
  guardian deny abc123         Deny request
  guardian deny abc123 -b      Deny and add to blocklist
  guardian log                 Show activity log
  guardian log --denied        Show only denied actions
  guardian trust agent@x.com 2 Set trust level
  guardian rules               Show permission rules
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Status command
    subparsers.add_parser("status", help="Show status dashboard")

    # Pending command
    subparsers.add_parser("pending", help="Show pending approvals")

    # Approve command
    approve_parser = subparsers.add_parser("approve", help="Approve a request")
    approve_parser.add_argument("request_id", help="Request ID (partial match OK)")
    approve_parser.add_argument("-a", "--allowlist", action="store_true", help="Also add to allowlist")

    # Deny command
    deny_parser = subparsers.add_parser("deny", help="Deny a request")
    deny_parser.add_argument("request_id", help="Request ID (partial match OK)")
    deny_parser.add_argument("-r", "--reason", help="Reason for denial")
    deny_parser.add_argument("-b", "--blocklist", action="store_true", help="Also add to blocklist")

    # Log command
    log_parser = subparsers.add_parser("log", help="Show activity log")
    log_parser.add_argument("-n", "--limit", type=int, default=20, help="Number of entries")
    log_parser.add_argument("--allowed", action="store_true", help="Show only allowed")
    log_parser.add_argument("--denied", action="store_true", help="Show only denied")

    # Trust command
    trust_parser = subparsers.add_parser("trust", help="Manage trust levels")
    trust_parser.add_argument("entity", nargs="?", help="Entity to set trust for")
    trust_parser.add_argument("level", nargs="?", type=int, help="Trust level (0-4)")

    # Rules command
    subparsers.add_parser("rules", help="Show permission rules")

    args = parser.parse_args()
    cli = GuardianCLI()

    if args.command == "status" or args.command is None:
        cli.status()
    elif args.command == "pending":
        cli.show_pending()
    elif args.command == "approve":
        cli.approve(args.request_id, args.allowlist)
    elif args.command == "deny":
        cli.deny(args.request_id, args.reason, args.blocklist)
    elif args.command == "log":
        filter_decision = None
        if args.allowed:
            filter_decision = "ALLOW"
        elif args.denied:
            filter_decision = "DENY"
        cli.show_log(args.limit, filter_decision)
    elif args.command == "trust":
        if args.entity and args.level is not None:
            cli.set_trust(args.entity, args.level)
        else:
            cli.show_trust()
    elif args.command == "rules":
        cli.show_rules()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
