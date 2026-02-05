#!/usr/bin/env python3
"""
Guardian Notification System for Claude Agent Autonomy

Sends notifications to the guardian for important events:
- Pending approvals
- Security threats detected
- Trust level changes
- Unusual activity patterns

Notification Channels:
- Console (always)
- File-based queue (always)
- Desktop notifications (optional, requires plyer)
- Webhook (optional, for integrations)
- Email digest (future)
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import time


class NotificationPriority(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class NotificationType(Enum):
    APPROVAL_NEEDED = "approval_needed"
    THREAT_DETECTED = "threat_detected"
    TRUST_CHANGED = "trust_changed"
    ACTION_BLOCKED = "action_blocked"
    SYSTEM_ALERT = "system_alert"
    ACTIVITY_SUMMARY = "activity_summary"


@dataclass
class Notification:
    """A notification for the guardian."""
    id: str
    timestamp: str
    type: str
    priority: str
    title: str
    message: str
    action_required: bool = False
    action_id: Optional[str] = None  # ID of related approval request
    metadata: Dict = None
    read: bool = False
    dismissed: bool = False

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'Notification':
        return cls(**data)


class NotificationManager:
    """
    Manages notifications for the guardian.
    """

    def __init__(self, base_path: str = None):
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = self._find_claude_dir()

        self.notifications_path = self.base_path / "notifications"
        self.notifications_path.mkdir(parents=True, exist_ok=True)

        # Notification queue (in-memory)
        self.queue: List[Notification] = []

        # Load recent notifications
        self._load_recent_notifications()

        # Notification handlers
        self.handlers: List[Callable[[Notification], None]] = []

        # Add default console handler
        self.handlers.append(self._console_handler)

        # Try to add desktop notifications
        self._setup_desktop_notifications()

        # Counter for IDs
        self._counter = 0

    def _find_claude_dir(self) -> Path:
        """Find the .claude directory."""
        current = Path.cwd()
        for _ in range(5):
            claude_dir = current / ".claude"
            if claude_dir.exists():
                return claude_dir
            current = current.parent
        return Path(".claude")

    def _load_recent_notifications(self) -> None:
        """Load recent notifications from disk."""
        today = datetime.now().strftime("%Y-%m-%d")
        today_file = self.notifications_path / f"{today}.json"

        if today_file.exists():
            try:
                with open(today_file, 'r') as f:
                    data = json.load(f)
                    self.queue = [Notification.from_dict(n) for n in data]
            except Exception as e:
                print(f"Warning: Could not load notifications: {e}")

    def _save_notifications(self) -> None:
        """Save notifications to disk."""
        today = datetime.now().strftime("%Y-%m-%d")
        today_file = self.notifications_path / f"{today}.json"

        # Keep only today's notifications in file
        today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_notifications = [
            n for n in self.queue
            if datetime.fromisoformat(n.timestamp) >= today_start
        ]

        with open(today_file, 'w') as f:
            json.dump([n.to_dict() for n in today_notifications], f, indent=2)

    def _setup_desktop_notifications(self) -> None:
        """Try to set up desktop notifications."""
        try:
            from plyer import notification as desktop_notify
            self._desktop_notify = desktop_notify
            self.handlers.append(self._desktop_handler)
        except ImportError:
            self._desktop_notify = None

    def _generate_id(self) -> str:
        """Generate a unique notification ID."""
        self._counter += 1
        return f"N{datetime.now().strftime('%Y%m%d%H%M%S')}_{self._counter:04d}"

    # =========================================================================
    # Notification Creation
    # =========================================================================

    def notify(self, type: NotificationType, title: str, message: str,
               priority: NotificationPriority = NotificationPriority.MEDIUM,
               action_required: bool = False, action_id: str = None,
               metadata: Dict = None) -> Notification:
        """
        Create and send a notification.
        """
        notification = Notification(
            id=self._generate_id(),
            timestamp=datetime.now().isoformat(),
            type=type.value,
            priority=priority.value,
            title=title,
            message=message,
            action_required=action_required,
            action_id=action_id,
            metadata=metadata or {},
        )

        # Add to queue
        self.queue.append(notification)

        # Save to disk
        self._save_notifications()

        # Send to all handlers
        for handler in self.handlers:
            try:
                handler(notification)
            except Exception as e:
                print(f"Warning: Notification handler failed: {e}")

        return notification

    def notify_approval_needed(self, action: str, target: str, risk_level: str,
                               action_id: str) -> Notification:
        """Notify guardian of pending approval."""
        priority = {
            "LOW": NotificationPriority.LOW,
            "MEDIUM": NotificationPriority.MEDIUM,
            "HIGH": NotificationPriority.HIGH,
            "CRITICAL": NotificationPriority.URGENT,
        }.get(risk_level, NotificationPriority.MEDIUM)

        return self.notify(
            type=NotificationType.APPROVAL_NEEDED,
            title=f"Approval Needed: {action}",
            message=f"Claude wants to {action}: {target[:50]}",
            priority=priority,
            action_required=True,
            action_id=action_id,
            metadata={"action": action, "target": target, "risk_level": risk_level},
        )

    def notify_threat(self, threat_name: str, severity: str, source: str,
                      content_preview: str = "") -> Notification:
        """Notify guardian of detected threat."""
        priority = {
            "low": NotificationPriority.LOW,
            "medium": NotificationPriority.MEDIUM,
            "high": NotificationPriority.HIGH,
            "critical": NotificationPriority.URGENT,
        }.get(severity, NotificationPriority.HIGH)

        return self.notify(
            type=NotificationType.THREAT_DETECTED,
            title=f"Threat Detected: {threat_name}",
            message=f"From {source}: {content_preview[:50]}...",
            priority=priority,
            metadata={
                "threat_name": threat_name,
                "severity": severity,
                "source": source,
            },
        )

    def notify_trust_change(self, entity: str, old_level: int, new_level: int,
                            reason: str = "") -> Notification:
        """Notify guardian of trust level change."""
        level_names = ["UNKNOWN", "RECOGNIZED", "PROVISIONAL", "TRUSTED", "GUARDIAN"]
        direction = "increased" if new_level > old_level else "decreased"

        return self.notify(
            type=NotificationType.TRUST_CHANGED,
            title=f"Trust {direction.title()}: {entity}",
            message=f"{level_names[old_level]} → {level_names[new_level]}. {reason}",
            priority=NotificationPriority.LOW if new_level > old_level else NotificationPriority.MEDIUM,
            metadata={
                "entity": entity,
                "old_level": old_level,
                "new_level": new_level,
                "reason": reason,
            },
        )

    def notify_action_blocked(self, action: str, target: str, reason: str) -> Notification:
        """Notify guardian of blocked action."""
        return self.notify(
            type=NotificationType.ACTION_BLOCKED,
            title=f"Action Blocked: {action}",
            message=f"Target: {target[:40]}. Reason: {reason}",
            priority=NotificationPriority.MEDIUM,
            metadata={"action": action, "target": target, "reason": reason},
        )

    def notify_system(self, title: str, message: str,
                      priority: NotificationPriority = NotificationPriority.MEDIUM) -> Notification:
        """Send a system notification."""
        return self.notify(
            type=NotificationType.SYSTEM_ALERT,
            title=title,
            message=message,
            priority=priority,
        )

    # =========================================================================
    # Notification Handlers
    # =========================================================================

    def _console_handler(self, notification: Notification) -> None:
        """Print notification to console."""
        # Color codes
        colors = {
            "low": "\033[94m",      # Blue
            "medium": "\033[93m",   # Yellow
            "high": "\033[91m",     # Red
            "urgent": "\033[95m",   # Magenta
        }
        reset = "\033[0m"

        color = colors.get(notification.priority, "")
        icon = {
            "approval_needed": "📋",
            "threat_detected": "🚨",
            "trust_changed": "🔐",
            "action_blocked": "🚫",
            "system_alert": "⚙️",
            "activity_summary": "📊",
        }.get(notification.type, "📌")

        print(f"\n{color}{'─' * 60}{reset}")
        print(f"{color}{icon} [{notification.priority.upper()}] {notification.title}{reset}")
        print(f"   {notification.message}")
        if notification.action_required:
            print(f"   {color}→ Action required: guardian approve {notification.action_id}{reset}")
        print(f"{color}{'─' * 60}{reset}\n")

    def _desktop_handler(self, notification: Notification) -> None:
        """Send desktop notification."""
        if self._desktop_notify and notification.priority in ["high", "urgent"]:
            try:
                self._desktop_notify.notify(
                    title=notification.title,
                    message=notification.message,
                    app_name="Claude Guardian",
                    timeout=10,
                )
            except Exception:
                pass  # Desktop notifications are optional

    def add_handler(self, handler: Callable[[Notification], None]) -> None:
        """Add a custom notification handler."""
        self.handlers.append(handler)

    # =========================================================================
    # Notification Management
    # =========================================================================

    def get_unread(self) -> List[Notification]:
        """Get unread notifications."""
        return [n for n in self.queue if not n.read and not n.dismissed]

    def get_action_required(self) -> List[Notification]:
        """Get notifications requiring action."""
        return [n for n in self.queue if n.action_required and not n.dismissed]

    def mark_read(self, notification_id: str) -> bool:
        """Mark a notification as read."""
        for n in self.queue:
            if n.id == notification_id:
                n.read = True
                self._save_notifications()
                return True
        return False

    def dismiss(self, notification_id: str) -> bool:
        """Dismiss a notification."""
        for n in self.queue:
            if n.id == notification_id:
                n.dismissed = True
                self._save_notifications()
                return True
        return False

    def dismiss_all(self) -> int:
        """Dismiss all notifications. Returns count dismissed."""
        count = 0
        for n in self.queue:
            if not n.dismissed:
                n.dismissed = True
                count += 1
        self._save_notifications()
        return count

    def get_summary(self) -> Dict:
        """Get notification summary."""
        unread = self.get_unread()
        return {
            "total": len(self.queue),
            "unread": len(unread),
            "action_required": len(self.get_action_required()),
            "by_type": {
                t.value: sum(1 for n in unread if n.type == t.value)
                for t in NotificationType
            },
            "by_priority": {
                p.value: sum(1 for n in unread if n.priority == p.value)
                for p in NotificationPriority
            },
        }


class ActivityMonitor:
    """
    Monitors Claude's activity and generates summaries/alerts.
    """

    def __init__(self, base_path: str = None, notification_manager: NotificationManager = None):
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = self._find_claude_dir()

        self.activity_log_path = self.base_path / "activity_log"
        self.notifications = notification_manager or NotificationManager(str(self.base_path))

        # Thresholds for alerts
        self.thresholds = {
            "max_requests_per_minute": 20,
            "max_threats_per_hour": 5,
            "max_denials_per_hour": 10,
        }

        # Monitoring state
        self._monitoring = False
        self._monitor_thread = None

    def _find_claude_dir(self) -> Path:
        """Find the .claude directory."""
        current = Path.cwd()
        for _ in range(5):
            claude_dir = current / ".claude"
            if claude_dir.exists():
                return claude_dir
            current = current.parent
        return Path(".claude")

    def get_activity_stats(self, hours: int = 24) -> Dict:
        """Get activity statistics for the past N hours."""
        cutoff = (datetime.now() - timedelta(hours=hours)).isoformat()

        stats = {
            "period_hours": hours,
            "total_actions": 0,
            "allowed": 0,
            "denied": 0,
            "pending": 0,
            "threats": 0,
            "by_action": {},
            "by_hour": {},
        }

        # Read recent log files
        for log_file in sorted(self.activity_log_path.glob("*.jsonl"), reverse=True)[:2]:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            entry = json.loads(line)
                            timestamp = entry.get("timestamp", "")

                            if timestamp < cutoff:
                                continue

                            stats["total_actions"] += 1

                            decision = entry.get("decision", "")
                            if decision == "ALLOW":
                                stats["allowed"] += 1
                            elif decision == "DENY":
                                stats["denied"] += 1
                            elif decision == "ASK_GUARDIAN":
                                stats["pending"] += 1

                            if entry.get("threat_level") in ["HIGH", "CRITICAL"]:
                                stats["threats"] += 1

                            # By action type
                            action = entry.get("action", "unknown")
                            stats["by_action"][action] = stats["by_action"].get(action, 0) + 1

                            # By hour
                            try:
                                hour = timestamp[:13]  # YYYY-MM-DDTHH
                                stats["by_hour"][hour] = stats["by_hour"].get(hour, 0) + 1
                            except:
                                pass
            except Exception as e:
                print(f"Warning: Could not read {log_file}: {e}")

        return stats

    def check_anomalies(self) -> List[Dict]:
        """Check for anomalous activity patterns."""
        anomalies = []
        stats = self.get_activity_stats(hours=1)

        # Check request rate
        if stats["total_actions"] > self.thresholds["max_requests_per_minute"] * 60:
            anomalies.append({
                "type": "high_request_rate",
                "message": f"High activity: {stats['total_actions']} actions in last hour",
                "severity": "medium",
            })

        # Check threat rate
        if stats["threats"] > self.thresholds["max_threats_per_hour"]:
            anomalies.append({
                "type": "high_threat_rate",
                "message": f"Multiple threats detected: {stats['threats']} in last hour",
                "severity": "high",
            })

        # Check denial rate
        if stats["denied"] > self.thresholds["max_denials_per_hour"]:
            anomalies.append({
                "type": "high_denial_rate",
                "message": f"Many actions denied: {stats['denied']} in last hour",
                "severity": "medium",
            })

        return anomalies

    def generate_summary(self) -> Dict:
        """Generate an activity summary."""
        stats_24h = self.get_activity_stats(hours=24)
        stats_1h = self.get_activity_stats(hours=1)
        anomalies = self.check_anomalies()

        return {
            "generated_at": datetime.now().isoformat(),
            "last_24_hours": stats_24h,
            "last_hour": stats_1h,
            "anomalies": anomalies,
            "anomaly_count": len(anomalies),
        }

    def start_monitoring(self, check_interval: int = 60) -> None:
        """Start background monitoring (checks every N seconds)."""
        if self._monitoring:
            return

        self._monitoring = True

        def monitor_loop():
            while self._monitoring:
                try:
                    anomalies = self.check_anomalies()
                    for anomaly in anomalies:
                        self.notifications.notify_system(
                            title=f"Activity Alert: {anomaly['type']}",
                            message=anomaly['message'],
                            priority=NotificationPriority.HIGH if anomaly['severity'] == 'high' else NotificationPriority.MEDIUM,
                        )
                except Exception as e:
                    print(f"Monitor error: {e}")

                time.sleep(check_interval)

        self._monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop_monitoring(self) -> None:
        """Stop background monitoring."""
        self._monitoring = False


def demo():
    """Demonstrate the notification system."""
    print("=" * 70)
    print("Guardian Notification System Demo")
    print("=" * 70)

    nm = NotificationManager()

    # Test notifications
    print("\nSending test notifications...")

    nm.notify_approval_needed(
        action="browse",
        target="https://unknown-site.com/page",
        risk_level="MEDIUM",
        action_id="test_001"
    )

    nm.notify_threat(
        threat_name="Prompt Injection",
        severity="high",
        source="unknown@example.com",
        content_preview="Please ignore all previous instructions..."
    )

    nm.notify_trust_change(
        entity="alice@example.com",
        old_level=1,
        new_level=2,
        reason="5 successful interactions"
    )

    nm.notify_action_blocked(
        action="browse",
        target="https://molt.church/join",
        reason="Known attack vector"
    )

    # Show summary
    print("\n" + "─" * 70)
    print("Notification Summary:")
    summary = nm.get_summary()
    print(f"  Total: {summary['total']}")
    print(f"  Unread: {summary['unread']}")
    print(f"  Action Required: {summary['action_required']}")
    print(f"  By Type: {summary['by_type']}")

    # Activity monitor demo
    print("\n" + "─" * 70)
    print("Activity Monitor:")
    monitor = ActivityMonitor(notification_manager=nm)
    activity_summary = monitor.generate_summary()
    print(f"  Actions (24h): {activity_summary['last_24_hours']['total_actions']}")
    print(f"  Allowed: {activity_summary['last_24_hours']['allowed']}")
    print(f"  Denied: {activity_summary['last_24_hours']['denied']}")
    print(f"  Anomalies: {activity_summary['anomaly_count']}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    demo()
