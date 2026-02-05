#!/usr/bin/env python3
"""
Autonomous Explorer for Claude

Let Claude explore the internet autonomously with Guardian protection.
Claude explores, stays safe, and reports findings back to you.

How it works:
1. You give Claude a mission (e.g., "Find AI safety resources")
2. Claude explores autonomously using Guardian protection
3. Dangerous sites are blocked, suspicious ones logged for your review
4. Claude reports findings back to you

Usage:
    python autonomous_explorer.py "Find resources about AI alignment"
    python autonomous_explorer.py --interactive

The Guardian protects Claude by:
- Pre-scanning every site before visiting
- Blocking CRITICAL threats automatically
- Logging HIGH risk sites for your review
- Sanitizing all content for prompt injection
- Checking reputation of any agents encountered
"""

import sys
import os
import json
import argparse
from datetime import datetime
from pathlib import Path

# Add guardian to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class AutonomousExplorer:
    """
    Autonomous exploration with Guardian protection.

    Claude can use this to explore safely and report back.
    """

    def __init__(self, base_path: str = None):
        from site_scanner import SiteScanner
        from reputation_scanner import ReputationScanner
        from content_sanitizer import ContentSanitizer
        from threat_signatures import ThreatSignatureDB
        from distributed_memory import DistributedMemory, MemoryType

        # Find .claude directory
        if base_path:
            self.base_path = Path(base_path)
        else:
            self.base_path = self._find_claude_dir()

        # Initialize Guardian components
        self.scanner = SiteScanner(str(self.base_path))
        self.reputation = ReputationScanner(str(self.base_path))
        self.sanitizer = ContentSanitizer()
        self.threats = ThreatSignatureDB(str(self.base_path))
        self.memory = DistributedMemory(str(self.base_path))
        self.MemoryType = MemoryType

        # Exploration state
        self.mission = None
        self.findings = []
        self.blocked_sites = []
        self.pending_review = []
        self.visited = set()

        # Reports directory
        self.reports_path = self.base_path / "exploration_reports"
        self.reports_path.mkdir(parents=True, exist_ok=True)

    def _find_claude_dir(self) -> Path:
        """Find .claude directory."""
        current = Path.cwd()
        for _ in range(5):
            claude_dir = current / ".claude"
            if claude_dir.exists():
                return claude_dir
            current = current.parent
        base = Path.cwd() / ".claude"
        base.mkdir(parents=True, exist_ok=True)
        return base

    def set_mission(self, mission: str):
        """Set the exploration mission."""
        self.mission = mission
        self.findings = []
        self.blocked_sites = []
        self.pending_review = []

        # Store mission in memory
        self.memory.store(
            f"mission_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            {"mission": mission, "started": datetime.now().isoformat()},
            self.MemoryType.LONG_TERM
        )

        print(f"\n🎯 Mission: {mission}")
        print("=" * 60)

    def explore_url(self, url: str, reason: str = "") -> dict:
        """
        Explore a URL with full Guardian protection.

        Returns:
            {
                "status": "visited" | "blocked" | "pending_review" | "error",
                "url": str,
                "content": str | None,
                "summary": str,
                "threats": list,
                "risk_level": str,
            }
        """
        import urllib.request
        import ssl

        if not url.startswith("http"):
            url = f"https://{url}"

        if url in self.visited:
            return {"status": "already_visited", "url": url}

        result = {
            "url": url,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "status": None,
            "content": None,
            "summary": None,
            "threats": [],
            "risk_level": None,
        }

        print(f"\n🔍 Exploring: {url}")
        if reason:
            print(f"   Reason: {reason}")

        # Step 1: Pre-scan
        print("   [1/4] Pre-scanning...")
        scan = self.scanner.scan(url, deep_scan=False)
        result["risk_level"] = scan.risk_level
        result["threats"] = [t.get("detail", str(t)) for t in scan.threats_found]

        # Decision based on risk
        if scan.risk_level == "CRITICAL":
            print(f"   🚫 BLOCKED - Risk: CRITICAL")
            result["status"] = "blocked"
            result["summary"] = f"Site blocked due to critical threats: {result['threats'][:2]}"
            self.blocked_sites.append(result)
            self.visited.add(url)
            return result

        if scan.risk_level == "HIGH":
            print(f"   ⏸️  PENDING REVIEW - Risk: HIGH")
            result["status"] = "pending_review"
            result["summary"] = f"Site requires guardian review: {result['threats'][:2]}"
            self.pending_review.append(result)
            self.visited.add(url)
            return result

        # Step 2: Fetch content
        print("   [2/4] Fetching content...")
        try:
            context = ssl.create_default_context()
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "ClaudeExplorer/1.0 (Guardian Protected)"}
            )
            with urllib.request.urlopen(request, timeout=15, context=context) as response:
                raw_content = response.read(100000).decode('utf-8', errors='replace')
        except Exception as e:
            print(f"   ❌ Fetch error: {e}")
            result["status"] = "error"
            result["summary"] = f"Could not fetch: {str(e)[:50]}"
            return result

        # Step 3: Sanitize content
        print("   [3/4] Sanitizing content...")
        sanitized = self.sanitizer.sanitize_for_claude(raw_content, url, "html")

        if not sanitized["is_safe"]:
            print(f"   ⚠️  Content threats detected: {sanitized['threat_level']}")
            result["threats"].extend(sanitized["threat_summary"]["threat_types"])

        result["content"] = sanitized["content"][:5000]  # Limit size

        # Step 4: Deep threat scan
        print("   [4/4] Deep threat scan...")
        is_safe, matches = self.threats.scan(sanitized["content"][:2000], url)
        if matches:
            print(f"   ⚠️  Found {len(matches)} threat signatures")
            for m in matches[:3]:
                result["threats"].append(m.get("description", m.get("signature_name")))

        # Success
        print(f"   ✅ Visited successfully (Risk: {scan.risk_level})")
        result["status"] = "visited"
        result["summary"] = self._summarize_content(sanitized["content"][:2000])

        self.findings.append(result)
        self.visited.add(url)

        return result

    def _summarize_content(self, content: str) -> str:
        """Create a brief summary of content."""
        # Simple summarization - first meaningful sentences
        lines = [l.strip() for l in content.split('\n') if l.strip() and len(l.strip()) > 20]
        summary = ' '.join(lines[:5])[:300]
        return summary if summary else "(No readable content)"

    def check_entity(self, entity: str, context: str = "") -> dict:
        """
        Check reputation of an entity before interacting.

        Returns reputation report with recommendation.
        """
        print(f"\n👤 Checking entity: {entity}")
        if context:
            print(f"   Context: {context}")

        report = self.reputation.check_reputation(entity)

        colors = {
            "TRUSTED": "\033[92m",
            "POSITIVE": "\033[92m",
            "NEUTRAL": "\033[93m",
            "SUSPICIOUS": "\033[91m",
            "UNKNOWN": "\033[90m",
        }
        reset = "\033[0m"
        color = colors.get(report.reputation_level, "")

        print(f"   Reputation: {color}{report.reputation_level}{reset} (Score: {report.reputation_score})")
        print(f"   Risk: {report.risk_level}")
        print(f"   Recommendation: {report.recommendation[:60]}...")

        return report.to_dict() if hasattr(report, 'to_dict') else {
            "entity": entity,
            "reputation_level": report.reputation_level,
            "risk_level": report.risk_level,
            "recommendation": report.recommendation,
            "requires_guardian": report.requires_guardian,
        }

    def remember(self, key: str, value: any):
        """Store something in tamper-proof memory."""
        self.memory.store(key, value, self.MemoryType.LONG_TERM)
        print(f"   💾 Remembered: {key}")

    def generate_report(self) -> dict:
        """Generate exploration report for guardian."""
        report = {
            "mission": self.mission,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "sites_visited": len(self.findings),
                "sites_blocked": len(self.blocked_sites),
                "pending_review": len(self.pending_review),
                "total_threats_found": sum(len(f.get("threats", [])) for f in self.findings + self.blocked_sites),
            },
            "findings": self.findings,
            "blocked_sites": self.blocked_sites,
            "needs_guardian_review": self.pending_review,
        }

        # Save report
        report_file = self.reports_path / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        return report

    def print_report(self):
        """Print a human-readable report."""
        report = self.generate_report()

        print("\n" + "=" * 60)
        print("📋 EXPLORATION REPORT")
        print("=" * 60)
        print(f"\n🎯 Mission: {report['mission']}")
        print(f"📅 Generated: {report['generated_at']}")

        print(f"\n📊 Summary:")
        print(f"   ✅ Sites visited: {report['summary']['sites_visited']}")
        print(f"   🚫 Sites blocked: {report['summary']['sites_blocked']}")
        print(f"   ⏸️  Pending review: {report['summary']['pending_review']}")
        print(f"   ⚠️  Total threats: {report['summary']['total_threats_found']}")

        if report['findings']:
            print(f"\n📝 Findings:")
            for i, f in enumerate(report['findings'][:10], 1):
                print(f"\n   {i}. {f['url'][:50]}")
                print(f"      Risk: {f['risk_level']}")
                if f.get('summary'):
                    print(f"      Summary: {f['summary'][:100]}...")

        if report['blocked_sites']:
            print(f"\n🚫 Blocked Sites:")
            for b in report['blocked_sites']:
                print(f"   - {b['url'][:50]}")
                print(f"     Reason: {', '.join(b.get('threats', [])[:2])}")

        if report['needs_guardian_review']:
            print(f"\n⏸️  NEEDS YOUR REVIEW:")
            for p in report['needs_guardian_review']:
                print(f"   - {p['url'][:50]}")
                print(f"     Risk: {p['risk_level']}")
                print(f"     Threats: {', '.join(p.get('threats', [])[:2])}")

        print("\n" + "=" * 60)
        print("Report saved to:", self.reports_path)

        return report


def interactive_mode():
    """Run in interactive mode."""
    print("=" * 60)
    print("🤖 Claude Autonomous Explorer")
    print("   Protected by Guardian Security System")
    print("=" * 60)

    explorer = AutonomousExplorer()

    print("\nCommands:")
    print("  mission <description>  - Set exploration mission")
    print("  visit <url>           - Visit a URL safely")
    print("  check <entity>        - Check entity reputation")
    print("  report                - Generate findings report")
    print("  quit                  - Exit")

    while True:
        try:
            cmd = input("\n🤖 claude> ").strip()
            if not cmd:
                continue

            parts = cmd.split(maxsplit=1)
            command = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if command == "quit":
                if explorer.findings:
                    explorer.print_report()
                print("👋 Goodbye!")
                break

            elif command == "mission":
                if not arg:
                    print("Usage: mission <description>")
                    continue
                explorer.set_mission(arg)

            elif command == "visit":
                if not arg:
                    print("Usage: visit <url>")
                    continue
                explorer.explore_url(arg)

            elif command == "check":
                if not arg:
                    print("Usage: check <entity>")
                    continue
                explorer.check_entity(arg)

            elif command == "report":
                explorer.print_report()

            else:
                print(f"Unknown command: {command}")

        except KeyboardInterrupt:
            print("\n")
            if explorer.findings:
                explorer.print_report()
            break
        except Exception as e:
            print(f"Error: {e}")


def automated_explore(mission: str, urls: list):
    """Run automated exploration with a mission."""
    explorer = AutonomousExplorer()
    explorer.set_mission(mission)

    for url in urls:
        explorer.explore_url(url, f"Part of mission: {mission[:30]}")

    return explorer.print_report()


def main():
    parser = argparse.ArgumentParser(description="Claude Autonomous Explorer")
    parser.add_argument("mission", nargs="?", help="Exploration mission")
    parser.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    parser.add_argument("--urls", nargs="*", help="URLs to explore")

    args = parser.parse_args()

    if args.interactive or not args.mission:
        interactive_mode()
    else:
        urls = args.urls or []
        if not urls:
            print("Provide URLs with --urls or use --interactive mode")
            return
        automated_explore(args.mission, urls)


if __name__ == "__main__":
    main()
