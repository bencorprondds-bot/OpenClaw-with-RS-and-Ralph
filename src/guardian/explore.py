#!/usr/bin/env python3
"""
Guardian Explorer - Let Claude safely browse the internet

This script lets you browse websites with full Guardian protection:
1. Pre-scans sites before visiting
2. Checks reputation of entities
3. Sanitizes content for threats
4. Logs all activity for guardian review

Usage:
    python explore.py

Commands:
    visit <url>      - Pre-scan and visit a website
    scan <url>       - Just pre-scan without visiting
    check <entity>   - Check reputation before interacting
    search <query>   - Search (shows what would happen)
    pending          - Show pending approvals
    log              - Show recent activity
    help             - Show commands
    quit             - Exit
"""

import sys
import os

# Add the guardian directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pathlib import Path
from datetime import datetime


def get_base_path():
    """Find .claude directory."""
    current = Path.cwd()
    for _ in range(5):
        claude_dir = current / ".claude"
        if claude_dir.exists():
            return str(claude_dir)
        current = current.parent

    # Create if doesn't exist
    base = Path.cwd() / ".claude"
    base.mkdir(parents=True, exist_ok=True)
    return str(base)


def main():
    print("=" * 70)
    print("🛡️  Guardian Explorer - Safe Internet Browsing for Claude")
    print("=" * 70)
    print()

    try:
        from site_scanner import SiteScanner
        from reputation_scanner import ReputationScanner
        from content_sanitizer import ContentSanitizer
        from threat_signatures import ThreatSignatureDB

        base_path = get_base_path()
        print(f"📁 Using: {base_path}")

        # Initialize components
        scanner = SiteScanner(base_path)
        reputation = ReputationScanner(base_path)
        sanitizer = ContentSanitizer()
        threats = ThreatSignatureDB(base_path)

        print("✓ Guardian systems initialized")
        print()
        print("Commands: visit, scan, check, pending, log, help, quit")
        print()

    except ImportError as e:
        print(f"Error: {e}")
        print("Make sure you're in the src/guardian directory")
        return

    while True:
        try:
            cmd = input("\n🌐 explore> ").strip()

            if not cmd:
                continue

            parts = cmd.split(maxsplit=1)
            command = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            # QUIT
            if command in ["quit", "exit", "q"]:
                print("👋 Goodbye!")
                break

            # HELP
            elif command == "help":
                print(__doc__)

            # VISIT - Pre-scan and fetch a URL
            elif command == "visit":
                if not arg:
                    print("Usage: visit <url>")
                    print("Example: visit https://en.wikipedia.org/wiki/AI")
                    continue

                url = arg if arg.startswith("http") else f"https://{arg}"
                print(f"\n🔍 Pre-scanning: {url}")

                # Step 1: Pre-scan
                result = scanner.scan(url, deep_scan=False)

                # Show risk level with colors
                colors = {
                    "LOW": "\033[92m",      # Green
                    "MEDIUM": "\033[93m",   # Yellow
                    "HIGH": "\033[91m",     # Red
                    "CRITICAL": "\033[95m", # Magenta
                }
                reset = "\033[0m"
                color = colors.get(result.risk_level, "")

                print(f"\n📊 Risk Level: {color}{result.risk_level}{reset} (Score: {result.risk_score})")

                if result.threats_found:
                    print(f"\n⚠️  Threats Detected ({len(result.threats_found)}):")
                    for t in result.threats_found[:5]:
                        print(f"   - [{t.get('severity', '?')}] {t.get('detail', 'Unknown')}")

                # Decision
                if result.risk_level == "CRITICAL":
                    print(f"\n🚫 BLOCKED - Site is dangerous, not visiting")
                    print(f"   Recommendations:")
                    for r in result.recommendations[:3]:
                        print(f"   - {r}")

                elif result.risk_level == "HIGH":
                    print(f"\n⏸️  PAUSED - Requires guardian approval")
                    print(f"   This site has HIGH risk indicators.")
                    print(f"   Guardian must approve before visiting.")

                    # Ask for manual override
                    override = input("\n   Override and visit anyway? (yes/no): ").strip().lower()
                    if override == "yes":
                        print(f"\n   ⚠️  Visiting with caution...")
                        _fetch_and_display(url, sanitizer, threats)
                    else:
                        print(f"   ✓ Good choice. Site not visited.")

                elif result.risk_level == "MEDIUM":
                    print(f"\n⚡ CAUTION - Proceeding with extra sanitization")
                    _fetch_and_display(url, sanitizer, threats)

                else:  # LOW
                    print(f"\n✅ SAFE - Proceeding normally")
                    _fetch_and_display(url, sanitizer, threats)

            # SCAN - Just pre-scan without visiting
            elif command == "scan":
                if not arg:
                    print("Usage: scan <url>")
                    continue

                url = arg if arg.startswith("http") else f"https://{arg}"
                print(f"\n🔍 Scanning: {url}")

                result = scanner.scan(url, deep_scan=True)

                colors = {
                    "LOW": "\033[92m",
                    "MEDIUM": "\033[93m",
                    "HIGH": "\033[91m",
                    "CRITICAL": "\033[95m",
                }
                reset = "\033[0m"
                color = colors.get(result.risk_level, "")

                print(f"\n📊 Results:")
                print(f"   Risk Level: {color}{result.risk_level}{reset}")
                print(f"   Risk Score: {result.risk_score}/100")
                print(f"   SSL Valid: {'✓' if result.ssl_info.get('is_valid') else '✗'}")
                print(f"   Safe to Visit: {'Yes' if result.is_safe else 'No'}")

                if result.threats_found:
                    print(f"\n⚠️  Threats ({len(result.threats_found)}):")
                    for t in result.threats_found[:5]:
                        print(f"   - [{t.get('severity', '?')}] {t.get('detail', 'Unknown')}")

                print(f"\n💡 Recommendations:")
                for r in result.recommendations:
                    print(f"   - {r}")

            # CHECK - Check reputation of an entity
            elif command == "check":
                if not arg:
                    print("Usage: check <email/username/domain>")
                    print("Example: check someone@example.com")
                    continue

                print(f"\n🔍 Checking reputation: {arg}")
                report = reputation.check_reputation(arg)

                rep_colors = {
                    "TRUSTED": "\033[92m",
                    "POSITIVE": "\033[92m",
                    "NEUTRAL": "\033[93m",
                    "SUSPICIOUS": "\033[91m",
                    "UNKNOWN": "\033[90m",
                }
                risk_colors = {
                    "LOW": "\033[92m",
                    "MEDIUM": "\033[93m",
                    "HIGH": "\033[91m",
                    "CRITICAL": "\033[95m",
                }
                reset = "\033[0m"

                rep_color = rep_colors.get(report.reputation_level, "")
                risk_color = risk_colors.get(report.risk_level, "")

                print(f"\n📊 Reputation: {rep_color}{report.reputation_level}{reset} (Score: {report.reputation_score})")
                print(f"   Risk Level: {risk_color}{report.risk_level}{reset}")
                print(f"   Confidence: {report.confidence:.0%}")

                if report.red_flags:
                    print(f"\n🚩 Red Flags:")
                    for flag in report.red_flags[:5]:
                        print(f"   - [{flag.get('severity', '?')}] {flag.get('detail', 'Unknown')}")

                if report.positive_signals:
                    print(f"\n✓ Positive Signals:")
                    for signal in report.positive_signals[:3]:
                        print(f"   + {signal.get('detail', 'Unknown')}")

                print(f"\n💡 Recommendation: {report.recommendation}")
                print(f"   Requires Guardian: {'Yes' if report.requires_guardian else 'No'}")

            # PENDING - Show pending approvals
            elif command == "pending":
                queue_path = Path(base_path) / "approval_queue"
                if not queue_path.exists():
                    print("\n📭 No pending approvals")
                    continue

                pending = list(queue_path.glob("*.json"))
                if not pending:
                    print("\n📭 No pending approvals")
                else:
                    print(f"\n📬 Pending Approvals ({len(pending)}):")
                    import json
                    for p in pending[:10]:
                        try:
                            with open(p) as f:
                                data = json.load(f)
                            print(f"   - {p.stem}: {data.get('action', '?')} → {data.get('target', '?')[:40]}")
                        except:
                            print(f"   - {p.stem}: (error reading)")

            # LOG - Show recent activity
            elif command == "log":
                print(f"\n📜 Recent Activity:")
                print(f"   Scanner: {scanner.stats}")
                print(f"   Reputation: {reputation.stats}")

            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for available commands")

        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")


def _fetch_and_display(url: str, sanitizer, threats):
    """Fetch URL and display sanitized content."""
    import urllib.request
    import ssl

    try:
        context = ssl.create_default_context()
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "ClaudeGuardian/1.0"}
        )

        print(f"\n📥 Fetching content...")

        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            content = response.read(50000).decode('utf-8', errors='replace')

        # Sanitize
        result = sanitizer.sanitize_for_claude(content, url, "html")

        if not result["is_safe"]:
            print(f"\n⚠️  Content has threats: {result['threat_summary']['threat_types']}")
            print(f"   Threat Level: {result['threat_level']}")

        # Show preview
        preview = result["content"][:500] if result["content"] else "(no content)"
        print(f"\n📄 Content Preview:")
        print("-" * 50)
        print(preview.replace('\n', ' ')[:500])
        print("-" * 50)
        print(f"\n   Total length: {len(result['content'])} chars")

    except Exception as e:
        print(f"\n❌ Fetch error: {e}")


if __name__ == "__main__":
    main()
