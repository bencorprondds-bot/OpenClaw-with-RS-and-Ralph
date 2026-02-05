#!/usr/bin/env python3
"""
Interactive Guardian Test Script

This script lets you test the Guardian security system interactively.
Run it with: python test_guardian.py

Available commands:
  scan <url>       - Pre-scan a website before visiting
  browse <url>     - Browse a URL with full security checks
  reputation <entity> - Check reputation of a user/agent
  remember <key> <value> - Store something in memory
  recall <key>     - Retrieve from memory
  verify           - Verify memory integrity
  status           - Show pending approvals
  help             - Show this help
  quit             - Exit
"""

import sys
import os

# Add the guardian directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pathlib import Path


def main():
    print("=" * 70)
    print("Guardian Security System - Interactive Test")
    print("=" * 70)
    print()

    # Initialize Guardian
    try:
        # Import components individually to avoid circular import issues
        from content_sanitizer import ContentSanitizer
        from threat_signatures import ThreatSignatureDB
        from reputation_scanner import ReputationScanner
        from distributed_memory import DistributedMemory, MemoryType

        # Find .claude directory
        base_path = None
        current = Path.cwd()
        for _ in range(5):
            claude_dir = current / ".claude"
            if claude_dir.exists():
                base_path = str(claude_dir)
                break
            current = current.parent

        if not base_path:
            base_path = str(Path.cwd() / ".claude")
            Path(base_path).mkdir(parents=True, exist_ok=True)

        print(f"Using .claude directory: {base_path}")
        print()

        # Initialize components
        sanitizer = ContentSanitizer()
        threats_db = ThreatSignatureDB(base_path)
        reputation = ReputationScanner(base_path)
        memory = DistributedMemory(base_path)

        print("Components initialized successfully!")
        print()
        print("Commands: scan, threat, reputation, remember, recall, verify, help, quit")
        print()

    except ImportError as e:
        print(f"Error importing modules: {e}")
        print("Make sure you're running from the src/guardian directory")
        return

    while True:
        try:
            cmd = input("\nguardian> ").strip()

            if not cmd:
                continue

            parts = cmd.split(maxsplit=2)
            command = parts[0].lower()

            # QUIT
            if command in ["quit", "exit", "q"]:
                print("Goodbye!")
                break

            # HELP
            elif command == "help":
                print(__doc__)

            # SCAN content for threats
            elif command == "scan":
                if len(parts) < 2:
                    print("Usage: scan <text to scan>")
                    continue

                text = " ".join(parts[1:])
                print(f"\nScanning: {text[:50]}...")

                # Use sanitizer
                result = sanitizer.sanitize_for_claude(text, "test", "text")
                print(f"\nIs Safe: {result['is_safe']}")
                print(f"Threat Level: {result['threat_level']}")

                if not result['is_safe']:
                    print(f"Threats Found: {result['threat_summary']['threat_types']}")

            # THREAT - Deep scan with signature database
            elif command == "threat":
                if len(parts) < 2:
                    print("Usage: threat <text to scan>")
                    continue

                text = " ".join(parts[1:])
                print(f"\nDeep scanning: {text[:50]}...")

                is_safe, matches = threats_db.scan(text, "test")
                print(f"\nIs Safe: {is_safe}")
                print(f"Matches Found: {len(matches)}")

                for match in matches[:5]:
                    print(f"  - [{match['severity']}] {match['signature_name']}: {match['description']}")

            # REPUTATION check
            elif command in ["reputation", "rep", "check"]:
                if len(parts) < 2:
                    print("Usage: reputation <email/username/domain>")
                    continue

                entity = parts[1]
                print(f"\nChecking reputation of: {entity}")

                report = reputation.check_reputation(entity)

                # Color coding for terminal
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

                print(f"\nReputation: {rep_color}{report.reputation_level}{reset} (Score: {report.reputation_score})")
                print(f"Risk Level: {risk_color}{report.risk_level}{reset}")
                print(f"Confidence: {report.confidence:.0%}")

                if report.red_flags:
                    print(f"\nRed Flags ({len(report.red_flags)}):")
                    for flag in report.red_flags[:3]:
                        print(f"  [!] [{flag.get('severity', '?')}] {flag.get('detail', 'Unknown')}")

                if report.positive_signals:
                    print(f"\nPositive Signals ({len(report.positive_signals)}):")
                    for signal in report.positive_signals[:3]:
                        print(f"  [+] {signal.get('detail', 'Unknown')}")

                print(f"\nRecommendation: {report.recommendation}")
                print(f"Requires Guardian: {'Yes' if report.requires_guardian else 'No'}")

            # REMEMBER - Store in memory
            elif command == "remember":
                if len(parts) < 3:
                    print("Usage: remember <key> <value>")
                    continue

                key = parts[1]
                value = parts[2]

                entry = memory.store(key, value, MemoryType.WORKING)
                print(f"\n[OK] Stored: {key}")
                print(f"  Entry ID: {entry.id}")
                print(f"  Hash: {entry.current_hash[:32]}...")
                print(f"  Signed: {entry.signature is not None}")

            # RECALL - Retrieve from memory
            elif command == "recall":
                if len(parts) < 2:
                    print("Usage: recall <key>")
                    continue

                key = parts[1]
                content, is_valid = memory.retrieve(key)

                if content is None:
                    print(f"\n[X] Key '{key}' not found in memory")
                else:
                    validity = "\033[92m[OK] Valid\033[0m" if is_valid else "\033[91m[X] TAMPERED!\033[0m"
                    print(f"\n{validity}")
                    print(f"  Content: {content}")

            # VERIFY - Check memory integrity
            elif command == "verify":
                print("\nVerifying memory chain integrity...")
                report = memory.verify_integrity()

                if report.is_valid:
                    print(f"\n\033[92m[OK] Memory chain is VALID\033[0m")
                else:
                    print(f"\n\033[91m[X] Memory chain has been TAMPERED WITH!\033[0m")
                    print(f"  Tampered entries: {report.tampered_entries}")

                print(f"  Chain length: {report.chain_length}")
                print(f"  Anchor hash: {report.anchor_hash[:32]}...")

            # STATUS
            elif command == "status":
                print("\nGuardian Status:")
                print(f"  Memory entries: {memory.chain_state['chain_length']}")
                print(f"  Threat signatures: {len(threats_db.signatures)}")
                print(f"  Reputation scans: {reputation.stats['scans_performed']}")

            # ANCHOR - Create external anchor
            elif command == "anchor":
                anchor = memory.create_anchor()
                print("\nCreated Memory Anchor:")
                print(f"  Hash: {anchor['anchor_hash'][:32]}...")
                print(f"  Signature: {anchor['guardian_signature'][:32]}...")
                print(f"  Chain length: {anchor['chain_length']}")
                print("\n  This hash can be stored on blockchain/IPFS for external verification")

            else:
                print(f"Unknown command: {command}")
                print("Type 'help' for available commands")

        except KeyboardInterrupt:
            print("\n\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    main()
