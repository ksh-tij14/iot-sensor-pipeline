"""Revoke (or restore) one sensor in the live keystore.

Takes effect immediately: the gateway, fork and validation re-read the keystore
when it changes, so a revoked device is refused (403 revoked_sensor) from its
next reading on - no restart needed.

Usage, from the repo root:
    python scripts/revoke_sensor.py esp32-002            # revoke
    python scripts/revoke_sensor.py esp32-002 --restore  # un-revoke
    python scripts/revoke_sensor.py --list
"""

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / "gateway" / "keystore.local.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("sensor_id", nargs="?")
    parser.add_argument("--restore", action="store_true", help="un-revoke instead")
    parser.add_argument("--list", action="store_true", help="show every sensor's status")
    parser.add_argument("--keystore", default=str(LOCAL), help="keystore file (default: the live one)")
    args = parser.parse_args()

    path = Path(args.keystore)
    if not path.exists():
        print(f"{path} not found - run scripts/rotate-keys.ps1 first.")
        return 1
    keystore = json.loads(path.read_text(encoding="utf-8"))

    if args.list or not args.sensor_id:
        for sid, entry in keystore.items():
            print(f"{sid:<12} {'REVOKED' if entry.get('revoked') else 'active'}")
        return 0
    if args.sensor_id not in keystore:
        print(f"Unknown sensor {args.sensor_id!r}. Known: {', '.join(keystore)}")
        return 1

    keystore[args.sensor_id]["revoked"] = not args.restore
    # Rewrite in place (same file), so Docker's file mount sees the change.
    with open(path, "r+", encoding="utf-8") as f:
        f.seek(0)
        f.write(json.dumps(keystore, indent=2) + "\n")
        f.truncate()
    print(f"{args.sensor_id} {'restored' if args.restore else 'REVOKED'} - effective immediately.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
