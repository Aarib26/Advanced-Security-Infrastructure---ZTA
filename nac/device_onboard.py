#!/usr/bin/env python3
"""
device_onboard.py — dynamic ZTA NAC onboarding.

Replaces the old device_onboard.py (hardcoded 3-device DEVICES dict). This
version has NO hardcoded device list — it runs as a FreeRADIUS post-auth
hook (or standalone for testing) against whatever device just authenticated,
and posture is assessed at whatever depth is actually possible for that
device:

  Tier 1 (real posture) — device has a trusted SSH key already provisioned
    in ~/.ssh/zta_managed/<ip-or-hostname>.key (e.g. RoadmapLabs). Pulls
    real posture: OS info, patch-management presence, disk encryption
    status where checkable.

  Tier 2 (auth-only) — device authenticated via FreeRADIUS but has no SSH
    trust relationship (BYOD, IoT). The only honest signal is "did 802.1X
    pass", plus a MAC OUI hint. This is the correct permanent behavior for
    untrusted devices, not a placeholder — a NAC system that could fully
    inspect an unmanaged BYOD phone's internals wouldn't be zero trust.

Keeps the same log_entry shape as the old script (timestamp, device_id,
auth_result, posture_score, posture_issues, access_decision, event_type)
so anything already expecting that format (Logstash filters, dashboards)
doesn't need to change — just the SOURCE of the values is now real/dynamic
instead of a hardcoded dict lookup.

Usage as a FreeRADIUS post-auth hook:
    python3 device_onboard.py --device-id <Calling-Station-Id or username> \
        --ip <Framed-IP-Address> --auth-result accept

Usage standalone for testing (runs actual radtest, same as old script):
    python3 device_onboard.py --device-id laptop-alice-001 --password <pw> --test-radius

Environment:
    ZTA_NAC_LOG        default /var/log/zta-nac.log
    ZTA_SSH_KEY_DIR    default ~/.ssh/zta_managed/
"""

import argparse
import json
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

NAC_LOG_PATH = os.environ.get("ZTA_NAC_LOG", "/var/log/zta-nac.log")
SSH_KEY_DIR = Path(os.environ.get("ZTA_SSH_KEY_DIR", str(Path.home() / ".ssh" / "zta_managed")))
SSH_TIMEOUT_SECONDS = 5


def radius_auth(device_id: str, password: str) -> bool:
    """Same radtest invocation as the old script — kept identical since it
    already worked correctly."""
    try:
        result = subprocess.run(
            ["radtest", device_id, password, "localhost", "0", "testing123"],
            capture_output=True, text=True, timeout=5
        )
        return "Access-Accept" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"radtest failed: {e}", file=sys.stderr)
        return False


def find_ssh_key_for(ip_or_host: str) -> Path | None:
    """No hardcoded device list — whatever keys exist in SSH_KEY_DIR define
    the managed (Tier 1) fleet. Add a key file, that device becomes Tier 1;
    remove it, it falls back to Tier 2. No code change needed either way."""
    if not ip_or_host or not SSH_KEY_DIR.is_dir():
        return None
    candidate = SSH_KEY_DIR / f"{ip_or_host}.key"
    return candidate if candidate.is_file() else None


def collect_posture_ssh(ip_or_host: str, key_path: Path) -> tuple[int, list[str]]:
    """Real posture pull over SSH for Tier 1 devices. Returns (score, issues)
    in the same shape the old check_posture() used, so downstream consumers
    of posture_score/posture_issues don't need to change."""
    remote_cmd = (
        "cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION)=' ; "
        "(which unattended-upgrades >/dev/null 2>&1 && echo PATCH_MGMT=yes || echo PATCH_MGMT=no) ; "
        "(lsblk -o NAME,FSTYPE 2>/dev/null | grep -qi crypto_LUKS && echo DISK_ENCRYPTED=yes || echo DISK_ENCRYPTED=no)"
    )
    try:
        result = subprocess.run(
            [
                "ssh", "-i", str(key_path),
                "-o", "BatchMode=yes",
                "-o", f"ConnectTimeout={SSH_TIMEOUT_SECONDS}",
                "-o", "StrictHostKeyChecking=accept-new",
                ip_or_host, remote_cmd,
            ],
            capture_output=True, text=True, timeout=SSH_TIMEOUT_SECONDS + 3,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return 0, [f"SSH posture check failed: {e}"]

    if result.returncode != 0:
        return 0, [f"SSH reachable but posture command failed: {result.stderr.strip()[:200]}"]

    output = result.stdout
    score = 100
    issues = []

    if "PATCH_MGMT=no" in output:
        issues.append("No patch-management tooling detected")
        score -= 30
    if "DISK_ENCRYPTED=no" in output:
        issues.append("Disk encryption not detected")
        score -= 25
    # AV status has no reliable cross-distro check without an agent — left
    # out rather than faked; note this honestly rather than hardcoding a
    # score deduction for a signal we can't actually observe.

    return score, issues


def mac_oui_hint(mac: str) -> str:
    """Soft device-type hint only — never treated as a posture signal."""
    return mac.upper().replace("-", ":")[:8] if mac else "unknown"


def onboard(device_id: str, ip: str, mac: str, auth_ok: bool) -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()

    print(f"\n{'='*60}")
    print(f"DEVICE ONBOARDING: {device_id}")
    print(f"{'='*60}")
    print(f"Timestamp: {timestamp}")

    print(f"\n[STEP 1] FreeRADIUS 802.1X Authentication...")
    print(f"  Result: {'Access-Accept' if auth_ok else 'Access-Reject'}")

    if not auth_ok:
        print(f"  -> Device BLOCKED at authentication layer")
        print(f"  -> No further posture checks performed")
        return {
            "timestamp": timestamp,
            "device_id": device_id,
            "ip": ip,
            "auth_result": "reject",
            "posture_score": None,
            "posture_issues": [],
            "access_decision": "blocked",
            "event_type": "device_onboard",
        }

    print(f"\n[STEP 2] Posture Evaluation...")
    key = find_ssh_key_for(ip)
    hostname = None
    if key is None:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            key = find_ssh_key_for(hostname)
        except (socket.herror, socket.gaierror, OSError):
            hostname = None

    if key is not None:
        posture_tier = "full"
        score, issues = collect_posture_ssh(hostname or ip, key)
        print(f"  Tier: full (SSH-verified)")
        print(f"  Posture Score: {score}/100")
        for issue in issues:
            print(f"  - {issue}")
    else:
        posture_tier = "auth_only"
        score = None
        issues = [f"No SSH trust relationship — auth-only posture (MAC OUI: {mac_oui_hint(mac)})"]
        print(f"  Tier: auth_only (no SSH trust relationship — BYOD/IoT)")
        print(f"  MAC OUI hint: {mac_oui_hint(mac)}")

    print(f"\n[STEP 3] Access Decision...")
    if posture_tier == "auth_only":
        decision = "LIMITED ACCESS — auth-only tier, restricted routes"
        pomerium_tier = "restricted"
    elif score is not None and score >= 70:
        decision = "FULL ACCESS — posture-verified"
        pomerium_tier = "standard"
    elif score is not None and score >= 40:
        decision = "LIMITED ACCESS — step-up MFA required, restricted routes"
        pomerium_tier = "restricted"
    else:
        decision = "REMEDIATION — isolated segment, SOC notified"
        pomerium_tier = "blocked"

    print(f"  Decision: {decision}")
    print(f"  Pomerium tier: {pomerium_tier}")

    return {
        "timestamp": timestamp,
        "device_id": device_id,
        "ip": ip,
        "mac": mac,
        "auth_result": "accept",
        "posture_tier": posture_tier,
        "posture_score": score,
        "posture_issues": issues,
        "access_decision": pomerium_tier,
        "event_type": "device_onboard",
    }


def write_log(record: dict):
    with open(NAC_LOG_PATH, "a") as f:
        f.write(json.dumps(record) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Dynamic ZTA NAC onboarding")
    parser.add_argument("--device-id", required=True, help="Device/username identifier")
    parser.add_argument("--ip", default="", help="Device IP address (post-auth, for posture tier lookup)")
    parser.add_argument("--mac", default="", help="Device MAC address (for OUI hint on Tier 2 devices)")
    parser.add_argument("--auth-result", choices=["accept", "reject"],
                         help="Pre-determined FreeRADIUS auth outcome (use this when called from a post-auth hook)")
    parser.add_argument("--password", default=None,
                         help="Only used with --test-radius, to run a live radtest instead of trusting --auth-result")
    parser.add_argument("--test-radius", action="store_true",
                         help="Run actual radtest against FreeRADIUS instead of trusting --auth-result")
    args = parser.parse_args()

    if args.test_radius:
        if not args.password:
            print("ERROR: --test-radius requires --password", file=sys.stderr)
            sys.exit(1)
        auth_ok = radius_auth(args.device_id, args.password)
    elif args.auth_result:
        auth_ok = args.auth_result == "accept"
    else:
        print("ERROR: supply either --auth-result (from a RADIUS hook) or --test-radius --password (standalone test)", file=sys.stderr)
        sys.exit(1)

    record = onboard(args.device_id, args.ip, args.mac, auth_ok)

    try:
        write_log(record)
        print(f"\n  Logged to {NAC_LOG_PATH}")
    except PermissionError:
        print(f"ERROR: cannot write to {NAC_LOG_PATH} — run with sudo or fix permissions", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
