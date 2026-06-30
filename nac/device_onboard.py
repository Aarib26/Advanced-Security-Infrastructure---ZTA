#!/usr/bin/env python3
"""
ZTA Device Onboarding Simulator
Simulates: device presents → RADIUS auth → posture check → access decision
"""
import subprocess
import json
import datetime
import sys

DEVICES = {
    "laptop-alice-001": {
        "password": "compliant-cert-xyz",
        "os_version": "Ubuntu 24.04",
        "patch_level": "current",
        "disk_encrypted": True,
        "av_status": "active",
        "expected": "COMPLIANT"
    },
    "laptop-old-002": {
        "password": "old-device-cert",
        "os_version": "Ubuntu 18.04",
        "patch_level": "outdated",
        "disk_encrypted": False,
        "av_status": "inactive",
        "expected": "NON-COMPLIANT"
    },
    "iot-sensor-003": {
        "password": "iot-device-key",
        "os_version": "embedded-linux",
        "patch_level": "unknown",
        "disk_encrypted": False,
        "av_status": "none",
        "expected": "IOT-RESTRICTED"
    }
}

def check_posture(device_id, device_info):
    """Simulate osquery-style posture evaluation."""
    issues = []
    score = 100
    
    if device_info["patch_level"] != "current":
        issues.append("OS patches outdated")
        score -= 30
    if not device_info["disk_encrypted"]:
        issues.append("Disk encryption disabled")
        score -= 25
    if device_info["av_status"] != "active":
        issues.append("AV not active")
        score -= 20
    
    return score, issues

def radius_auth(device_id, password):
    """Run actual radtest against FreeRADIUS."""
    result = subprocess.run(
        ["radtest", device_id, password, "localhost", "0", "testing123"],
        capture_output=True, text=True, timeout=5
    )
    return "Access-Accept" in result.stdout

def onboard_device(device_id):
    device = DEVICES.get(device_id)
    if not device:
        print(f"Unknown device: {device_id}")
        return

    print(f"\n{'='*60}")
    print(f"DEVICE ONBOARDING: {device_id}")
    print(f"{'='*60}")
    print(f"Timestamp: {datetime.datetime.utcnow().isoformat()}Z")
    print(f"OS: {device['os_version']}")

    # Step 1: RADIUS authentication
    print(f"\n[STEP 1] FreeRADIUS 802.1X Authentication...")
    auth_ok = radius_auth(device_id, device["password"])
    print(f"  Result: {'Access-Accept ✓' if auth_ok else 'Access-Reject ✗'}")

    if not auth_ok:
        print(f"  → Device BLOCKED at authentication layer")
        print(f"  → No further posture checks performed")
        return

    # Step 2: Posture evaluation (osquery simulation)
    print(f"\n[STEP 2] Posture Evaluation (osquery agent)...")
    score, issues = check_posture(device_id, device)
    print(f"  Posture Score: {score}/100")
    if issues:
        for issue in issues:
            print(f"  ⚠ {issue}")

    # Step 3: Access decision
    # Step 3: Access decision
    print(f"\n[STEP 3] Access Decision...")
    if device.get("os_version") == "embedded-linux":
        decision = "IOT-RESTRICTED — Isolated IoT segment, limited egress only"
        pomerium_tier = "iot-restricted"
    elif score >= 70:
        decision = "FULL ACCESS — Corporate network segment"
        pomerium_tier = "standard"
    elif score >= 40:
        decision = "LIMITED ACCESS — Step-up MFA required, restricted routes"
        pomerium_tier = "restricted"
    else:
        decision = "REMEDIATION — Isolated segment, SOC notified"
        pomerium_tier = "blocked"
    print(f"  Decision: {decision}")
    print(f"  Pomerium tier: {pomerium_tier}")
    print(f"  Expected: {device['expected']}")

    # Log to file for ES ingestion
    log_entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "device_id": device_id,
        "auth_result": "accept" if auth_ok else "reject",
        "posture_score": score,
        "posture_issues": issues,
        "access_decision": pomerium_tier,
        "event_type": "device_onboard"
    }
    with open("/var/log/zta-nac.log", "a") as f:
        f.write(json.dumps(log_entry) + "\n")
    print(f"\n  Logged to /var/log/zta-nac.log")

if __name__ == "__main__":
    print("ZTA Device Onboarding System — Live Demonstration")
    print("Testing three device profiles:\n")
    for device_id in DEVICES:
        onboard_device(device_id)
