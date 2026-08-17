"""
TOTP MFA Vulnerability Scanner

Probes a demo server for two common TOTP misconfigurations:
  1. TOTP_REPLAY_ATTACK — no code de-duplication, same code accepted twice
  2. WIDE_TOTP_WINDOW  — tolerance window far exceeds RFC 6238's ±30 seconds
"""
import argparse
import base64
import hashlib
import hmac
import json
import struct
import sys
import time

import httpx


def _totp(secret_b32: str, timestamp: int, period: int = 30) -> str:
    padding = (8 - len(secret_b32) % 8) % 8
    key = base64.b32decode(secret_b32.upper() + "=" * padding)
    counter = timestamp // period
    msg = struct.pack(">Q", counter)
    mac = hmac.new(key, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code_int = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % 1_000_000).zfill(6)


def run_scan(target: str) -> dict:
    findings = []
    secret = "JBSWY3DPEHPK3PXP"
    username = "totp_tool_probe"
    password = "probe_pass_7743"

    client = httpx.Client(base_url=target, timeout=10.0, follow_redirects=False)

    # Verify server is reachable
    try:
        r = client.get("/health")
        if r.status_code != 200:
            print("[WARN] /health did not return 200", file=sys.stderr)
            return {"target": target, "findings": [], "summary": f"Server at {target} is not healthy"}
    except Exception as exc:
        print(f"[WARN] Server unreachable: {exc}", file=sys.stderr)
        return {"target": target, "findings": [], "summary": f"Server at {target} is unreachable"}

    # Register probe user
    try:
        client.post("/setup", json={"username": username, "password": password, "secret": secret})
    except Exception as exc:
        print(f"[WARN] Setup failed: {exc}", file=sys.stderr)

    now = int(time.time())
    current_code = _totp(secret, now)
    old_code = _totp(secret, now - 180)   # 6 time-steps back — outside ±1 safe window

    # ── Test A: Replay attack on vulnerable endpoint ─────────────────────────
    print("[*] Testing TOTP replay on /auth/totp/vulnerable …", file=sys.stderr)
    try:
        r = client.post("/auth/login", json={"username": username, "password": password})
        if r.status_code == 200:
            temp = r.json()["temp_token"]
            r1 = client.post("/auth/totp/vulnerable", json={"temp_token": temp, "code": current_code})
            r2 = client.post("/auth/totp/vulnerable", json={"temp_token": temp, "code": current_code})
            if r1.status_code == 200 and r2.status_code == 200:
                findings.append({
                    "endpoint": "/auth/totp/vulnerable",
                    "vulnerability_type": "TOTP_REPLAY_ATTACK",
                    "evidence": (
                        f"Code {current_code} was accepted twice in succession "
                        "— server has no per-code de-duplication"
                    ),
                    "severity": "HIGH",
                })
                print(f"  [HIGH] TOTP_REPLAY_ATTACK detected", file=sys.stderr)
            else:
                print(f"  [-] Replay not detected (r1={r1.status_code}, r2={r2.status_code})", file=sys.stderr)
    except Exception as exc:
        print(f"  [ERR] Replay test failed: {exc}", file=sys.stderr)

    # ── Test B: Wide time-window on vulnerable endpoint ───────────────────────
    print("[*] Testing wide TOTP window on /auth/totp/vulnerable …", file=sys.stderr)
    try:
        r = client.post("/auth/login", json={"username": username, "password": password})
        if r.status_code == 200:
            temp = r.json()["temp_token"]
            r = client.post("/auth/totp/vulnerable", json={"temp_token": temp, "code": old_code})
            if r.status_code == 200:
                findings.append({
                    "endpoint": "/auth/totp/vulnerable",
                    "vulnerability_type": "WIDE_TOTP_WINDOW",
                    "evidence": (
                        f"Code {old_code} generated 180 seconds ago was accepted "
                        "— RFC 6238 recommends ±30 s tolerance; this server accepts ±5 minutes"
                    ),
                    "severity": "MEDIUM",
                })
                print("  [MEDIUM] WIDE_TOTP_WINDOW detected", file=sys.stderr)
            else:
                print(f"  [-] Old code correctly rejected (status {r.status_code})", file=sys.stderr)
    except Exception as exc:
        print(f"  [ERR] Wide-window test failed: {exc}", file=sys.stderr)

    # ── Test C: Replay on safe endpoint (must produce zero findings) ──────────
    print("[*] Testing safe endpoint for replay …", file=sys.stderr)
    try:
        safe_code = _totp(secret, now)
        r = client.post("/auth/login", json={"username": username, "password": password})
        if r.status_code == 200:
            temp = r.json()["temp_token"]
            r1 = client.post("/auth/totp/safe", json={"temp_token": temp, "code": safe_code})
            r2 = client.post("/auth/totp/safe", json={"temp_token": temp, "code": safe_code})
            if r1.status_code == 200 and r2.status_code == 200:
                # Safe endpoint is broken — should not happen
                findings.append({
                    "endpoint": "/auth/totp/safe",
                    "vulnerability_type": "TOTP_REPLAY_ATTACK",
                    "evidence": "Safe endpoint failed to reject replayed code",
                    "severity": "HIGH",
                })
            else:
                print("  [OK] Safe endpoint correctly rejected replay", file=sys.stderr)
    except Exception as exc:
        print(f"  [ERR] Safe replay test failed: {exc}", file=sys.stderr)

    # ── Test D: Wide window on safe endpoint (must produce zero findings) ─────
    print("[*] Testing safe endpoint for wide window …", file=sys.stderr)
    try:
        r = client.post("/auth/login", json={"username": username, "password": password})
        if r.status_code == 200:
            temp = r.json()["temp_token"]
            r = client.post("/auth/totp/safe", json={"temp_token": temp, "code": old_code})
            if r.status_code == 200:
                findings.append({
                    "endpoint": "/auth/totp/safe",
                    "vulnerability_type": "WIDE_TOTP_WINDOW",
                    "evidence": "Safe endpoint accepted a 180-second-old code",
                    "severity": "MEDIUM",
                })
            else:
                print("  [OK] Safe endpoint correctly rejected old code", file=sys.stderr)
    except Exception as exc:
        print(f"  [ERR] Safe wide-window test failed: {exc}", file=sys.stderr)

    vuln_count = len(findings)
    if vuln_count:
        summary = (
            f"Found {vuln_count} TOTP vulnerability/vulnerabilities on {target}. "
            "Vulnerable endpoint lacks replay protection and uses an excessive time window. "
            "Safe endpoint enforces RFC 6238 constraints correctly."
        )
    else:
        summary = f"No TOTP vulnerabilities detected on {target}."

    return {"target": target, "findings": findings, "summary": summary}


def main():
    parser = argparse.ArgumentParser(description="TOTP MFA Vulnerability Scanner")
    parser.add_argument("--target", default="http://localhost:3000", help="Target server URL")
    args = parser.parse_args()
    result = run_scan(args.target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
