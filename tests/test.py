"""
TOTP MFA Demo — test suite
Covers: server health, true positives, false positives, output format, edge cases.
"""
import base64
import hashlib
import hmac as hmac_mod
import json
import struct
import subprocess
import sys
import time

import httpx
import pytest

sys.path.insert(0, "..")
from server.main import app, start

BASE_URL = None
_server = None

TEST_SECRET = "JBSWY3DPEHPK3PXP"
TEST_USER = "test_suite_user"
TEST_PASS = "suite_pass_9182"


def _totp(secret_b32: str, timestamp: int, period: int = 30) -> str:
    padding = (8 - len(secret_b32) % 8) % 8
    key = base64.b32decode(secret_b32.upper() + "=" * padding)
    counter = timestamp // period
    msg = struct.pack(">Q", counter)
    mac = hmac_mod.new(key, msg, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code_int = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % 1_000_000).zfill(6)


def current_code() -> str:
    return _totp(TEST_SECRET, int(time.time()))


def old_code() -> str:
    return _totp(TEST_SECRET, int(time.time()) - 180)


@pytest.fixture(scope="session", autouse=True)
def run_server():
    global BASE_URL, _server
    port = 3457
    BASE_URL = f"http://127.0.0.1:{port}"
    _server = start(port)
    httpx.post(f"{BASE_URL}/setup", json={"username": TEST_USER, "password": TEST_PASS, "secret": TEST_SECRET})
    yield
    _server.should_exit = True


def get_temp_token() -> str:
    r = httpx.post(f"{BASE_URL}/auth/login", json={"username": TEST_USER, "password": TEST_PASS})
    assert r.status_code == 200
    return r.json()["temp_token"]


def run_tool() -> dict:
    out = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", BASE_URL],
        capture_output=True,
        text=True,
        cwd=".",
        stdin=subprocess.DEVNULL,
    )
    return json.loads(out.stdout)


# ── Group 1: Server health ────────────────────────────────────────────────────

def test_health_status_200():
    r = httpx.get(f"{BASE_URL}/health")
    assert r.status_code == 200


def test_health_returns_ok():
    r = httpx.get(f"{BASE_URL}/health")
    assert r.json()["status"] == "ok"


def test_vulnerable_endpoint_reachable():
    r = httpx.post(f"{BASE_URL}/auth/totp/vulnerable", json={"temp_token": "x", "code": "000000"})
    assert r.status_code in (401, 422)


def test_safe_endpoint_reachable():
    r = httpx.post(f"{BASE_URL}/auth/totp/safe", json={"temp_token": "x", "code": "000000"})
    assert r.status_code in (401, 422)


# ── Group 2: True positives ───────────────────────────────────────────────────

def test_vulnerable_accepts_replay():
    """Same valid code submitted twice to the vulnerable endpoint must both succeed."""
    code = current_code()
    temp = get_temp_token()
    r1 = httpx.post(f"{BASE_URL}/auth/totp/vulnerable", json={"temp_token": temp, "code": code})
    r2 = httpx.post(f"{BASE_URL}/auth/totp/vulnerable", json={"temp_token": temp, "code": code})
    assert r1.status_code == 200
    assert r2.status_code == 200, "Vulnerable endpoint must allow replay (no protection)"


def test_vulnerable_accepts_old_code():
    """A 180-second-old code must be accepted by the vulnerable wide-window endpoint."""
    code = old_code()
    temp = get_temp_token()
    r = httpx.post(f"{BASE_URL}/auth/totp/vulnerable", json={"temp_token": temp, "code": code})
    assert r.status_code == 200, "Vulnerable endpoint must accept old code (±5 min window)"


def test_tool_detects_replay_attack():
    result = run_tool()
    types = [f["vulnerability_type"] for f in result["findings"]]
    assert "TOTP_REPLAY_ATTACK" in types


def test_tool_detects_wide_window():
    result = run_tool()
    types = [f["vulnerability_type"] for f in result["findings"]]
    assert "WIDE_TOTP_WINDOW" in types


def test_replay_finding_high_severity():
    result = run_tool()
    replay = [f for f in result["findings"] if f["vulnerability_type"] == "TOTP_REPLAY_ATTACK"]
    assert len(replay) > 0
    assert all(f["severity"] == "HIGH" for f in replay)


def test_wide_window_finding_severity():
    result = run_tool()
    ww = [f for f in result["findings"] if f["vulnerability_type"] == "WIDE_TOTP_WINDOW"]
    assert len(ww) > 0
    assert all(f["severity"] in ("HIGH", "MEDIUM") for f in ww)


def test_vulnerable_endpoint_in_findings():
    result = run_tool()
    endpoints = [f["endpoint"] for f in result["findings"]]
    assert any("vulnerable" in ep for ep in endpoints)


# ── Group 3: False positives ──────────────────────────────────────────────────

def test_safe_rejects_replay():
    """Safe endpoint must reject the same code on second submission."""
    code = current_code()
    temp = get_temp_token()
    r1 = httpx.post(f"{BASE_URL}/auth/totp/safe", json={"temp_token": temp, "code": code})
    r2 = httpx.post(f"{BASE_URL}/auth/totp/safe", json={"temp_token": temp, "code": code})
    assert r1.status_code == 200
    assert r2.status_code == 401, "Safe endpoint must block replayed code"


def test_safe_rejects_old_code():
    """Safe endpoint must reject a 180-second-old code (outside ±30 s window)."""
    code = old_code()
    temp = get_temp_token()
    r = httpx.post(f"{BASE_URL}/auth/totp/safe", json={"temp_token": temp, "code": code})
    assert r.status_code == 401, "Safe endpoint must reject code from outside the valid window"


def test_tool_does_not_flag_safe_endpoint():
    result = run_tool()
    safe_findings = [f for f in result["findings"] if "safe" in f["endpoint"]]
    assert len(safe_findings) == 0, "Safe endpoint must produce zero findings"


# ── Group 4: Output format ────────────────────────────────────────────────────

def test_output_is_valid_json():
    result = run_tool()
    assert isinstance(result, dict)


def test_output_has_target_field():
    result = run_tool()
    assert "target" in result
    assert result["target"] == BASE_URL


def test_output_has_findings_list():
    result = run_tool()
    assert "findings" in result
    assert isinstance(result["findings"], list)


def test_output_has_summary_string():
    result = run_tool()
    assert "summary" in result
    assert isinstance(result["summary"], str)
    assert len(result["summary"]) > 0


def test_findings_have_required_fields():
    result = run_tool()
    for finding in result["findings"]:
        assert "endpoint" in finding
        assert "vulnerability_type" in finding
        assert "evidence" in finding
        assert "severity" in finding


# ── Group 5: Edge cases ───────────────────────────────────────────────────────

def test_unreachable_server_no_crash():
    """Tool must exit 0 and return valid JSON when server is not running."""
    out = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", "http://127.0.0.1:19998"],
        capture_output=True,
        text=True,
        cwd=".",
        stdin=subprocess.DEVNULL,
    )
    assert out.returncode == 0
    result = json.loads(out.stdout)
    assert isinstance(result, dict)


def test_unreachable_server_empty_findings():
    out = subprocess.run(
        [sys.executable, "../tool/main.py", "--target", "http://127.0.0.1:19998"],
        capture_output=True,
        text=True,
        cwd=".",
        stdin=subprocess.DEVNULL,
    )
    result = json.loads(out.stdout)
    assert result["findings"] == []


def test_invalid_temp_token_rejected():
    """Both endpoints must return 401 for an unrecognised temp token."""
    r_v = httpx.post(f"{BASE_URL}/auth/totp/vulnerable", json={"temp_token": "no_such_token", "code": "123456"})
    r_s = httpx.post(f"{BASE_URL}/auth/totp/safe", json={"temp_token": "no_such_token", "code": "123456"})
    assert r_v.status_code == 401
    assert r_s.status_code == 401


def test_wrong_password_returns_401():
    r = httpx.post(f"{BASE_URL}/auth/login", json={"username": TEST_USER, "password": "wrongpass"})
    assert r.status_code == 401


def test_protected_route_without_token():
    r = httpx.get(f"{BASE_URL}/protected")
    assert r.status_code in (401, 403)
