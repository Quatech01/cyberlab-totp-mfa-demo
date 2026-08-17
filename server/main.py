import base64
import hashlib
import hmac
import secrets
import struct
import threading
import time
import urllib.request

import uvicorn
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

app = FastAPI()

# In-memory stores
_users: dict = {}          # {username: {password, totp_secret}}
_temp_tokens: dict = {}    # {temp_token: username}
_access_tokens: dict = {}  # {access_token: username}
_used_codes: set = set()   # {(username, code)} — replay protection for safe endpoint


def _totp_codes(secret_b32: str, ts: int = None, window: int = 0, period: int = 30) -> list:
    """Return all valid TOTP codes within ±window steps of ts."""
    if ts is None:
        ts = int(time.time())
    try:
        padding = (8 - len(secret_b32) % 8) % 8
        key = base64.b32decode(secret_b32.upper() + "=" * padding)
    except Exception:
        return []
    codes = []
    for offset in range(-window, window + 1):
        counter = ts // period + offset
        msg = struct.pack(">Q", counter)
        mac = hmac.new(key, msg, hashlib.sha1).digest()
        trunc_offset = mac[-1] & 0x0F
        code_int = struct.unpack(">I", mac[trunc_offset : trunc_offset + 4])[0] & 0x7FFFFFFF
        codes.append(str(code_int % 1_000_000).zfill(6))
    return codes


class SetupRequest(BaseModel):
    username: str
    password: str
    secret: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TotpRequest(BaseModel):
    temp_token: str
    code: str


security = HTTPBearer()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/setup")
def setup(req: SetupRequest):
    """Register (or update) a user with the given TOTP secret."""
    _users[req.username] = {"password": req.password, "totp_secret": req.secret}
    return {"ok": True, "username": req.username}


@app.post("/auth/login")
def login(req: LoginRequest):
    user = _users.get(req.username)
    if not user or user["password"] != req.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    temp_token = secrets.token_hex(16)
    _temp_tokens[temp_token] = req.username
    return {"temp_token": temp_token, "message": "Enter your TOTP code to complete login"}


@app.post("/auth/totp/vulnerable")
def totp_vulnerable(req: TotpRequest):
    """
    VULNERABLE endpoint — two flaws:
    1. Accepts codes within a ±10-step window (±5 minutes) instead of the RFC-recommended ±1 step.
    2. No replay protection — the same valid code can be submitted multiple times.
    """
    username = _temp_tokens.get(req.temp_token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired temp token")
    user = _users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    valid = _totp_codes(user["totp_secret"], window=10)
    if req.code not in valid:
        raise HTTPException(status_code=401, detail="Invalid TOTP code")
    access_token = secrets.token_hex(16)
    _access_tokens[access_token] = username
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/auth/totp/safe")
def totp_safe(req: TotpRequest):
    """
    SAFE endpoint — correct implementation:
    1. Accepts codes only within ±1 step (±30 seconds) per RFC 6238.
    2. Tracks used codes to prevent replay attacks within the valid window.
    """
    username = _temp_tokens.get(req.temp_token)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid or expired temp token")
    user = _users.get(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    valid = _totp_codes(user["totp_secret"], window=1)
    if req.code not in valid:
        raise HTTPException(status_code=401, detail="Invalid TOTP code")
    code_key = (username, req.code)
    if code_key in _used_codes:
        raise HTTPException(status_code=401, detail="TOTP code already used (replay prevented)")
    _used_codes.add(code_key)
    access_token = secrets.token_hex(16)
    _access_tokens[access_token] = username
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/protected")
def protected(credentials: HTTPAuthorizationCredentials = Depends(security)):
    username = _access_tokens.get(credentials.credentials)
    if not username:
        raise HTTPException(status_code=401, detail="Invalid access token")
    return {"message": "Access granted", "user": username}


def start(port: int = 3000):
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/health")
            break
        except Exception:
            time.sleep(0.2)
    return server


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=3000)
