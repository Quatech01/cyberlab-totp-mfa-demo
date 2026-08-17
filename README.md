# TOTP Multi-Factor Authentication Demo

A hands-on demonstration of two critical TOTP (Time-based One-Time Password) implementation flaws: replay attacks and excessively wide time-window acceptance.

## What This Demonstrates

TOTP (RFC 6238) is the algorithm behind every authenticator app code. It generates 6-digit codes that expire every 30 seconds by deriving them from a shared secret and the current Unix timestamp divided into 30-second intervals (called "time steps"). When correctly implemented, each code is valid for a single login within a narrow window. Two common misconfigurations undermine this guarantee:

**1. TOTP Replay Attack (HIGH)** — If the server does not track which codes have already been used, an attacker who intercepts a valid code during its 30-second validity window can reuse it to authenticate independently. The code is, in effect, a reusable password for 30 seconds.

**2. Wide Time Window (MEDIUM)** — RFC 6238 recommends accepting codes within ±1 time step (±30 seconds) to tolerate clock skew between client and server. Servers that use ±10 steps (±5 minutes) or more allow an attacker to steal a code during a longer window — including codes captured in network logs or over the shoulder.

## How It Works

```
┌───────────────────────────────────────────────────────────┐
│  server/main.py  (FastAPI)                                │
│                                                           │
│  POST /setup          register user + TOTP secret         │
│  POST /auth/login     verify password → temp_token        │
│  POST /auth/totp/vulnerable  (FLAWED)                     │
│    • accepts ±10-step window (±5 minutes)                 │
│    • no replay protection                                 │
│  POST /auth/totp/safe  (CORRECT)                          │
│    • accepts ±1-step window (±30 seconds)                 │
│    • tracks used codes, rejects replays                   │
│  GET  /protected      requires bearer token               │
└───────────────────────────────────────────────────────────┘
              │
              │ httpx (localhost only)
              ▼
┌───────────────────────────────────────────────────────────┐
│  tool/main.py                                             │
│                                                           │
│  1. Registers probe user with known TOTP secret           │
│  2. Logs in, submits same code twice → REPLAY_ATTACK      │
│  3. Submits 180-second-old code     → WIDE_TOTP_WINDOW    │
│  4. Verifies safe endpoint rejects both                   │
│  5. Outputs structured JSON findings                      │
└───────────────────────────────────────────────────────────┘
```

The tests prove every claim: the vulnerable endpoint genuinely accepts both attacks, the safe endpoint rejects both, and the tool's output matches expectations.

## Quick Start

```bash
# Install server dependencies
cd server && pip install -r requirements.txt

# Run the demo server (separate terminal)
python main.py

# Install tool dependencies
cd ../tool && pip install -r requirements.txt

# Run the scanner
python main.py --target http://localhost:3000
```

To run the full test suite:

```bash
cd tests
pip install -r requirements.txt
python -m pytest test.py -v
```

## Example Output

```json
{
  "target": "http://localhost:3000",
  "findings": [
    {
      "endpoint": "/auth/totp/vulnerable",
      "vulnerability_type": "TOTP_REPLAY_ATTACK",
      "evidence": "Code 847291 was accepted twice in succession — server has no per-code de-duplication",
      "severity": "HIGH"
    },
    {
      "endpoint": "/auth/totp/vulnerable",
      "vulnerability_type": "WIDE_TOTP_WINDOW",
      "evidence": "Code 312048 generated 180 seconds ago was accepted — RFC 6238 recommends ±30 s tolerance; this server accepts ±5 minutes",
      "severity": "MEDIUM"
    }
  ],
  "summary": "Found 2 TOTP vulnerability/vulnerabilities on http://localhost:3000. Vulnerable endpoint lacks replay protection and uses an excessive time window. Safe endpoint enforces RFC 6238 constraints correctly."
}
```

## Key Takeaways

- **Track used codes server-side.** Store every code accepted during the current valid window keyed by (user, code). Reject any code already in that set.
- **Enforce a narrow time window.** The RFC recommends ±1 step (±30 seconds). Going wider trades security for convenience; going to ±10 steps or more effectively extends the attack window to minutes.
- **TOTP is not a password.** It protects against credential replay across sessions, not within a single session. Without de-duplication, anyone who captures a code over the network, from an over-the-shoulder view, or via phishing has a 30-second re-use window.
- **The HMAC-SHA1 algorithm is correct but key management matters.** The security of TOTP depends entirely on the shared secret remaining secret. Keys should be generated server-side, transmitted only once (via QR code), and never logged.

## Further Reading

- [RFC 6238 — TOTP: Time-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)
- [RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc4226)
- [OWASP — Multi-Factor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
