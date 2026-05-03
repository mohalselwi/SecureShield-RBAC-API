# SecureShield — RBAC API (Mini Project II)

A small Flask backend that demonstrates a robust authentication flow built on
JWT and an access-control mechanism that gates features by role
(`user` vs `admin`). Built around the **Principle of Least Privilege**:
a standard user cannot reach admin-only routes, even by tampering with their
own token.

## Features (mapped to project tasks)

| Task | What it does | Where it lives |
| ---- | ------------ | -------------- |
| 1 — Secure password storage | Passwords are salted + hashed with **bcrypt** before going to SQLite. Plain text is never persisted. | `register()` in `app.py` |
| 2 — JWT issuance | `POST /login` returns an HS256-signed JWT with `sub`, `role`, `jti`, `iat`, `exp`. | `issue_jwt()` / `login()` |
| 3 — Token validation | `@token_required` decorator parses, verifies signature, checks expiry, checks revocation. | `token_required()` |
| 4 — Role-based routing | `GET /profile` for any logged-in user; `DELETE /user/<id>` only for admins. | `@role_required("admin")` |
| 5 — Token revocation | `POST /logout` records the token's `jti` in a blacklist table; revoked tokens are rejected on subsequent calls. | `revoke_token()` / `is_token_revoked()` |
| 6 — Defensive logging | Every denied attempt (missing/invalid/expired/revoked token, role mismatch, bad password) is appended to `security.log` with timestamp, method, path, IP, and attempted username. | `log_unauthorized()` |

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                        # listens on http://127.0.0.1:5000
```

On first run, two demo accounts are seeded so you can try every endpoint
immediately:

| Username | Password         | Role   |
| -------- | ---------------- | ------ |
| `admin`  | `AdminPass123!`  | admin  |
| `alice`  | `UserPass123!`   | user   |

To override the JWT signing key (recommended for anything beyond local demo):

```bash
export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python app.py
```

## Endpoints

| Method | Path             | Auth required | Allowed roles |
| ------ | ---------------- | ------------- | ------------- |
| GET    | `/`              | no            | —             |
| POST   | `/register`      | no            | —             |
| POST   | `/login`         | no            | —             |
| GET    | `/profile`       | yes           | user, admin   |
| DELETE | `/user/<id>`     | yes           | admin only    |
| POST   | `/logout`        | yes           | user, admin   |

All responses are JSON.

## Live-demo walkthrough

The recorded video must show three things. Below is the exact set of `curl`
commands the demo script (`demo.sh`) automates.

### 1) Successful login

```bash
curl -s -X POST http://127.0.0.1:5000/login \
     -H "Content-Type: application/json" \
     -d '{"username":"alice","password":"UserPass123!"}'
# -> {"access_token":"eyJhbGciOi...", "token_type":"Bearer", "role":"user"}
```

### 2) Access denied (user tries an admin route)

```bash
TOKEN=<paste alice's token here>
curl -s -o /dev/null -w "%{http_code}\n" \
     -X DELETE http://127.0.0.1:5000/user/1 \
     -H "Authorization: Bearer $TOKEN"
# -> 403
tail -n 1 security.log
# -> ...DENIED reason=role_denied:required=admin ... user=alice
```

### 3) Tamper test (re-encoded role)

Paste alice's token into [jwt.io](https://jwt.io), change `"role":"user"` to
`"role":"admin"`, copy the resulting token (now signed with the wrong key),
and replay it:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
     -X DELETE http://127.0.0.1:5000/user/1 \
     -H "Authorization: Bearer $TAMPERED_TOKEN"
# -> 401   (server rejects the bad signature; security.log shows reason=invalid_signature)
```

This is the punchline of the demo: even though the payload now claims
`role=admin`, the signature was not produced with `SECRET_KEY`, so the server
refuses the token.

## Running the included demo script

```bash
# In one terminal
python app.py

# In another terminal
chmod +x demo.sh
./demo.sh
```

The script registers a fresh user, logs in as both roles, walks through the
denied-access and tamper scenarios, and prints the new lines that appear in
`security.log` after each.

## Project layout

```
SecureShield/
├── app.py              # The application (~290 lines, single file by design)
├── requirements.txt    # Flask, Flask-Bcrypt, PyJWT
├── demo.sh             # End-to-end curl walkthrough
├── report.docx         # 2-page write-up: salting, rainbow tables, JWT payload risks
├── .env.example        # Template for SECRET_KEY / JWT_EXPIRY_MINUTES
├── .gitignore
├── secureshield.db     # Created on first run (gitignored)
└── security.log        # Created on first denied request (gitignored)
```

## Security notes baked into the code

- **Salting is automatic.** `bcrypt.generate_password_hash` generates a fresh
  random salt per call, so two users with the same password end up with
  different hashes. This is what defeats rainbow-table attacks — see
  `report.docx` for the full discussion.
- **The JWT carries claims, not credentials.** Only `username`, `role`,
  `jti`, `iat`, `exp` are signed into the token. Passwords, emails, and other
  PII are deliberately **not** included. Anyone who intercepts the token can
  base64-decode the payload — putting secrets there would leak them.
- **Per-token revocation.** Each issued JWT has a unique `jti`. Logout adds
  that single ID to a blacklist instead of rotating the global secret, which
  would invalidate every other live session.
- **Defence in depth on errors.** `debug=False`, generic JSON error
  responses, and `Authorization: Bearer …` parsing that fails closed if the
  header is missing or malformed.
