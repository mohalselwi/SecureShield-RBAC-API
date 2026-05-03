#!/usr/bin/env bash
#
# End-to-end demo for the SecureShield RBAC API.
# Start the server first:  python app.py
#
# Walks through:
#   1) Successful login (user role)
#   2) Profile access (allowed)
#   3) Admin-only DELETE attempt as user (403 + security.log entry)
#   4) Login as admin (admin role)
#   5) Admin DELETE succeeds
#   6) Logout invalidates the token (subsequent calls fail with 401)
#   7) Tamper test: a JWT re-signed with the wrong key is rejected
#
# Requires:  curl, python3 (for the tamper-test forging step)

set -u
BASE="${BASE:-http://127.0.0.1:5000}"

hr() { printf '\n\033[1m── %s ──\033[0m\n' "$*"; }
say() { printf '  \033[2m%s\033[0m\n' "$*"; }

extract() {
  python3 -c "import sys, json; print(json.loads(sys.stdin.read()).get('$1',''))"
}

hr "1) Login as alice (role=user)"
ALICE_LOGIN=$(curl -s -X POST "$BASE/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"UserPass123!"}')
echo "$ALICE_LOGIN"
ALICE_TOKEN=$(echo "$ALICE_LOGIN" | extract access_token)
[ -n "$ALICE_TOKEN" ] || { echo "login failed; is the server running?" >&2; exit 1; }

hr "2) GET /profile as alice (expect 200)"
curl -s -w "\nHTTP %{http_code}\n" "$BASE/profile" \
  -H "Authorization: Bearer $ALICE_TOKEN"

hr "3) DELETE /user/1 as alice (expect 403 — Access Denied)"
curl -s -w "\nHTTP %{http_code}\n" -X DELETE "$BASE/user/1" \
  -H "Authorization: Bearer $ALICE_TOKEN"
say "Last line of security.log:"
tail -n 1 security.log 2>/dev/null || say "(no security.log yet)"

hr "4) Login as admin (role=admin)"
ADMIN_LOGIN=$(curl -s -X POST "$BASE/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"AdminPass123!"}')
echo "$ADMIN_LOGIN"
ADMIN_TOKEN=$(echo "$ADMIN_LOGIN" | extract access_token)

hr "5) Register a throwaway victim user, then delete it as admin"
curl -s -X POST "$BASE/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"victim","password":"VictimPass1!","role":"user"}'
echo
VICTIM_ID=$(curl -s "$BASE/profile" -H "Authorization: Bearer $(curl -s -X POST $BASE/login -H 'Content-Type: application/json' -d '{"username":"victim","password":"VictimPass1!"}' | extract access_token)" | extract id)
say "Victim user id: $VICTIM_ID"
curl -s -w "\nHTTP %{http_code}\n" -X DELETE "$BASE/user/$VICTIM_ID" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

hr "6) Logout alice, then retry /profile (expect 401 — token revoked)"
curl -s -X POST "$BASE/logout" -H "Authorization: Bearer $ALICE_TOKEN"
echo
curl -s -w "\nHTTP %{http_code}\n" "$BASE/profile" \
  -H "Authorization: Bearer $ALICE_TOKEN"

hr "7) Tamper test: forge a token by signing with the wrong key"
FORGED=$(python3 - "$ALICE_TOKEN" <<'PY'
import jwt, sys, json, base64
src = sys.argv[1]
hdr_b64, pl_b64, _ = src.split(".")
payload = json.loads(base64.urlsafe_b64decode(pl_b64 + "==").decode())
payload["role"] = "admin"
print(jwt.encode(payload, "attacker-guessed-secret", algorithm="HS256"))
PY
)
say "Forged token (claims role=admin, signed with wrong key): ${FORGED:0:60}…"
curl -s -w "\nHTTP %{http_code}\n" -X DELETE "$BASE/user/1" \
  -H "Authorization: Bearer $FORGED"
say "Last line of security.log:"
tail -n 1 security.log

hr "Done."
