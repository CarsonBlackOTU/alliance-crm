# Alliance CRM — Intentionally Vulnerable Training Target

> ⚠️ **This application is deliberately insecure.** It is a teaching target for a
> university penetration-testing course, in the same category as OWASP Juice
> Shop, DVWA, and WebGoat. It contains real, exploitable vulnerabilities and
> stores credentials insecurely **on purpose**. Run it **only** inside an
> isolated lab (host-only VirtualBox network, no internet exposure) with
> **fake data only**. Never deploy it publicly or put real personal data in it.

"Alliance CRM" is a fictional client-management system for an invented nonprofit,
**Alliance Veteran Wellness**. It holds (fake) veteran intake records, program
enrollment, and private case/counselling notes — the kind of sensitive data a
small nonprofit handles — so the vulnerabilities map onto realistic risks.

- **Backend:** Node.js + Express
- **Database:** PostgreSQL (via `docker-compose`)
- **Front end:** plain HTML/JS in `public/` (talks to the REST API)
- **Auth:** JWT (HS256)

---

## 1. Setup

### Prerequisites
- Docker + Docker Compose (for PostgreSQL)
- Node.js 18+ and npm

### Install & run
```bash
# 1. Install backend dependencies
npm install

# 2. Start PostgreSQL (seeds schema + fake data on first run)
docker compose up -d

# 3. Start the app
npm start
```

The app listens on `http://<HOST>:4000` (default `HOST=0.0.0.0`, `PORT=4000`).

- Public intake form: `http://<HOST>:4000/`
- Staff portal login: `http://<HOST>:4000/portal.html`

### Binding to the host-only lab network
Edit `.env` and set `HOST` to your VM's **host-only adapter** IP (e.g.
`192.168.56.10`) so the app is reachable from Kali on the host-only network but
not from anywhere else. `0.0.0.0` is fine inside a fully isolated VM.

### Re-seeding the database
The seed in `db/init.sql` runs only when the Postgres volume is empty:
```bash
docker compose down -v && docker compose up -d
```

---

## 2. Seed staff credentials (per role)

All passwords are stored as **unsalted MD5** (intentional weakness). Documented
plaintext:

| Username   | Password    | Role              | Intended access |
|------------|-------------|-------------------|-----------------|
| `director` | `admin123`  | Executive Director (**admin**) | Everything, incl. staff management |
| `pmanager` | `Welcome1`  | Program Manager   | All clients, programs, reports, exports; no staff mgmt |
| `intake`   | `Welcome1`  | Intake Coordinator | Create/view/edit intake data; no case notes |
| `peer`     | `Welcome1`  | Peer Support Worker | Only their **own assigned** clients, incl. case notes |
| `volunteer`| `volunteer` | Volunteer/Admin Assistant | Read-only, limited fields (name, contact) |

> Note: `Welcome1` is deliberately **reused** across three accounts, and
> `admin123` is a never-changed default. See `VULNERABILITIES.md` (A07).

See `ROLE_MATRIX.md` for the full intended permission matrix, and
`VULNERABILITIES.md` for where the implementation deliberately fails to enforce it.

---

## 3. Fake data

- ~50 clients with obviously fake details (`@example.test` emails, `555-01xx`
  phones, invented names, fictional programs).
- 5 staff users (above).
- A handful of seeded case notes.

No real people, no real data.

---

## 4. Project layout

```
alliance-crm/
├── docker-compose.yml      # PostgreSQL
├── .env                    # secrets, committed on purpose (A02)
├── server.js               # Express app + misconfig vulns (A05)
├── db/init.sql             # schema + seed (MD5 passwords)
├── backup/
│   └── alliance_crm_dump.sql   # exposed DB dump (A05)
├── src/
│   ├── auth.js             # JWT + MD5 helpers (A02)
│   ├── db.js               # pg pool (+ raw() for the SQLi endpoint)
│   └── routes/
│       ├── auth.js         # login/reset (A07)
│       ├── intake.js       # public form (A04)
│       ├── clients.js      # search SQLi (A03), IDOR (A01), export (A04), XSS (A03)
│       ├── users.js        # mass-assignment priv-esc (A01)
│       └── import.js       # SSRF (A10)
└── public/                 # plain HTML/JS front end
```

Every deliberately vulnerable line is tagged with a `// VULN A0X` comment so you
can grep for them:
```bash
grep -rn "VULN A0" .
```

---

## 5. Documentation

- **`ROLE_MATRIX.md`** — intended permissions per role.
- **`VULNERABILITIES.md`** — the full vulnerability register with exact
  reproduction steps, payloads, tools, impact in plain language, and fixes.
- **`TESTS.md`** — a short test proving each vulnerability works.

---

## 6. Branches

This is the **`vulnerable`** branch. A `hardened` branch is intentionally **not**
created yet (that's the remediation exercise).

## 7. AI disclosure

This training target was generated with AI assistance (Claude). Disclose per your
course's academic-integrity policy.
