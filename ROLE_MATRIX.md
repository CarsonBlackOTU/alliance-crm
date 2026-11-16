# ROLE_MATRIX.md — Intended Permissions

This is the **intended** (design) permission model for Alliance CRM. The point of
the exercise is that the implementation does **not** fully enforce it — the gaps
are the vulnerabilities (see `VULNERABILITIES.md`, especially A01). "Enforced
where" notes whether a control is applied in the UI, the API, both, or neither.

## Roles

| Key               | Role                         | Seed user   |
|-------------------|------------------------------|-------------|
| `admin`           | Executive Director           | `director`  |
| `program_manager` | Program Manager              | `pmanager`  |
| `intake`          | Intake Coordinator           | `intake`    |
| `peer_support`    | Peer Support Worker          | `peer`      |
| `volunteer`       | Volunteer / Admin Assistant  | `volunteer` |

## Intended capability matrix

| Capability                                   | admin | program_manager | intake | peer_support | volunteer |
|----------------------------------------------|:-----:|:---------------:|:------:|:------------:|:---------:|
| View **all** client records                  |  ✅   |       ✅        |   ✅   | ❌ (own only) | ✅ (limited fields) |
| View client full fields (notes, needs, etc.) |  ✅   |       ✅        |   ✅   | ✅ (own only) | ❌ (name/contact only) |
| Create client / intake record                |  ✅   |       ✅        |   ✅   |      ❌       |    ❌     |
| Edit client record                           |  ✅   |       ✅        |   ✅   | ✅ (own only) |    ❌     |
| View case notes                              |  ✅   |       ✅        |   ❌   | ✅ (own only) |    ❌     |
| Add case notes                               |  ✅   |       ✅        |   ❌   | ✅ (own only) |    ❌     |
| Enroll client in a program                   |  ✅   |       ✅        |   ❌   |      ❌       |    ❌     |
| Export client records                        |  ✅   |       ✅        |   ❌   |      ❌       |    ❌     |
| View staff list                              |  ✅   |       ❌        |   ❌   |      ❌       |    ❌     |
| Create / edit / delete staff                 |  ✅   |       ❌        |   ❌   |      ❌       |    ❌     |
| Change a user's **role**                     |  ✅   |       ❌        |   ❌   |      ❌       |    ❌     |

Legend: ✅ allowed · ❌ denied · "own only" = limited to clients where
`assigned_staff_id` = the logged-in user.

## Where each control is (and isn't) enforced in this build

| Intended control | UI enforced? | API enforced? | Notes |
|---|---|---|---|
| Peer support sees own clients only | ✅ (list view hides others) | ❌ | `GET /api/clients/:id` has **no** ownership check → IDOR (A01) |
| Volunteer read-only / limited fields | ✅ (list view trims fields, hides edit tools) | ❌ | `GET/PUT /api/clients/:id` ignore role → IDOR + unauthorized edit (A01) |
| Intake has no case-note access | ✅ (no UI shown for it) | ❌ | `POST /api/clients/:id/notes` doesn't check role |
| Only admin manages staff | ✅ (page labeled admin-only) | ⚠️ partial | `POST`/`DELETE /api/users` **are** admin-gated; `GET /api/users` and `PATCH /api/users/:id` are **not** |
| Only admin changes roles | ✅ (no role selector in profile UI) | ❌ | `PATCH /api/users/:id` accepts a `role` field from anyone → privilege escalation (A01) |
| Export restricted to admin/PM | ⚠️ loose | ❌ | `GET /api/export/clients` only requires a valid login, no role check, no size cap (A04) |

> The deliberate design is: **the UI enforces the matrix, the API mostly does
> not.** A tester who goes past the browser (Burp/ZAP) finds the real boundary is
> missing.
