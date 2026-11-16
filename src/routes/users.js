// Staff management. Intended to be admin-only, but with deliberate gaps.
const express = require('express');
const db = require('../db');
const { authRequired, requireRole, md5 } = require('../auth');

const router = express.Router();
router.use(authRequired);

// GET /api/users  - list staff. Intended admin-only; here ANY logged-in user
// can list staff accounts (usernames, roles, emails).  // VULN A01
router.get('/', async (req, res) => {
  const result = await db.query(
    'SELECT id, username, full_name, email, role, created_at FROM staff ORDER BY id'
  );
  res.json({ rows: result.rows });
});

// GET /api/users/:id
router.get('/:id', async (req, res) => {
  const result = await db.query(
    'SELECT id, username, full_name, email, role FROM staff WHERE id = $1',
    [req.params.id]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: 'not found' });
  res.json(result.rows[0]);
});

// ---------------------------------------------------------------------------
// PATCH /api/users/:id  - "update your profile".
// MASS ASSIGNMENT / PRIVILEGE ESCALATION: whatever fields are in the body get
// written, including `role`. There is no check that the caller is an admin, and
// no check that the caller is only editing their own record. So any logged-in
// staff member can PATCH themselves (or anyone) to role=admin.
// // VULN A01 (privilege escalation: staff -> admin)
// ---------------------------------------------------------------------------
router.patch('/:id', async (req, res) => {
  const allowed = ['full_name', 'email', 'username', 'role', 'password']; // <- 'role' should NOT be here
  const sets = [];
  const vals = [];
  let i = 1;
  for (const field of allowed) {
    if (req.body[field] !== undefined) {
      if (field === 'password') {
        sets.push(`password_hash = $${i++}`);
        vals.push(md5(req.body.password));
      } else {
        sets.push(`${field} = $${i++}`);
        vals.push(req.body[field]); // role accepted blindly  // VULN A01
      }
    }
  }
  if (sets.length === 0) return res.status(400).json({ error: 'nothing to update' });
  vals.push(req.params.id);
  const result = await db.query(
    `UPDATE staff SET ${sets.join(', ')} WHERE id = $${i} RETURNING id, username, full_name, email, role`,
    vals
  );
  if (result.rows.length === 0) return res.status(404).json({ error: 'not found' });
  res.json(result.rows[0]);
});

// POST /api/users  - create staff. THIS one is properly admin-gated (so there
// is a real privilege boundary that the escalation above lets you cross).
router.post('/', requireRole('admin'), async (req, res) => {
  const { username, full_name, email, role, password } = req.body || {};
  if (!username || !role || !password) {
    return res.status(400).json({ error: 'username, role, password required' });
  }
  const result = await db.query(
    `INSERT INTO staff (username, full_name, email, role, password_hash)
     VALUES ($1,$2,$3,$4,$5) RETURNING id, username, full_name, email, role`,
    [username, full_name, email, role, md5(password)]
  );
  res.status(201).json(result.rows[0]);
});

// DELETE /api/users/:id  - admin-gated.
router.delete('/:id', requireRole('admin'), async (req, res) => {
  await db.query('DELETE FROM staff WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

module.exports = router;
