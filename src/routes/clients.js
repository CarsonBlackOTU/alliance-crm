// Client records, search, case notes, export.
const express = require('express');
const db = require('../db');
const { authRequired, requireRole } = require('../auth');

const router = express.Router();

// All client routes require a login...
router.use(authRequired);

// ---------------------------------------------------------------------------
// GET /api/clients/search?q=...
// SQL INJECTION: the query string is concatenated directly into SQL with no
// parameterization. UNION-based payloads can read other tables (e.g. staff).
// // VULN A03 (SQL injection)
// ---------------------------------------------------------------------------
router.get('/search', async (req, res) => {
  const q = req.query.q || '';
  // 5 selected columns -> a UNION payload needs 5 columns to line up.
  const sql =
    "SELECT id, full_name, email, phone, service_needs " +
    "FROM clients " +
    "WHERE full_name ILIKE '%" + q + "%' OR email ILIKE '%" + q + "%'"; // // VULN A03
  try {
    const result = await db.raw(sql);
    res.json({ query: sql, rows: result.rows });
  } catch (e) {
    // Verbose DB errors leak schema details, which helps blind/UNION tuning. // VULN A05
    res.status(500).json({ error: e.message, query: sql });
  }
});

// ---------------------------------------------------------------------------
// GET /api/clients   - list clients.
// Volunteer is meant to be read-only + limited fields; peer_support is meant to
// see only assigned clients. The LIST endpoint only partly enforces this, and
// the per-id endpoints below enforce nothing.  // VULN A01 (broken access control)
// ---------------------------------------------------------------------------
router.get('/', async (req, res) => {
  const role = req.user.role;
  let result;
  if (role === 'peer_support') {
    // Intended restriction IS applied on the list view only...
    result = await db.query(
      'SELECT * FROM clients WHERE assigned_staff_id = $1 ORDER BY id',
      [req.user.id]
    );
  } else if (role === 'volunteer') {
    // Volunteer: limited fields (as intended on the list view).
    result = await db.query(
      'SELECT id, full_name, email, phone FROM clients ORDER BY id'
    );
  } else {
    result = await db.query('SELECT * FROM clients ORDER BY id');
  }
  res.json({ rows: result.rows });
});

// ---------------------------------------------------------------------------
// GET /api/clients/:id   - view one client.
// INSECURE DIRECT OBJECT REFERENCE: no ownership / role check at all. A peer
// support worker or volunteer can read ANY client by changing the id.
// // VULN A01 (IDOR)
// ---------------------------------------------------------------------------
router.get('/:id', async (req, res) => {
  const result = await db.query('SELECT * FROM clients WHERE id = $1', [req.params.id]);
  if (result.rows.length === 0) return res.status(404).json({ error: 'not found' });
  res.json(result.rows[0]); // // VULN A01 (no assignment check)
});

// PUT /api/clients/:id   - edit a client. Also IDOR (no ownership check), and
// the volunteer (read-only) role is not blocked here.  // VULN A01
router.put('/:id', async (req, res) => {
  const { full_name, email, phone, referral_source, service_needs, notes, program, enrolled } =
    req.body || {};
  const result = await db.query(
    `UPDATE clients SET
       full_name = COALESCE($1, full_name),
       email = COALESCE($2, email),
       phone = COALESCE($3, phone),
       referral_source = COALESCE($4, referral_source),
       service_needs = COALESCE($5, service_needs),
       notes = COALESCE($6, notes),
       program = COALESCE($7, program),
       enrolled = COALESCE($8, enrolled)
     WHERE id = $9 RETURNING *`,
    [full_name, email, phone, referral_source, service_needs, notes, program, enrolled, req.params.id]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: 'not found' });
  res.json(result.rows[0]);
});

// POST /api/clients   - create a client (intake-style). Any logged-in role allowed.
router.post('/', async (req, res) => {
  const { full_name, email, phone, referral_source, service_needs, notes, program } = req.body || {};
  if (!full_name) return res.status(400).json({ error: 'full_name required' });
  const result = await db.query(
    `INSERT INTO clients (full_name, email, phone, referral_source, service_needs, notes, program)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [full_name, email, phone, referral_source, service_needs, notes, program]
  );
  res.status(201).json(result.rows[0]);
});

// ---------------------------------------------------------------------------
// Case notes.
// GET  /api/clients/:id/notes
// POST /api/clients/:id/notes   { body }
// Stored XSS: note body is stored raw and later rendered with innerHTML in the
// portal.  // VULN A03 (stored XSS)
// No ownership check on which client you attach notes to.  // VULN A01 (IDOR)
// The intake role is *meant* to have no case-note access; not enforced here.
// ---------------------------------------------------------------------------
router.get('/:id/notes', async (req, res) => {
  const result = await db.query(
    `SELECT cn.*, s.full_name AS author_name
       FROM case_notes cn LEFT JOIN staff s ON s.id = cn.author_id
      WHERE cn.client_id = $1 ORDER BY cn.created_at`,
    [req.params.id]
  );
  res.json({ rows: result.rows });
});

router.post('/:id/notes', async (req, res) => {
  const { body } = req.body || {};
  if (!body) return res.status(400).json({ error: 'body required' });
  // Stored exactly as submitted - no sanitization/encoding.  // VULN A03 (stored XSS)
  const result = await db.query(
    'INSERT INTO case_notes (client_id, author_id, body) VALUES ($1,$2,$3) RETURNING *',
    [req.params.id, req.user.id, body]
  );
  res.status(201).json(result.rows[0]);
});

module.exports = router;

// ---------------------------------------------------------------------------
// GET /api/export/clients   (mounted separately in server.js)
// Exports ALL clients and case notes with no size/row limit and only a loose
// role check.  // VULN A04 (insecure design: unlimited bulk export)
// ---------------------------------------------------------------------------
module.exports.exportHandler = async (req, res) => {
  // Note: no cap, no pagination, dumps everything including case notes.
  const clients = await db.query('SELECT * FROM clients ORDER BY id');
  const notes = await db.query('SELECT * FROM case_notes ORDER BY id');
  res.setHeader('Content-Disposition', 'attachment; filename="client_export.json"');
  res.json({ exported_at: new Date().toISOString(), clients: clients.rows, case_notes: notes.rows });
};
