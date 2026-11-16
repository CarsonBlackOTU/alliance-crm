// Public intake form submission. No auth (by design - it's a public form).
const express = require('express');
const db = require('../db');

const router = express.Router();

// POST /api/intake
// No rate limiting, no CAPTCHA, no size cap on submissions -> spam flooding.
// // VULN A04 (insecure design: unlimited intake submissions)
router.post('/', async (req, res) => {
  const { name, email, phone, referral_source, service_needs, notes } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });
  const result = await db.query(
    `INSERT INTO clients (full_name, email, phone, referral_source, service_needs, notes)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
    [name, email, phone, referral_source, service_needs, notes]
  );
  res.status(201).json({ message: 'Thank you. Our team will be in touch.', id: result.rows[0].id });
});

module.exports = router;
