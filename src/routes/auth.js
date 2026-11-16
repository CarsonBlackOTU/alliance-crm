// Login, logout, and password reset.
const express = require('express');
const crypto = require('crypto');
const db = require('../db');
const { md5, signToken } = require('../auth');

const router = express.Router();

// POST /api/auth/login
// No rate limiting, no lockout.  // VULN A07 (brute force)
// Distinct error messages reveal whether a username exists.  // VULN A07 (user enumeration)
router.post('/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'username and password required' });
  }

  const result = await db.query('SELECT * FROM staff WHERE username = $1', [username]);
  if (result.rows.length === 0) {
    // Enumeration: different message/status for "no such user".  // VULN A07
    return res.status(404).json({ error: 'No account with that username' });
  }

  const user = result.rows[0];
  if (user.password_hash !== md5(password)) {
    // Enumeration: different message for "wrong password".  // VULN A07
    return res.status(401).json({ error: 'Incorrect password' });
  }

  const token = signToken(user);
  // Cookie set WITHOUT HttpOnly / Secure / SameSite.  // VULN A05 (cookie flags)
  res.cookie('token', token, { httpOnly: false, secure: false });
  res.json({
    token,
    user: { id: user.id, username: user.username, full_name: user.full_name, role: user.role },
  });
});

router.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// POST /api/auth/reset-request  { username }
// Returns a PREDICTABLE reset token derived from username + today's date,
// and even echoes it back in the response.  // VULN A07 (predictable reset token)
router.post('/reset-request', async (req, res) => {
  const { username } = req.body || {};
  const result = await db.query('SELECT id FROM staff WHERE username = $1', [username]);
  if (result.rows.length === 0) {
    return res.status(404).json({ error: 'No account with that username' }); // enumeration again
  }
  const staffId = result.rows[0].id;
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const token = md5(username + ':' + today); // guessable: md5(username + ":" + date)
  await db.query(
    'INSERT INTO password_resets (staff_id, token) VALUES ($1, $2)',
    [staffId, token]
  );
  res.json({ message: 'Reset token generated', reset_token: token });
});

// POST /api/auth/reset  { username, token, new_password }
router.post('/reset', async (req, res) => {
  const { username, token, new_password } = req.body || {};
  const r = await db.query(
    `SELECT pr.id, pr.staff_id FROM password_resets pr
       JOIN staff s ON s.id = pr.staff_id
      WHERE s.username = $1 AND pr.token = $2 AND pr.used = false
      ORDER BY pr.created_at DESC LIMIT 1`,
    [username, token]
  );
  if (r.rows.length === 0) return res.status(400).json({ error: 'invalid token' });
  await db.query('UPDATE staff SET password_hash = $1 WHERE id = $2', [
    md5(new_password),
    r.rows[0].staff_id,
  ]);
  await db.query('UPDATE password_resets SET used = true WHERE id = $1', [r.rows[0].id]);
  res.json({ message: 'Password updated' });
});

module.exports = router;
