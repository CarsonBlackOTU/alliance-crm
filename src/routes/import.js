// "Import logo / referral document from URL" feature.
const express = require('express');
const db = require('../db');
const { authRequired } = require('../auth');

const router = express.Router();
router.use(authRequired);

// POST /api/import/url   { url }
// SSRF: the server fetches ANY url the user supplies and returns the response
// body + status + headers. No allow-list, no scheme/host restrictions, so this
// reaches internal services (link-local metadata, localhost admin panels, other
// VMs on the host-only net, etc.).  // VULN A10 (SSRF)
router.post('/url', async (req, res) => {
  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'url required' });
  try {
    const r = await fetch(url); // // VULN A10 - no validation of url
    const bodyText = await r.text();
    res.json({
      fetched: url,
      status: r.status,
      content_type: r.headers.get('content-type'),
      // Reflecting the body back is what makes the SSRF easy to demonstrate.
      body: bodyText.slice(0, 5000),
    });
  } catch (e) {
    res.status(502).json({ error: 'fetch failed', detail: e.message, fetched: url });
  }
});

module.exports = router;
