// ============================================================================
// Alliance CRM - main server.
// INTENTIONALLY VULNERABLE training target. Run only in an isolated lab.
// ============================================================================
// Tiny inline .env loader (avoids an extra dependency).
const fs = require('fs');
try {
  const envPath = require('path').join(__dirname, '.env');
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^\s*([\w.-]+)\s*=\s*(.*)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
} catch (e) { /* no .env present; fall back to process env / defaults */ }

const path = require('path');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const serveIndex = require('serve-index');

const { authRequired, requireRole, JWT_SECRET } = require('./src/auth');
const authRoutes = require('./src/routes/auth');
const intakeRoutes = require('./src/routes/intake');
const clientRoutes = require('./src/routes/clients');
const userRoutes = require('./src/routes/users');
const importRoutes = require('./src/routes/import');

const app = express();

// --- Permissive CORS: reflects any origin and allows credentials.  // VULN A05
app.use(cors({ origin: true, credentials: true }));

// --- Keep the X-Powered-By banner (Express default) AND add a verbose Server
//     banner advertising versions.  // VULN A05 (version disclosure)
// (Note: we intentionally do NOT call app.disable('x-powered-by').)
app.use((req, res, next) => {
  res.setHeader('Server', 'Express/4.19.2 (Ubuntu) Node/22');
  // No CSP, no X-Frame-Options, no HSTS, no X-Content-Type-Options.  // VULN A05
  next();
});

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// --- API routes -----------------------------------------------------------
app.use('/api/auth', authRoutes);
app.use('/api/intake', intakeRoutes);
app.use('/api/clients', clientRoutes);
app.use('/api/users', userRoutes);
app.use('/api/import', importRoutes);

// Bulk export mounted here.  // VULN A04 (no size limit)
app.get('/api/export/clients', authRequired, clientRoutes.exportHandler);

// --- API docs, openly readable (helps scanners + attackers map the API). // VULN A05
app.get('/api/docs', (req, res) => {
  res.json({
    service: 'Alliance CRM API',
    version: '1.0.0',
    auth: 'JWT (HS256). Send Authorization: Bearer <token> or token cookie.',
    endpoints: [
      'POST /api/auth/login {username,password}',
      'POST /api/auth/reset-request {username}',
      'POST /api/auth/reset {username,token,new_password}',
      'POST /api/intake {name,email,phone,referral_source,service_needs,notes}',
      'GET  /api/clients',
      'GET  /api/clients/search?q=',
      'GET  /api/clients/:id',
      'PUT  /api/clients/:id',
      'POST /api/clients',
      'GET  /api/clients/:id/notes',
      'POST /api/clients/:id/notes {body}',
      'GET  /api/export/clients',
      'GET  /api/users',
      'PATCH /api/users/:id (accepts role)',
      'POST /api/users (admin)',
      'DELETE /api/users/:id (admin)',
      'POST /api/import/url {url}',
    ],
  });
});

// --- Debug endpoint that dumps environment + config.  // VULN A05 (sensitive exposure)
app.get('/debug', (req, res) => {
  res.json({
    node: process.version,
    uptime_s: process.uptime(),
    jwt_secret: JWT_SECRET,            // leaking the signing secret!  // VULN A02/A05
    env: process.env,                  // includes DATABASE_URL, DEFAULT_ADMIN_PASSWORD...
    cwd: process.cwd(),
  });
});

// --- Exposed /backup directory WITH directory listing + the DB dump.  // VULN A05
app.use(
  '/backup',
  express.static(path.join(__dirname, 'backup'), { dotfiles: 'allow' }),
  serveIndex(path.join(__dirname, 'backup'), { icons: true, hidden: true })
);

// --- Exposed /.git directory (source + history leak).  // VULN A05
app.use(
  '/.git',
  express.static(path.join(__dirname, '.git'), { dotfiles: 'allow' }),
  serveIndex(path.join(__dirname, '.git'), { icons: true, hidden: true })
);

// --- Serve the committed .env directly.  // VULN A02/A05
// (regex route so the leading-dot path matches reliably)
app.get(/^\/\.env$/, (req, res) => {
  try {
    res.type('text/plain').send(fs.readFileSync(path.join(__dirname, '.env'), 'utf8'));
  } catch (e) {
    res.status(404).send('not found');
  }
});

// --- Static front end (ordinary, crawlable pages). -------------------------
app.use('/', express.static(path.join(__dirname, 'public')));

const HOST = process.env.HOST || '0.0.0.0';
const PORT = process.env.PORT || 4000;
app.listen(PORT, HOST, () => {
  console.log(`Alliance CRM listening on http://${HOST}:${PORT}`);
  console.log('WARNING: intentionally vulnerable. Isolated lab use only.');
});
