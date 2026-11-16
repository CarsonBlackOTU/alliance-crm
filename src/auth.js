// Authentication / JWT helpers.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Weak, hardcoded fallback secret; also shipped in the committed .env.  // VULN A02 / A07
const JWT_SECRET = process.env.JWT_SECRET || 'alliance';

// Unsalted MD5, matching how passwords are stored in the DB.  // VULN A02
function md5(input) {
  return crypto.createHash('md5').update(String(input)).digest('hex');
}

// Tokens are signed but NEVER expire (no exp claim).  // VULN A07
function signToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET
  );
}

// Middleware: require a valid token. The role inside the token is trusted as-is.
// Because JWT_SECRET is weak/guessable, a forged token with role=admin also works. // VULN A01/A02
function authRequired(req, res, next) {
  // Accept token from Authorization: Bearer, or from the non-HttpOnly cookie.
  let token = null;
  const header = req.headers['authorization'] || '';
  if (header.startsWith('Bearer ')) token = header.slice(7);
  if (!token && req.cookies && req.cookies.token) token = req.cookies.token;

  if (!token) return res.status(401).json({ error: 'missing token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload; // { id, username, role }
    next();
  } catch (e) {
    return res.status(401).json({ error: 'invalid token' });
  }
}

// Helper some (not all) endpoints use to gate by role.
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

module.exports = { md5, signToken, authRequired, requireRole, JWT_SECRET };
