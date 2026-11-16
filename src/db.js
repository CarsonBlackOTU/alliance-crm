// PostgreSQL connection pool.
const { Pool } = require('pg');

const pool = new Pool({
  connectionString:
    process.env.DATABASE_URL ||
    'postgres://alliance:alliance_pg_pw@127.0.0.1:5433/alliance_crm',
});

module.exports = {
  // Parameterized query helper (used by MOST endpoints).
  query: (text, params) => pool.query(text, params),
  // Raw, unparameterized passthrough (used by the deliberately vulnerable search).
  raw: (text) => pool.query(text),
  pool,
};
