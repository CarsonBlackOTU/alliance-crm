-- ============================================================================
-- Alliance CRM - schema + seed data
-- Fictional veteran wellness nonprofit. ALL DATA IS FAKE (@example.test,
-- 555-01xx numbers, invented names). Do not put real data here.
-- ============================================================================

DROP TABLE IF EXISTS case_notes CASCADE;
DROP TABLE IF EXISTS password_resets CASCADE;
DROP TABLE IF EXISTS clients CASCADE;
DROP TABLE IF EXISTS staff CASCADE;
DROP TABLE IF EXISTS programs CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;

-- --- Staff / users --------------------------------------------------------
CREATE TABLE staff (
  id            SERIAL PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  full_name     TEXT NOT NULL,
  email         TEXT NOT NULL,
  role          TEXT NOT NULL,              -- admin | program_manager | intake | peer_support | volunteer
  -- Passwords stored as UNSALTED MD5 via postgres md5().  // VULN A02 (crypto failure)
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMP DEFAULT now()
);

-- --- Programs -------------------------------------------------------------
CREATE TABLE programs (
  id          SERIAL PRIMARY KEY,
  name        TEXT NOT NULL,
  description TEXT
);

-- --- Clients (veterans) ---------------------------------------------------
CREATE TABLE clients (
  id               SERIAL PRIMARY KEY,
  full_name        TEXT NOT NULL,
  email            TEXT,
  phone            TEXT,
  referral_source  TEXT,
  service_needs    TEXT,
  notes            TEXT,                     -- free-text intake notes
  program          TEXT,
  enrolled         BOOLEAN DEFAULT false,
  assigned_staff_id INTEGER REFERENCES staff(id),
  created_at       TIMESTAMP DEFAULT now()
);

-- --- Case notes (sensitive, counselling-style) ----------------------------
CREATE TABLE case_notes (
  id         SERIAL PRIMARY KEY,
  client_id  INTEGER NOT NULL REFERENCES clients(id),
  author_id  INTEGER REFERENCES staff(id),
  body       TEXT NOT NULL,                  -- stored raw, rendered with innerHTML  // VULN A03 (stored XSS)
  created_at TIMESTAMP DEFAULT now()
);

-- --- Password resets ------------------------------------------------------
CREATE TABLE password_resets (
  id         SERIAL PRIMARY KEY,
  staff_id   INTEGER REFERENCES staff(id),
  token      TEXT NOT NULL,                  -- predictable token  // VULN A07
  used       BOOLEAN DEFAULT false,
  created_at TIMESTAMP DEFAULT now()
);

-- --- Audit log table exists but the app NEVER writes to it.  // VULN A09 ---
CREATE TABLE audit_log (
  id         SERIAL PRIMARY KEY,
  actor      TEXT,
  action     TEXT,
  created_at TIMESTAMP DEFAULT now()
);

-- ============================================================================
-- SEED: 5 staff users.
-- Passwords are hashed with unsalted MD5. Documented plaintext (also in README):
--   director  / admin123     (admin)            <- default bootstrap pw, never changed
--   pmanager  / Welcome1      (program_manager)  <- reused password
--   intake    / Welcome1      (intake)           <- reused password
--   peer      / Welcome1      (peer_support)     <- reused password
--   volunteer / volunteer     (volunteer)
-- Reused "Welcome1" across 3 accounts is VULN A07 (shared/reused password).
-- ============================================================================
INSERT INTO staff (username, full_name, email, role, password_hash) VALUES
  ('director',  'Janet Reyes',   'janet.reyes@example.test',  'admin',           md5('admin123')),
  ('pmanager',  'Marcus Chen',   'marcus.chen@example.test',  'program_manager', md5('Welcome1')),
  ('intake',    'Tanya Wilson',  'tanya.wilson@example.test', 'intake',          md5('Welcome1')),
  ('peer',      'Derek Patel',   'derek.patel@example.test',  'peer_support',    md5('Welcome1')),
  ('volunteer', 'Alice Kim',     'alice.kim@example.test',    'volunteer',       md5('volunteer'));

INSERT INTO programs (name, description) VALUES
  ('Housing First',            'Rapid re-housing and rental assistance for veterans at risk of homelessness'),
  ('Peer Support Circle',      'Weekly peer-led group sessions'),
  ('Employment Bridge',        'Resume help, interview prep, employer connections'),
  ('Behavioral Health Access', 'Referral and navigation to counselling services'),
  ('Benefits Navigation',      'Help filing VA and state benefit claims');

-- ============================================================================
-- SEED: 50 fake clients, generated programmatically.
-- ============================================================================
INSERT INTO clients (full_name, email, phone, referral_source, service_needs, notes, program, enrolled, assigned_staff_id)
SELECT
  fn || ' ' || ln                                                        AS full_name,
  lower(fn) || '.' || lower(ln) || g || '@example.test'                  AS email,
  '555-01' || lpad(g::text, 2, '0')                                      AS phone,
  (ARRAY['VA Hospital','Self-referral','Community Partner','Walk-in','Shelter Staff','Family Member','Online Form'])[1 + (g * 3 % 7)] AS referral_source,
  (ARRAY['Housing assistance','Employment help','Benefits claim','Counselling referral','Food security','Transportation'])[1 + (g * 5 % 6)] AS service_needs,
  'Intake completed by phone. Veteran reports needing follow-up. (sample note #' || g || ')' AS notes,
  (ARRAY['Housing First','Peer Support Circle','Employment Bridge','Behavioral Health Access','Benefits Navigation'])[1 + (g % 5)] AS program,
  (g % 3 = 0)                                                            AS enrolled,
  (ARRAY[2, 3, 4, 4, NULL]::int[])[1 + (g % 5)]                          AS assigned_staff_id
FROM generate_series(1, 50) AS g
CROSS JOIN LATERAL (
  SELECT
    (ARRAY['James','Maria','Robert','Linda','Michael','Patricia','David','Jennifer','William','Elizabeth',
           'Richard','Susan','Joseph','Jessica','Thomas','Karen','Charles','Nancy','Daniel','Sandra'])[1 + (g * 7 % 20)] AS fn,
    (ARRAY['Anderson','Brooks','Carter','Diaz','Evans','Foster','Garcia','Hughes','Ibrahim','Jackson',
           'Khan','Lopez','Morgan','Nguyen','Owens','Price','Quinn','Russo','Sullivan','Turner'])[1 + (g * 11 % 20)] AS ln
) names;

-- A few seeded case notes (gives scanners/testers existing sensitive content to view).
-- Client ids 1..50 exist; assign notes authored by the peer support worker (id 4).
INSERT INTO case_notes (client_id, author_id, body) VALUES
  (4,  4, 'Veteran attended first Peer Support Circle session. Discussed sleep difficulties. Follow up in 2 weeks.'),
  (8,  4, 'Housing application submitted. Client anxious about timeline; provided reassurance and crisis line number.'),
  (12, 2, 'Enrolled in Employment Bridge. Resume drafted. Note: client disclosed prior financial hardship - handle sensitively.'),
  (16, 4, 'Missed appointment. Left voicemail. Will attempt contact again Thursday.'),
  (20, 2, 'Benefits claim in progress. Awaiting documentation from VA.');

-- Convenience: make sure the clients the peer worker (id 4) is "assigned" to are clear.
-- (Assignment above gives several clients assigned_staff_id = 4.)
