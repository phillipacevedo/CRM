// ── CRM Backend Server ──────────────────────────────────────────────────
// Node.js + Express + SQLite + JWT auth
// Client, prospect & industry-contact mgmt with time tracking and billing (IOLTA trust).
// Integrates with DealTracker (matters), SPV-Tracker (SSO), and Leaderboard (exports).
require('dotenv').config();

const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');
const nodemailer = require('nodemailer');
const Database   = require('better-sqlite3');
const rateLimit  = require('express-rate-limit');
const PDFDocument = require('pdfkit');

// Optional: Anthropic SDK for receipt OCR. Server still boots if package or key is missing.
let anthropicClient = null;
try {
  const Anthropic = require('@anthropic-ai/sdk');
  if (process.env.ANTHROPIC_API_KEY) anthropicClient = new Anthropic();
} catch { /* SDK not installed — receipt reading endpoint will return 503 */ }

// ── CONFIG ──────────────────────────────────────────────────────────────
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set.');
  process.exit(1);
}
if (JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET is too short. Use at least 32 random characters.');
  process.exit(1);
}
const JWT_EXPIRY     = '7d';
const BCRYPT_ROUNDS  = 12;
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60;
const DB_PATH = process.env.DB_PATH
  || (process.env.RENDER ? '/data/crm.db' : path.join(__dirname, 'data', 'crm.db'));
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';
const DT_URL  = (process.env.DT_URL  || 'https://dt.phillipacevedo.com').replace(/\/$/, '');
const SPV_URL = (process.env.SPV_URL || 'https://spv.phillipacevedo.com').replace(/\/$/, '');
const LB_URL  = (process.env.LB_URL  || 'https://lb.phillipacevedo.com').replace(/\/$/, '');

// ── ROLES ───────────────────────────────────────────────────────────────
// Rank determines permission level. Higher rank = more access.
const ROLES = {
  admin:              { rank: 100, label: 'Admin' },
  partner:            { rank: 90,  label: 'Partner' },
  associate:          { rank: 70,  label: 'Associate' },
  'project-assistant':{ rank: 60,  label: 'Project Assistant' },
  paralegal:          { rank: 55,  label: 'Paralegal' },
  secretary:          { rank: 40,  label: 'Secretary' },
  staff:              { rank: 20,  label: 'Staff' },
};
const VALID_ROLES = Object.keys(ROLES);

function rankOf(role) { return ROLES[role]?.rank || 0; }

// Capability predicates — single source of truth for permission checks.
const CAPS = {
  manageUsers:      u => !!u.isAdmin,                         // Admin only
  viewAllContacts:  u => rankOf(u.role) >= 40,                // Secretary+
  editContacts:     u => rankOf(u.role) >= 40,                // Secretary+
  logTime:          u => rankOf(u.role) >= 55 && rankOf(u.role) !== 40, // Paralegal, PA, Associate, Partner, Admin
  viewRates:        u => rankOf(u.role) >= 90 || u.isAdmin,   // Partner+
  manageBilling:    u => rankOf(u.role) >= 90 || u.isAdmin,   // Partner+
  manageFirm:       u => !!u.isAdmin,
  conflictCheck:    u => rankOf(u.role) >= 20,                // All
};

function requireCap(capName) {
  return (req, res, next) => {
    const cap = CAPS[capName];
    if (!cap || !cap(req.user)) {
      return res.status(403).json({ error: `Your role (${req.user.role}) is not permitted for this action` });
    }
    next();
  };
}

// ── EMAIL (optional SMTP) ───────────────────────────────────────────────
const smtpConfigured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const mailer = smtpConfigured
  ? nodemailer.createTransport({
      host:   process.env.SMTP_HOST,
      port:   parseInt(process.env.SMTP_PORT || '587'),
      secure: process.env.SMTP_PORT === '465',
      auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

function sanitizeEmailHeader(s) { return String(s || '').replace(/[\r\n]/g, '').slice(0, 200); }

async function sendResetEmail(toEmail, resetUrl) {
  if (!mailer) { console.log(`[No SMTP] Reset link for ${toEmail}: ${resetUrl}`); return; }
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  await mailer.sendMail({
    from, to: toEmail,
    subject: 'CRM — Reset your password',
    text: `Click to reset your password (expires in 1 hour):\n\n${resetUrl}`,
    html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
      <h2 style="color:#0f1f3d">Reset your password</h2>
      <p>Click below to set a new password. Link expires in <strong>1 hour</strong>.</p>
      <p><a href="${resetUrl}" style="background:#c9a227;color:#0f1f3d;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">Reset Password</a></p>
      <p style="color:#aaa;font-size:12px">CRM &middot; phillipacevedo.com</p></div>`,
  });
}

async function sendInviteEmail(toEmail, inviteUrl, firmName, invitedByName) {
  const sf = sanitizeEmailHeader(firmName), sn = sanitizeEmailHeader(invitedByName);
  if (!mailer) { console.log(`[No SMTP] Invite link for ${toEmail}: ${inviteUrl}`); return; }
  const from = process.env.SMTP_FROM || process.env.SMTP_USER;
  await mailer.sendMail({
    from, to: toEmail,
    subject: `You've been invited to ${sf} CRM`,
    text: `${sn} invited you to join ${sf} on CRM.\n\n${inviteUrl}\n\nExpires in 72 hours.`,
    html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto">
      <h2 style="color:#0f1f3d">You've been invited</h2>
      <p><strong>${sn}</strong> invited you to join <strong>${sf}</strong> on CRM.</p>
      <p><a href="${inviteUrl}" style="background:#c9a227;color:#0f1f3d;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:600">Accept Invite</a></p>
      <p style="color:#888;font-size:13px">Expires in <strong>72 hours</strong>.</p></div>`,
  });
}

// ── VALIDATION ──────────────────────────────────────────────────────────
const MAX_NAME = 100, MAX_FIRM = 200, MAX_EMAIL = 254, MAX_PASSWORD = 128, MAX_NOTE = 50000;

function lenErr(v, max, field) {
  if (typeof v !== 'string') return `${field} must be a string`;
  if (v.trim().length > max)  return `${field} must be ${max} characters or fewer`;
  return null;
}

// ── RATE LIMITERS ───────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15*60*1000, max: 15, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in 15 minutes.' },
});
const forgotPasswordLimiter = rateLimit({
  windowMs: 60*60*1000, max: 5, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many reset requests. Try again later.' },
});

// ── DATABASE SETUP ──────────────────────────────────────────────────────
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS firms (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    settings   TEXT DEFAULT '{}',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS users (
    email         TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    first_name    TEXT,
    last_name     TEXT,
    name          TEXT,
    role          TEXT DEFAULT 'associate',
    firm_id       TEXT REFERENCES firms(id),
    is_admin      INTEGER DEFAULT 0,
    default_rate  REAL DEFAULT 0,
    active        INTEGER DEFAULT 1,
    created_at    TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS firm_data (
    firm_id    TEXT PRIMARY KEY REFERENCES firms(id),
    data       TEXT NOT NULL DEFAULT '{}',
    version    INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS user_profiles (
    email      TEXT PRIMARY KEY REFERENCES users(email) ON DELETE CASCADE,
    data       TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS password_resets (
    token TEXT PRIMARY KEY, email TEXT NOT NULL,
    expires_at TEXT NOT NULL, used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS invites (
    token TEXT PRIMARY KEY, email TEXT NOT NULL,
    firm_id TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    role TEXT DEFAULT 'associate', is_admin INTEGER DEFAULT 0,
    expires_at TEXT NOT NULL, used INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS token_denylist (
    jti TEXT PRIMARY KEY, expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  -- Companies (organizations contacts can belong to)
  CREATE TABLE IF NOT EXISTS companies (
    id         TEXT PRIMARY KEY,
    firm_id    TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    website    TEXT,
    industry   TEXT,
    address    TEXT,
    notes      TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );

  -- Contacts (clients, prospects, opposing counsel, judges, experts, etc.)
  CREATE TABLE IF NOT EXISTS contacts (
    id             TEXT PRIMARY KEY,
    firm_id        TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    type           TEXT NOT NULL DEFAULT 'prospect',
    -- types: client, prospect, opposing-counsel, co-counsel, judge, expert, referral, vendor, other
    first_name     TEXT,
    last_name      TEXT,
    full_name      TEXT,
    email          TEXT,
    phone          TEXT,
    title          TEXT,
    company_id     TEXT REFERENCES companies(id) ON DELETE SET NULL,
    company_name   TEXT,   -- denormalized for easier search/display
    address        TEXT,
    linkedin       TEXT,
    referred_by_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    pipeline_stage TEXT,   -- only meaningful for type='prospect'
    tags           TEXT DEFAULT '[]',  -- JSON array of tags
    privilege      INTEGER DEFAULT 0,  -- 1 = privileged/confidential notes
    owner_email    TEXT,                -- primary relationship owner
    notes          TEXT,
    next_action    TEXT,                -- short text, e.g. "Follow up re NDA"
    next_action_at TEXT,                -- ISO date
    last_activity_at TEXT,
    created_by     TEXT,
    created_at     TEXT DEFAULT (datetime('now')),
    updated_at     TEXT DEFAULT (datetime('now'))
  );

  -- Interactions (calls, emails, meetings, notes)
  CREATE TABLE IF NOT EXISTS interactions (
    id          TEXT PRIMARY KEY,
    firm_id     TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    contact_id  TEXT REFERENCES contacts(id) ON DELETE CASCADE,
    company_id  TEXT REFERENCES companies(id) ON DELETE SET NULL,
    matter_id   TEXT,
    kind        TEXT NOT NULL,   -- call | email | meeting | note | task
    subject     TEXT,
    body        TEXT,
    occurred_at TEXT DEFAULT (datetime('now')),
    created_by  TEXT,
    created_at  TEXT DEFAULT (datetime('now'))
  );

  -- Matters (can be local to CRM or a mirror/link to a DT matter)
  CREATE TABLE IF NOT EXISTS matters (
    id              TEXT PRIMARY KEY,
    firm_id         TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    dt_matter_id    TEXT,   -- if linked to a DealTracker matter
    client_contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    client_name     TEXT,
    name            TEXT NOT NULL,
    description     TEXT,
    billing_type    TEXT DEFAULT 'hourly',  -- hourly | flat | contingency
    flat_fee        REAL DEFAULT 0,
    status          TEXT DEFAULT 'active',  -- active | closed | on-hold
    opened_at       TEXT DEFAULT (datetime('now')),
    closed_at       TEXT,
    created_by      TEXT,
    created_at      TEXT DEFAULT (datetime('now')),
    updated_at      TEXT DEFAULT (datetime('now'))
  );

  -- Rate overrides: per-user-per-matter rate (beats user.default_rate)
  CREATE TABLE IF NOT EXISTS matter_rates (
    matter_id   TEXT NOT NULL REFERENCES matters(id) ON DELETE CASCADE,
    user_email  TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
    rate        REAL NOT NULL,
    updated_at  TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (matter_id, user_email)
  );

  -- Time entries
  CREATE TABLE IF NOT EXISTS time_entries (
    id           TEXT PRIMARY KEY,
    firm_id      TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    user_email   TEXT NOT NULL,
    matter_id    TEXT NOT NULL REFERENCES matters(id) ON DELETE CASCADE,
    date         TEXT NOT NULL,     -- YYYY-MM-DD
    minutes      INTEGER NOT NULL,  -- stored as minutes; displayed as decimal hours
    rate         REAL DEFAULT 0,    -- snapshot of rate at time of entry
    description  TEXT,
    billable     INTEGER DEFAULT 1,
    invoice_id   TEXT REFERENCES invoices(id) ON DELETE SET NULL,
    status       TEXT DEFAULT 'draft', -- draft | billed
    created_at   TEXT DEFAULT (datetime('now')),
    updated_at   TEXT DEFAULT (datetime('now'))
  );

  -- Invoices
  CREATE TABLE IF NOT EXISTS invoices (
    id            TEXT PRIMARY KEY,
    firm_id       TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    number        TEXT,   -- INV-2026-0001
    client_contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    client_name   TEXT,
    matter_id     TEXT REFERENCES matters(id) ON DELETE SET NULL,
    issued_at     TEXT,
    due_at        TEXT,
    subtotal      REAL DEFAULT 0,
    tax           REAL DEFAULT 0,
    total         REAL DEFAULT 0,
    amount_paid   REAL DEFAULT 0,
    status        TEXT DEFAULT 'draft',  -- draft | sent | paid | void
    notes         TEXT,
    created_by    TEXT,
    created_at    TEXT DEFAULT (datetime('now')),
    updated_at    TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS invoice_lines (
    id           TEXT PRIMARY KEY,
    invoice_id   TEXT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    kind         TEXT NOT NULL,  -- time | flat | expense
    description  TEXT,
    time_entry_id TEXT REFERENCES time_entries(id) ON DELETE SET NULL,
    quantity     REAL DEFAULT 1,
    rate         REAL DEFAULT 0,
    amount       REAL DEFAULT 0,
    sort_order   INTEGER DEFAULT 0
  );

  -- Trust ledger (IOLTA): deposits, withdrawals, transfers against a client
  CREATE TABLE IF NOT EXISTS trust_ledger (
    id           TEXT PRIMARY KEY,
    firm_id      TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    client_contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    client_name  TEXT,
    matter_id    TEXT REFERENCES matters(id) ON DELETE SET NULL,
    kind         TEXT NOT NULL,  -- deposit | withdrawal | transfer-to-operating | fee-applied | refund
    amount       REAL NOT NULL,  -- positive = deposit; negative = outflow
    reference    TEXT,            -- check #, wire ref, invoice #
    occurred_at  TEXT DEFAULT (datetime('now')),
    notes        TEXT,
    created_by   TEXT,
    created_at   TEXT DEFAULT (datetime('now'))
  );

  -- Live timers: one active timer per user. Row exists only while running/paused.
  CREATE TABLE IF NOT EXISTS timers (
    user_email          TEXT PRIMARY KEY REFERENCES users(email) ON DELETE CASCADE,
    firm_id             TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    matter_id           TEXT REFERENCES matters(id) ON DELETE CASCADE,
    description         TEXT,
    started_at          TEXT,           -- ISO ts when current run began; NULL when paused
    accumulated_seconds INTEGER DEFAULT 0,  -- total from prior pauses
    created_at          TEXT DEFAULT (datetime('now'))
  );

  -- Conflict check audit log (append-only; required for legal ethics compliance)
  CREATE TABLE IF NOT EXISTS conflict_checks (
    id                 TEXT PRIMARY KEY,
    firm_id            TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    run_by_email       TEXT NOT NULL,
    run_by_name        TEXT,
    ran_at             TEXT DEFAULT (datetime('now')),
    query              TEXT NOT NULL,            -- raw multi-line query the user typed
    terms              TEXT NOT NULL,            -- JSON array of parsed terms
    total_hits         INTEGER NOT NULL DEFAULT 0,
    results_snapshot   TEXT NOT NULL,            -- frozen JSON of matches at check time
    context            TEXT DEFAULT 'standalone',-- standalone | client-intake | matter-intake
    related_contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    acknowledged       INTEGER DEFAULT 0,        -- 1 if user accepted hits existed
    notes              TEXT
  );

  -- Expenses (billable or non-billable disbursements per matter)
  CREATE TABLE IF NOT EXISTS expenses (
    id           TEXT PRIMARY KEY,
    firm_id      TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    matter_id    TEXT NOT NULL REFERENCES matters(id) ON DELETE CASCADE,
    user_email   TEXT NOT NULL,
    date         TEXT NOT NULL,    -- YYYY-MM-DD
    category     TEXT,             -- filing-fee | travel | copying | postage | expert | meal | other
    description  TEXT,
    amount       REAL NOT NULL,
    billable     INTEGER DEFAULT 1,
    markup_pct   REAL DEFAULT 0,   -- e.g. 0.10 for 10% markup when billed
    receipt_url  TEXT,
    invoice_id   TEXT REFERENCES invoices(id) ON DELETE SET NULL,
    status       TEXT DEFAULT 'draft',  -- draft | billed
    created_at   TEXT DEFAULT (datetime('now')),
    updated_at   TEXT DEFAULT (datetime('now'))
  );

  -- Receipt PDFs / images attached to expenses (stored as BLOBs in SQLite)
  CREATE TABLE IF NOT EXISTS expense_attachments (
    id           TEXT PRIMARY KEY,
    expense_id   TEXT NOT NULL REFERENCES expenses(id) ON DELETE CASCADE,
    firm_id      TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    mime_type    TEXT NOT NULL,
    size         INTEGER NOT NULL,
    data         BLOB NOT NULL,
    uploaded_by  TEXT NOT NULL,
    created_at   TEXT DEFAULT (datetime('now'))
  );
`);

// ── MIGRATIONS (idempotent ALTERs) ──────────────────────────────────────
const migrations = [
  `ALTER TABLE users ADD COLUMN default_rate REAL DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN active INTEGER DEFAULT 1`,
  `ALTER TABLE users ADD COLUMN discount_rate REAL`,
  `ALTER TABLE contacts ADD COLUMN billing_increment_minutes INTEGER`,
  `ALTER TABLE matters  ADD COLUMN billing_increment_minutes INTEGER`,
  `ALTER TABLE contacts ADD COLUMN mailing_address TEXT`,
  `ALTER TABLE contacts ADD COLUMN date_of_birth TEXT`,
  `ALTER TABLE contacts ADD COLUMN client_since TEXT`,
  `ALTER TABLE contacts ADD COLUMN secondary_email TEXT`,
  `ALTER TABLE contacts ADD COLUMN secondary_phone TEXT`,
  `ALTER TABLE contacts ADD COLUMN industry TEXT`,
  `ALTER TABLE contacts ADD COLUMN tax_id_last4 TEXT`,
  `ALTER TABLE contacts ADD COLUMN preferred_contact TEXT`,
  `ALTER TABLE time_entries ADD COLUMN start_time TEXT`,
  `ALTER TABLE firms ADD COLUMN logo_data BLOB`,
  `ALTER TABLE firms ADD COLUMN logo_mime TEXT`,
];
for (const m of migrations) {
  try { db.exec(m); } catch(e) { /* column already exists */ }
}

// ── INDEXES ─────────────────────────────────────────────────────────────
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_users_firm ON users(firm_id);
  CREATE INDEX IF NOT EXISTS idx_contacts_firm ON contacts(firm_id);
  CREATE INDEX IF NOT EXISTS idx_contacts_type ON contacts(firm_id, type);
  CREATE INDEX IF NOT EXISTS idx_contacts_owner ON contacts(owner_email);
  CREATE INDEX IF NOT EXISTS idx_contacts_company ON contacts(company_id);
  CREATE INDEX IF NOT EXISTS idx_contacts_name ON contacts(firm_id, full_name);
  CREATE INDEX IF NOT EXISTS idx_companies_firm ON companies(firm_id);
  CREATE INDEX IF NOT EXISTS idx_companies_name ON companies(firm_id, name);
  CREATE INDEX IF NOT EXISTS idx_interactions_contact ON interactions(contact_id);
  CREATE INDEX IF NOT EXISTS idx_interactions_firm_time ON interactions(firm_id, occurred_at);
  CREATE INDEX IF NOT EXISTS idx_matters_firm ON matters(firm_id);
  CREATE INDEX IF NOT EXISTS idx_matters_client ON matters(client_contact_id);
  CREATE INDEX IF NOT EXISTS idx_time_firm_date ON time_entries(firm_id, date);
  CREATE INDEX IF NOT EXISTS idx_time_user_date ON time_entries(user_email, date);
  CREATE INDEX IF NOT EXISTS idx_time_matter ON time_entries(matter_id);
  CREATE INDEX IF NOT EXISTS idx_time_invoice ON time_entries(invoice_id);
  CREATE INDEX IF NOT EXISTS idx_invoices_firm ON invoices(firm_id);
  CREATE INDEX IF NOT EXISTS idx_invoices_client ON invoices(client_contact_id);
  CREATE INDEX IF NOT EXISTS idx_invoice_lines_invoice ON invoice_lines(invoice_id);
  CREATE INDEX IF NOT EXISTS idx_trust_firm ON trust_ledger(firm_id);
  CREATE INDEX IF NOT EXISTS idx_trust_client ON trust_ledger(client_contact_id);
  CREATE INDEX IF NOT EXISTS idx_conflict_checks_firm ON conflict_checks(firm_id, ran_at);
  CREATE INDEX IF NOT EXISTS idx_conflict_checks_runner ON conflict_checks(run_by_email);
  CREATE INDEX IF NOT EXISTS idx_conflict_checks_contact ON conflict_checks(related_contact_id);
  CREATE INDEX IF NOT EXISTS idx_expenses_firm_date ON expenses(firm_id, date);
  CREATE INDEX IF NOT EXISTS idx_expenses_matter ON expenses(matter_id);
  CREATE INDEX IF NOT EXISTS idx_expenses_invoice ON expenses(invoice_id);
  CREATE INDEX IF NOT EXISTS idx_expense_attachments_expense ON expense_attachments(expense_id);
  CREATE INDEX IF NOT EXISTS idx_token_denylist_expires ON token_denylist(expires_at);
`);

// ── SEED FIRM + ADMIN (first boot only) ─────────────────────────────────
const seedAdminEmail = (process.env.SEED_ADMIN_EMAIL || 'pacevedo67@gmail.com').toLowerCase().trim();
const seedFirmName   = process.env.SEED_FIRM_NAME || 'Acevedo Law';
(function seedIfEmpty() {
  const firmCount = db.prepare('SELECT COUNT(*) AS c FROM firms').get().c;
  if (firmCount > 0) return;

  const firmId = '_' + crypto.randomBytes(8).toString('hex');
  db.prepare('INSERT INTO firms (id, name) VALUES (?, ?)').run(firmId, seedFirmName);
  db.prepare('INSERT INTO firm_data (firm_id, data, version) VALUES (?, ?, 1)').run(firmId, JSON.stringify({
    pipelineStages: [
      { id: 'lead',       label: 'Lead' },
      { id: 'qualified',  label: 'Qualified' },
      { id: 'meeting',    label: 'Meeting Held' },
      { id: 'pitched',    label: 'Pitched' },
      { id: 'engaged',    label: 'Engaged (Won)' },
      { id: 'lost',       label: 'Lost' },
    ],
    tags: ['VIP','Referral Source','Warm','Cold','Requires Follow-up'],
  }));

  const seedPw = process.env.SEED_ADMIN_PASSWORD;
  if (!seedPw || seedPw.length < 8) {
    console.log(`[SEED] Firm "${seedFirmName}" created (id=${firmId}). No admin user yet — set SEED_ADMIN_PASSWORD env and restart, or run: node reset-password.js ${seedAdminEmail} <pw> after first admin is created.`);
    return;
  }
  const hash = bcrypt.hashSync(seedPw, BCRYPT_ROUNDS);
  db.prepare('INSERT INTO users (email, password_hash, first_name, last_name, name, role, firm_id, is_admin) VALUES (?,?,?,?,?,?,?,?)')
    .run(seedAdminEmail, hash, 'Phillip', 'Acevedo', 'Phillip Acevedo', 'admin', firmId, 1);
  console.log(`[SEED] Created admin ${seedAdminEmail} for firm "${seedFirmName}".`);
})();

// ── HELPERS ─────────────────────────────────────────────────────────────
function uid(prefix='_') {
  return prefix + crypto.randomBytes(8).toString('hex') + Date.now().toString(36);
}

const fmtMoney = (n) => '$' + (Number(n) || 0).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

function makeToken(user, firm) {
  return jwt.sign({
    jti: crypto.randomBytes(16).toString('hex'),
    email: user.email, name: user.name, role: user.role,
    isAdmin: !!user.is_admin, firmId: user.firm_id,
    firmName: firm?.name || '',
  }, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

function parseJSON(s, fallback) { try { return JSON.parse(s); } catch(e) { return fallback; } }

function fullName(first, last) { return [first, last].map(s => (s || '').trim()).filter(Boolean).join(' '); }

// ── EXPRESS APP ─────────────────────────────────────────────────────────
const app = express();

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

if (ALLOWED_ORIGIN === '*' && process.env.NODE_ENV === 'production') {
  console.warn('WARNING: ALLOWED_ORIGIN is "*" in production. Set it to your domain.');
}
app.use(cors(ALLOWED_ORIGIN === '*' ? {} : { origin: ALLOWED_ORIGIN, credentials: true }));
app.use(express.json({ limit: '20mb' }));
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html') || filePath.endsWith('.js')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

// ── COOKIE HELPERS ──────────────────────────────────────────────────────
function setAuthCookie(res, token) {
  const secure = process.env.NODE_ENV === 'production';
  res.setHeader('Set-Cookie',
    `auth_token=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${COOKIE_MAX_AGE}${secure ? '; Secure' : ''}`);
}
function clearAuthCookie(res) {
  res.setHeader('Set-Cookie', 'auth_token=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
}
function getTokenFromRequest(req) {
  const cookieHeader = req.headers.cookie || '';
  const m = cookieHeader.match(/(?:^|;\s*)auth_token=([^;]+)/);
  if (m) return m[1];
  const h = req.headers.authorization || '';
  if (h.startsWith('Bearer ')) return h.slice(7);
  return null;
}

// ── AUTH MIDDLEWARE ─────────────────────────────────────────────────────
function authRequired(req, res, next) {
  const token = getTokenFromRequest(req);
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.jti) {
      const denied = db.prepare('SELECT 1 FROM token_denylist WHERE jti = ?').get(payload.jti);
      if (denied) return res.status(401).json({ error: 'Session revoked. Sign in again.' });
    }
    req.user = payload;
    next();
  } catch(e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}
const adminRequired = requireCap('manageUsers');

function verifyFirmMembership(req, res, next) {
  const u = db.prepare('SELECT firm_id, active FROM users WHERE email = ?').get(req.user.email);
  if (!u || u.firm_id !== req.user.firmId) {
    return res.status(403).json({ error: 'You no longer have access to this firm' });
  }
  if (!u.active) return res.status(403).json({ error: 'Your account has been deactivated' });
  next();
}

// ═══════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════

app.post('/api/auth/logout', authRequired, (req, res) => {
  const token = getTokenFromRequest(req);
  if (token) {
    try {
      const p = jwt.decode(token);
      if (p?.jti && p?.exp) {
        const exp = new Date(p.exp * 1000).toISOString();
        db.prepare('INSERT OR IGNORE INTO token_denylist (jti, expires_at) VALUES (?, ?)').run(p.jti, exp);
        db.prepare("DELETE FROM token_denylist WHERE expires_at < datetime('now')").run();
      }
    } catch(e) {}
  }
  clearAuthCookie(res);
  res.json({ ok: true });
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const emailLower = email.toLowerCase().trim();
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(emailLower);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  if (!user.active) return res.status(403).json({ error: 'Account deactivated. Contact your admin.' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });

  const firm = db.prepare('SELECT * FROM firms WHERE id = ?').get(user.firm_id);
  const token = makeToken(user, firm);
  setAuthCookie(res, token);
  res.json({
    token,
    user: {
      email: user.email, name: user.name, role: user.role, isAdmin: !!user.is_admin,
      firmId: user.firm_id, firmName: firm?.name || '',
    }
  });
});

app.get('/api/auth/me', authRequired, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(req.user.email);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const firm = db.prepare('SELECT * FROM firms WHERE id = ?').get(u.firm_id);
  res.json({
    email: u.email, name: u.name, firstName: u.first_name, lastName: u.last_name,
    role: u.role, isAdmin: !!u.is_admin, firmId: u.firm_id, firmName: firm?.name || '',
    defaultRate: u.default_rate || 0,
  });
});

app.post('/api/auth/change-password', authRequired, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Current and new password required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 chars' });
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(req.user.email);
  const ok = u && await bcrypt.compare(currentPassword, u.password_hash);
  if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });
  const h = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  db.prepare('UPDATE users SET password_hash = ? WHERE email = ?').run(h, req.user.email);
  res.json({ ok: true });
});

app.post('/api/auth/forgot-password', forgotPasswordLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const emailLower = email.toLowerCase().trim();
  const u = db.prepare('SELECT email FROM users WHERE email = ?').get(emailLower);
  if (!u) return res.json({ ok: true });
  db.prepare('DELETE FROM password_resets WHERE email = ?').run(emailLower);
  const t = crypto.randomBytes(32).toString('hex');
  const exp = new Date(Date.now() + 3600*1000).toISOString();
  db.prepare('INSERT INTO password_resets (token, email, expires_at) VALUES (?,?,?)').run(t, emailLower, exp);
  const base = req.headers.origin || `${req.protocol}://${req.get('host')}`;
  await sendResetEmail(emailLower, `${base}/reset-password?token=${t}`);
  res.json({ ok: true });
});

app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return res.status(400).json({ error: 'Token and new password required' });
  if (newPassword.length < 8) return res.status(400).json({ error: 'Password must be at least 8 chars' });
  const r = db.prepare('SELECT * FROM password_resets WHERE token = ? AND used = 0').get(token);
  if (!r) return res.status(400).json({ error: 'Invalid or used reset link' });
  if (new Date(r.expires_at) < new Date()) return res.status(400).json({ error: 'Reset link expired' });
  const h = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  db.prepare('UPDATE users SET password_hash = ? WHERE email = ?').run(h, r.email);
  db.prepare('UPDATE password_resets SET used = 1 WHERE token = ?').run(token);
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(r.email);
  const f = db.prepare('SELECT * FROM firms WHERE id = ?').get(u.firm_id);
  const at = makeToken(u, f);
  setAuthCookie(res, at);
  res.json({ ok: true, token: at });
});

app.post('/api/auth/refresh', authRequired, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(req.user.email);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const f = db.prepare('SELECT * FROM firms WHERE id = ?').get(u.firm_id);
  const t = makeToken(u, f);
  setAuthCookie(res, t);
  res.json({ token: t });
});

// ── SSO EXCHANGES (accept tokens from sibling apps) ─────────────────────
async function exchangeFrom(url, token, res) {
  const r = await fetch(`${url}/api/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(5000),
  });
  if (!r.ok) return res.status(401).json({ error: 'Source token invalid or expired' });
  const d = await r.json();
  const email = d.email?.toLowerCase().trim();
  if (!email) return res.status(401).json({ error: 'No email from source' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !user.active) return res.status(403).json({ error: 'No active CRM account for this email' });
  const firm = db.prepare('SELECT * FROM firms WHERE id = ?').get(user.firm_id);
  const crmToken = makeToken(user, firm);
  setAuthCookie(res, crmToken);
  res.json({ ok: true });
}

app.post('/api/auth/dt-exchange', async (req, res) => {
  if (!req.body?.token) return res.status(400).json({ error: 'token required' });
  try { await exchangeFrom(DT_URL, req.body.token, res); }
  catch(e) { res.status(503).json({ error: 'Could not reach DealTracker' }); }
});

app.post('/api/auth/spv-exchange', async (req, res) => {
  if (!req.body?.token) return res.status(400).json({ error: 'token required' });
  try { await exchangeFrom(SPV_URL, req.body.token, res); }
  catch(e) { res.status(503).json({ error: 'Could not reach SPV Tracker' }); }
});

// ═══════════════════════════════════════════════════════════════════════
// USER / SEAT MANAGEMENT
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/me/profile', authRequired, (req, res) => {
  const r = db.prepare('SELECT data FROM user_profiles WHERE email = ?').get(req.user.email);
  res.json(r ? parseJSON(r.data, {}) : {});
});

app.put('/api/me/profile', authRequired, (req, res) => {
  db.prepare(`INSERT INTO user_profiles (email, data, updated_at) VALUES (?, ?, datetime('now'))
              ON CONFLICT(email) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`)
    .run(req.user.email, JSON.stringify(req.body));
  res.json({ ok: true });
});

app.put('/api/me', authRequired, (req, res) => {
  const { firstName, lastName } = req.body;
  if (!firstName || !lastName) return res.status(400).json({ error: 'First and last name required' });
  const e = lenErr(firstName, MAX_NAME, 'First name') || lenErr(lastName, MAX_NAME, 'Last name');
  if (e) return res.status(400).json({ error: e });
  const full = fullName(firstName, lastName);
  db.prepare('UPDATE users SET first_name = ?, last_name = ?, name = ? WHERE email = ?')
    .run(firstName.trim(), lastName.trim(), full, req.user.email);
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(req.user.email);
  const f = db.prepare('SELECT * FROM firms WHERE id = ?').get(u.firm_id);
  const t = makeToken(u, f);
  setAuthCookie(res, t);
  res.json({ ok: true, token: t });
});

app.get('/api/seats', authRequired, verifyFirmMembership, (req, res) => {
  const users = db.prepare('SELECT email, first_name, last_name, name, role, is_admin, default_rate, discount_rate, active, created_at FROM users WHERE firm_id = ? ORDER BY created_at').all(req.user.firmId);
  const canSeeRates = CAPS.viewRates(req.user);
  res.json({
    roles: Object.entries(ROLES).map(([id, v]) => ({ id, label: v.label, rank: v.rank })),
    users: users.map(u => ({
      email: u.email, firstName: u.first_name, lastName: u.last_name, name: u.name,
      role: u.role, isAdmin: !!u.is_admin, active: !!u.active,
      defaultRate:  canSeeRates ? u.default_rate  : null,
      discountRate: canSeeRates ? u.discount_rate : null,
      createdAt: u.created_at,
    }))
  });
});

app.post('/api/seats/invite', authRequired, adminRequired, async (req, res) => {
  const { email, role, isAdmin } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  if (role && !VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  const emailLower = email.toLowerCase().trim();
  const exists = db.prepare('SELECT email FROM users WHERE email = ?').get(emailLower);
  if (exists) return res.status(409).json({ error: 'An account with this email already exists' });

  db.prepare('DELETE FROM invites WHERE email = ? AND firm_id = ?').run(emailLower, req.user.firmId);
  const token = crypto.randomBytes(32).toString('hex');
  const exp   = new Date(Date.now() + 72*3600*1000).toISOString();
  db.prepare('INSERT INTO invites (token, email, firm_id, role, is_admin, expires_at) VALUES (?,?,?,?,?,?)')
    .run(token, emailLower, req.user.firmId, role || 'associate', isAdmin ? 1 : 0, exp);
  const firm = db.prepare('SELECT * FROM firms WHERE id = ?').get(req.user.firmId);
  const base = req.headers.origin || `${req.protocol}://${req.get('host')}`;
  await sendInviteEmail(emailLower, `${base}/accept-invite?token=${token}`, firm.name, req.user.name);
  res.json({ ok: true });
});

app.get('/api/auth/invite-info', (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).json({ error: 'Token required' });
  const i = db.prepare('SELECT * FROM invites WHERE token = ? AND used = 0').get(token);
  if (!i) return res.status(404).json({ error: 'Invalid or used invite' });
  if (new Date(i.expires_at) < new Date()) return res.status(410).json({ error: 'Invite expired' });
  const f = db.prepare('SELECT name FROM firms WHERE id = ?').get(i.firm_id);
  res.json({ email: i.email, firmName: f?.name || '', role: i.role });
});

app.post('/api/auth/accept-invite', authLimiter, async (req, res) => {
  const { token, firstName, lastName, password } = req.body;
  if (!token || !firstName || !lastName || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 chars' });
  const i = db.prepare('SELECT * FROM invites WHERE token = ? AND used = 0').get(token);
  if (!i) return res.status(404).json({ error: 'Invalid invite' });
  if (new Date(i.expires_at) < new Date()) return res.status(410).json({ error: 'Invite expired' });
  const exists = db.prepare('SELECT email FROM users WHERE email = ?').get(i.email);
  if (exists) return res.status(409).json({ error: 'Account exists — try logging in' });

  const full = fullName(firstName, lastName);
  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  db.transaction(() => {
    db.prepare('INSERT INTO users (email, password_hash, first_name, last_name, name, role, firm_id, is_admin) VALUES (?,?,?,?,?,?,?,?)')
      .run(i.email, hash, firstName.trim(), lastName.trim(), full, i.role, i.firm_id, i.is_admin);
    db.prepare('UPDATE invites SET used = 1 WHERE token = ?').run(token);
  })();

  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(i.email);
  const f = db.prepare('SELECT * FROM firms WHERE id = ?').get(i.firm_id);
  const at = makeToken(u, f);
  setAuthCookie(res, at);
  res.json({ ok: true, token: at });
});

app.put('/api/seats/:email', authRequired, adminRequired, (req, res) => {
  const emailLower = req.params.email.toLowerCase().trim();
  const u = db.prepare('SELECT * FROM users WHERE email = ? AND firm_id = ?').get(emailLower, req.user.firmId);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const { firstName, lastName, role, defaultRate, discountRate, active } = req.body;
  if (role && !VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  const newFirst = (firstName ?? u.first_name ?? '').trim();
  const newLast  = (lastName  ?? u.last_name  ?? '').trim();
  const newRole  = role || u.role;
  const newName  = fullName(newFirst, newLast) || u.name;
  const newRate  = typeof defaultRate  === 'number' ? defaultRate  : u.default_rate;
  const newDisc  = 'discountRate' in (req.body || {})
    ? (discountRate === null || discountRate === '' ? null : Number(discountRate))
    : u.discount_rate;
  const newActive = typeof active === 'boolean' ? (active ? 1 : 0) : u.active;
  db.prepare('UPDATE users SET first_name=?, last_name=?, name=?, role=?, default_rate=?, discount_rate=?, active=? WHERE email=?')
    .run(newFirst, newLast, newName, newRole, newRate, newDisc, newActive, emailLower);
  res.json({ ok: true });
});

app.patch('/api/seats/:email', authRequired, adminRequired, (req, res) => {
  const emailLower = req.params.email.toLowerCase().trim();
  if (emailLower === req.user.email) return res.status(400).json({ error: "You can't change your own admin flag" });
  const u = db.prepare('SELECT * FROM users WHERE email = ? AND firm_id = ?').get(emailLower, req.user.firmId);
  if (!u) return res.status(404).json({ error: 'User not found' });
  const v = req.body.isAdmin ? 1 : 0;
  db.prepare('UPDATE users SET is_admin = ? WHERE email = ?').run(v, emailLower);
  res.json({ ok: true });
});

app.delete('/api/seats/:email', authRequired, adminRequired, (req, res) => {
  const emailLower = req.params.email.toLowerCase().trim();
  if (emailLower === req.user.email) return res.status(400).json({ error: "You can't remove yourself" });
  const u = db.prepare('SELECT * FROM users WHERE email = ? AND firm_id = ?').get(emailLower, req.user.firmId);
  if (!u) return res.status(404).json({ error: 'User not found' });
  // Soft-delete: mark inactive so historical time entries / invoices remain readable.
  db.prepare('UPDATE users SET active = 0 WHERE email = ?').run(emailLower);
  res.json({ ok: true });
});

app.post('/api/seats/:email/reset-password', authRequired, adminRequired, async (req, res) => {
  const emailLower = req.params.email.toLowerCase().trim();
  const u = db.prepare('SELECT email FROM users WHERE email = ? AND firm_id = ?').get(emailLower, req.user.firmId);
  if (!u) return res.status(404).json({ error: 'User not found' });
  db.prepare('DELETE FROM password_resets WHERE email = ?').run(emailLower);
  const t = crypto.randomBytes(32).toString('hex');
  const exp = new Date(Date.now() + 3600*1000).toISOString();
  db.prepare('INSERT INTO password_resets (token, email, expires_at) VALUES (?,?,?)').run(t, emailLower, exp);
  const base = req.headers.origin || `${req.protocol}://${req.get('host')}`;
  await sendResetEmail(emailLower, `${base}/reset-password?token=${t}`);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════
// FIRM SETTINGS (pipeline stages, tags, custom fields — JSON blob)
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/firm', authRequired, verifyFirmMembership, (req, res) => {
  const f = db.prepare('SELECT * FROM firms WHERE id = ?').get(req.user.firmId);
  const s = parseJSON(f.settings, {});
  const data = parseJSON(db.prepare('SELECT data FROM firm_data WHERE firm_id = ?').get(req.user.firmId)?.data || '{}', {});
  res.json({ id: f.id, name: f.name, settings: s, pipelineStages: data.pipelineStages || [], tags: data.tags || [], hasLogo: !!f.logo_data });
});

app.put('/api/firm', authRequired, requireCap('manageFirm'), (req, res) => {
  const { name, settings, pipelineStages, tags } = req.body;
  if (name) db.prepare('UPDATE firms SET name = ? WHERE id = ?').run(name.trim(), req.user.firmId);
  if (settings) db.prepare('UPDATE firms SET settings = ? WHERE id = ?').run(JSON.stringify(settings), req.user.firmId);
  if (pipelineStages || tags) {
    const row = db.prepare('SELECT data FROM firm_data WHERE firm_id = ?').get(req.user.firmId);
    const cur = parseJSON(row?.data || '{}', {});
    if (pipelineStages) cur.pipelineStages = pipelineStages;
    if (tags)           cur.tags = tags;
    db.prepare(`INSERT INTO firm_data (firm_id, data, version, updated_at) VALUES (?, ?, 1, datetime('now'))
                ON CONFLICT(firm_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`)
      .run(req.user.firmId, JSON.stringify(cur));
  }
  res.json({ ok: true });
});

// Firm logo (used in invoice PDFs). Stored as a BLOB on the firms row — same
// pattern as expense_attachments. GET is auth-required so logos don't leak.
const LOGO_MIME_WHITELIST = new Set(['image/png', 'image/jpeg', 'image/jpg']);
const LOGO_MAX_BYTES = 2 * 1024 * 1024;
app.get('/api/firm/logo', authRequired, verifyFirmMembership, (req, res) => {
  const row = db.prepare('SELECT logo_data, logo_mime FROM firms WHERE id = ?').get(req.user.firmId);
  if (!row || !row.logo_data) return res.status(404).json({ error: 'No logo set' });
  res.setHeader('Content-Type', row.logo_mime || 'image/png');
  res.setHeader('Cache-Control', 'private, max-age=60');
  res.send(row.logo_data);
});
app.post('/api/firm/logo', authRequired, requireCap('manageFirm'), (req, res) => {
  const { mimeType, dataBase64 } = req.body || {};
  if (!mimeType || !dataBase64) return res.status(400).json({ error: 'mimeType and dataBase64 required' });
  if (!LOGO_MIME_WHITELIST.has(mimeType)) return res.status(400).json({ error: 'Logo must be PNG or JPEG' });
  let buf;
  try { buf = Buffer.from(dataBase64, 'base64'); }
  catch { return res.status(400).json({ error: 'Invalid base64' }); }
  if (buf.length === 0) return res.status(400).json({ error: 'Empty file' });
  if (buf.length > LOGO_MAX_BYTES) return res.status(413).json({ error: `Logo too large (max ${LOGO_MAX_BYTES / 1024 / 1024} MB)` });
  db.prepare('UPDATE firms SET logo_data = ?, logo_mime = ? WHERE id = ?').run(buf, mimeType, req.user.firmId);
  res.json({ ok: true, size: buf.length, mimeType });
});
app.delete('/api/firm/logo', authRequired, requireCap('manageFirm'), (req, res) => {
  db.prepare('UPDATE firms SET logo_data = NULL, logo_mime = NULL WHERE id = ?').run(req.user.firmId);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════
// CONTACTS
// ═══════════════════════════════════════════════════════════════════════

function visibleContactWhere(user) {
  // Staff can only see contacts they own; everyone else sees all firm contacts.
  if (CAPS.viewAllContacts(user)) return { sql: 'firm_id = ?', params: [user.firmId] };
  return { sql: 'firm_id = ? AND owner_email = ?', params: [user.firmId, user.email] };
}

app.get('/api/contacts', authRequired, verifyFirmMembership, (req, res) => {
  const w = visibleContactWhere(req.user);
  const { q, type, tag, owner, stage } = req.query;
  let sql = `SELECT * FROM contacts WHERE ${w.sql}`;
  const params = [...w.params];
  if (type)  { sql += ' AND type = ?';  params.push(type); }
  if (owner) { sql += ' AND owner_email = ?'; params.push(String(owner).toLowerCase()); }
  if (stage) { sql += ' AND pipeline_stage = ?'; params.push(stage); }
  if (q) {
    sql += ' AND (full_name LIKE ? OR email LIKE ? OR company_name LIKE ? OR notes LIKE ?)';
    const like = `%${q}%`;
    params.push(like, like, like, like);
  }
  sql += ' ORDER BY updated_at DESC LIMIT 1000';
  const rows = db.prepare(sql).all(...params);
  let filtered = rows.map(r => ({ ...r, tags: parseJSON(r.tags, []) }));
  if (tag) filtered = filtered.filter(r => r.tags.includes(tag));
  res.json(filtered);
});

function validateIncrement(v) {
  if (v == null || v === '') return null;
  const n = parseInt(v, 10);
  if (!VALID_INCREMENTS.includes(n)) throw new Error(`Billing increment must be one of: ${VALID_INCREMENTS.join(', ')} minutes`);
  return n;
}

app.post('/api/contacts', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const b = req.body || {};
  const id = uid('c_');
  const first = (b.firstName || '').trim();
  const last  = (b.lastName  || '').trim();
  const full  = (b.fullName || fullName(first, last) || b.companyName || 'Unnamed').trim();
  const now = new Date().toISOString();
  let inc;
  try { inc = validateIncrement(b.billingIncrementMinutes); } catch(e) { return res.status(400).json({ error: e.message }); }
  const last4 = b.taxIdLast4 ? String(b.taxIdLast4).replace(/\D/g, '').slice(-4) : null;
  db.prepare(`INSERT INTO contacts (
      id, firm_id, type, first_name, last_name, full_name, email, phone, title,
      company_id, company_name, address, linkedin, referred_by_id, pipeline_stage,
      tags, privilege, owner_email, notes, next_action, next_action_at,
      billing_increment_minutes,
      mailing_address, date_of_birth, client_since, secondary_email, secondary_phone,
      industry, tax_id_last4, preferred_contact,
      created_by, created_at, updated_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    id, req.user.firmId, b.type || 'prospect', first, last, full,
    b.email || null, b.phone || null, b.title || null,
    b.companyId || null, b.companyName || null, b.address || null, b.linkedin || null,
    b.referredById || null, b.pipelineStage || null,
    JSON.stringify(b.tags || []), b.privilege ? 1 : 0, (b.ownerEmail || req.user.email).toLowerCase(),
    b.notes || null, b.nextAction || null, b.nextActionAt || null,
    inc,
    b.mailingAddress || null, b.dateOfBirth || null, b.clientSince || null,
    b.secondaryEmail || null, b.secondaryPhone || null,
    b.industry || null, last4, b.preferredContact || null,
    req.user.email, now, now
  );
  const c = db.prepare('SELECT * FROM contacts WHERE id = ?').get(id);
  res.json({ ...c, tags: parseJSON(c.tags, []) });
});

app.put('/api/contacts/:id', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const existing = db.prepare('SELECT * FROM contacts WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!existing) return res.status(404).json({ error: 'Contact not found' });
  // Staff: can only edit own contacts
  if (!CAPS.viewAllContacts(req.user) && existing.owner_email !== req.user.email) {
    return res.status(403).json({ error: 'Not your contact' });
  }
  const b = req.body || {};
  const first = b.firstName ?? existing.first_name ?? '';
  const last  = b.lastName  ?? existing.last_name  ?? '';
  const full  = (b.fullName || fullName(first, last) || b.companyName || existing.full_name || 'Unnamed').trim();
  let inc;
  try { inc = 'billingIncrementMinutes' in b ? validateIncrement(b.billingIncrementMinutes) : existing.billing_increment_minutes; }
  catch(e) { return res.status(400).json({ error: e.message }); }
  const last4 = 'taxIdLast4' in b
    ? (b.taxIdLast4 ? String(b.taxIdLast4).replace(/\D/g, '').slice(-4) : null)
    : existing.tax_id_last4;
  db.prepare(`UPDATE contacts SET
      type = COALESCE(?, type),
      first_name = ?, last_name = ?, full_name = ?,
      email = ?, phone = ?, title = ?,
      company_id = ?, company_name = ?, address = ?, linkedin = ?,
      referred_by_id = ?, pipeline_stage = ?,
      tags = ?, privilege = ?, owner_email = ?,
      notes = ?, next_action = ?, next_action_at = ?,
      billing_increment_minutes = ?,
      mailing_address = ?, date_of_birth = ?, client_since = ?,
      secondary_email = ?, secondary_phone = ?,
      industry = ?, tax_id_last4 = ?, preferred_contact = ?,
      updated_at = datetime('now')
    WHERE id = ? AND firm_id = ?`).run(
    b.type || null, (first||'').trim(), (last||'').trim(), full,
    b.email ?? existing.email, b.phone ?? existing.phone, b.title ?? existing.title,
    b.companyId ?? existing.company_id, b.companyName ?? existing.company_name,
    b.address ?? existing.address, b.linkedin ?? existing.linkedin,
    b.referredById ?? existing.referred_by_id, b.pipelineStage ?? existing.pipeline_stage,
    JSON.stringify(b.tags ?? parseJSON(existing.tags, [])),
    typeof b.privilege === 'boolean' ? (b.privilege ? 1 : 0) : existing.privilege,
    (b.ownerEmail ?? existing.owner_email).toLowerCase(),
    b.notes ?? existing.notes, b.nextAction ?? existing.next_action, b.nextActionAt ?? existing.next_action_at,
    inc,
    b.mailingAddress ?? existing.mailing_address,
    b.dateOfBirth ?? existing.date_of_birth,
    b.clientSince ?? existing.client_since,
    b.secondaryEmail ?? existing.secondary_email,
    b.secondaryPhone ?? existing.secondary_phone,
    b.industry ?? existing.industry,
    last4,
    b.preferredContact ?? existing.preferred_contact,
    req.params.id, req.user.firmId
  );
  const c = db.prepare('SELECT * FROM contacts WHERE id = ?').get(req.params.id);
  res.json({ ...c, tags: parseJSON(c.tags, []) });
});

app.delete('/api/contacts/:id', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const existing = db.prepare('SELECT owner_email FROM contacts WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!existing) return res.status(404).json({ error: 'Contact not found' });
  if (!CAPS.viewAllContacts(req.user) && existing.owner_email !== req.user.email) {
    return res.status(403).json({ error: 'Not your contact' });
  }
  db.prepare('DELETE FROM contacts WHERE id = ? AND firm_id = ?').run(req.params.id, req.user.firmId);
  res.json({ ok: true });
});

// Move pipeline stage (drag-and-drop kanban)
app.patch('/api/contacts/:id/stage', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const { stage } = req.body;
  const r = db.prepare(`UPDATE contacts SET pipeline_stage = ?, updated_at = datetime('now')
                        WHERE id = ? AND firm_id = ? AND type = 'prospect'`).run(stage || null, req.params.id, req.user.firmId);
  if (r.changes === 0) return res.status(404).json({ error: 'Prospect not found' });
  res.json({ ok: true });
});

// Conflict check: search + log (single endpoint). Every call creates an audit entry
// unless ?log=0 is passed (used only by the UI's read-only "view past check" flow).
app.get('/api/conflict-check', authRequired, verifyFirmMembership, (req, res) => {
  const raw = String(req.query.q || '');
  const terms = raw.split(/[,\n]+/).map(s => s.trim()).filter(t => t.length >= 2);
  if (terms.length === 0) return res.json({ results: [], logId: null });

  const results = terms.map(term => {
    const like = `%${term}%`;
    const contacts = db.prepare(`SELECT id, full_name, email, type, company_name, notes, owner_email FROM contacts
      WHERE firm_id = ? AND (full_name LIKE ? OR email LIKE ? OR company_name LIKE ? OR notes LIKE ?)
      LIMIT 50`).all(req.user.firmId, like, like, like, like);
    const matters = db.prepare(`SELECT id, name, description, client_name, status FROM matters
      WHERE firm_id = ? AND (name LIKE ? OR description LIKE ? OR client_name LIKE ?)
      LIMIT 50`).all(req.user.firmId, like, like, like);
    return { term, contacts, matters, hits: contacts.length + matters.length };
  });

  let logId = null;
  if (req.query.log !== '0') {
    logId = uid('cc_');
    const totalHits = results.reduce((s, r) => s + r.hits, 0);
    db.prepare(`INSERT INTO conflict_checks
        (id, firm_id, run_by_email, run_by_name, query, terms, total_hits, results_snapshot, context, related_contact_id, acknowledged, notes)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      logId, req.user.firmId, req.user.email, req.user.name,
      raw, JSON.stringify(terms), totalHits, JSON.stringify({ results }),
      req.query.context || 'standalone',
      req.query.relatedContactId || null,
      req.query.acknowledged === '1' ? 1 : 0,
      null);
  }
  res.json({ results, logId });
});

// List past conflict checks. Everyone in the firm can view; admins additionally see notes edits.
app.get('/api/conflict-checks', authRequired, verifyFirmMembership, (req, res) => {
  const { contactId, userEmail, limit } = req.query;
  let sql = `SELECT id, run_by_email, run_by_name, ran_at, query, terms, total_hits, context, related_contact_id, acknowledged, notes
             FROM conflict_checks WHERE firm_id = ?`;
  const p = [req.user.firmId];
  if (contactId) { sql += ' AND related_contact_id = ?'; p.push(contactId); }
  if (userEmail) { sql += ' AND run_by_email = ?'; p.push(String(userEmail).toLowerCase()); }
  sql += ' ORDER BY ran_at DESC LIMIT ?';
  p.push(Math.min(parseInt(limit) || 200, 1000));
  const rows = db.prepare(sql).all(...p);
  res.json(rows.map(r => ({ ...r, terms: parseJSON(r.terms, []) })));
});

app.get('/api/conflict-checks/:id', authRequired, verifyFirmMembership, (req, res) => {
  const r = db.prepare('SELECT * FROM conflict_checks WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!r) return res.status(404).json({ error: 'Not found' });
  res.json({ ...r, terms: parseJSON(r.terms, []), results_snapshot: parseJSON(r.results_snapshot, { results: [] }) });
});

// Annotate a past check (add notes, or update acknowledgement). Immutable core fields are not editable.
app.patch('/api/conflict-checks/:id', authRequired, verifyFirmMembership, (req, res) => {
  const r = db.prepare('SELECT * FROM conflict_checks WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!r) return res.status(404).json({ error: 'Not found' });
  if (r.run_by_email !== req.user.email && !req.user.isAdmin) return res.status(403).json({ error: 'Only the runner or an admin can annotate' });
  const { notes, acknowledged } = req.body || {};
  db.prepare('UPDATE conflict_checks SET notes = COALESCE(?, notes), acknowledged = COALESCE(?, acknowledged) WHERE id = ?')
    .run(notes ?? null, typeof acknowledged === 'boolean' ? (acknowledged ? 1 : 0) : null, req.params.id);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════
// COMPANIES
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/companies', authRequired, verifyFirmMembership, (req, res) => {
  const { q } = req.query;
  let sql = 'SELECT * FROM companies WHERE firm_id = ?';
  const params = [req.user.firmId];
  if (q) { sql += ' AND (name LIKE ? OR industry LIKE ?)'; params.push(`%${q}%`, `%${q}%`); }
  sql += ' ORDER BY name LIMIT 500';
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/companies', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const b = req.body || {};
  if (!b.name?.trim()) return res.status(400).json({ error: 'Name required' });
  const id = uid('co_');
  const now = new Date().toISOString();
  db.prepare(`INSERT INTO companies (id, firm_id, name, website, industry, address, notes, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`).run(
    id, req.user.firmId, b.name.trim(), b.website || null, b.industry || null, b.address || null, b.notes || null, req.user.email, now, now);
  res.json(db.prepare('SELECT * FROM companies WHERE id = ?').get(id));
});

app.put('/api/companies/:id', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const b = req.body || {};
  const r = db.prepare(`UPDATE companies SET
      name = COALESCE(?, name), website = ?, industry = ?, address = ?, notes = ?,
      updated_at = datetime('now')
    WHERE id = ? AND firm_id = ?`).run(
    b.name?.trim() || null, b.website ?? null, b.industry ?? null, b.address ?? null, b.notes ?? null,
    req.params.id, req.user.firmId);
  if (r.changes === 0) return res.status(404).json({ error: 'Company not found' });
  res.json(db.prepare('SELECT * FROM companies WHERE id = ?').get(req.params.id));
});

app.delete('/api/companies/:id', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const r = db.prepare('DELETE FROM companies WHERE id = ? AND firm_id = ?').run(req.params.id, req.user.firmId);
  if (r.changes === 0) return res.status(404).json({ error: 'Company not found' });
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════
// INTERACTIONS
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/interactions', authRequired, verifyFirmMembership, (req, res) => {
  const { contactId, companyId, matterId, limit } = req.query;
  let sql = 'SELECT * FROM interactions WHERE firm_id = ?';
  const params = [req.user.firmId];
  if (contactId) { sql += ' AND contact_id = ?'; params.push(contactId); }
  if (companyId) { sql += ' AND company_id = ?'; params.push(companyId); }
  if (matterId)  { sql += ' AND matter_id = ?';  params.push(matterId); }
  sql += ' ORDER BY occurred_at DESC LIMIT ?';
  params.push(Math.min(parseInt(limit) || 200, 1000));
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/interactions', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const b = req.body || {};
  const id = uid('i_');
  const e = lenErr(b.body || '', MAX_NOTE, 'Body');
  if (e) return res.status(400).json({ error: e });
  db.prepare(`INSERT INTO interactions (id, firm_id, contact_id, company_id, matter_id, kind, subject, body, occurred_at, created_by)
              VALUES (?,?,?,?,?,?,?,?,?,?)`).run(
    id, req.user.firmId, b.contactId || null, b.companyId || null, b.matterId || null,
    b.kind || 'note', b.subject || null, b.body || null,
    b.occurredAt || new Date().toISOString(), req.user.email);
  if (b.contactId) {
    db.prepare(`UPDATE contacts SET last_activity_at = datetime('now'), updated_at = datetime('now') WHERE id = ? AND firm_id = ?`).run(b.contactId, req.user.firmId);
  }
  res.json(db.prepare('SELECT * FROM interactions WHERE id = ?').get(id));
});

app.delete('/api/interactions/:id', authRequired, verifyFirmMembership, (req, res) => {
  // Only author or admin can delete
  const i = db.prepare('SELECT * FROM interactions WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!i) return res.status(404).json({ error: 'Not found' });
  if (i.created_by !== req.user.email && !req.user.isAdmin) return res.status(403).json({ error: 'Only the author or an admin can delete' });
  db.prepare('DELETE FROM interactions WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════
// MATTERS (CRM-local, optional link to DealTracker)
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/matters', authRequired, verifyFirmMembership, (req, res) => {
  const { status, clientId } = req.query;
  let sql = 'SELECT * FROM matters WHERE firm_id = ?';
  const params = [req.user.firmId];
  if (status)   { sql += ' AND status = ?';            params.push(status); }
  if (clientId) { sql += ' AND client_contact_id = ?'; params.push(clientId); }
  sql += ' ORDER BY opened_at DESC';
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/matters', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const b = req.body || {};
  if (!b.name?.trim()) return res.status(400).json({ error: 'Matter name required' });
  if (b.billingType && !['hourly','flat','contingency'].includes(b.billingType)) return res.status(400).json({ error: 'Invalid billingType' });
  let inc;
  try { inc = validateIncrement(b.billingIncrementMinutes); } catch(e) { return res.status(400).json({ error: e.message }); }
  const id = uid('m_');
  db.prepare(`INSERT INTO matters (id, firm_id, dt_matter_id, client_contact_id, client_name, name, description, billing_type, flat_fee, status, billing_increment_minutes, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    id, req.user.firmId, b.dtMatterId || null, b.clientContactId || null, b.clientName || null,
    b.name.trim(), b.description || null, b.billingType || 'hourly', b.flatFee || 0, b.status || 'active', inc, req.user.email);
  res.json(db.prepare('SELECT * FROM matters WHERE id = ?').get(id));
});

app.put('/api/matters/:id', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const existing = db.prepare('SELECT * FROM matters WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!existing) return res.status(404).json({ error: 'Matter not found' });
  const b = req.body || {};
  if (b.billingType && !['hourly','flat','contingency'].includes(b.billingType)) return res.status(400).json({ error: 'Invalid billingType' });
  let inc;
  try { inc = 'billingIncrementMinutes' in b ? validateIncrement(b.billingIncrementMinutes) : existing.billing_increment_minutes; }
  catch(e) { return res.status(400).json({ error: e.message }); }
  db.prepare(`UPDATE matters SET
      name = COALESCE(?, name), description = ?, billing_type = COALESCE(?, billing_type),
      flat_fee = COALESCE(?, flat_fee), status = COALESCE(?, status),
      client_contact_id = ?, client_name = ?, dt_matter_id = ?,
      billing_increment_minutes = ?,
      closed_at = CASE WHEN ? = 'closed' AND status != 'closed' THEN datetime('now') ELSE closed_at END,
      updated_at = datetime('now')
    WHERE id = ? AND firm_id = ?`).run(
    b.name?.trim() || null, b.description ?? null, b.billingType || null,
    typeof b.flatFee === 'number' ? b.flatFee : null, b.status || null,
    b.clientContactId ?? null, b.clientName ?? null, b.dtMatterId ?? null,
    inc,
    b.status || '', req.params.id, req.user.firmId);
  res.json(db.prepare('SELECT * FROM matters WHERE id = ?').get(req.params.id));
});

app.delete('/api/matters/:id', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const r = db.prepare('DELETE FROM matters WHERE id = ? AND firm_id = ?').run(req.params.id, req.user.firmId);
  if (r.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

// Per-matter rate overrides (Admin/Partner only)
app.get('/api/matters/:id/rates', authRequired, verifyFirmMembership, requireCap('viewRates'), (req, res) => {
  const rows = db.prepare('SELECT matter_id, user_email, rate FROM matter_rates WHERE matter_id = ?').all(req.params.id);
  res.json(rows);
});

app.put('/api/matters/:id/rates', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  // body: [{ userEmail, rate }]
  const list = Array.isArray(req.body) ? req.body : [];
  const tx = db.transaction((items) => {
    db.prepare('DELETE FROM matter_rates WHERE matter_id = ?').run(req.params.id);
    const ins = db.prepare('INSERT INTO matter_rates (matter_id, user_email, rate) VALUES (?,?,?)');
    items.forEach(it => ins.run(req.params.id, String(it.userEmail).toLowerCase(), Number(it.rate) || 0));
  });
  tx(list);
  res.json({ ok: true });
});

// Pull DealTracker matters (proxy to DT API for linking)
app.get('/api/dt/matters', authRequired, verifyFirmMembership, async (req, res) => {
  // We don't have DT's JWT here, so expose just public-safe info via a DT endpoint.
  // Fallback: return empty list with a hint that the user should log into DT and manually enter the dtMatterId.
  try {
    const r = await fetch(`${DT_URL}/api/clients/export`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return res.json({ matters: [], hint: 'DT unreachable — enter dtMatterId manually' });
    const clients = await r.json();
    res.json({ clients });
  } catch(e) {
    res.json({ clients: [], hint: 'DT unreachable' });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// TIME ENTRIES
// ═══════════════════════════════════════════════════════════════════════

function effectiveRate(userEmail, matterId) {
  const override = db.prepare('SELECT rate FROM matter_rates WHERE matter_id = ? AND user_email = ?').get(matterId, userEmail);
  if (override) return override.rate;
  const u = db.prepare('SELECT default_rate FROM users WHERE email = ?').get(userEmail);
  return u?.default_rate || 0;
}

const DEFAULT_INCREMENT_MIN = 6;  // firm default = 0.1 hr (6 min)
const VALID_INCREMENTS = [6, 15];

// Resolve the billing increment in minutes for a matter: matter → client → firm default (6).
function effectiveIncrementMinutes(matterId) {
  const m = db.prepare('SELECT billing_increment_minutes, client_contact_id FROM matters WHERE id = ?').get(matterId);
  if (!m) return DEFAULT_INCREMENT_MIN;
  if (m.billing_increment_minutes) return m.billing_increment_minutes;
  if (m.client_contact_id) {
    const c = db.prepare('SELECT billing_increment_minutes FROM contacts WHERE id = ?').get(m.client_contact_id);
    if (c?.billing_increment_minutes) return c.billing_increment_minutes;
  }
  return DEFAULT_INCREMENT_MIN;
}

app.get('/api/time', authRequired, verifyFirmMembership, (req, res) => {
  const { from, to, matterId, userEmail, status } = req.query;
  let sql = 'SELECT * FROM time_entries WHERE firm_id = ?';
  const params = [req.user.firmId];
  // Role scoping: non-billing roles see only their own time.
  if (!CAPS.manageBilling(req.user)) {
    sql += ' AND user_email = ?';
    params.push(req.user.email);
  } else if (userEmail) {
    sql += ' AND user_email = ?';
    params.push(String(userEmail).toLowerCase());
  }
  if (from) { sql += ' AND date >= ?'; params.push(from); }
  if (to)   { sql += ' AND date <= ?'; params.push(to); }
  if (matterId) { sql += ' AND matter_id = ?'; params.push(matterId); }
  if (status)   { sql += ' AND status = ?';    params.push(status); }
  sql += ' ORDER BY date DESC, created_at DESC LIMIT 2000';
  const rows = db.prepare(sql).all(...params);
  // Hide rate from users who can't see rates
  const canSeeRates = CAPS.viewRates(req.user);
  res.json(rows.map(r => canSeeRates ? r : { ...r, rate: null }));
});

function normStartTime(v) {
  if (v == null || v === '') return null;
  const s = String(v).trim();
  if (!/^\d{1,2}:\d{2}$/.test(s)) return null;
  const [h, m] = s.split(':').map(Number);
  if (h < 0 || h > 23 || m < 0 || m > 59) return null;
  return String(h).padStart(2, '0') + ':' + String(m).padStart(2, '0');
}

app.post('/api/time', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const b = req.body || {};
  if (!b.matterId || !b.date || !b.minutes) return res.status(400).json({ error: 'matterId, date, and minutes required' });
  const m = db.prepare('SELECT id FROM matters WHERE id = ? AND firm_id = ?').get(b.matterId, req.user.firmId);
  if (!m) return res.status(404).json({ error: 'Matter not found' });
  const targetUser = (b.userEmail && req.user.isAdmin) ? String(b.userEmail).toLowerCase() : req.user.email;
  const rate = effectiveRate(targetUser, b.matterId);
  const id = uid('t_');
  db.prepare(`INSERT INTO time_entries (id, firm_id, user_email, matter_id, date, minutes, rate, description, billable, start_time) VALUES (?,?,?,?,?,?,?,?,?,?)`).run(
    id, req.user.firmId, targetUser, b.matterId, b.date, Math.max(0, parseInt(b.minutes)), rate,
    b.description || null, b.billable === false ? 0 : 1, normStartTime(b.startTime));
  res.json(db.prepare('SELECT * FROM time_entries WHERE id = ?').get(id));
});

app.put('/api/time/:id', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const existing = db.prepare('SELECT * FROM time_entries WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!existing) return res.status(404).json({ error: 'Entry not found' });
  if (existing.user_email !== req.user.email && !CAPS.manageBilling(req.user)) return res.status(403).json({ error: 'Not your entry' });
  if (existing.status === 'billed' && !req.user.isAdmin) return res.status(400).json({ error: 'Billed entries cannot be edited' });
  const b = req.body || {};
  const startTime = 'startTime' in b ? normStartTime(b.startTime) : existing.start_time;
  db.prepare(`UPDATE time_entries SET
      date = COALESCE(?, date), minutes = COALESCE(?, minutes),
      description = COALESCE(?, description), billable = COALESCE(?, billable),
      start_time = ?,
      updated_at = datetime('now')
    WHERE id = ?`).run(
    b.date || null, typeof b.minutes === 'number' ? b.minutes : null,
    b.description ?? null, typeof b.billable === 'boolean' ? (b.billable?1:0) : null,
    startTime,
    req.params.id);
  res.json(db.prepare('SELECT * FROM time_entries WHERE id = ?').get(req.params.id));
});

app.delete('/api/time/:id', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const t = db.prepare('SELECT * FROM time_entries WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!t) return res.status(404).json({ error: 'Not found' });
  if (t.user_email !== req.user.email && !CAPS.manageBilling(req.user)) return res.status(403).json({ error: 'Not your entry' });
  if (t.status === 'billed') return res.status(400).json({ error: 'Billed entries cannot be deleted' });
  db.prepare('DELETE FROM time_entries WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════
// INVOICES
// ═══════════════════════════════════════════════════════════════════════

function nextInvoiceNumber(firmId) {
  const year = new Date().getFullYear();
  const row = db.prepare("SELECT number FROM invoices WHERE firm_id = ? AND number LIKE ? ORDER BY number DESC LIMIT 1").get(firmId, `INV-${year}-%`);
  if (!row) return `INV-${year}-0001`;
  const n = parseInt(row.number.split('-')[2] || '0', 10) + 1;
  return `INV-${year}-${String(n).padStart(4, '0')}`;
}

app.get('/api/invoices', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const { status, clientId, matterId } = req.query;
  let sql = 'SELECT * FROM invoices WHERE firm_id = ?';
  const p = [req.user.firmId];
  if (status)   { sql += ' AND status = ?'; p.push(status); }
  if (clientId) { sql += ' AND client_contact_id = ?'; p.push(clientId); }
  if (matterId) { sql += ' AND matter_id = ?'; p.push(matterId); }
  sql += ' ORDER BY created_at DESC LIMIT 500';
  res.json(db.prepare(sql).all(...p));
});

app.get('/api/invoices/:id', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  const lines = db.prepare('SELECT * FROM invoice_lines WHERE invoice_id = ? ORDER BY sort_order, id').all(req.params.id);
  res.json({ ...inv, lines });
});

// Draft an invoice from time entries + optional flat-fee lines
app.post('/api/invoices', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const b = req.body || {};
  if (!b.matterId && !b.clientContactId) return res.status(400).json({ error: 'matterId or clientContactId required' });
  const matter = b.matterId ? db.prepare('SELECT * FROM matters WHERE id = ? AND firm_id = ?').get(b.matterId, req.user.firmId) : null;
  const client = b.clientContactId ? db.prepare('SELECT * FROM contacts WHERE id = ? AND firm_id = ?').get(b.clientContactId, req.user.firmId) : null;
  const clientContactId = b.clientContactId || matter?.client_contact_id || null;
  const clientName      = client?.full_name || matter?.client_name || b.clientName || null;

  const id = uid('inv_');
  const number = nextInvoiceNumber(req.user.firmId);
  const now = new Date().toISOString();

  // Build lines: include all unbilled billable time for this matter (if billing hourly),
  // plus the matter's flat fee (if type=flat and not yet billed), plus any b.extraLines provided.
  const lines = [];
  let sort = 0;
  if (matter) {
    if (matter.billing_type === 'hourly') {
      const times = db.prepare(`SELECT t.*, u.name AS user_name FROM time_entries t
                                LEFT JOIN users u ON u.email = t.user_email
                                WHERE t.matter_id = ? AND t.firm_id = ? AND t.status = 'draft' AND t.billable = 1
                                ORDER BY t.date`).all(matter.id, req.user.firmId);
      times.forEach(t => {
        const hours = t.minutes / 60;
        const amount = +(hours * t.rate).toFixed(2);
        lines.push({
          id: uid('il_'), kind: 'time', description: `${t.user_name || t.user_email} — ${t.date}${t.description ? ': ' + t.description : ''}`,
          time_entry_id: t.id, quantity: +hours.toFixed(2), rate: t.rate, amount, sort_order: sort++
        });
      });
    } else if (matter.billing_type === 'flat' && matter.flat_fee > 0) {
      lines.push({ id: uid('il_'), kind: 'flat', description: `Flat fee — ${matter.name}`,
        time_entry_id: null, quantity: 1, rate: matter.flat_fee, amount: matter.flat_fee, sort_order: sort++ });
    }
    // Always include unbilled billable expenses for this matter (independent of billing_type)
    const expenses = db.prepare(`SELECT * FROM expenses WHERE matter_id = ? AND firm_id = ? AND status = 'draft' AND billable = 1 ORDER BY date`).all(matter.id, req.user.firmId);
    expenses.forEach(e => {
      const gross = +(Number(e.amount) * (1 + Number(e.markup_pct || 0))).toFixed(2);
      lines.push({
        id: uid('il_'), kind: 'expense',
        description: `${(EXPENSE_CATEGORIES.includes(e.category) ? e.category : 'expense')} — ${e.date}${e.description ? ': ' + e.description : ''}`,
        time_entry_id: null, quantity: 1, rate: gross, amount: gross, sort_order: sort++,
        _expense_id: e.id,
      });
    });
  }
  (b.extraLines || []).forEach(l => {
    lines.push({ id: uid('il_'), kind: l.kind || 'expense', description: l.description || '',
      time_entry_id: null, quantity: Number(l.quantity) || 1, rate: Number(l.rate) || 0,
      amount: Number(l.amount ?? (Number(l.quantity) || 1) * (Number(l.rate) || 0)), sort_order: sort++ });
  });

  const subtotal = +lines.reduce((s, l) => s + (l.amount || 0), 0).toFixed(2);
  const taxRate  = Number(b.taxRate) || 0;
  const tax      = +(subtotal * taxRate).toFixed(2);
  const total    = +(subtotal + tax).toFixed(2);

  const tx = db.transaction(() => {
    db.prepare(`INSERT INTO invoices (id, firm_id, number, client_contact_id, client_name, matter_id, issued_at, due_at, subtotal, tax, total, status, notes, created_by)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      id, req.user.firmId, number, clientContactId, clientName, matter?.id || null,
      b.issuedAt || now, b.dueAt || null, subtotal, tax, total, 'draft', b.notes || null, req.user.email);
    const ins = db.prepare(`INSERT INTO invoice_lines (id, invoice_id, kind, description, time_entry_id, quantity, rate, amount, sort_order) VALUES (?,?,?,?,?,?,?,?,?)`);
    lines.forEach(l => ins.run(l.id, id, l.kind, l.description, l.time_entry_id, l.quantity, l.rate, l.amount, l.sort_order));
    // Mark time entries as billed against this invoice
    const markTime = db.prepare(`UPDATE time_entries SET invoice_id = ?, status = 'billed', updated_at = datetime('now') WHERE id = ?`);
    lines.filter(l => l.time_entry_id).forEach(l => markTime.run(id, l.time_entry_id));
    // Mark expenses as billed too
    const markExp = db.prepare(`UPDATE expenses SET invoice_id = ?, status = 'billed', updated_at = datetime('now') WHERE id = ?`);
    lines.filter(l => l._expense_id).forEach(l => markExp.run(id, l._expense_id));
  });
  tx();

  res.json({ id, number, subtotal, tax, total });
});

// Edit a draft invoice: metadata (dates, notes, taxRate) and line fields.
// Locked once status leaves 'draft' (sent/paid/void) — void+regenerate for structural changes.
app.patch('/api/invoices/:id', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  if (inv.status !== 'draft') return res.status(400).json({ error: 'Only draft invoices can be edited. Void first.' });
  const b = req.body || {};
  const existingLines = db.prepare('SELECT id FROM invoice_lines WHERE invoice_id = ?').all(req.params.id);
  const existingIds = new Set(existingLines.map(l => l.id));

  const tx = db.transaction(() => {
    if (Array.isArray(b.lines)) {
      const updLine = db.prepare(`UPDATE invoice_lines SET description = ?, quantity = ?, rate = ?, amount = ? WHERE id = ? AND invoice_id = ?`);
      for (const l of b.lines) {
        if (!l.id || !existingIds.has(l.id)) continue;
        const qty = Number(l.quantity) || 0;
        const rate = Number(l.rate) || 0;
        const amount = +(Number(l.amount ?? (qty * rate)) || 0).toFixed(2);
        updLine.run(String(l.description || ''), qty, rate, amount, l.id, req.params.id);
      }
    }
    const rows = db.prepare('SELECT amount FROM invoice_lines WHERE invoice_id = ?').all(req.params.id);
    const subtotal = +rows.reduce((s, r) => s + (Number(r.amount) || 0), 0).toFixed(2);
    const currentRate = inv.subtotal > 0 ? inv.tax / inv.subtotal : 0;
    const taxRate = (b.taxRate === undefined || b.taxRate === null || b.taxRate === '') ? currentRate : Number(b.taxRate);
    const tax = +(subtotal * (Number.isFinite(taxRate) ? taxRate : 0)).toFixed(2);
    const total = +(subtotal + tax).toFixed(2);
    db.prepare(`UPDATE invoices SET issued_at = ?, due_at = ?, notes = ?, subtotal = ?, tax = ?, total = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(
        b.issuedAt !== undefined ? (b.issuedAt || null) : inv.issued_at,
        b.dueAt    !== undefined ? (b.dueAt    || null) : inv.due_at,
        b.notes    !== undefined ? (b.notes    || null) : inv.notes,
        subtotal, tax, total, req.params.id);
  });
  tx();
  res.json({ ok: true });
});

app.patch('/api/invoices/:id/status', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const { status } = req.body;
  if (!['draft','sent','paid','void'].includes(status)) return res.status(400).json({ error: 'Invalid status' });
  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  db.prepare(`UPDATE invoices SET status = ?, amount_paid = CASE WHEN ? = 'paid' THEN total ELSE amount_paid END, updated_at = datetime('now') WHERE id = ?`)
    .run(status, status, req.params.id);
  // If voided, release the time entries and expenses
  if (status === 'void') {
    db.prepare(`UPDATE time_entries SET invoice_id = NULL, status = 'draft', updated_at = datetime('now') WHERE invoice_id = ?`).run(req.params.id);
    db.prepare(`UPDATE expenses     SET invoice_id = NULL, status = 'draft', updated_at = datetime('now') WHERE invoice_id = ?`).run(req.params.id);
  }
  res.json({ ok: true });
});

app.delete('/api/invoices/:id', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  if (inv.status !== 'draft') return res.status(400).json({ error: 'Only draft invoices can be deleted. Void first.' });
  db.transaction(() => {
    db.prepare(`UPDATE time_entries SET invoice_id = NULL, status = 'draft', updated_at = datetime('now') WHERE invoice_id = ?`).run(req.params.id);
    db.prepare(`UPDATE expenses     SET invoice_id = NULL, status = 'draft', updated_at = datetime('now') WHERE invoice_id = ?`).run(req.params.id);
    db.prepare('DELETE FROM invoices WHERE id = ?').run(req.params.id);
  })();
  res.json({ ok: true });
});

// Render an invoice PDF into the supplied PDFDocument. Shared between the real
// PDF route and the settings-page preview so both stay visually identical.
function renderInvoicePdf(doc, { firm, firmSettings, inv, lines, matter, client, timeEntries, outstanding, logoBuffer }) {
  // Branding / customization
  const template   = firmSettings.invoiceTemplate || 'ap';
  const accent     = firmSettings.accentColor || '#1e3a5f';
  const logoText   = firmSettings.invoiceLogoText || (firm.name || '').toUpperCase();
  const firmAddr   = firmSettings.address || '';
  const remitName  = firmSettings.remitPayeeName || firm.name || '';
  const remitAddr  = firmSettings.remitAddress || firmAddr;
  const wire = {
    beneficiaryName:    firmSettings.wireBeneficiaryName || remitName,
    beneficiaryAddress: firmSettings.wireBeneficiaryAddress || remitAddr,
    accountNumber:      firmSettings.wireAccountNumber || '',
    routingNumber:      firmSettings.wireRoutingNumber || '',
    bankName:           firmSettings.wireBankName || '',
    bankAddress:        firmSettings.wireBankAddress || '',
  };
  const footerText = firmSettings.invoiceFooterText || 'INVOICES ARE PAYABLE UPON RECEIPT';
  const muted = '#666';
  const border = '#c8d3e0';

  // Fallback to the original simple format if the firm prefers it
  if (template === 'simple') {
    doc.fontSize(20).fillColor(accent).text(firm.name, 50, 50);
    if (firmAddr) doc.fontSize(10).fillColor(muted).text(firmAddr);
    doc.fontSize(24).fillColor(accent).text('INVOICE', 400, 50, { align: 'right' });
    doc.fontSize(10).fillColor('#333').text(inv.number || '', 400, 80, { align: 'right' });
    doc.moveTo(50, 130).lineTo(562, 130).strokeColor('#ddd').stroke();
    doc.fontSize(9).fillColor('#888').text('BILL TO', 50, 150);
    doc.fontSize(11).fillColor('#111').text(inv.client_name || '—', 50, 165);
    doc.fontSize(9).fillColor('#888').text('ISSUED', 380, 150);
    doc.fontSize(11).fillColor('#111').text((inv.issued_at || '').slice(0,10), 380, 165);
    doc.fontSize(9).fillColor('#888').text('DUE', 480, 150);
    doc.fontSize(11).fillColor('#111').text((inv.due_at || '').slice(0,10) || '—', 480, 165);
    let y = 220;
    doc.moveTo(50, y).lineTo(562, y).strokeColor('#ddd').stroke();
    y += 10;
    doc.fontSize(9).fillColor('#888');
    doc.text('DESCRIPTION', 50, y);
    doc.text('QTY', 340, y, { width: 50, align: 'right' });
    doc.text('RATE', 400, y, { width: 70, align: 'right' });
    doc.text('AMOUNT', 480, y, { width: 80, align: 'right' });
    y += 16;
    doc.moveTo(50, y).lineTo(562, y).strokeColor('#ddd').stroke();
    y += 8;
    doc.fontSize(10).fillColor('#111');
    lines.forEach(l => {
      const h = Math.max(18, Math.ceil((l.description || '').length / 55) * 14);
      doc.text(l.description || '', 50, y, { width: 280 });
      doc.text(String(l.quantity), 340, y, { width: 50, align: 'right' });
      doc.text(fmtMoney(l.rate), 400, y, { width: 70, align: 'right' });
      doc.text(fmtMoney(l.amount), 480, y, { width: 80, align: 'right' });
      y += h;
      if (y > 700) { doc.addPage(); y = 60; }
    });
    y += 10;
    doc.moveTo(340, y).lineTo(562, y).strokeColor('#ddd').stroke();
    y += 10;
    doc.fontSize(10).fillColor('#333');
    doc.text('Subtotal', 340, y, { width: 140, align: 'right' });
    doc.text(fmtMoney(inv.subtotal), 480, y, { width: 80, align: 'right' });
    y += 16;
    if (inv.tax > 0) {
      doc.text('Tax', 340, y, { width: 140, align: 'right' });
      doc.text(fmtMoney(inv.tax), 480, y, { width: 80, align: 'right' });
      y += 16;
    }
    doc.fontSize(12).fillColor(accent);
    doc.text('TOTAL', 340, y, { width: 140, align: 'right' });
    doc.text(fmtMoney(inv.total), 480, y, { width: 80, align: 'right' });
    if (inv.notes) {
      y += 50;
      doc.fontSize(9).fillColor('#888').text('NOTES', 50, y);
      y += 12;
      doc.fontSize(10).fillColor('#333').text(inv.notes, 50, y, { width: 512 });
    }
    return;
  }

  // ─── AP template ──────────────────────────────────────────────────────────
  const PAGE_LEFT = 50, PAGE_RIGHT = 562, PAGE_WIDTH = PAGE_RIGHT - PAGE_LEFT;
  // PDFKit's default 50pt bottom margin auto-inserts a page if text would cross
  // y=742 (= 792-50). Keep all positioning within that envelope.
  const PAGE_BOTTOM = 720;

  const longDate = (s) => {
    if (!s) return '';
    const d = new Date(s);
    return isNaN(d) ? String(s).slice(0,10) :
      d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
  };
  const shortDate = (s) => {
    if (!s) return '';
    const m = String(s).match(/^(\d{4})-(\d{2})-(\d{2})/);
    if (m) return `${parseInt(m[2])}/${parseInt(m[3])}/${m[1].slice(2)}`;
    const d = new Date(s);
    return isNaN(d) ? String(s) : d.toLocaleDateString('en-US', { year: '2-digit', month: 'numeric', day: 'numeric' });
  };
  const timekeeperName = (t) => t.user_name || [t.user_first, t.user_last].filter(Boolean).join(' ') || t.user_email || '';

  // Logo: try the provided buffer, otherwise fall back to the text variant.
  const tryImage = (x, y, opts) => {
    if (!logoBuffer) return null;
    try { doc.image(logoBuffer, x, y, opts); return true; }
    catch { return null; }
  };

  const clientLines = [];
  if (inv.client_name) clientLines.push(inv.client_name);
  if (client?.address) clientLines.push(...String(client.address).split(/\r?\n/).map(s => s.trim()).filter(Boolean));
  else if (client?.company_name && client.company_name !== inv.client_name) clientLines.push(client.company_name);
  if (client?.email) clientLines.push(client.email);

  // Draw a header. Returns the y-position at which content may start.
  // Full header reserves room for ACH block; short header is compact for
  // subsequent pages. Both now *measure* their content rather than using
  // hard-coded magic numbers, so tall logos / long client blocks don't clip.
  const drawHeader = (short) => {
    if (short) {
      const topY = 40;
      const logoH = short ? 26 : 50;
      if (!tryImage(PAGE_LEFT, topY, { fit: [180, logoH] })) {
        doc.font('Helvetica-Bold').fontSize(12).fillColor(accent)
           .text(logoText, PAGE_LEFT, topY + 4, { width: 260, lineBreak: false, ellipsis: true });
      }
      doc.font('Helvetica-Bold').fontSize(16).fillColor(accent)
         .text('INVOICE', PAGE_LEFT, topY, { width: PAGE_WIDTH, align: 'right' });
      doc.font('Helvetica').fontSize(9).fillColor(muted)
         .text(`${inv.number || ''}  ·  ${longDate(inv.issued_at)}`, PAGE_LEFT, topY + 18, { width: PAGE_WIDTH, align: 'right' });

      let y = topY + logoH + 8;
      doc.font('Helvetica').fontSize(9).fillColor('#222');
      for (const line of clientLines) {
        doc.text(line, PAGE_LEFT, y, { width: PAGE_WIDTH * 0.6 });
        y += 11;
      }
      y = Math.max(y, topY + logoH + 8);
      doc.moveTo(PAGE_LEFT, y + 6).lineTo(PAGE_RIGHT, y + 6).strokeColor(accent).lineWidth(0.5).stroke();
      return y + 22;
    }

    // Full header (cover page)
    const topY = 50;
    const logoMaxH = 60, logoMaxW = 280;
    let logoBottom = topY;
    if (tryImage(PAGE_LEFT, topY, { fit: [logoMaxW, logoMaxH] })) {
      logoBottom = topY + logoMaxH;
    } else {
      doc.font('Helvetica-Bold').fontSize(24).fillColor(accent)
         .text(logoText, PAGE_LEFT, topY + 10, { width: logoMaxW, lineBreak: false, ellipsis: true });
      logoBottom = topY + 44;
    }
    doc.font('Helvetica-Bold').fontSize(28).fillColor(accent)
       .text('INVOICE', PAGE_LEFT, topY + 12, { width: PAGE_WIDTH, align: 'right' });

    const dividerY = Math.max(logoBottom + 6, topY + 58);
    doc.moveTo(PAGE_LEFT, dividerY).lineTo(PAGE_RIGHT, dividerY).strokeColor(accent).lineWidth(1.5).stroke();

    // Bill-to (left) and invoice meta (right)
    const blockTop = dividerY + 16;
    doc.font('Helvetica').fontSize(10).fillColor('#111');
    let ly = blockTop;
    for (const line of clientLines) {
      doc.text(line, PAGE_LEFT, ly, { width: PAGE_WIDTH * 0.55 });
      ly += 13;
    }

    const metaX = PAGE_LEFT + PAGE_WIDTH * 0.58;
    const metaW = PAGE_WIDTH - PAGE_WIDTH * 0.58;
    doc.font('Helvetica-Bold').fontSize(10).fillColor('#111')
       .text(`Invoice No. ${inv.number || ''}`, metaX, blockTop, { width: metaW, align: 'right' });
    doc.font('Helvetica').fontSize(10).fillColor('#333')
       .text(longDate(inv.issued_at), metaX, blockTop + 14, { width: metaW, align: 'right' });
    if (inv.due_at) {
      doc.text('Due: ' + longDate(inv.due_at), metaX, blockTop + 28, { width: metaW, align: 'right' });
    }

    const metaBottom = blockTop + (inv.due_at ? 44 : 28);
    return Math.max(ly, metaBottom) + 20;
  };

  // Render a table (header + rows). Handles auto-sized header and rows, and
  // page-breaks while preserving the short header and the table head.
  const renderTable = (cols, rows, opts = {}) => {
    const headerPad = 6;
    const cellPad = 5;
    const headerFontSize = opts.headerFontSize || 9;
    const bodyFontSize   = opts.bodyFontSize   || 9.5;

    const drawHeaderRow = () => {
      doc.font('Helvetica-Bold').fontSize(headerFontSize);
      let maxH = 0;
      for (const c of cols) {
        const h = doc.heightOfString(c.label, { width: c.w - cellPad * 2, align: c.align || 'left' });
        if (h > maxH) maxH = h;
      }
      const rowH = maxH + headerPad * 2;
      doc.save().rect(PAGE_LEFT, y, PAGE_WIDTH, rowH).fill(accent).restore();
      doc.font('Helvetica-Bold').fontSize(headerFontSize).fillColor('#fff');
      for (const c of cols) {
        doc.text(c.label, c.x + cellPad, y + headerPad, { width: c.w - cellPad * 2, align: c.align || 'left' });
      }
      y += rowH;
    };

    drawHeaderRow();

    doc.font('Helvetica').fontSize(bodyFontSize).fillColor('#111');
    for (const row of rows) {
      // Measure the row using the tallest cell.
      let maxH = 14;
      for (let i = 0; i < cols.length; i++) {
        const cell = row[i] == null ? '' : String(row[i]);
        const h = doc.heightOfString(cell, { width: cols[i].w - cellPad * 2, align: cols[i].align || 'left' });
        if (h > maxH) maxH = h;
      }
      const rowH = maxH + 8;
      // Page break if needed — redraw the short header and table head.
      if (y + rowH > PAGE_BOTTOM - 40) {
        doc.addPage();
        y = drawHeader(true);
        drawHeaderRow();
      }
      for (let i = 0; i < cols.length; i++) {
        const cell = row[i] == null ? '' : String(row[i]);
        doc.font('Helvetica').fontSize(bodyFontSize).fillColor('#111')
           .text(cell, cols[i].x + cellPad, y + 4, { width: cols[i].w - cellPad * 2, align: cols[i].align || 'left' });
      }
      doc.moveTo(PAGE_LEFT, y + rowH).lineTo(PAGE_RIGHT, y + rowH).strokeColor(border).lineWidth(0.3).stroke();
      y += rowH;
    }
  };

  // Write centered + sized title, advancing y by actual (measured) height.
  const writeTitle = (text, size, align = 'left') => {
    doc.font('Helvetica-Bold').fontSize(size).fillColor(accent);
    const h = doc.heightOfString(text, { width: PAGE_WIDTH, align });
    doc.text(text, PAGE_LEFT, y, { width: PAGE_WIDTH, align });
    y += h + 8;
  };

  // ═══ Page 1: Cover + Billing Summary ════════════════════════════════════
  let y = drawHeader(false);

  writeTitle('BILLING SUMMARY', 14, 'center');
  doc.font('Helvetica-Oblique').fontSize(10).fillColor('#333');
  const subtitleText = `For Professional Services Rendered as of ${longDate(inv.issued_at)}`;
  const subtitleH = doc.heightOfString(subtitleText, { width: PAGE_WIDTH, align: 'center' });
  doc.text(subtitleText, PAGE_LEFT, y, { width: PAGE_WIDTH, align: 'center' });
  y += subtitleH + 16;

  // Totals
  const servicesTotal = lines.filter(l => l.kind === 'time' || l.kind === 'flat').reduce((s, l) => s + (Number(l.amount) || 0), 0);
  const costsTotal    = lines.filter(l => l.kind === 'expense').reduce((s, l) => s + (Number(l.amount) || 0), 0);
  const matterLabel   = matter?.dt_matter_id || (inv.matter_id ? inv.matter_id.replace(/^mat_/, '').slice(0, 8) : '—');
  const matterDesc    = matter?.name || matter?.description || '';

  // Summary table: balanced columns so no header wraps awkwardly
  const sumCols = [
    { label: 'Matter #',    x: PAGE_LEFT,       w: 64,  align: 'left'  },
    { label: 'Description', x: PAGE_LEFT + 64,  w: 216, align: 'left'  },
    { label: 'Fees',        x: PAGE_LEFT + 280, w: 80,  align: 'right' },
    { label: 'Costs',       x: PAGE_LEFT + 360, w: 76,  align: 'right' },
    { label: 'Total',       x: PAGE_LEFT + 436, w: 76,  align: 'right' },
  ];
  renderTable(sumCols, [
    [matterLabel, matterDesc, fmtMoney(servicesTotal), fmtMoney(costsTotal), fmtMoney(inv.subtotal)],
  ], { headerFontSize: 9, bodyFontSize: 10 });

  // Totals row — manually styled (shaded)
  const totalsH = 24;
  doc.save().rect(PAGE_LEFT, y, PAGE_WIDTH, totalsH).fill('#eef2f7').restore();
  doc.font('Helvetica-Bold').fontSize(10).fillColor('#111')
     .text('Total', sumCols[0].x + 5, y + 7, { width: sumCols[1].x + sumCols[1].w - sumCols[0].x - 10 });
  doc.text(fmtMoney(servicesTotal), sumCols[2].x + 5, y + 7, { width: sumCols[2].w - 10, align: 'right' });
  doc.text(fmtMoney(costsTotal),    sumCols[3].x + 5, y + 7, { width: sumCols[3].w - 10, align: 'right' });
  doc.text(fmtMoney(inv.subtotal),  sumCols[4].x + 5, y + 7, { width: sumCols[4].w - 10, align: 'right' });
  y += totalsH + 8;

  if (inv.tax > 0) {
    doc.font('Helvetica').fontSize(10).fillColor('#333');
    doc.text('Tax', sumCols[3].x - 80, y, { width: 140 + 80, align: 'right' });
    doc.text(fmtMoney(inv.tax), sumCols[4].x + 5, y, { width: sumCols[4].w - 10, align: 'right' });
    y += 16;
    doc.font('Helvetica-Bold').fontSize(11).fillColor(accent);
    doc.text('Invoice Total', sumCols[3].x - 80, y, { width: 140 + 80, align: 'right' });
    doc.text(fmtMoney(inv.total), sumCols[4].x + 5, y, { width: sumCols[4].w - 10, align: 'right' });
    y += 20;
  }

  doc.font('Helvetica-Oblique').fontSize(10).fillColor(muted)
     .text('Payment Details on Last Page', PAGE_LEFT, PAGE_BOTTOM - 20, { width: PAGE_WIDTH, align: 'center', lineBreak: false });

  // ═══ Professional Services detail ═══════════════════════════════════════
  if (timeEntries.length > 0) {
    doc.addPage();
    y = drawHeader(true);
    writeTitle(`Summary of Professional Services — ${matterDesc || matterLabel}`, 12, 'left');

    const tCols = [
      { label: 'Date',        x: PAGE_LEFT,       w: 58,  align: 'left'  },
      { label: 'Timekeeper',  x: PAGE_LEFT + 58,  w: 100, align: 'left'  },
      { label: 'Description', x: PAGE_LEFT + 158, w: 198, align: 'left'  },
      { label: 'Hours',       x: PAGE_LEFT + 356, w: 46,  align: 'right' },
      { label: 'Rate',        x: PAGE_LEFT + 402, w: 54,  align: 'right' },
      { label: 'Amount',      x: PAGE_LEFT + 456, w: 56,  align: 'right' },
    ];
    const rows = [];
    let total = 0;
    let totalHours = 0;
    const byTimekeeper = new Map();
    for (const t of timeEntries) {
      const hours = (Number(t.minutes) || 0) / 60;
      const amount = +(hours * (Number(t.rate) || 0)).toFixed(2);
      total += amount;
      totalHours += hours;
      const tk = timekeeperName(t) || '(unassigned)';
      const agg = byTimekeeper.get(tk) || { hours: 0, amount: 0 };
      agg.hours += hours;
      agg.amount += amount;
      byTimekeeper.set(tk, agg);
      rows.push([shortDate(t.date), timekeeperName(t), t.description || '', hours.toFixed(2), fmtMoney(t.rate), fmtMoney(amount)]);
    }
    renderTable(tCols, rows);

    // Footer row — total hours + total amount
    y += 4;
    doc.moveTo(PAGE_LEFT, y).lineTo(PAGE_RIGHT, y).strokeColor(accent).lineWidth(1).stroke();
    y += 8;
    doc.font('Helvetica-Bold').fontSize(10).fillColor(accent)
       .text('Total Professional Services Rendered', PAGE_LEFT, y, { width: tCols[3].x - PAGE_LEFT - 5, align: 'right' });
    doc.text(totalHours.toFixed(2), tCols[3].x + 5, y, { width: tCols[3].w - 10, align: 'right' });
    doc.text(fmtMoney(total),       tCols[5].x + 5, y, { width: tCols[5].w - 10, align: 'right' });
    y += 24;

    // Summary by timekeeper
    if (byTimekeeper.size > 0) {
      // Page-break if this section wouldn't have room for a title + at least
      // a header row and one data row (~80pt).
      if (y + 80 > PAGE_BOTTOM) {
        doc.addPage();
        y = drawHeader(true);
      }
      writeTitle('Summary by Timekeeper', 12, 'left');
      const tkCols = [
        { label: 'Timekeeper', x: PAGE_LEFT,       w: 300, align: 'left'  },
        { label: 'Hours',      x: PAGE_LEFT + 300, w: 100, align: 'right' },
        { label: 'Amount',     x: PAGE_LEFT + 400, w: 112, align: 'right' },
      ];
      const tkRows = [...byTimekeeper.entries()]
        .sort((a, b) => b[1].amount - a[1].amount)
        .map(([name, v]) => [name, v.hours.toFixed(2), fmtMoney(v.amount)]);
      renderTable(tkCols, tkRows);

      y += 4;
      doc.moveTo(PAGE_LEFT, y).lineTo(PAGE_RIGHT, y).strokeColor(accent).lineWidth(1).stroke();
      y += 8;
      doc.font('Helvetica-Bold').fontSize(10).fillColor(accent)
         .text('Total', PAGE_LEFT, y, { width: tkCols[1].x - PAGE_LEFT - 5, align: 'right' });
      doc.text(totalHours.toFixed(2), tkCols[1].x + 5, y, { width: tkCols[1].w - 10, align: 'right' });
      doc.text(fmtMoney(total),       tkCols[2].x + 5, y, { width: tkCols[2].w - 10, align: 'right' });
      y += 20;
    }
  }

  // ═══ Expense detail ═════════════════════════════════════════════════════
  const expenseLines = lines.filter(l => l.kind === 'expense');
  if (expenseLines.length > 0) {
    doc.addPage();
    y = drawHeader(true);
    writeTitle(`Summary of Costs — ${matterDesc || matterLabel}`, 12, 'left');

    const eCols = [
      { label: 'Description', x: PAGE_LEFT,       w: 400, align: 'left'  },
      { label: 'Amount',      x: PAGE_LEFT + 400, w: 112, align: 'right' },
    ];
    renderTable(eCols, expenseLines.map(l => [l.description || '', fmtMoney(l.amount)]));

    y += 4;
    doc.moveTo(PAGE_LEFT, y).lineTo(PAGE_RIGHT, y).strokeColor(accent).lineWidth(1).stroke();
    y += 8;
    doc.font('Helvetica-Bold').fontSize(10).fillColor(accent)
       .text('Total Costs', PAGE_LEFT, y, { width: eCols[0].w + eCols[0].x - PAGE_LEFT, align: 'right' });
    doc.text(fmtMoney(costsTotal), eCols[1].x + 5, y, { width: eCols[1].w - 10, align: 'right' });
    y += 20;
  }

  // ═══ Remittance page ════════════════════════════════════════════════════
  doc.addPage();
  y = drawHeader(true);
  writeTitle('REMITTANCE', 16, 'center');
  y += 4;

  const currentDue = +(Number(inv.total) - Number(inv.amount_paid || 0)).toFixed(2);
  const totalDue = +(currentDue + outstanding).toFixed(2);

  const bal = (label, amount, emphasize) => {
    if (emphasize) {
      const h = 28;
      doc.save().rect(PAGE_LEFT, y, PAGE_WIDTH, h).fill(accent).restore();
      doc.font('Helvetica-Bold').fontSize(12).fillColor('#fff');
      doc.text(label, PAGE_LEFT + 14, y + 8, { width: PAGE_WIDTH * 0.65 });
      doc.text(fmtMoney(amount), PAGE_LEFT, y + 8, { width: PAGE_WIDTH - 14, align: 'right' });
      y += h + 6;
    } else {
      const h = 22;
      doc.font('Helvetica').fontSize(11).fillColor('#222');
      doc.text(label, PAGE_LEFT + 14, y + 6, { width: PAGE_WIDTH * 0.65 });
      doc.text(fmtMoney(amount), PAGE_LEFT, y + 6, { width: PAGE_WIDTH - 14, align: 'right' });
      doc.moveTo(PAGE_LEFT, y + h).lineTo(PAGE_RIGHT, y + h).strokeColor(border).lineWidth(0.5).stroke();
      y += h + 2;
    }
  };
  bal('Current Balance Due This Invoice', currentDue, false);
  bal('Outstanding Balance',              outstanding, false);
  bal('TOTAL BALANCE DUE',                totalDue, true);

  y += 18;
  const block = (title, textLines) => {
    if (!textLines.filter(Boolean).length) return;
    doc.font('Helvetica-Bold').fontSize(11).fillColor(accent).text(title, PAGE_LEFT, y, { width: PAGE_WIDTH });
    y += 16;
    doc.font('Helvetica').fontSize(10).fillColor('#111');
    for (const line of textLines.filter(Boolean)) {
      doc.text(line, PAGE_LEFT + 14, y, { width: PAGE_WIDTH - 14 });
      y += 13;
    }
    y += 14;
  };

  if (remitName || remitAddr) {
    block('All checks should be made payable to:', [remitName, ...(remitAddr ? String(remitAddr).split(/\r?\n/) : [])]);
  }

  if (wire.accountNumber || wire.routingNumber || wire.bankName) {
    doc.font('Helvetica-Bold').fontSize(11).fillColor(accent).text('For payment by wire or ACH in USD:', PAGE_LEFT, y, { width: PAGE_WIDTH });
    y += 18;
    const wireRows = [
      ['Beneficiary Name',    wire.beneficiaryName],
      ['Beneficiary Address', wire.beneficiaryAddress],
      ['Account Number',      wire.accountNumber],
      ['ABA Routing Number',  wire.routingNumber],
      ['Bank Name',           wire.bankName],
      ['Bank Address',        wire.bankAddress],
    ].filter(([, v]) => v);
    const labelW = 150;
    for (const [label, value] of wireRows) {
      const valLines = String(value).split(/\r?\n/).filter(Boolean);
      doc.font('Helvetica').fontSize(10);
      const valH = valLines.reduce((h, line) => h + doc.heightOfString(line, { width: PAGE_WIDTH - labelW - 20 }), 0) + 6;
      const rh = Math.max(22, valH);
      doc.save().rect(PAGE_LEFT, y, PAGE_WIDTH, rh).fill('#f5f7fb').restore();
      doc.rect(PAGE_LEFT, y, PAGE_WIDTH, rh).strokeColor(border).lineWidth(0.5).stroke();
      doc.font('Helvetica-Bold').fontSize(10).fillColor('#222').text(label, PAGE_LEFT + 10, y + 6, { width: labelW - 10 });
      doc.font('Helvetica').fontSize(10).fillColor('#111').text(valLines.join('\n'), PAGE_LEFT + labelW + 4, y + 6, { width: PAGE_WIDTH - labelW - 14 });
      y += rh;
    }
    y += 18;
  }

  if (inv.notes) {
    doc.font('Helvetica-Bold').fontSize(10).fillColor(accent).text('Notes', PAGE_LEFT, y, { width: PAGE_WIDTH });
    y += 14;
    doc.font('Helvetica').fontSize(10).fillColor('#333').text(inv.notes, PAGE_LEFT, y, { width: PAGE_WIDTH });
    y += doc.heightOfString(inv.notes, { width: PAGE_WIDTH }) + 14;
  }

  if (footerText) {
    doc.font('Helvetica-Bold').fontSize(11).fillColor(accent)
       .text(footerText, PAGE_LEFT, PAGE_BOTTOM - 16, { width: PAGE_WIDTH, align: 'center', lineBreak: false });
  }
}

// Invoice PDF — renders a saved invoice using the firm's current settings.
app.get('/api/invoices/:id/pdf', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  const lines = db.prepare('SELECT * FROM invoice_lines WHERE invoice_id = ? ORDER BY sort_order').all(req.params.id);
  const firm  = db.prepare('SELECT * FROM firms WHERE id = ?').get(req.user.firmId);
  const firmSettings = parseJSON(firm.settings, {});
  const logoBuffer = firm.logo_data || null;
  const matter = inv.matter_id ? db.prepare('SELECT * FROM matters WHERE id = ? AND firm_id = ?').get(inv.matter_id, req.user.firmId) : null;
  const client = inv.client_contact_id ? db.prepare('SELECT * FROM contacts WHERE id = ? AND firm_id = ?').get(inv.client_contact_id, req.user.firmId) : null;
  const timeEntries = db.prepare(`
    SELECT t.*, u.name AS user_name, u.first_name AS user_first, u.last_name AS user_last
    FROM time_entries t LEFT JOIN users u ON u.email = t.user_email
    WHERE t.invoice_id = ? ORDER BY t.date, t.created_at
  `).all(req.params.id);
  const outstandingRow = inv.client_contact_id ? db.prepare(`
    SELECT COALESCE(SUM(total - amount_paid), 0) AS bal
    FROM invoices WHERE firm_id = ? AND client_contact_id = ? AND id != ? AND status = 'sent'
  `).get(req.user.firmId, inv.client_contact_id, inv.id) : { bal: 0 };
  const outstanding = Number(outstandingRow.bal) || 0;

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `inline; filename="${inv.number || inv.id}.pdf"`);
  const doc = new PDFDocument({ size: 'LETTER', margin: 50 });
  doc.pipe(res);
  renderInvoicePdf(doc, { firm, firmSettings, inv, lines, matter, client, timeEntries, outstanding, logoBuffer });
  doc.end();
});

// Invoice preview — renders a watermarked sample invoice using settings
// supplied in the body merged over the firm's saved settings, so admins can
// preview customization changes before saving.
app.post('/api/invoices/preview', authRequired, verifyFirmMembership, requireCap('manageFirm'), (req, res) => {
  const firm = db.prepare('SELECT * FROM firms WHERE id = ?').get(req.user.firmId);
  const saved = parseJSON(firm.settings, {});
  const override = (req.body && typeof req.body.settings === 'object' && req.body.settings) || {};
  const firmSettings = { ...saved, ...override };
  // Prefer an in-memory logo override (from a file-input that hasn't been saved yet)
  let logoBuffer = firm.logo_data || null;
  const logoOverride = req.body && req.body.logo;
  if (logoOverride && typeof logoOverride === 'object' && logoOverride.dataBase64) {
    try { logoBuffer = Buffer.from(logoOverride.dataBase64, 'base64'); } catch {}
  } else if (logoOverride === null) {
    // Explicit null = user just clicked "Remove logo" but hasn't saved
    logoBuffer = null;
  }

  // Fake sample data — intentionally generic so the preview doesn't look like
  // a real client's invoice. All names, addresses, and dollar amounts here are
  // placeholders; real invoices are populated from time entries + expenses.
  const year = new Date().getFullYear();
  const issueDate = new Date().toISOString();
  const fakeEntryDate = (() => {
    const d = new Date();
    d.setDate(d.getDate() - 14);
    return d.toISOString().slice(0, 10);
  })();
  const fakeEntryDate2 = (() => {
    const d = new Date();
    d.setDate(d.getDate() - 10);
    return d.toISOString().slice(0, 10);
  })();

  const inv = {
    id: 'preview',
    number: `INV-${year}-SAMPLE`,
    client_name: 'Acme Holdings, Inc.',
    client_contact_id: 'preview_client',
    matter_id: 'preview_matter',
    issued_at: issueDate,
    due_at: null,
    subtotal: 2275,
    tax: 0,
    total: 2275,
    amount_paid: 0,
    status: 'draft',
    notes: 'Sample invoice for preview purposes only. Replace firm, remittance, and wire details in Settings → Invoice customization.',
  };
  const matter = {
    id: 'preview_matter',
    name: 'General Corporate Advisory Services',
    description: 'General Corporate Advisory Services',
    dt_matter_id: 'SAMPLE',
  };
  const client = {
    id: 'preview_client',
    full_name: 'Acme Holdings, Inc.',
    company_name: 'Acme Holdings, Inc.',
    address: '1209 Orange Street\nWilmington, DE 19801',
    email: 'ap@acmeholdings.example',
  };
  const lines = [
    { id: 'pl1', kind: 'time',    description: 'J. Doe — Draft stock purchase agreement',       quantity: 3.5,  rate: 450, amount: 1575, sort_order: 0 },
    { id: 'pl2', kind: 'time',    description: 'J. Doe — Conference with client re: diligence', quantity: 1.0,  rate: 450, amount:  450, sort_order: 1 },
    { id: 'pl3', kind: 'expense', description: 'Delaware franchise tax filing fee',             quantity: 1,    rate: 175, amount:  175, sort_order: 2 },
    { id: 'pl4', kind: 'expense', description: 'Courier delivery (overnight)',                  quantity: 1,    rate:  75, amount:   75, sort_order: 3 },
  ];
  const timeEntries = [
    { date: fakeEntryDate,  user_name: 'Jane Doe', minutes: 210, rate: 450, description: 'Draft and revise stock purchase agreement; circulate issues list to client.' },
    { date: fakeEntryDate2, user_name: 'Jane Doe', minutes:  60, rate: 450, description: 'Telephone conference with client regarding due diligence findings and next steps.' },
  ];
  const outstanding = 850;

  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', 'inline; filename="invoice-preview.pdf"');
  const doc = new PDFDocument({ size: 'LETTER', margin: 50, bufferPages: true });
  doc.pipe(res);
  renderInvoicePdf(doc, { firm, firmSettings, inv, lines, matter, client, timeEntries, outstanding, logoBuffer });
  // Diagonal "PREVIEW" watermark on every page (requires bufferPages).
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    doc.save();
    doc.fillColor('#d0d7e2').opacity(0.35).fontSize(90).font('Helvetica-Bold');
    doc.rotate(-30, { origin: [306, 396] });
    doc.text('PREVIEW', 0, 360, { width: 612, align: 'center' });
    doc.restore();
  }
  doc.end();
});

// ═══════════════════════════════════════════════════════════════════════
// TRUST LEDGER (IOLTA)
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/trust', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const { clientId, matterId } = req.query;
  let sql = 'SELECT * FROM trust_ledger WHERE firm_id = ?';
  const p = [req.user.firmId];
  if (clientId) { sql += ' AND client_contact_id = ?'; p.push(clientId); }
  if (matterId) { sql += ' AND matter_id = ?';         p.push(matterId); }
  sql += ' ORDER BY occurred_at DESC LIMIT 1000';
  const rows = db.prepare(sql).all(...p);
  // Balances summary
  const balances = db.prepare(`SELECT client_contact_id, client_name, SUM(amount) AS balance
      FROM trust_ledger WHERE firm_id = ? GROUP BY client_contact_id, client_name ORDER BY balance DESC`)
    .all(req.user.firmId);
  res.json({ entries: rows, balances });
});

app.post('/api/trust', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const b = req.body || {};
  const kinds = ['deposit','withdrawal','transfer-to-operating','fee-applied','refund'];
  if (!kinds.includes(b.kind)) return res.status(400).json({ error: 'Invalid kind' });
  if (typeof b.amount !== 'number' || b.amount === 0) return res.status(400).json({ error: 'Non-zero amount required' });
  if (!b.clientContactId) return res.status(400).json({ error: 'Client required — every IOLTA entry must be paired with a client' });
  // Verify the client exists within this firm
  const client = db.prepare('SELECT id, full_name FROM contacts WHERE id = ? AND firm_id = ?').get(b.clientContactId, req.user.firmId);
  if (!client) return res.status(400).json({ error: 'Client not found in this firm' });
  // Enforce sign convention
  const amount = b.kind === 'deposit' ? Math.abs(b.amount) : -Math.abs(b.amount);
  // Prevent overdraw per client
  {
    const cur = db.prepare('SELECT COALESCE(SUM(amount),0) AS bal FROM trust_ledger WHERE firm_id = ? AND client_contact_id = ?').get(req.user.firmId, b.clientContactId).bal;
    if (cur + amount < -0.001) return res.status(400).json({ error: `Insufficient trust balance. Current: ${fmtMoney(cur)}` });
  }
  const id = uid('tr_');
  db.prepare(`INSERT INTO trust_ledger (id, firm_id, client_contact_id, client_name, matter_id, kind, amount, reference, occurred_at, notes, created_by)
              VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
    id, req.user.firmId, b.clientContactId || null, b.clientName || null, b.matterId || null,
    b.kind, amount, b.reference || null, b.occurredAt || new Date().toISOString(), b.notes || null, req.user.email);
  res.json(db.prepare('SELECT * FROM trust_ledger WHERE id = ?').get(id));
});

app.delete('/api/trust/:id', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  // IOLTA: never hard-delete. Post a reversing entry instead.
  const t = db.prepare('SELECT * FROM trust_ledger WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!t) return res.status(404).json({ error: 'Not found' });
  const id = uid('tr_');
  db.prepare(`INSERT INTO trust_ledger (id, firm_id, client_contact_id, client_name, matter_id, kind, amount, reference, occurred_at, notes, created_by)
              VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
    id, req.user.firmId, t.client_contact_id, t.client_name, t.matter_id,
    'refund', -t.amount, `REVERSE ${t.id}`, new Date().toISOString(),
    `Reversal of ${t.kind} posted ${t.occurred_at}`, req.user.email);
  res.json({ ok: true, reversalId: id });
});

// ═══════════════════════════════════════════════════════════════════════
// CSV IMPORT / EXPORT
// ═══════════════════════════════════════════════════════════════════════

function csvEscape(v) {
  if (v == null) return '';
  const s = String(v);
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

app.get('/api/contacts/export.csv', authRequired, verifyFirmMembership, (req, res) => {
  const w = visibleContactWhere(req.user);
  const rows = db.prepare(`SELECT * FROM contacts WHERE ${w.sql} ORDER BY full_name`).all(...w.params);
  const headers = ['id','type','full_name','first_name','last_name','email','phone','title','company_name','address','linkedin','pipeline_stage','owner_email','next_action','next_action_at','notes','created_at'];
  const lines = [headers.join(',')];
  rows.forEach(r => lines.push(headers.map(h => csvEscape(r[h])).join(',')));
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="contacts-${new Date().toISOString().slice(0,10)}.csv"`);
  res.send(lines.join('\n'));
});

// CSV import — accepts { rows: [...] } after the client parses CSV.
app.post('/api/contacts/import', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const rows = Array.isArray(req.body?.rows) ? req.body.rows : [];
  let inserted = 0, skipped = 0;
  const tx = db.transaction(() => {
    const ins = db.prepare(`INSERT INTO contacts (
        id, firm_id, type, first_name, last_name, full_name, email, phone, title,
        company_name, address, linkedin, pipeline_stage, tags, privilege, owner_email,
        notes, next_action, next_action_at, created_by, created_at, updated_at
      ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
    rows.forEach(r => {
      const first = (r.firstName || r.first_name || '').trim();
      const last  = (r.lastName  || r.last_name  || '').trim();
      const full  = (r.fullName || r.full_name || fullName(first, last) || r.companyName || '').trim();
      if (!full) { skipped++; return; }
      const now = new Date().toISOString();
      ins.run(uid('c_'), req.user.firmId, r.type || 'prospect', first, last, full,
        r.email || null, r.phone || null, r.title || null,
        r.companyName || r.company_name || null, r.address || null, r.linkedin || null,
        r.pipelineStage || r.pipeline_stage || null, JSON.stringify(r.tags || []), r.privilege ? 1 : 0,
        (r.ownerEmail || r.owner_email || req.user.email).toLowerCase(),
        r.notes || null, r.nextAction || null, r.nextActionAt || null,
        req.user.email, now, now);
      inserted++;
    });
  });
  tx();
  res.json({ inserted, skipped });
});

// ═══════════════════════════════════════════════════════════════════════
// DASHBOARD
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/dashboard', authRequired, verifyFirmMembership, (req, res) => {
  const firmId = req.user.firmId;
  const w = visibleContactWhere(req.user);
  const totalContacts = db.prepare(`SELECT COUNT(*) AS c FROM contacts WHERE ${w.sql}`).get(...w.params).c;
  const byType = db.prepare(`SELECT type, COUNT(*) AS c FROM contacts WHERE ${w.sql} GROUP BY type`).all(...w.params);
  const overdue = db.prepare(`SELECT id, full_name, next_action, next_action_at FROM contacts
                              WHERE ${w.sql} AND next_action_at IS NOT NULL AND next_action_at < date('now')
                              ORDER BY next_action_at LIMIT 20`).all(...w.params);
  const thisWeek = db.prepare(`SELECT id, full_name, next_action, next_action_at FROM contacts
                              WHERE ${w.sql} AND next_action_at BETWEEN date('now') AND date('now','+7 day')
                              ORDER BY next_action_at LIMIT 20`).all(...w.params);
  const recent = db.prepare(`SELECT * FROM interactions WHERE firm_id = ? ORDER BY occurred_at DESC LIMIT 10`).all(firmId);

  // Billing snapshot (partner/admin only)
  let billing = null;
  if (CAPS.manageBilling(req.user)) {
    const unbilled = db.prepare(`SELECT COALESCE(SUM(minutes * rate / 60), 0) AS v FROM time_entries
                                 WHERE firm_id = ? AND status = 'draft' AND billable = 1`).get(firmId).v;
    const outstanding = db.prepare(`SELECT COALESCE(SUM(total - amount_paid), 0) AS v FROM invoices
                                    WHERE firm_id = ? AND status IN ('sent')`).get(firmId).v;
    const trustTotal = db.prepare(`SELECT COALESCE(SUM(amount), 0) AS v FROM trust_ledger WHERE firm_id = ?`).get(firmId).v;
    billing = { unbilledWip: unbilled, outstandingAR: outstanding, trustBalance: trustTotal };
  }
  res.json({ totalContacts, byType, overdue, thisWeek, recent, billing });
});

// ═══════════════════════════════════════════════════════════════════════
// PUBLIC EXPORTS (for Leaderboard)
// ═══════════════════════════════════════════════════════════════════════

app.get('/api/contacts/export', (req, res) => {
  // Simple list of client/prospect names. No PII beyond name + company.
  const rows = db.prepare(`SELECT full_name, company_name, type FROM contacts WHERE type IN ('client','prospect') ORDER BY full_name`).all();
  res.json(rows.map(r => ({ name: r.full_name, company: r.company_name || '', type: r.type })));
});

app.get('/api/staff/export', (req, res) => {
  const users = db.prepare(`SELECT name, email FROM users WHERE active = 1 ORDER BY name`).all();
  res.json(users.map(u => ({ name: u.name, email: u.email })));
});

// ═══════════════════════════════════════════════════════════════════════
// TIMERS (live stopwatch — one per user)
// ═══════════════════════════════════════════════════════════════════════

function timerElapsedSeconds(t) {
  if (!t) return 0;
  const base = Number(t.accumulated_seconds || 0);
  if (!t.started_at) return base;  // paused
  return base + Math.max(0, Math.floor((Date.now() - new Date(t.started_at).getTime()) / 1000));
}

function timerToJSON(t) {
  if (!t) return null;
  const matter = t.matter_id ? db.prepare('SELECT id, name, client_name FROM matters WHERE id = ?').get(t.matter_id) : null;
  return {
    matterId: t.matter_id,
    matterName: matter?.name || null,
    clientName: matter?.client_name || null,
    description: t.description,
    running: !!t.started_at,
    elapsedSeconds: timerElapsedSeconds(t),
    startedAt: t.started_at,
    incrementMinutes: t.matter_id ? effectiveIncrementMinutes(t.matter_id) : DEFAULT_INCREMENT_MIN,
  };
}

app.get('/api/timer', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const t = db.prepare('SELECT * FROM timers WHERE user_email = ?').get(req.user.email);
  res.json(timerToJSON(t));
});

// Start a new timer (replaces any existing timer — if existing was running, it's discarded).
// To preserve prior work, call /api/timer/stop first.
app.post('/api/timer/start', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const { matterId, description } = req.body || {};
  if (!matterId) return res.status(400).json({ error: 'matterId required' });
  const m = db.prepare('SELECT id FROM matters WHERE id = ? AND firm_id = ?').get(matterId, req.user.firmId);
  if (!m) return res.status(404).json({ error: 'Matter not found' });
  const now = new Date().toISOString();
  db.prepare(`INSERT INTO timers (user_email, firm_id, matter_id, description, started_at, accumulated_seconds)
              VALUES (?, ?, ?, ?, ?, 0)
              ON CONFLICT(user_email) DO UPDATE SET
                firm_id = excluded.firm_id, matter_id = excluded.matter_id,
                description = excluded.description, started_at = excluded.started_at,
                accumulated_seconds = 0`)
    .run(req.user.email, req.user.firmId, matterId, description || null, now);
  res.json(timerToJSON(db.prepare('SELECT * FROM timers WHERE user_email = ?').get(req.user.email)));
});

app.post('/api/timer/pause', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const t = db.prepare('SELECT * FROM timers WHERE user_email = ?').get(req.user.email);
  if (!t) return res.status(404).json({ error: 'No timer running' });
  if (!t.started_at) return res.json(timerToJSON(t));  // already paused
  const elapsed = timerElapsedSeconds(t);
  db.prepare('UPDATE timers SET started_at = NULL, accumulated_seconds = ? WHERE user_email = ?').run(elapsed, req.user.email);
  res.json(timerToJSON(db.prepare('SELECT * FROM timers WHERE user_email = ?').get(req.user.email)));
});

app.post('/api/timer/resume', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const t = db.prepare('SELECT * FROM timers WHERE user_email = ?').get(req.user.email);
  if (!t) return res.status(404).json({ error: 'No timer to resume' });
  if (t.started_at) return res.json(timerToJSON(t));  // already running
  db.prepare('UPDATE timers SET started_at = ? WHERE user_email = ?').run(new Date().toISOString(), req.user.email);
  res.json(timerToJSON(db.prepare('SELECT * FROM timers WHERE user_email = ?').get(req.user.email)));
});

app.patch('/api/timer', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  // Update description or matter of a running/paused timer (not the elapsed time).
  const t = db.prepare('SELECT * FROM timers WHERE user_email = ?').get(req.user.email);
  if (!t) return res.status(404).json({ error: 'No timer' });
  const { matterId, description } = req.body || {};
  if (matterId) {
    const m = db.prepare('SELECT id FROM matters WHERE id = ? AND firm_id = ?').get(matterId, req.user.firmId);
    if (!m) return res.status(404).json({ error: 'Matter not found' });
  }
  db.prepare('UPDATE timers SET matter_id = COALESCE(?, matter_id), description = COALESCE(?, description) WHERE user_email = ?')
    .run(matterId || null, description ?? null, req.user.email);
  res.json(timerToJSON(db.prepare('SELECT * FROM timers WHERE user_email = ?').get(req.user.email)));
});

// Stop — commits the elapsed time as a time_entry and clears the timer.
// Rounds up to the nearest 6 minutes (0.1 hr) by default, which is standard legal billing increment.
app.post('/api/timer/stop', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const t = db.prepare('SELECT * FROM timers WHERE user_email = ?').get(req.user.email);
  if (!t) return res.status(404).json({ error: 'No timer to stop' });
  if (!t.matter_id) return res.status(400).json({ error: 'Timer has no matter — set one first' });
  const elapsed = timerElapsedSeconds(t);
  const rawMinutes = elapsed / 60;
  const inc = effectiveIncrementMinutes(t.matter_id);
  // Round UP to the resolved increment (matter > client > firm default). ?rounding=raw disables.
  const minutes = req.query.rounding === 'raw' ? Math.round(rawMinutes) : Math.max(inc, Math.ceil(rawMinutes / inc) * inc);
  const rate = effectiveRate(req.user.email, t.matter_id);
  const entryId = uid('t_');
  const date = (req.body?.date) || new Date().toISOString().slice(0, 10);
  const description = (req.body?.description ?? t.description) || null;
  const billable = req.body?.billable === false ? 0 : 1;

  db.transaction(() => {
    db.prepare(`INSERT INTO time_entries (id, firm_id, user_email, matter_id, date, minutes, rate, description, billable)
                VALUES (?,?,?,?,?,?,?,?,?)`).run(
      entryId, req.user.firmId, req.user.email, t.matter_id, date, minutes, rate, description, billable);
    db.prepare('DELETE FROM timers WHERE user_email = ?').run(req.user.email);
  })();

  res.json({
    ok: true,
    entry: db.prepare('SELECT * FROM time_entries WHERE id = ?').get(entryId),
    rawSeconds: elapsed,
  });
});

app.delete('/api/timer', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  db.prepare('DELETE FROM timers WHERE user_email = ?').run(req.user.email);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════
// EXPENSES
// ═══════════════════════════════════════════════════════════════════════

const EXPENSE_CATEGORIES = ['filing-fee','travel','copying','postage','expert','meal','legal-research','other'];

app.get('/api/expenses', authRequired, verifyFirmMembership, (req, res) => {
  const { matterId, status, from, to, userEmail } = req.query;
  let sql = `SELECT e.*, (SELECT COUNT(*) FROM expense_attachments a WHERE a.expense_id = e.id) AS receipt_count
             FROM expenses e WHERE e.firm_id = ?`;
  const p = [req.user.firmId];
  // Non-billing roles see only their own expenses (same scoping as time entries).
  if (!CAPS.manageBilling(req.user)) { sql += ' AND e.user_email = ?'; p.push(req.user.email); }
  else if (userEmail) { sql += ' AND e.user_email = ?'; p.push(String(userEmail).toLowerCase()); }
  if (matterId) { sql += ' AND e.matter_id = ?'; p.push(matterId); }
  if (status)   { sql += ' AND e.status = ?';    p.push(status); }
  if (from)     { sql += ' AND e.date >= ?';     p.push(from); }
  if (to)       { sql += ' AND e.date <= ?';     p.push(to); }
  sql += ' ORDER BY e.date DESC, e.created_at DESC LIMIT 2000';
  res.json(db.prepare(sql).all(...p));
});

app.post('/api/expenses', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const b = req.body || {};
  if (!b.matterId || !b.date || typeof b.amount !== 'number') return res.status(400).json({ error: 'matterId, date, and amount required' });
  const m = db.prepare('SELECT id FROM matters WHERE id = ? AND firm_id = ?').get(b.matterId, req.user.firmId);
  if (!m) return res.status(404).json({ error: 'Matter not found' });
  if (b.category && !EXPENSE_CATEGORIES.includes(b.category)) return res.status(400).json({ error: 'Invalid category' });
  const targetUser = (b.userEmail && req.user.isAdmin) ? String(b.userEmail).toLowerCase() : req.user.email;
  const id = uid('e_');
  db.prepare(`INSERT INTO expenses (id, firm_id, matter_id, user_email, date, category, description, amount, billable, markup_pct, receipt_url)
              VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
    id, req.user.firmId, b.matterId, targetUser, b.date,
    b.category || 'other', b.description || null, Number(b.amount),
    b.billable === false ? 0 : 1, Number(b.markupPct) || 0, b.receiptUrl || null);
  res.json(db.prepare('SELECT * FROM expenses WHERE id = ?').get(id));
});

app.put('/api/expenses/:id', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const existing = db.prepare('SELECT * FROM expenses WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!existing) return res.status(404).json({ error: 'Expense not found' });
  if (existing.user_email !== req.user.email && !CAPS.manageBilling(req.user)) return res.status(403).json({ error: 'Not your expense' });
  if (existing.status === 'billed' && !req.user.isAdmin) return res.status(400).json({ error: 'Billed expenses cannot be edited' });
  const b = req.body || {};
  if (b.category && !EXPENSE_CATEGORIES.includes(b.category)) return res.status(400).json({ error: 'Invalid category' });
  db.prepare(`UPDATE expenses SET
      date = COALESCE(?, date), category = COALESCE(?, category), description = COALESCE(?, description),
      amount = COALESCE(?, amount), billable = COALESCE(?, billable), markup_pct = COALESCE(?, markup_pct),
      receipt_url = COALESCE(?, receipt_url), updated_at = datetime('now')
    WHERE id = ?`).run(
    b.date || null, b.category || null, b.description ?? null,
    typeof b.amount === 'number' ? b.amount : null,
    typeof b.billable === 'boolean' ? (b.billable ? 1 : 0) : null,
    typeof b.markupPct === 'number' ? b.markupPct : null,
    b.receiptUrl ?? null, req.params.id);
  res.json(db.prepare('SELECT * FROM expenses WHERE id = ?').get(req.params.id));
});

app.delete('/api/expenses/:id', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const e = db.prepare('SELECT * FROM expenses WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!e) return res.status(404).json({ error: 'Not found' });
  if (e.user_email !== req.user.email && !CAPS.manageBilling(req.user)) return res.status(403).json({ error: 'Not your expense' });
  if (e.status === 'billed') return res.status(400).json({ error: 'Billed expenses cannot be deleted' });
  db.prepare('DELETE FROM expense_attachments WHERE expense_id = ?').run(req.params.id);
  db.prepare('DELETE FROM expenses WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── Expense receipt attachments ─────────────────────────────────────────
const RECEIPT_MIME_WHITELIST = new Set([
  'application/pdf',
  'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/heic', 'image/heif',
]);
const MAX_RECEIPT_BYTES = 10 * 1024 * 1024; // 10 MB per file

function loadExpenseForAttachment(req, res) {
  const exp = db.prepare('SELECT * FROM expenses WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!exp) { res.status(404).json({ error: 'Expense not found' }); return null; }
  // Owners and billing managers can read attachments; everyone else: only their own.
  if (exp.user_email !== req.user.email && !CAPS.manageBilling(req.user)) {
    res.status(403).json({ error: 'Not your expense' }); return null;
  }
  return exp;
}

app.get('/api/expenses/:id/attachments', authRequired, verifyFirmMembership, (req, res) => {
  const exp = loadExpenseForAttachment(req, res); if (!exp) return;
  const rows = db.prepare(`SELECT id, filename, mime_type, size, uploaded_by, created_at
                           FROM expense_attachments WHERE expense_id = ? ORDER BY created_at`).all(exp.id);
  res.json(rows);
});

app.post('/api/expenses/:id/attachments', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const exp = loadExpenseForAttachment(req, res); if (!exp) return;
  if (exp.status === 'billed' && !req.user.isAdmin) return res.status(400).json({ error: 'Billed expenses are locked' });
  const { filename, mimeType, dataBase64 } = req.body || {};
  if (!filename || !mimeType || !dataBase64) return res.status(400).json({ error: 'filename, mimeType, dataBase64 required' });
  if (!RECEIPT_MIME_WHITELIST.has(mimeType)) return res.status(400).json({ error: 'Only PDF and image files (JPEG, PNG, GIF, WebP, HEIC) are allowed' });
  let buf;
  try { buf = Buffer.from(dataBase64, 'base64'); }
  catch { return res.status(400).json({ error: 'Invalid base64 data' }); }
  if (buf.length === 0) return res.status(400).json({ error: 'Empty file' });
  if (buf.length > MAX_RECEIPT_BYTES) return res.status(413).json({ error: `File too large (max ${MAX_RECEIPT_BYTES / 1024 / 1024} MB)` });
  const id = uid('att_');
  const safeName = String(filename).slice(0, 255);
  db.prepare(`INSERT INTO expense_attachments (id, expense_id, firm_id, filename, mime_type, size, data, uploaded_by)
              VALUES (?,?,?,?,?,?,?,?)`).run(id, exp.id, req.user.firmId, safeName, mimeType, buf.length, buf, req.user.email);
  res.json({ id, filename: safeName, mime_type: mimeType, size: buf.length, uploaded_by: req.user.email });
});

app.get('/api/expenses/:id/attachments/:aid', authRequired, verifyFirmMembership, (req, res) => {
  const exp = loadExpenseForAttachment(req, res); if (!exp) return;
  const a = db.prepare('SELECT * FROM expense_attachments WHERE id = ? AND expense_id = ?').get(req.params.aid, exp.id);
  if (!a) return res.status(404).json({ error: 'Attachment not found' });
  const disposition = req.query.download ? 'attachment' : 'inline';
  res.setHeader('Content-Type', a.mime_type);
  res.setHeader('Content-Length', a.size);
  res.setHeader('Content-Disposition', `${disposition}; filename="${a.filename.replace(/"/g, '')}"`);
  res.send(a.data);
});

app.delete('/api/expenses/:id/attachments/:aid', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const exp = loadExpenseForAttachment(req, res); if (!exp) return;
  if (exp.status === 'billed' && !req.user.isAdmin) return res.status(400).json({ error: 'Billed expenses are locked' });
  const r = db.prepare('DELETE FROM expense_attachments WHERE id = ? AND expense_id = ?').run(req.params.aid, exp.id);
  if (r.changes === 0) return res.status(404).json({ error: 'Attachment not found' });
  res.json({ ok: true });
});

// Receipt OCR — send a receipt (PDF or image) to Claude and return structured fields.
const OCR_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
const MAX_OCR_BYTES = 5 * 1024 * 1024;

app.post('/api/expenses/extract', authRequired, verifyFirmMembership, requireCap('logTime'), async (req, res) => {
  if (!anthropicClient) {
    return res.status(503).json({ error: 'Receipt reading is not configured on this server. Set ANTHROPIC_API_KEY and install @anthropic-ai/sdk.' });
  }
  const { filename, mimeType, dataBase64 } = req.body || {};
  if (!filename || !mimeType || !dataBase64) return res.status(400).json({ error: 'filename, mimeType, dataBase64 required' });
  const isPdf = mimeType === 'application/pdf';
  if (!isPdf && !OCR_IMAGE_TYPES.has(mimeType)) {
    return res.status(400).json({ error: 'Receipt reading supports PDF, JPEG, PNG, GIF, and WebP. HEIC photos are not supported — convert to JPEG first.' });
  }
  let buf;
  try { buf = Buffer.from(dataBase64, 'base64'); }
  catch { return res.status(400).json({ error: 'Invalid base64 data' }); }
  if (buf.length === 0) return res.status(400).json({ error: 'Empty file' });
  if (buf.length > MAX_OCR_BYTES) return res.status(413).json({ error: `File too large for receipt reading (max ${MAX_OCR_BYTES / 1024 / 1024} MB)` });

  const fileBlock = isPdf
    ? { type: 'document', source: { type: 'base64', media_type: mimeType, data: dataBase64 } }
    : { type: 'image',    source: { type: 'base64', media_type: mimeType, data: dataBase64 } };

  try {
    const response = await anthropicClient.messages.create({
      model: 'claude-sonnet-4-6',
      max_tokens: 1024,
      system: `You extract structured data from receipts and invoices for a law firm's expense tracker. Reply with ONLY a JSON object (no prose, no code fences) with these keys:
- amount: number — the total amount paid, in dollars, with no currency symbol. Use the grand total including tax and tip.
- description: string — a concise note suitable for an expense line item. Lead with the vendor name, then what was purchased. Example: "Starbucks — coffee meeting with co-counsel".
- date: string — the transaction date in YYYY-MM-DD format, or an empty string if not visible.
- category: string — one of: filing-fee, travel, copying, postage, expert, meal, legal-research, other.
- vendor: string — the vendor or merchant name.

If the document is clearly not a receipt or invoice, respond with {"error": "Not a receipt"}.`,
      messages: [{
        role: 'user',
        content: [fileBlock, { type: 'text', text: 'Extract the receipt details as JSON.' }],
      }],
    });

    const text = (response.content || []).filter(b => b.type === 'text').map(b => b.text).join('').trim();
    const cleaned = text.replace(/^```(?:json)?\s*/i, '').replace(/```\s*$/, '').trim();
    let parsed;
    try { parsed = JSON.parse(cleaned); }
    catch {
      return res.status(502).json({ error: 'Could not parse receipt — try entering the details manually' });
    }
    if (parsed && parsed.error) return res.status(422).json({ error: parsed.error });
    res.json({
      amount: typeof parsed.amount === 'number' ? parsed.amount : Number(parsed.amount) || null,
      description: parsed.description || '',
      date: parsed.date || '',
      category: parsed.category || '',
      vendor: parsed.vendor || '',
    });
  } catch (e) {
    const status = e && e.status;
    if (status === 401) return res.status(503).json({ error: 'Receipt reading is misconfigured (invalid API key)' });
    if (status === 429) return res.status(429).json({ error: 'Receipt reading is rate-limited — try again in a moment' });
    console.error('Receipt extract error:', e.message);
    res.status(502).json({ error: 'Receipt reading failed: ' + (e.message || 'unknown error') });
  }
});

// ═══════════════════════════════════════════════════════════════════════
// HEALTH + SPA FALLBACK + ERROR HANDLER
// ═══════════════════════════════════════════════════════════════════════

app.get('/health', (req, res) => {
  try { db.prepare('SELECT 1').get(); res.json({ status: 'ok', uptime: process.uptime() }); }
  catch(e) { res.status(503).json({ status: 'error' }); }
});

app.get('*', (req, res) => {
  if (req.path === '/app' || req.path === '/app.html') return res.sendFile(path.join(__dirname, 'public', 'app.html'));
  if (req.path === '/reset-password') return res.sendFile(path.join(__dirname, 'public', 'reset-password.html'));
  if (req.path === '/accept-invite')  return res.sendFile(path.join(__dirname, 'public', 'accept-invite.html'));
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('[ERROR]', new Date().toISOString(), err.stack || err.message || err);
  res.status(err.status || 500).json({ error: 'Internal server error' });
});

// Periodic cleanup
setInterval(() => {
  try {
    db.prepare("DELETE FROM token_denylist WHERE expires_at < datetime('now')").run();
    db.prepare("DELETE FROM password_resets WHERE expires_at < datetime('now') OR used = 1").run();
    db.prepare("DELETE FROM invites WHERE expires_at < datetime('now') AND used = 0").run();
  } catch(e) { console.warn('Cleanup error:', e.message); }
}, 60*60*1000);

app.listen(PORT, () => {
  console.log(`
  ┌─────────────────────────────────────────────┐
  │  CRM Server                                 │
  │  Landing:  http://localhost:${PORT}             │
  │  App:      http://localhost:${PORT}/app         │
  │  API:      http://localhost:${PORT}/api         │
  │  DB:       ${DB_PATH}
  └─────────────────────────────────────────────┘`);
});
