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
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(path.dirname(DB_PATH), 'backups');
const BACKUP_RETAIN = parseInt(process.env.BACKUP_RETAIN, 10) || 14;
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
const INBOUND_EMAIL_SECRET  = process.env.INBOUND_EMAIL_SECRET  || '';
const INBOUND_EMAIL_ADDRESS = process.env.INBOUND_EMAIL_ADDRESS || '';
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

// ── PAYMENT-SECRET ENCRYPTION (Stripe keys, Mercury token) ──────────────
// AES-256-GCM keyed off PAYMENTS_KEK (base64, 32 bytes). If the KEK is missing,
// `paymentsEnabled` stays false and config endpoints refuse to save credentials.
// Storage format: base64(iv|authTag|ciphertext). IV is 12 bytes, tag is 16.
let PAYMENTS_KEK_BUF = null;
let paymentsEnabled = false;
if (process.env.PAYMENTS_KEK) {
  try {
    const buf = Buffer.from(process.env.PAYMENTS_KEK, 'base64');
    if (buf.length !== 32) throw new Error(`PAYMENTS_KEK must decode to 32 bytes (got ${buf.length})`);
    PAYMENTS_KEK_BUF = buf;
    paymentsEnabled = true;
  } catch (e) {
    console.error('WARN: PAYMENTS_KEK invalid — payment features disabled.', e.message);
  }
} else {
  console.log('[payments] PAYMENTS_KEK not set — payment features disabled. Generate with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'base64\'))"');
}
function encryptSecret(plain) {
  if (!PAYMENTS_KEK_BUF) throw new Error('PAYMENTS_KEK not configured');
  if (plain == null || plain === '') return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', PAYMENTS_KEK_BUF, iv);
  const ct = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}
function decryptSecret(stored) {
  if (!PAYMENTS_KEK_BUF) throw new Error('PAYMENTS_KEK not configured');
  if (!stored) return null;
  const buf = Buffer.from(stored, 'base64');
  if (buf.length < 28) throw new Error('Ciphertext too short');
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', PAYMENTS_KEK_BUF, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}
// Masks secret keys for read endpoints — show only the last 4 chars.
function maskSecret(s) {
  if (!s) return null;
  const str = String(s);
  return str.length <= 4 ? '••••' : '••••' + str.slice(-4);
}

// Stripe SDK is loaded lazily so the server boots even if `stripe` is not installed.
let stripeSdk = null;
try { stripeSdk = require('stripe'); }
catch { console.log('[payments] stripe npm package not installed — pay-link endpoints will return 503'); }

// Returns a Stripe client scoped to a firm's stored secret key. Throws with a
// status-tagged error so routes can forward the status code directly.
function getStripeClient(firmId) {
  if (!stripeSdk) throw Object.assign(new Error('Stripe SDK is not installed on the server'), { status: 503 });
  if (!paymentsEnabled) throw Object.assign(new Error('PAYMENTS_KEK is not configured on the server'), { status: 503 });
  const row = db.prepare('SELECT stripe_secret_key, stripe_publishable, stripe_webhook_secret FROM firm_payment_config WHERE firm_id = ?').get(firmId);
  if (!row || !row.stripe_secret_key) throw Object.assign(new Error('Stripe is not connected for this firm. Configure it in Settings → Payments.'), { status: 503 });
  const sk = decryptSecret(row.stripe_secret_key);
  if (!sk) throw Object.assign(new Error('Stripe secret key could not be decrypted'), { status: 500 });
  return {
    client:        stripeSdk(sk, { apiVersion: '2024-06-20' }),
    publishable:   row.stripe_publishable || '',
    webhookSecret: row.stripe_webhook_secret ? decryptSecret(row.stripe_webhook_secret) : null,
  };
}

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

  -- Live timers: a user can have multiple concurrent timers (e.g. one per matter).
  -- Each row exists only while running/paused; stop commits to time_entries and deletes the row.
  CREATE TABLE IF NOT EXISTS timers (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email          TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
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

  -- Tasks / deadlines on matters (Phase 5.5)
  CREATE TABLE IF NOT EXISTS matter_tasks (
    id          TEXT PRIMARY KEY,
    matter_id   TEXT NOT NULL REFERENCES matters(id) ON DELETE CASCADE,
    firm_id     TEXT NOT NULL REFERENCES firms(id)   ON DELETE CASCADE,
    description TEXT NOT NULL,
    due_date    TEXT,
    assigned_to TEXT,
    status      TEXT NOT NULL DEFAULT 'open',
    created_by  TEXT NOT NULL,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now'))
  );

  -- Documents attached to matters (Phase 5.3)
  CREATE TABLE IF NOT EXISTS matter_documents (
    id           TEXT PRIMARY KEY,
    matter_id    TEXT NOT NULL REFERENCES matters(id) ON DELETE CASCADE,
    firm_id      TEXT NOT NULL REFERENCES firms(id)   ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    mime_type    TEXT NOT NULL,
    size         INTEGER NOT NULL,
    data         BLOB NOT NULL,
    uploaded_by  TEXT NOT NULL,
    created_at   TEXT DEFAULT (datetime('now'))
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

  -- ── PAYMENTS & BANK RECONCILIATION ──────────────────────────────────
  -- See PAYMENTS_DESIGN.md for the full design. Secrets are encrypted with
  -- PAYMENTS_KEK (AES-256-GCM). Storing them is refused when KEK is missing.
  CREATE TABLE IF NOT EXISTS firm_payment_config (
    firm_id                      TEXT PRIMARY KEY REFERENCES firms(id) ON DELETE CASCADE,
    stripe_account_id            TEXT,
    stripe_secret_key            TEXT,   -- encrypted
    stripe_publishable           TEXT,
    stripe_webhook_secret        TEXT,   -- encrypted
    mercury_token                TEXT,   -- encrypted
    mercury_operating_account_id TEXT,
    mercury_trust_account_id     TEXT,
    ach_enabled                  INTEGER DEFAULT 1,
    card_enabled                 INTEGER DEFAULT 1,
    updated_at                   TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS invoice_payments (
    id                       TEXT PRIMARY KEY,
    firm_id                  TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    invoice_id               TEXT REFERENCES invoices(id) ON DELETE SET NULL,
    client_contact_id        TEXT REFERENCES contacts(id) ON DELETE SET NULL,
    destination              TEXT NOT NULL,   -- 'operating' | 'trust'
    amount                   REAL NOT NULL,
    currency                 TEXT DEFAULT 'usd',
    method                   TEXT,            -- stripe_card|stripe_ach|wire|check|manual
    status                   TEXT NOT NULL,   -- pending|succeeded|failed|refunded
    stripe_payment_intent_id TEXT UNIQUE,
    stripe_charge_id         TEXT,
    mercury_txn_id           TEXT UNIQUE,
    trust_ledger_id          TEXT REFERENCES trust_ledger(id) ON DELETE SET NULL,
    occurred_at              TEXT,
    raw_json                 TEXT,
    created_at               TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS payment_links (
    token        TEXT PRIMARY KEY,
    firm_id      TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    invoice_id   TEXT REFERENCES invoices(id) ON DELETE CASCADE,
    destination  TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    expires_at   TEXT,
    used_at      TEXT,
    created_by   TEXT,
    created_at   TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS bank_transactions (
    id                    TEXT PRIMARY KEY,   -- Mercury's transaction id
    firm_id               TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    account_id            TEXT NOT NULL,
    account_role          TEXT,               -- 'operating' | 'trust'
    amount                REAL NOT NULL,
    posted_at             TEXT,
    counterparty          TEXT,
    memo                  TEXT,
    external_id           TEXT,
    reconciled_payment_id TEXT REFERENCES invoice_payments(id) ON DELETE SET NULL,
    raw_json              TEXT,
    fetched_at            TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS mercury_sync_state (
    firm_id        TEXT PRIMARY KEY REFERENCES firms(id) ON DELETE CASCADE,
    last_synced_at TEXT,
    last_cursor    TEXT
  );

  -- Invoice adjustments: write-downs (courtesy discounts, bad debt) and write-ups.
  -- Stored signed (writedown=negative). Original invoices.total stays immutable;
  -- net billed = total + sum(adjustments). Append-only conceptually — admins can
  -- void via a reversing entry, no in-place edits, so the audit trail is clean.
  CREATE TABLE IF NOT EXISTS invoice_adjustments (
    id           TEXT PRIMARY KEY,
    firm_id      TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
    invoice_id   TEXT NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
    amount       REAL NOT NULL,                -- signed: negative = writedown
    kind         TEXT NOT NULL,                -- writedown|writeup|courtesy|bad_debt
    occurred_at  TEXT DEFAULT (datetime('now')),
    reason       TEXT,
    created_by   TEXT,
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
  `ALTER TABLE contacts ADD COLUMN originating_attorney_email TEXT`,
  `ALTER TABLE contacts ADD COLUMN origination_split_pct REAL`,
  `ALTER TABLE contacts ADD COLUMN billing_attorney_email TEXT`,
  `ALTER TABLE contacts ADD COLUMN client_number INTEGER`,
  `ALTER TABLE matters  ADD COLUMN matter_number INTEGER`,
  `ALTER TABLE contacts ADD COLUMN primary_contact_name TEXT`,
  `ALTER TABLE contacts ADD COLUMN primary_contact_title TEXT`,
  `ALTER TABLE contacts ADD COLUMN primary_contact_email TEXT`,
  `ALTER TABLE contacts ADD COLUMN primary_contact_phone TEXT`,
  // Manual payments + write-downs. invoice_payments existed for Stripe-only;
  // the next three columns let it serve as the source of truth for all cash
  // (check, wire, ach, cash, trust-applied, manual). amount_writedown is the
  // denormalized sum of invoice_adjustments per invoice — kept for fast filter
  // queries on the dashboard.
  `ALTER TABLE invoice_payments ADD COLUMN reference TEXT`,
  `ALTER TABLE invoice_payments ADD COLUMN notes TEXT`,
  `ALTER TABLE invoice_payments ADD COLUMN created_by TEXT`,
  `ALTER TABLE invoices ADD COLUMN amount_writedown REAL DEFAULT 0`,
  `ALTER TABLE bank_transactions ADD COLUMN source TEXT DEFAULT 'mercury'`,
  `ALTER TABLE users   ADD COLUMN dt_subscriber INTEGER DEFAULT 0`,
  `ALTER TABLE matters ADD COLUMN dt_data TEXT`,
  `ALTER TABLE matters ADD COLUMN billing_schedule TEXT`,
  `ALTER TABLE matters ADD COLUMN trust_min_balance REAL DEFAULT 0`,
  `ALTER TABLE matters ADD COLUMN trust_replenish_to REAL`,
];
// Only swallow "duplicate column" errors (idempotency). Anything else — syntax
// typos, missing table, permission issues — is a real problem and should fail
// loudly at boot rather than silently leave the schema half-applied.
for (const m of migrations) {
  try { db.exec(m); }
  catch(e) {
    if (!/duplicate column name/i.test(e.message)) {
      console.error(`Migration failed: ${m}\n  → ${e.message}`);
      throw e;
    }
  }
  // Post-check: for each ALTER TABLE ... ADD COLUMN, verify the column really
  // landed. Belt-and-suspenders against a future change accidentally weakening
  // the idempotency catch above.
  const match = m.match(/^ALTER TABLE (\w+) ADD COLUMN (\w+)/i);
  if (match) {
    const [, table, column] = match;
    const has = db.prepare(`SELECT 1 AS ok FROM pragma_table_info(?) WHERE name = ?`).get(table, column);
    if (!has) { console.error(`Migration post-check failed: ${table}.${column} missing after ALTER`); throw new Error(`Migration post-check: ${table}.${column} not applied`); }
  }
}

// Multi-timer migration: the original timers table had user_email as PRIMARY KEY
// (one row per user). Detect that and rebuild with id as PK so one user can hold
// several concurrent timers.
try {
  const hasIdCol = db.prepare(`SELECT 1 AS ok FROM pragma_table_info('timers') WHERE name = 'id'`).get();
  if (!hasIdCol) {
    db.exec(`
      CREATE TABLE timers_new (
        id                  INTEGER PRIMARY KEY AUTOINCREMENT,
        user_email          TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
        firm_id             TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
        matter_id           TEXT REFERENCES matters(id) ON DELETE CASCADE,
        description         TEXT,
        started_at          TEXT,
        accumulated_seconds INTEGER DEFAULT 0,
        created_at          TEXT DEFAULT (datetime('now'))
      );
      INSERT INTO timers_new (user_email, firm_id, matter_id, description, started_at, accumulated_seconds, created_at)
        SELECT user_email, firm_id, matter_id, description, started_at, accumulated_seconds, created_at FROM timers;
      DROP TABLE timers;
      ALTER TABLE timers_new RENAME TO timers;
    `);
  }
} catch(e) { console.error('Timer multi-row migration failed:', e.message); }

// Backfill: any contact with a NULL owner_email gets the contact's created_by,
// falling back to the firm's first admin email. Staff visibility depends on
// owner_email being set (see visibleContactWhere), so a NULL here would make
// the contact invisible to non-admins. One-time fix; the write paths now
// guarantee owner_email is always set.
try {
  const nulls = db.prepare(`SELECT id, firm_id, created_by FROM contacts WHERE owner_email IS NULL OR owner_email = ''`).all();
  if (nulls.length) {
    const adminForFirm = db.prepare(`SELECT email FROM users WHERE firm_id = ? AND is_admin = 1 AND active = 1 ORDER BY email LIMIT 1`);
    const update = db.prepare(`UPDATE contacts SET owner_email = ? WHERE id = ?`);
    let fixed = 0;
    for (const row of nulls) {
      const fallback = (row.created_by && String(row.created_by).toLowerCase().trim())
                    || adminForFirm.get(row.firm_id)?.email
                    || null;
      if (fallback) { update.run(fallback, row.id); fixed++; }
    }
    if (fixed) console.log(`[migration] Backfilled owner_email on ${fixed}/${nulls.length} contacts.`);
    else if (nulls.length) console.warn(`[migration] ${nulls.length} contacts have NULL owner_email and no resolvable fallback — inspect manually.`);
  }
} catch(e) { console.error('owner_email backfill failed:', e.message); }

// Backfill: assign per-firm sequential client_number to any existing
// type='client' contact missing one. Order by created_at so the oldest client
// gets #1. Subsequent inserts continue from MAX+1 (see POST /api/contacts).
try {
  const firms = db.prepare(`SELECT DISTINCT firm_id FROM contacts WHERE type = 'client' AND client_number IS NULL`).all();
  for (const f of firms) {
    const maxRow = db.prepare(`SELECT COALESCE(MAX(client_number), 0) AS m FROM contacts WHERE firm_id = ?`).get(f.firm_id);
    let next = (maxRow?.m || 0) + 1;
    const rows = db.prepare(`SELECT id FROM contacts WHERE firm_id = ? AND type = 'client' AND client_number IS NULL ORDER BY created_at, id`).all(f.firm_id);
    const upd = db.prepare(`UPDATE contacts SET client_number = ? WHERE id = ?`);
    for (const r of rows) { upd.run(next, r.id); next++; }
    if (rows.length) console.log(`[migration] Assigned client_number to ${rows.length} contacts in firm ${f.firm_id}`);
  }
} catch(e) { console.error('client_number backfill failed:', e.message); }

// Backfill: assign per-client sequential matter_number to any existing matter
// with a client_contact_id but no matter_number. Order by opened_at so the
// oldest matter under a client gets 00001.
try {
  const clients = db.prepare(`SELECT DISTINCT client_contact_id FROM matters WHERE client_contact_id IS NOT NULL AND matter_number IS NULL`).all();
  for (const c of clients) {
    const maxRow = db.prepare(`SELECT COALESCE(MAX(matter_number), 0) AS m FROM matters WHERE client_contact_id = ?`).get(c.client_contact_id);
    let next = (maxRow?.m || 0) + 1;
    const rows = db.prepare(`SELECT id FROM matters WHERE client_contact_id = ? AND matter_number IS NULL ORDER BY opened_at, id`).all(c.client_contact_id);
    const upd = db.prepare(`UPDATE matters SET matter_number = ? WHERE id = ?`);
    for (const r of rows) { upd.run(next, r.id); next++; }
    if (rows.length) console.log(`[migration] Assigned matter_number to ${rows.length} matters under client ${c.client_contact_id}`);
  }
} catch(e) { console.error('matter_number backfill failed:', e.message); }

// Backfill: clientless matters also get a number (per-firm sequence) so the
// invoice can always print a real matter no. instead of falling back to the
// internal uuid. The number is independent of the per-client sequence — the
// display logic in fmtMatterFullId just shows it without a "{client#}-" prefix.
try {
  const firms = db.prepare(`SELECT DISTINCT firm_id FROM matters WHERE client_contact_id IS NULL AND matter_number IS NULL`).all();
  for (const f of firms) {
    const maxRow = db.prepare(`SELECT COALESCE(MAX(matter_number), 0) AS m FROM matters WHERE firm_id = ? AND client_contact_id IS NULL`).get(f.firm_id);
    let next = (maxRow?.m || 0) + 1;
    const rows = db.prepare(`SELECT id FROM matters WHERE firm_id = ? AND client_contact_id IS NULL AND matter_number IS NULL ORDER BY opened_at, id`).all(f.firm_id);
    const upd = db.prepare(`UPDATE matters SET matter_number = ? WHERE id = ?`);
    for (const r of rows) { upd.run(next, r.id); next++; }
    if (rows.length) console.log(`[migration] Assigned matter_number to ${rows.length} clientless matters in firm ${f.firm_id}`);
  }
} catch(e) { console.error('clientless matter_number backfill failed:', e.message); }

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
  CREATE INDEX IF NOT EXISTS idx_matters_client_num ON matters(client_contact_id, matter_number);
  CREATE INDEX IF NOT EXISTS idx_contacts_firm_clinum ON contacts(firm_id, client_number);
  CREATE INDEX IF NOT EXISTS idx_time_firm_date ON time_entries(firm_id, date);
  CREATE INDEX IF NOT EXISTS idx_time_user_date ON time_entries(user_email, date);
  CREATE INDEX IF NOT EXISTS idx_time_matter ON time_entries(matter_id);
  CREATE INDEX IF NOT EXISTS idx_time_invoice ON time_entries(invoice_id);
  CREATE INDEX IF NOT EXISTS idx_invoices_firm ON invoices(firm_id);
  CREATE INDEX IF NOT EXISTS idx_invoices_client ON invoices(client_contact_id);
  -- Covers the outstanding-balance subquery on the invoice PDF route
  -- (WHERE firm_id = ? AND client_contact_id = ? AND status = 'sent').
  CREATE INDEX IF NOT EXISTS idx_invoices_client_status ON invoices(firm_id, client_contact_id, status);
  CREATE INDEX IF NOT EXISTS idx_invoice_lines_invoice ON invoice_lines(invoice_id);
  CREATE INDEX IF NOT EXISTS idx_trust_firm ON trust_ledger(firm_id);
  CREATE INDEX IF NOT EXISTS idx_trust_client ON trust_ledger(client_contact_id);
  CREATE INDEX IF NOT EXISTS idx_conflict_checks_firm ON conflict_checks(firm_id, ran_at);
  CREATE INDEX IF NOT EXISTS idx_conflict_checks_runner ON conflict_checks(run_by_email);
  CREATE INDEX IF NOT EXISTS idx_conflict_checks_contact ON conflict_checks(related_contact_id);
  CREATE INDEX IF NOT EXISTS idx_expenses_firm_date ON expenses(firm_id, date);
  CREATE INDEX IF NOT EXISTS idx_expenses_matter ON expenses(matter_id);
  CREATE INDEX IF NOT EXISTS idx_expenses_invoice ON expenses(invoice_id);
  CREATE INDEX IF NOT EXISTS idx_matter_tasks_matter   ON matter_tasks(matter_id);
  CREATE INDEX IF NOT EXISTS idx_matter_tasks_assignee ON matter_tasks(firm_id, assigned_to, status);
  CREATE INDEX IF NOT EXISTS idx_matter_documents_matter ON matter_documents(matter_id);
  CREATE INDEX IF NOT EXISTS idx_expense_attachments_expense ON expense_attachments(expense_id);
  CREATE INDEX IF NOT EXISTS idx_token_denylist_expires ON token_denylist(expires_at);
  CREATE INDEX IF NOT EXISTS idx_timers_user ON timers(user_email);
  CREATE INDEX IF NOT EXISTS idx_invpay_invoice ON invoice_payments(invoice_id);
  CREATE INDEX IF NOT EXISTS idx_invpay_firm    ON invoice_payments(firm_id, status);
  CREATE INDEX IF NOT EXISTS idx_paylinks_invoice ON payment_links(invoice_id);
  CREATE INDEX IF NOT EXISTS idx_banktx_firm   ON bank_transactions(firm_id, posted_at);
  CREATE INDEX IF NOT EXISTS idx_banktx_unrec  ON bank_transactions(firm_id) WHERE reconciled_payment_id IS NULL;
  CREATE INDEX IF NOT EXISTS idx_invadj_invoice ON invoice_adjustments(invoice_id);
  CREATE INDEX IF NOT EXISTS idx_invadj_firm    ON invoice_adjustments(firm_id, occurred_at);
  CREATE INDEX IF NOT EXISTS idx_invpay_firm_occ ON invoice_payments(firm_id, occurred_at);
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

// ── STRIPE WEBHOOK (raw body; MUST be mounted before express.json) ──────
// Stripe's signature verification hashes the raw request bytes, so this
// route reads the body as a Buffer. All other routes below use JSON parsing.
app.post('/api/pay/stripe-webhook', express.raw({ type: 'application/json', limit: '1mb' }), async (req, res) => {
  if (!stripeSdk) return res.status(503).send('stripe SDK missing');
  const sig = req.headers['stripe-signature'];
  if (!sig) return res.status(400).send('missing signature');

  // Find the firm whose webhook secret verifies this payload. With a single-firm
  // deployment there is at most one row; iterating keeps this honest for future
  // multi-firm support and avoids having to trust unsigned payload metadata.
  let event = null, firmId = null;
  try {
    const cfgs = db.prepare(`SELECT firm_id, stripe_webhook_secret FROM firm_payment_config
                             WHERE stripe_webhook_secret IS NOT NULL`).all();
    // webhooks.constructEvent is HMAC-only and doesn't hit Stripe's API, but
    // we still need an SDK instance to access it. Use a syntactically valid
    // placeholder key so older SDK versions that validate at construction pass.
    const verifier = stripeSdk('sk_test_placeholder_verification_only');
    for (const c of cfgs) {
      let whsec = null;
      try { whsec = decryptSecret(c.stripe_webhook_secret); }
      catch (e) {
        // Almost always means PAYMENTS_KEK was rotated without re-entering the
        // webhook secret. Left silent, every webhook silently ignores this firm
        // forever. Log loud and clear so admins notice.
        console.error(`[stripe-webhook] RECONCILE NEEDED — cannot decrypt webhook secret for firm ${c.firm_id}; re-enter it in Settings → Payments. Error:`, e.message);
        continue;
      }
      if (!whsec) continue;
      try {
        event = verifier.webhooks.constructEvent(req.body, sig, whsec);
        firmId = c.firm_id;
        break;
      } catch { /* wrong secret for this firm — try next */ }
    }
  } catch (e) {
    console.error('[stripe-webhook] verification error:', e.message);
    return res.status(400).send('verification error');
  }
  if (!event) return res.status(400).send('signature verification failed');

  try {
    if (event.type === 'payment_intent.succeeded') {
      handlePaymentIntentSucceeded(firmId, event.data.object);
    } else if (event.type === 'payment_intent.payment_failed') {
      const pi = event.data.object;
      db.prepare(`UPDATE invoice_payments SET status='failed', raw_json=?
                  WHERE stripe_payment_intent_id=? AND firm_id=?`)
        .run(JSON.stringify(pi), pi.id, firmId);
    } else if (event.type === 'charge.refunded') {
      handleChargeRefunded(firmId, event.data.object);
    }
  } catch (e) {
    // ACK with 202 instead of 500 so Stripe doesn't retry the same event for 3
    // days. A bug in our handler won't fix itself on retry; the error lives in
    // logs for manual reconciliation. Transient DB failures trade automatic
    // retry for a manual replay — acceptable for a single-firm deployment.
    console.error('[stripe-webhook] RECONCILE NEEDED — handler error for', event.type, 'eventId=', event.id, 'firmId=', firmId, '—', e.message, e.stack);
    return res.status(202).send('acked; handler error logged for reconciliation');
  }
  res.json({ received: true });
});

// Webhook event handlers. Kept out of the route body so they can be tested
// (and so the route stays readable). All DB writes are idempotent — Stripe
// retries events and the same event may arrive multiple times.
function handlePaymentIntentSucceeded(firmId, pi) {
  const existing = db.prepare(
    'SELECT * FROM invoice_payments WHERE stripe_payment_intent_id = ? AND firm_id = ?'
  ).get(pi.id, firmId);
  if (!existing) {
    console.warn('[webhook] PI succeeded but no invoice_payments row:', pi.id);
    return;
  }
  if (existing.status === 'succeeded') return;

  const charge = pi.charges?.data?.[0] || null;
  const method = charge?.payment_method_details?.type === 'us_bank_account'
    ? 'stripe_ach' : 'stripe_card';

  db.transaction(() => {
    db.prepare(`UPDATE invoice_payments
                SET status='succeeded', method=?, stripe_charge_id=?,
                    occurred_at=datetime('now'), raw_json=?
                WHERE id=?`)
      .run(method, charge?.id || null, JSON.stringify(pi), existing.id);

    if (existing.destination === 'operating' && existing.invoice_id) {
      const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?')
        .get(existing.invoice_id, firmId);
      if (inv) {
        const newPaid = Math.round(((inv.amount_paid || 0) + existing.amount) * 100) / 100;
        const fullyPaid = newPaid >= (inv.total || 0) - 0.005;
        const newStatus = fullyPaid ? 'paid' : (inv.status === 'draft' ? 'sent' : inv.status);
        db.prepare(`UPDATE invoices SET amount_paid=?, status=?, updated_at=datetime('now') WHERE id=?`)
          .run(newPaid, newStatus, inv.id);
      }
    } else if (existing.destination === 'trust') {
      // Trust-destination payments should write a trust_ledger deposit row.
      // Not yet implemented (step 3 of the payments rollout). Fail loudly so
      // the 202-on-error webhook path logs a RECONCILE NEEDED entry — the
      // payment row is already marked succeeded; a human needs to post the
      // matching trust ledger entry manually until the handler ships.
      throw new Error(`Trust-destination payment ${existing.id} succeeded but trust_ledger writer is not implemented yet — manual reconciliation required.`);
    }

    if (existing.invoice_id) {
      db.prepare(`UPDATE payment_links SET used_at=datetime('now')
                  WHERE firm_id=? AND invoice_id=? AND used_at IS NULL`)
        .run(firmId, existing.invoice_id);
    }
  })();
}

function handleChargeRefunded(firmId, ch) {
  // Full refunds only in step 2. Partial refunds are tracked but don't split
  // into multiple rows — revisit when the manual refund flow lands (step 6).
  const row = db.prepare(
    'SELECT * FROM invoice_payments WHERE stripe_charge_id = ? AND firm_id = ?'
  ).get(ch.id, firmId);
  if (!row || row.status === 'refunded') return;
  const rawRefund = (ch.amount_refunded || 0) / 100;
  if (rawRefund <= 0) return;
  // Clamp to the original payment amount. Stripe itself enforces this, but a
  // replayed/mangled webhook shouldn't be able to push our amount_paid math
  // into absurd territory. Log if the values disagree so we notice.
  const refundedAmount = Math.min(rawRefund, row.amount);
  if (rawRefund > row.amount + 0.005) {
    console.warn('[webhook] refund amount exceeds original payment — clamping', { chargeId: ch.id, paymentId: row.id, rawRefund, original: row.amount });
  }

  db.transaction(() => {
    db.prepare(`UPDATE invoice_payments SET status='refunded', raw_json=? WHERE id=?`)
      .run(JSON.stringify(ch), row.id);
    if (row.destination === 'operating' && row.invoice_id) {
      const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?')
        .get(row.invoice_id, firmId);
      if (inv) {
        const newPaid = Math.max(0, Math.round(((inv.amount_paid || 0) - refundedAmount) * 100) / 100);
        const shouldReopen = inv.status === 'paid' && newPaid < (inv.total || 0) - 0.005;
        const newStatus = shouldReopen ? 'sent' : inv.status;
        db.prepare(`UPDATE invoices SET amount_paid=?, status=?, updated_at=datetime('now') WHERE id=?`)
          .run(newPaid, newStatus, inv.id);
      }
    }
  })();
}

// Recompute an invoice's amount_paid + amount_writedown + status from the
// underlying invoice_payments + invoice_adjustments rows. Single source of
// truth for invoice math — manual payment, adjustment, and reversal endpoints
// all funnel through this so the row stays in sync with its ledger.
//
// The Stripe webhook handlers above intentionally do not call this — they know
// the delta (added or refunded amount) and do an inline UPDATE to keep the
// race window small. Both paths converge on the same columns.
function recomputeInvoiceTotals(invoiceId, firmId) {
  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(invoiceId, firmId);
  if (!inv) return null;

  const paidRow = db.prepare(`SELECT COALESCE(SUM(amount),0) AS s FROM invoice_payments
                              WHERE invoice_id = ? AND firm_id = ? AND status = 'succeeded'`).get(invoiceId, firmId);
  const adjRow  = db.prepare(`SELECT COALESCE(SUM(amount),0) AS s FROM invoice_adjustments
                              WHERE invoice_id = ? AND firm_id = ?`).get(invoiceId, firmId);

  const amountPaid      = Math.round(Number(paidRow.s || 0) * 100) / 100;
  const amountWritedown = Math.round(Number(adjRow.s  || 0) * 100) / 100; // signed; negative = writedown
  const netBilled       = Math.round((Number(inv.total || 0) + amountWritedown) * 100) / 100;
  const fullySettled    = netBilled > 0 && amountPaid >= netBilled - 0.005;

  // Void stays void. Otherwise: paid when settled (or when adjustments zero
  // out the bill); sent when partial cash has hit a draft; otherwise leave
  // status alone (admin can still PATCH manually).
  let nextStatus = inv.status;
  if (inv.status !== 'void') {
    if (fullySettled) nextStatus = 'paid';
    else if (netBilled <= 0 && (amountPaid > 0 || amountWritedown !== 0)) nextStatus = 'paid';
    else if (inv.status === 'draft' && amountPaid > 0) nextStatus = 'sent';
    else if (inv.status === 'paid' && !fullySettled) nextStatus = amountPaid > 0 ? 'sent' : 'draft';
  }

  db.prepare(`UPDATE invoices SET amount_paid = ?, amount_writedown = ?, status = ?, updated_at = datetime('now')
              WHERE id = ?`).run(amountPaid, amountWritedown, nextStatus, invoiceId);
  return { amountPaid, amountWritedown, netBilled, status: nextStatus };
}

// ── BACKUPS ─────────────────────────────────────────────────────────────
const backupState = { lastRunAt: null, lastSuccessAt: null, lastError: null, inProgress: false };

function listBackupFiles() {
  if (!fs.existsSync(BACKUP_DIR)) return [];
  return fs.readdirSync(BACKUP_DIR)
    .filter(f => /^crm-\d{4}-\d{2}-\d{2}(?:T\d{6})?\.db$/.test(f))
    .map(f => {
      const st = fs.statSync(path.join(BACKUP_DIR, f));
      return { filename: f, size: st.size, createdAt: st.mtime.toISOString() };
    })
    .sort((a, b) => b.filename.localeCompare(a.filename));
}

async function runBackup({ manual = false } = {}) {
  if (backupState.inProgress) return { skipped: 'already running' };
  backupState.inProgress = true;
  backupState.lastRunAt = new Date().toISOString();
  try {
    if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const today = new Date().toISOString().slice(0, 10);
    const base = manual ? `crm-${new Date().toISOString().replace(/[-:]/g,'').slice(0,15)}.db` : `crm-${today}.db`;
    const dest = path.join(BACKUP_DIR, base);
    await db.backup(dest);
    // Retention: keep newest BACKUP_RETAIN, delete the rest
    const all = listBackupFiles();
    for (const f of all.slice(BACKUP_RETAIN)) {
      try { fs.unlinkSync(path.join(BACKUP_DIR, f.filename)); } catch(e) { /* ignore */ }
    }
    backupState.lastSuccessAt = new Date().toISOString();
    backupState.lastError = null;
    console.log(`[backup] wrote ${dest} (${fs.statSync(dest).size} bytes)`);
    return { filename: base, size: fs.statSync(dest).size };
  } catch (e) {
    backupState.lastError = e.message || String(e);
    console.warn('[backup] failed:', e.message);
    throw e;
  } finally {
    backupState.inProgress = false;
  }
}

// Daily backup scheduler: run once on startup if today's backup missing,
// then check every hour. Idempotent — a date-stamped file is only written
// once per calendar day unless manually triggered.
function scheduleBackups() {
  const tick = () => {
    const today = new Date().toISOString().slice(0, 10);
    const have = listBackupFiles().some(f => f.filename === `crm-${today}.db`);
    if (!have) runBackup().catch(() => {});
  };
  setTimeout(tick, 30 * 1000); // startup grace
  setInterval(tick, 60 * 60 * 1000);
}

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public'), {
  etag: false,
  lastModified: false,
  setHeaders(res, filePath) {
    if (filePath.endsWith('.html') || filePath.endsWith('.js') || filePath.endsWith('.css')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
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
    if (payload && typeof payload.email === 'string') {
      payload.email = payload.email.toLowerCase().trim();
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
    defaultRate: u.default_rate || 0, dtSubscriber: !!u.dt_subscriber,
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

// Effective hourly rate for the caller, optionally for a specific matter:
// matter override → user default → 0. Lets the time-entry form preview
// hours × rate before save and surface a $0/hr warning when the user has no
// rate configured (currently a silent failure that produces $0 WIP entries).
//
// Roles without `viewRates` (associate/paralegal/etc.) get rate=null so the
// dollar amount stays hidden — but `hasRate` is always returned so the form
// can still warn them when their rate is unset, since that's a misconfiguration
// they need to flag to an admin, not confidential rate info.
app.get('/api/me/rate', authRequired, verifyFirmMembership, (req, res) => {
  const matterId = req.query.matterId ? String(req.query.matterId) : null;
  let rate, inc;
  if (matterId) {
    const m = db.prepare('SELECT id FROM matters WHERE id = ? AND firm_id = ?').get(matterId, req.user.firmId);
    if (!m) return res.status(404).json({ error: 'Matter not found' });
    rate = effectiveRate(req.user.email, matterId);
    inc = effectiveIncrementMinutes(matterId);
  } else {
    const u = db.prepare('SELECT default_rate FROM users WHERE email = ?').get(req.user.email);
    rate = u?.default_rate || 0;
    inc = firmDefaultIncrementMinutes(req.user.firmId);
  }
  const canSee = CAPS.viewRates(req.user);
  res.json({ matterId, rate: canSee ? rate : null, hasRate: rate > 0, incrementMinutes: inc });
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
  const users = db.prepare('SELECT email, first_name, last_name, name, role, is_admin, default_rate, discount_rate, active, dt_subscriber, created_at FROM users WHERE firm_id = ? ORDER BY created_at').all(req.user.firmId);
  const canSeeRates = CAPS.viewRates(req.user);
  res.json({
    roles: Object.entries(ROLES).map(([id, v]) => ({ id, label: v.label, rank: v.rank })),
    users: users.map(u => ({
      email: u.email, firstName: u.first_name, lastName: u.last_name, name: u.name,
      role: u.role, isAdmin: !!u.is_admin, active: !!u.active,
      dtSubscriber: !!u.dt_subscriber,
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
  const { firstName, lastName, role, defaultRate, discountRate, active, dtSubscriber } = req.body;
  if (role && !VALID_ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  const newFirst  = (firstName ?? u.first_name ?? '').trim();
  const newLast   = (lastName  ?? u.last_name  ?? '').trim();
  const newRole   = role || u.role;
  const newName   = fullName(newFirst, newLast) || u.name;
  const newRate   = typeof defaultRate   === 'number' ? defaultRate   : u.default_rate;
  const newDisc   = 'discountRate' in (req.body || {})
    ? (discountRate === null || discountRate === '' ? null : Number(discountRate))
    : u.discount_rate;
  const newActive = typeof active        === 'boolean' ? (active        ? 1 : 0) : u.active;
  const newDtSub  = typeof dtSubscriber  === 'boolean' ? (dtSubscriber  ? 1 : 0) : u.dt_subscriber;
  db.prepare('UPDATE users SET first_name=?, last_name=?, name=?, role=?, default_rate=?, discount_rate=?, active=?, dt_subscriber=? WHERE email=?')
    .run(newFirst, newLast, newName, newRole, newRate, newDisc, newActive, newDtSub, emailLower);
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
  res.json({ id: f.id, name: f.name, settings: s, pipelineStages: data.pipelineStages || [], tags: data.tags || [], expenseCategories: data.expenseCategories || [], hasLogo: !!f.logo_data, smtpConfigured, inboundEmailConfigured: !!INBOUND_EMAIL_SECRET, inboundEmailAddress: INBOUND_EMAIL_ADDRESS });
});

app.put('/api/firm', authRequired, requireCap('manageFirm'), (req, res) => {
  const { name, settings, pipelineStages, tags, expenseCategories } = req.body;
  if (name) db.prepare('UPDATE firms SET name = ? WHERE id = ?').run(name.trim(), req.user.firmId);
  if (settings) db.prepare('UPDATE firms SET settings = ? WHERE id = ?').run(JSON.stringify(settings), req.user.firmId);
  if (pipelineStages || tags || expenseCategories) {
    const row = db.prepare('SELECT data FROM firm_data WHERE firm_id = ?').get(req.user.firmId);
    const cur = parseJSON(row?.data || '{}', {});
    if (pipelineStages)    cur.pipelineStages    = pipelineStages;
    if (tags)              cur.tags              = tags;
    if (expenseCategories) cur.expenseCategories = expenseCategories;
    db.prepare(`INSERT INTO firm_data (firm_id, data, version, updated_at) VALUES (?, ?, 1, datetime('now'))
                ON CONFLICT(firm_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`)
      .run(req.user.firmId, JSON.stringify(cur));
  }
  res.json({ ok: true });
});

// Firm logo (used in invoice PDFs). Stored as a BLOB on the firms row — same
// pattern as expense_attachments. GET is auth-required so logos don't leak.
const LOGO_MIME_WHITELIST = new Set(['image/png', 'image/jpeg', 'image/jpg']);
// Generous defense-in-depth cap: the SPA pre-compresses large logos to ~1.5 MB
// via Canvas before posting, so a 5 MB ceiling here only kicks in for clients
// that bypass the browser flow.
const LOGO_MAX_BYTES = 5 * 1024 * 1024;
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

// ── BACKUP ROUTES ───────────────────────────────────────────────────────
app.get('/api/admin/backups', authRequired, requireCap('manageFirm'), (req, res) => {
  res.json({
    backups: listBackupFiles(),
    retain: BACKUP_RETAIN,
    lastRunAt:     backupState.lastRunAt,
    lastSuccessAt: backupState.lastSuccessAt,
    lastError:     backupState.lastError,
    inProgress:    backupState.inProgress,
  });
});

app.post('/api/admin/backups/run', authRequired, requireCap('manageFirm'), async (req, res) => {
  try {
    const result = await runBackup({ manual: true });
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Backup failed' });
  }
});

app.get('/api/admin/backups/:filename/download', authRequired, requireCap('manageFirm'), (req, res) => {
  const name = req.params.filename;
  if (!/^crm-\d{4}-\d{2}-\d{2}(?:T\d{6})?\.db$/.test(name)) return res.status(400).json({ error: 'Invalid filename' });
  const full = path.join(BACKUP_DIR, name);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'Not found' });
  res.download(full, name);
});

app.delete('/api/admin/backups/:filename', authRequired, requireCap('manageFirm'), (req, res) => {
  const name = req.params.filename;
  if (!/^crm-\d{4}-\d{2}-\d{2}(?:T\d{6})?\.db$/.test(name)) return res.status(400).json({ error: 'Invalid filename' });
  const full = path.join(BACKUP_DIR, name);
  if (!fs.existsSync(full)) return res.status(404).json({ error: 'Not found' });
  fs.unlinkSync(full);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════
// PAYMENT CONFIG (Stripe + Mercury credentials per firm)
// ═══════════════════════════════════════════════════════════════════════
// GET returns a redacted view — secrets are never sent back in plaintext.
// PUT accepts partial updates: only fields present in the body are touched.
// POST /test pings the provider APIs with the currently stored credentials
// and reports which ones work. Stripe/Mercury calls are issued server-side
// so the keys never reach the browser.

function readPaymentConfig(firmId) {
  return db.prepare('SELECT * FROM firm_payment_config WHERE firm_id = ?').get(firmId) || null;
}

app.get('/api/firm/payments', authRequired, requireCap('manageFirm'), (req, res) => {
  const row = readPaymentConfig(req.user.firmId);
  // Show whether the system can even accept payment secrets right now.
  const resp = {
    paymentsEnabled,            // PAYMENTS_KEK configured on this server
    connected: { stripe: false, mercury: false },
    stripeAccountId:            row?.stripe_account_id || '',
    stripePublishable:          row?.stripe_publishable || '',
    stripeSecretKeyMasked:      null,
    stripeWebhookSecretMasked:  null,
    mercuryTokenMasked:         null,
    mercuryOperatingAccountId:  row?.mercury_operating_account_id || '',
    mercuryTrustAccountId:      row?.mercury_trust_account_id || '',
    achEnabled:  row ? !!row.ach_enabled  : true,
    cardEnabled: row ? !!row.card_enabled : true,
    updatedAt:   row?.updated_at || null,
  };
  if (row && paymentsEnabled) {
    try {
      const sk = decryptSecret(row.stripe_secret_key);
      const wh = decryptSecret(row.stripe_webhook_secret);
      const mt = decryptSecret(row.mercury_token);
      resp.stripeSecretKeyMasked     = maskSecret(sk);
      resp.stripeWebhookSecretMasked = maskSecret(wh);
      resp.mercuryTokenMasked        = maskSecret(mt);
      resp.connected.stripe  = !!sk;
      resp.connected.mercury = !!mt;
    } catch (e) {
      // If decryption fails the KEK was rotated without re-encrypting rows.
      console.error('[payments] decrypt failed for firm', req.user.firmId, e.message);
    }
  }
  res.json(resp);
});

app.put('/api/firm/payments', authRequired, requireCap('manageFirm'), (req, res) => {
  if (!paymentsEnabled) {
    return res.status(503).json({ error: 'PAYMENTS_KEK is not configured on the server. Payment credentials cannot be stored.' });
  }
  const b = req.body || {};
  const firmId = req.user.firmId;
  const cur = readPaymentConfig(firmId);

  // Accept any subset of fields. `null` or empty string clears a field;
  // undefined leaves it unchanged.
  const next = {
    stripe_account_id:            cur?.stripe_account_id ?? null,
    stripe_secret_key:            cur?.stripe_secret_key ?? null,
    stripe_publishable:           cur?.stripe_publishable ?? null,
    stripe_webhook_secret:        cur?.stripe_webhook_secret ?? null,
    mercury_token:                cur?.mercury_token ?? null,
    mercury_operating_account_id: cur?.mercury_operating_account_id ?? null,
    mercury_trust_account_id:     cur?.mercury_trust_account_id ?? null,
    ach_enabled:  cur ? cur.ach_enabled  : 1,
    card_enabled: cur ? cur.card_enabled : 1,
  };

  const setPlain = (field, val) => {
    if (val === undefined) return;
    next[field] = (val === null || val === '') ? null : String(val).trim();
  };
  const setSecret = (field, val) => {
    if (val === undefined) return;
    if (val === null || val === '') { next[field] = null; return; }
    next[field] = encryptSecret(String(val).trim());
  };

  setPlain('stripe_account_id',            b.stripeAccountId);
  setPlain('stripe_publishable',           b.stripePublishable);
  setPlain('mercury_operating_account_id', b.mercuryOperatingAccountId);
  setPlain('mercury_trust_account_id',     b.mercuryTrustAccountId);
  setSecret('stripe_secret_key',           b.stripeSecretKey);
  setSecret('stripe_webhook_secret',       b.stripeWebhookSecret);
  setSecret('mercury_token',               b.mercuryToken);
  if (b.achEnabled  !== undefined) next.ach_enabled  = b.achEnabled  ? 1 : 0;
  if (b.cardEnabled !== undefined) next.card_enabled = b.cardEnabled ? 1 : 0;

  // Light validation on publishable-key format when provided, to catch paste errors early.
  if (next.stripe_publishable && !/^pk_(test|live)_/.test(next.stripe_publishable)) {
    return res.status(400).json({ error: 'Stripe publishable key should start with pk_test_ or pk_live_' });
  }

  db.prepare(`
    INSERT INTO firm_payment_config (
      firm_id, stripe_account_id, stripe_secret_key, stripe_publishable,
      stripe_webhook_secret, mercury_token, mercury_operating_account_id,
      mercury_trust_account_id, ach_enabled, card_enabled, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(firm_id) DO UPDATE SET
      stripe_account_id            = excluded.stripe_account_id,
      stripe_secret_key            = excluded.stripe_secret_key,
      stripe_publishable           = excluded.stripe_publishable,
      stripe_webhook_secret        = excluded.stripe_webhook_secret,
      mercury_token                = excluded.mercury_token,
      mercury_operating_account_id = excluded.mercury_operating_account_id,
      mercury_trust_account_id     = excluded.mercury_trust_account_id,
      ach_enabled                  = excluded.ach_enabled,
      card_enabled                 = excluded.card_enabled,
      updated_at                   = excluded.updated_at
  `).run(
    firmId, next.stripe_account_id, next.stripe_secret_key, next.stripe_publishable,
    next.stripe_webhook_secret, next.mercury_token, next.mercury_operating_account_id,
    next.mercury_trust_account_id, next.ach_enabled, next.card_enabled
  );
  res.json({ ok: true });
});

// Pings Stripe + Mercury with the stored credentials. Reports which ones
// are reachable. Requires global fetch (Node 18+); server.js already runs
// under that requirement. Timeouts keep a bad key from hanging the UI.
app.post('/api/firm/payments/test', authRequired, requireCap('manageFirm'), async (req, res) => {
  if (!paymentsEnabled) return res.status(503).json({ error: 'PAYMENTS_KEK not configured' });
  const row = readPaymentConfig(req.user.firmId);
  const out = { stripe: { ok: false }, mercury: { ok: false } };

  const timedFetch = async (url, init = {}, ms = 8000) => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), ms);
    try { return await fetch(url, { ...init, signal: ctrl.signal }); }
    finally { clearTimeout(t); }
  };

  // Stripe — hit /v1/account which always works for any valid secret key.
  try {
    const sk = row ? decryptSecret(row.stripe_secret_key) : null;
    if (!sk) { out.stripe.error = 'No Stripe secret key saved'; }
    else {
      const r = await timedFetch('https://api.stripe.com/v1/account', {
        headers: { Authorization: 'Bearer ' + sk },
      });
      if (r.ok) {
        const j = await r.json();
        out.stripe.ok = true;
        out.stripe.accountId    = j.id;
        out.stripe.livemode     = !!j.charges_enabled && !sk.startsWith('sk_test_');
        out.stripe.displayName  = j.settings?.dashboard?.display_name || j.email || null;
      } else {
        const j = await r.json().catch(() => ({}));
        out.stripe.error = j.error?.message || `HTTP ${r.status}`;
      }
    }
  } catch (e) { out.stripe.error = e.message; }

  // Mercury — list accounts endpoint is the canonical "is this token alive" check.
  try {
    const mt = row ? decryptSecret(row.mercury_token) : null;
    if (!mt) { out.mercury.error = 'No Mercury token saved'; }
    else {
      const r = await timedFetch('https://api.mercury.com/api/v1/accounts', {
        headers: { Authorization: 'Bearer ' + mt, Accept: 'application/json' },
      });
      if (r.ok) {
        const j = await r.json();
        const accts = Array.isArray(j.accounts) ? j.accounts : (Array.isArray(j) ? j : []);
        out.mercury.ok = true;
        out.mercury.accountCount = accts.length;
        out.mercury.accounts = accts.map(a => ({
          id:   a.id,
          name: a.nickname || a.name || a.accountNumber || a.id,
          kind: a.kind || a.type || null,
        }));
      } else {
        const j = await r.json().catch(() => ({}));
        out.mercury.error = j.message || j.error || `HTTP ${r.status}`;
      }
    }
  } catch (e) { out.mercury.error = e.message; }

  res.json(out);
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

function validateSplitPct(v) {
  if (v == null || v === '') return null;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0 || n > 100) throw new Error('Origination split must be between 0 and 100');
  return Math.round(n * 100) / 100;
}

function normalizeEmail(v) {
  if (v == null) return null;
  const s = String(v).trim().toLowerCase();
  return s || null;
}

// Next per-firm sequential client number. Called inside the POST/PUT handler so
// it sees the latest MAX. Concurrent inserts in better-sqlite3 are serialized
// by the single-writer SQLite lock, so MAX+1 is safe without an explicit BEGIN.
function nextClientNumber(firmId) {
  const row = db.prepare(`SELECT COALESCE(MAX(client_number), 0) + 1 AS n FROM contacts WHERE firm_id = ?`).get(firmId);
  return row.n;
}
// Next per-client sequential matter number (1 → 00001 in the UI).
function nextMatterNumber(clientContactId) {
  const row = db.prepare(`SELECT COALESCE(MAX(matter_number), 0) + 1 AS n FROM matters WHERE client_contact_id = ?`).get(clientContactId);
  return row.n;
}

// Next per-firm sequential matter number for matters that have no client.
// Independent of the per-client sequence — they live in distinct rows
// (client_contact_id IS NULL vs IS NOT NULL) so they never collide.
function nextFirmMatterNumber(firmId) {
  const row = db.prepare(`SELECT COALESCE(MAX(matter_number), 0) + 1 AS n FROM matters WHERE firm_id = ? AND client_contact_id IS NULL`).get(firmId);
  return row.n;
}

// Fetches a matter joined with its client's client_number, and lazily
// backfills matter_number for any matter that lacks one — whether it has a
// client (per-client sequence) or not (per-firm clientless sequence). The
// WHERE matter_number IS NULL guard makes concurrent calls idempotent.
// Returns null if the matter doesn't exist or doesn't belong to firmId.
function fetchMatterForInvoice(matterId, firmId) {
  if (!matterId) return null;
  let m = db.prepare(`SELECT m.*, c.client_number AS client_number
                      FROM matters m LEFT JOIN contacts c ON c.id = m.client_contact_id
                      WHERE m.id = ? AND m.firm_id = ?`).get(matterId, firmId);
  if (!m) return null;
  if (m.matter_number == null) {
    const n = m.client_contact_id ? nextMatterNumber(m.client_contact_id) : nextFirmMatterNumber(firmId);
    const r = db.prepare(`UPDATE matters SET matter_number = ? WHERE id = ? AND matter_number IS NULL`).run(n, m.id);
    if (r.changes) m.matter_number = n;
    else {
      // Another request beat us to it; re-read so the caller sees the assigned number.
      const fresh = db.prepare('SELECT matter_number FROM matters WHERE id = ?').get(m.id);
      if (fresh) m.matter_number = fresh.matter_number;
    }
  }
  return m;
}

app.post('/api/contacts', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const b = req.body || {};
  const id = uid('c_');
  const first = (b.firstName || '').trim();
  const last  = (b.lastName  || '').trim();
  const full  = (b.fullName || fullName(first, last) || b.companyName || 'Unnamed').trim();
  const now = new Date().toISOString();
  let inc, splitPct;
  try { inc = validateIncrement(b.billingIncrementMinutes); } catch(e) { return res.status(400).json({ error: e.message }); }
  try { splitPct = validateSplitPct(b.originationSplitPct); } catch(e) { return res.status(400).json({ error: e.message }); }
  const last4 = b.taxIdLast4 ? String(b.taxIdLast4).replace(/\D/g, '').slice(-4) : null;
  const type = b.type || 'prospect';
  const clientNumber = (type === 'client') ? nextClientNumber(req.user.firmId) : null;
  db.prepare(`INSERT INTO contacts (
      id, firm_id, type, first_name, last_name, full_name, email, phone, title,
      company_id, company_name, address, linkedin, referred_by_id, pipeline_stage,
      tags, privilege, owner_email, notes, next_action, next_action_at,
      billing_increment_minutes,
      mailing_address, date_of_birth, client_since, secondary_email, secondary_phone,
      industry, tax_id_last4, preferred_contact,
      originating_attorney_email, origination_split_pct, billing_attorney_email,
      client_number,
      primary_contact_name, primary_contact_title, primary_contact_email, primary_contact_phone,
      created_by, created_at, updated_at
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    id, req.user.firmId, type, first, last, full,
    b.email || null, b.phone || null, b.title || null,
    b.companyId || null, b.companyName || null, b.address || null, b.linkedin || null,
    b.referredById || null, b.pipelineStage || null,
    JSON.stringify(b.tags || []), b.privilege ? 1 : 0, normalizeEmail(b.ownerEmail) || req.user.email,
    b.notes || null, b.nextAction || null, b.nextActionAt || null,
    inc,
    b.mailingAddress || null, b.dateOfBirth || null, b.clientSince || null,
    b.secondaryEmail || null, b.secondaryPhone || null,
    b.industry || null, last4, b.preferredContact || null,
    normalizeEmail(b.originatingAttorneyEmail), splitPct, normalizeEmail(b.billingAttorneyEmail),
    clientNumber,
    b.primaryContactName || null, b.primaryContactTitle || null,
    normalizeEmail(b.primaryContactEmail) || null, b.primaryContactPhone || null,
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
  let inc, splitPct;
  try { inc = 'billingIncrementMinutes' in b ? validateIncrement(b.billingIncrementMinutes) : existing.billing_increment_minutes; }
  catch(e) { return res.status(400).json({ error: e.message }); }
  try { splitPct = 'originationSplitPct' in b ? validateSplitPct(b.originationSplitPct) : existing.origination_split_pct; }
  catch(e) { return res.status(400).json({ error: e.message }); }
  const last4 = 'taxIdLast4' in b
    ? (b.taxIdLast4 ? String(b.taxIdLast4).replace(/\D/g, '').slice(-4) : null)
    : existing.tax_id_last4;
  const origAttyEmail = 'originatingAttorneyEmail' in b
    ? normalizeEmail(b.originatingAttorneyEmail)
    : existing.originating_attorney_email;
  const billAttyEmail = 'billingAttorneyEmail' in b
    ? normalizeEmail(b.billingAttorneyEmail)
    : existing.billing_attorney_email;
  // Assign a client_number the first time a contact becomes type='client'.
  // Once assigned, the number is permanent — converting back to prospect and
  // forward again reuses the original number.
  const newType = b.type ?? existing.type;
  let clientNumber = existing.client_number;
  if (newType === 'client' && clientNumber == null) {
    clientNumber = nextClientNumber(req.user.firmId);
  }
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
      originating_attorney_email = ?, origination_split_pct = ?, billing_attorney_email = ?,
      client_number = ?,
      primary_contact_name = ?, primary_contact_title = ?,
      primary_contact_email = ?, primary_contact_phone = ?,
      updated_at = datetime('now')
    WHERE id = ? AND firm_id = ?`).run(
    b.type || null, (first||'').trim(), (last||'').trim(), full,
    b.email ?? existing.email, b.phone ?? existing.phone, b.title ?? existing.title,
    b.companyId ?? existing.company_id, b.companyName ?? existing.company_name,
    b.address ?? existing.address, b.linkedin ?? existing.linkedin,
    b.referredById ?? existing.referred_by_id, b.pipelineStage ?? existing.pipeline_stage,
    JSON.stringify(b.tags ?? parseJSON(existing.tags, [])),
    typeof b.privilege === 'boolean' ? (b.privilege ? 1 : 0) : existing.privilege,
    normalizeEmail(b.ownerEmail ?? existing.owner_email) || req.user.email,
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
    origAttyEmail, splitPct, billAttyEmail,
    clientNumber,
    b.primaryContactName ?? existing.primary_contact_name,
    b.primaryContactTitle ?? existing.primary_contact_title,
    'primaryContactEmail' in b ? (normalizeEmail(b.primaryContactEmail) || null) : existing.primary_contact_email,
    b.primaryContactPhone ?? existing.primary_contact_phone,
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

// Dedup check — warn before saving a contact with a matching email
app.get('/api/contacts/dedup-check', authRequired, verifyFirmMembership, (req, res) => {
  const { email, excludeId } = req.query;
  if (!email) return res.json([]);
  let sql = 'SELECT id, full_name, type, email FROM contacts WHERE firm_id = ? AND LOWER(email) = ?';
  const params = [req.user.firmId, String(email).trim().toLowerCase()];
  if (excludeId) { sql += ' AND id != ?'; params.push(excludeId); }
  res.json(db.prepare(sql).all(...params));
});

// Find all email-duplicate groups for the Find Duplicates tool in Settings
app.get('/api/contacts/duplicates', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const emails = db.prepare(
    `SELECT LOWER(email) AS email FROM contacts
     WHERE firm_id = ? AND email IS NOT NULL AND email != ''
     GROUP BY LOWER(email) HAVING COUNT(*) > 1`
  ).all(req.user.firmId).map(r => r.email);
  const groups = emails.map(email => {
    const contacts = db.prepare(
      `SELECT id, full_name, type, email, company_name, created_at FROM contacts
       WHERE firm_id = ? AND LOWER(email) = ? ORDER BY created_at ASC`
    ).all(req.user.firmId, email);
    return { email, contacts };
  });
  res.json(groups);
});

// Merge: absorb otherId into id; transfer all references then delete other
app.post('/api/contacts/:id/merge/:otherId', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const primary = db.prepare('SELECT * FROM contacts WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  const other   = db.prepare('SELECT * FROM contacts WHERE id = ? AND firm_id = ?').get(req.params.otherId, req.user.firmId);
  if (!primary || !other) return res.status(404).json({ error: 'Contact not found' });
  if (primary.id === other.id) return res.status(400).json({ error: 'Cannot merge a contact with itself' });
  db.transaction(() => {
    db.prepare(`UPDATE interactions SET contact_id        = ? WHERE contact_id        = ? AND firm_id = ?`).run(primary.id, other.id, req.user.firmId);
    db.prepare(`UPDATE matters       SET client_contact_id = ? WHERE client_contact_id = ? AND firm_id = ?`).run(primary.id, other.id, req.user.firmId);
    db.prepare(`UPDATE invoices      SET client_contact_id = ? WHERE client_contact_id = ? AND firm_id = ?`).run(primary.id, other.id, req.user.firmId);
    db.prepare(`UPDATE trust_ledger  SET contact_id        = ? WHERE contact_id        = ? AND firm_id = ?`).run(primary.id, other.id, req.user.firmId);
    db.prepare('DELETE FROM contacts WHERE id = ? AND firm_id = ?').run(other.id, req.user.firmId);
  })();
  res.json({ ok: true, primaryId: primary.id });
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

app.put('/api/interactions/:id', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const i = db.prepare('SELECT * FROM interactions WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!i) return res.status(404).json({ error: 'Not found' });
  if (i.created_by !== req.user.email && !req.user.isAdmin) return res.status(403).json({ error: 'Only the author or an admin can edit' });
  const b = req.body || {};
  db.prepare(`UPDATE interactions SET kind=?, subject=?, body=?, occurred_at=? WHERE id = ?`)
    .run(b.kind || i.kind, b.subject ?? i.subject, b.body ?? i.body,
         b.occurredAt || i.occurred_at, req.params.id);
  res.json(db.prepare('SELECT * FROM interactions WHERE id = ?').get(req.params.id));
});

app.delete('/api/interactions/:id', authRequired, verifyFirmMembership, (req, res) => {
  // Only author or admin can delete
  const i = db.prepare('SELECT * FROM interactions WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!i) return res.status(404).json({ error: 'Not found' });
  if (i.created_by !== req.user.email && !req.user.isAdmin) return res.status(403).json({ error: 'Only the author or an admin can delete' });
  db.prepare('DELETE FROM interactions WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ─── Outbound email from contact view (Phase 5.2) ───────────────────────
// Sends an email via SMTP and auto-logs it as an email interaction.
app.post('/api/contacts/:id/email', authRequired, verifyFirmMembership, requireCap('editContacts'), async (req, res) => {
  if (!mailer) return res.status(503).json({ error: 'Email sending is not configured (SMTP env vars missing)' });
  const contact = db.prepare('SELECT id, full_name, email FROM contacts WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!contact) return res.status(404).json({ error: 'Contact not found' });

  const { to, cc, subject, body } = req.body || {};
  if (!to || !subject || !body) return res.status(400).json({ error: 'to, subject, and body are required' });
  const e = lenErr(body, MAX_NOTE, 'Body');
  if (e) return res.status(400).json({ error: e });

  const fromAddr = process.env.SMTP_FROM || process.env.SMTP_USER;
  try {
    await mailer.sendMail({
      from: fromAddr,
      replyTo: req.user.email,
      to:  sanitizeEmailHeader(to),
      ...(cc ? { cc: sanitizeEmailHeader(cc) } : {}),
      subject: sanitizeEmailHeader(subject),
      text: body,
    });
  } catch (err) {
    console.error('[send-email] SMTP error:', err.message);
    return res.status(502).json({ error: 'Failed to send email: ' + err.message });
  }

  const iid = uid('i_');
  db.prepare(`INSERT INTO interactions (id, firm_id, contact_id, kind, subject, body, occurred_at, created_by)
              VALUES (?,?,?,'email',?,?,datetime('now'),?)`)
    .run(iid, req.user.firmId, contact.id, subject.slice(0, 500), body, req.user.email);
  db.prepare(`UPDATE contacts SET last_activity_at = datetime('now'), updated_at = datetime('now') WHERE id = ? AND firm_id = ?`)
    .run(contact.id, req.user.firmId);

  res.json({ ok: true, interactionId: iid });
});

// ═══════════════════════════════════════════════════════════════════════
// INBOUND EMAIL WEBHOOK (Phase 4.4)
// ═══════════════════════════════════════════════════════════════════════
// POST /api/webhooks/inbound-email
// Called by Mailgun, SendGrid, or Postmark inbound routing when an email
// is delivered to INBOUND_EMAIL_ADDRESS (the BCC logging address).
// Caller must supply the shared secret in X-Webhook-Secret header.
// Creates one interaction (kind='email') per CRM contact matched by address.

function extractEmailAddresses(headerStr) {
  if (!headerStr) return [];
  const found = [];
  const s = String(headerStr);
  // angle-addr:  "Name" <user@host>
  const angleRe = /<([^>@\s]+@[^>@\s]+)>/g;
  let m;
  while ((m = angleRe.exec(s)) !== null) found.push(m[1].toLowerCase());
  // bare addr-spec (not already inside <>)
  const stripped = s.replace(/<[^>]*>/g, '');
  const bareRe = /(?:^|[\s,;])([^\s,;<>"@]+@[^\s,;<>"]+)(?:[\s,;]|$)/g;
  while ((m = bareRe.exec(stripped)) !== null) found.push(m[1].toLowerCase());
  return [...new Set(found)];
}

app.post('/api/webhooks/inbound-email', (req, res) => {
  if (!INBOUND_EMAIL_SECRET) return res.status(503).json({ error: 'Inbound email not configured' });

  const provided = req.headers['x-webhook-secret'] || req.query.secret || '';
  if (!provided || provided !== INBOUND_EMAIL_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const b = req.body || {};

  // Normalize fields across inbound email providers:
  //   Mailgun:  sender, From, To, Cc, Subject, body-plain
  //   SendGrid: from,   to,   cc, subject, text
  //   Postmark: From,   To,   Cc, Subject, TextBody
  const fromRaw  = b.sender || b.from || b.From || '';
  const toRaw    = b.To     || b.to   || '';
  const ccRaw    = b.Cc     || b.cc   || '';
  const subject  = String(b.Subject || b.subject || '(no subject)').slice(0, 500);
  const bodyText = String(b['body-plain'] || b.TextBody || b.text || b['body-html'] || '').slice(0, 50000);
  const dateStr  = b.Date || b.date || new Date().toISOString();

  const allAddresses = [
    ...extractEmailAddresses(fromRaw),
    ...extractEmailAddresses(toRaw),
    ...extractEmailAddresses(ccRaw),
  ];

  if (!allAddresses.length) {
    return res.status(400).json({ error: 'No email addresses found in From/To/Cc' });
  }

  const firm = db.prepare('SELECT id FROM firms LIMIT 1').get();
  if (!firm) return res.status(500).json({ error: 'No firm found' });

  const placeholders = allAddresses.map(() => '?').join(',');
  const contacts = db.prepare(
    `SELECT id, full_name FROM contacts WHERE firm_id = ? AND LOWER(email) IN (${placeholders})`
  ).all(firm.id, ...allAddresses);

  if (!contacts.length) {
    return res.json({ ok: true, matched: 0, message: 'No matching contacts found' });
  }

  const occurredAt = (() => {
    try { return new Date(dateStr).toISOString(); } catch { return new Date().toISOString(); }
  })();

  const createdBy = extractEmailAddresses(fromRaw)[0] || 'inbound@email';

  const insertStmt = db.prepare(
    `INSERT INTO interactions (id, firm_id, contact_id, kind, subject, body, occurred_at, created_by)
     VALUES (?,?,?,'email',?,?,?,?)`
  );
  const touchContact = db.prepare(
    `UPDATE contacts SET last_activity_at = datetime('now'), updated_at = datetime('now') WHERE id = ? AND firm_id = ?`
  );

  db.transaction(() => {
    for (const c of contacts) {
      insertStmt.run(uid('i_'), firm.id, c.id, subject, bodyText, occurredAt, createdBy);
      touchContact.run(c.id, firm.id);
    }
  })();

  console.log(`[inbound-email] "${subject}" from ${createdBy} → ${contacts.length} contact(s): ${contacts.map(c => c.full_name).join(', ')}`);
  res.json({ ok: true, matched: contacts.length, contacts: contacts.map(c => c.full_name) });
});

// ═══════════════════════════════════════════════════════════════════════
// MATTERS (CRM-local, optional link to DealTracker)
// ═══════════════════════════════════════════════════════════════════════

// Matter rows expose the parent client's client_number alongside their own
// matter_number so the UI can render the combined identifier (e.g. "42-00001")
// without a second round-trip per row.
const MATTER_SELECT = `SELECT m.*, c.client_number AS client_number
  FROM matters m
  LEFT JOIN contacts c ON c.id = m.client_contact_id`;

app.get('/api/matters', authRequired, verifyFirmMembership, (req, res) => {
  const { status, clientId } = req.query;
  let sql = MATTER_SELECT + ' WHERE m.firm_id = ?';
  const params = [req.user.firmId];
  if (status)   { sql += ' AND m.status = ?';            params.push(status); }
  if (clientId) { sql += ' AND m.client_contact_id = ?'; params.push(clientId); }
  sql += ' ORDER BY m.opened_at DESC';
  res.json(db.prepare(sql).all(...params));
});

app.post('/api/matters', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const b = req.body || {};
  if (!b.name?.trim()) return res.status(400).json({ error: 'Matter name required' });
  if (b.billingType && !['hourly','flat','contingency'].includes(b.billingType)) return res.status(400).json({ error: 'Invalid billingType' });
  let inc;
  try { inc = validateIncrement(b.billingIncrementMinutes); } catch(e) { return res.status(400).json({ error: e.message }); }
  const id = uid('m_');
  const clientId = b.clientContactId || null;
  // Always assign a matter_number — per-client sequence when a client is set,
  // per-firm clientless sequence otherwise — so every matter has a real number
  // to print on invoices instead of falling back to the internal uuid.
  const matterNumber = clientId ? nextMatterNumber(clientId) : nextFirmMatterNumber(req.user.firmId);
  db.prepare(`INSERT INTO matters (id, firm_id, dt_matter_id, client_contact_id, client_name, name, description, billing_type, flat_fee, status, billing_increment_minutes, matter_number, created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
    id, req.user.firmId, b.dtMatterId || null, clientId, b.clientName || null,
    b.name.trim(), b.description || null, b.billingType || 'hourly', b.flatFee || 0, b.status || 'active', inc, matterNumber, req.user.email);
  res.json(db.prepare(MATTER_SELECT + ' WHERE m.id = ?').get(id));
});

app.put('/api/matters/:id', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const existing = db.prepare('SELECT * FROM matters WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!existing) return res.status(404).json({ error: 'Matter not found' });
  const b = req.body || {};
  if (b.billingType && !['hourly','flat','contingency'].includes(b.billingType)) return res.status(400).json({ error: 'Invalid billingType' });
  let inc;
  try { inc = 'billingIncrementMinutes' in b ? validateIncrement(b.billingIncrementMinutes) : existing.billing_increment_minutes; }
  catch(e) { return res.status(400).json({ error: e.message }); }
  // Matter numbers are scoped per-client (with a separate per-firm sequence
  // for clientless matters). If the matter's client changes, re-issue from the
  // appropriate sequence so it doesn't collide with the new bucket. If the
  // matter still has no number on a no-op edit, assign one now.
  const newClientId = ('clientContactId' in b) ? (b.clientContactId || null) : existing.client_contact_id;
  let matterNumber = existing.matter_number;
  if (newClientId !== existing.client_contact_id) {
    matterNumber = newClientId ? nextMatterNumber(newClientId) : nextFirmMatterNumber(req.user.firmId);
  } else if (matterNumber == null) {
    matterNumber = newClientId ? nextMatterNumber(newClientId) : nextFirmMatterNumber(req.user.firmId);
  }
  const nextBillingSchedule = 'billingSchedule' in b
    ? (b.billingSchedule ? JSON.stringify(b.billingSchedule) : null)
    : existing.billing_schedule;
  const nextTrustMin = 'trustMinBalance' in b
    ? (Number(b.trustMinBalance) || 0)
    : (existing.trust_min_balance || 0);
  const nextTrustTo  = 'trustReplenishTo' in b
    ? (b.trustReplenishTo == null || b.trustReplenishTo === '' ? null : Number(b.trustReplenishTo))
    : existing.trust_replenish_to;

  db.prepare(`UPDATE matters SET
      name = COALESCE(?, name), description = ?, billing_type = COALESCE(?, billing_type),
      flat_fee = COALESCE(?, flat_fee), status = COALESCE(?, status),
      client_contact_id = ?, client_name = ?, dt_matter_id = ?,
      billing_increment_minutes = ?,
      matter_number = ?,
      billing_schedule = ?, trust_min_balance = ?, trust_replenish_to = ?,
      closed_at = CASE WHEN ? = 'closed' AND status != 'closed' THEN datetime('now') ELSE closed_at END,
      updated_at = datetime('now')
    WHERE id = ? AND firm_id = ?`).run(
    b.name?.trim() || null, b.description ?? null, b.billingType || null,
    typeof b.flatFee === 'number' ? b.flatFee : null, b.status || null,
    newClientId, b.clientName ?? existing.client_name, b.dtMatterId ?? null,
    inc,
    matterNumber,
    nextBillingSchedule, nextTrustMin, nextTrustTo,
    b.status || '', req.params.id, req.user.firmId);
  res.json(db.prepare(MATTER_SELECT + ' WHERE m.id = ?').get(req.params.id));
});

// ── RECURRING BILLING HELPERS + CRON ────────────────────────────────────
// A recurring invoice is just a 1-line flat-fee invoice generated on a schedule
// stored as JSON on the matter. We deliberately do NOT sweep unbilled time —
// that's the manual POST /api/invoices code path and would double-count work
// the attorney was already logging against the same matter.
function getMatterTrustBalance(firmId, matterId) {
  const row = db.prepare(`SELECT COALESCE(SUM(amount), 0) AS bal FROM trust_ledger
                          WHERE firm_id = ? AND matter_id = ?`).get(firmId, matterId);
  return Number(row?.bal || 0);
}

function hasPendingReplenishment(firmId, matterId) {
  const row = db.prepare(`SELECT 1 AS ok FROM invoices
                          WHERE firm_id = ? AND matter_id = ?
                            AND status IN ('draft','sent')
                            AND notes LIKE 'Trust replenishment%'`).get(firmId, matterId);
  return !!row;
}

// monthly: add 1 month; quarterly: add 3 months. day_of_period 1-28 only
// (anything past 28 would skip Feb), clamped at the caller. Returns YYYY-MM-DD.
function advanceNextRunAt(prev, kind, day) {
  const d = new Date(prev + 'T00:00:00Z');
  const months = kind === 'quarterly' ? 3 : 1;
  d.setUTCMonth(d.getUTCMonth() + months);
  const dayClamped = Math.max(1, Math.min(28, parseInt(day, 10) || 1));
  d.setUTCDate(dayClamped);
  return d.toISOString().slice(0, 10);
}

// Create a single-line invoice for `amount` against a matter. Mirrors the
// transaction shape of POST /api/invoices (numbering, totals, draft status)
// but skips time-entry / expense sweep and the manageBilling permission check
// — callers are the cron job or an admin-gated route.
function createRecurringInvoice(firmId, matter, amount, description, notes, createdBy = 'system@recurring') {
  if (!matter || !amount || amount <= 0) return null;
  const id = uid('inv_');
  const number = nextInvoiceNumber(firmId);
  const now = new Date().toISOString();
  const subtotal = +Number(amount).toFixed(2);
  const total = subtotal;
  const lineId = uid('il_');
  const tx = db.transaction(() => {
    db.prepare(`INSERT INTO invoices (id, firm_id, number, client_contact_id, client_name, matter_id, issued_at, due_at, subtotal, tax, total, status, notes, created_by)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      id, firmId, number, matter.client_contact_id || null, matter.client_name || null, matter.id,
      now, null, subtotal, 0, total, 'draft', notes || null, createdBy);
    db.prepare(`INSERT INTO invoice_lines (id, invoice_id, kind, description, time_entry_id, quantity, rate, amount, sort_order)
                VALUES (?,?,?,?,?,?,?,?,?)`).run(
      lineId, id, 'flat', description, null, 1, subtotal, subtotal, 0);
  });
  tx();
  return { id, number, total };
}

// One pass over the recurring schedule for one matter. Returns {generated, replenished}
// counters. Idempotent — only fires when next_run_at <= today, and advances next_run_at
// so a re-run on the same day is a no-op. The replenishment check skips when an
// unpaid replenishment invoice is already outstanding.
function runRecurringForMatter(firmId, matter, today) {
  let generated = null, replenished = null;
  // 1) Scheduled billing
  if (matter.billing_schedule) {
    let sched;
    try { sched = JSON.parse(matter.billing_schedule); } catch { sched = null; }
    if (sched && sched.active && sched.next_run_at && sched.next_run_at <= today && Number(sched.amount) > 0) {
      const desc = sched.description || `Recurring fee — ${matter.name}`;
      generated = createRecurringInvoice(firmId, matter, Number(sched.amount), desc, null);
      sched.next_run_at = advanceNextRunAt(sched.next_run_at, sched.kind, sched.day_of_period);
      db.prepare('UPDATE matters SET billing_schedule = ?, updated_at = datetime(\'now\') WHERE id = ?')
        .run(JSON.stringify(sched), matter.id);
    }
  }
  // 2) Trust replenishment
  const floor = Number(matter.trust_min_balance || 0);
  if (floor > 0) {
    const bal = getMatterTrustBalance(firmId, matter.id);
    if (bal < floor && !hasPendingReplenishment(firmId, matter.id)) {
      const target = Number(matter.trust_replenish_to) > 0 ? Number(matter.trust_replenish_to) : floor;
      const shortfall = +(target - bal).toFixed(2);
      if (shortfall > 0) {
        replenished = createRecurringInvoice(
          firmId, matter, shortfall,
          `Trust replenishment — ${matter.name}`,
          `Trust replenishment (balance ${bal.toFixed(2)} below floor ${floor.toFixed(2)})`
        );
      }
    }
  }
  return { generated, replenished };
}

function runRecurringBilling() {
  const today = new Date().toISOString().slice(0, 10);
  const matters = db.prepare(`SELECT * FROM matters WHERE status = 'active'
                              AND (billing_schedule IS NOT NULL OR trust_min_balance > 0)`).all();
  let totalGen = 0, totalRep = 0;
  for (const m of matters) {
    try {
      const r = runRecurringForMatter(m.firm_id, m, today);
      if (r.generated)   totalGen++;
      if (r.replenished) totalRep++;
    } catch (e) {
      console.warn(`[recurring] matter ${m.id}: ${e.message}`);
    }
  }
  if (totalGen || totalRep) {
    console.log(`[recurring] ${today}: generated=${totalGen} replenished=${totalRep}`);
  }
  return { generated: totalGen, replenished: totalRep };
}

function scheduleRecurringBilling() {
  // Run once on boot (after a grace) then every hour. Idempotent — same-day
  // re-runs are no-ops because next_run_at advances after each generation.
  setTimeout(() => { try { runRecurringBilling(); } catch(e) { console.warn('[recurring]', e.message); } }, 45 * 1000);
  setInterval(() => { try { runRecurringBilling(); } catch(e) { console.warn('[recurring]', e.message); } }, 60 * 60 * 1000);
}

// Manual trigger — useful after editing a schedule or fixing a missed run.
app.post('/api/matters/:id/billing-schedule/run-now', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const m = db.prepare('SELECT * FROM matters WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!m) return res.status(404).json({ error: 'Matter not found' });
  if (m.status !== 'active') return res.status(400).json({ error: 'Matter is not active' });
  const today = new Date().toISOString().slice(0, 10);
  try {
    const r = runRecurringForMatter(req.user.firmId, m, today);
    res.json({ ok: true, ...r });
  } catch (e) {
    res.status(500).json({ error: e.message || 'Failed' });
  }
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
  // Drop rows without a positive rate so we never persist bogus 0 overrides
  // (those would short-circuit the user's default rate at lookup time).
  const list = (Array.isArray(req.body) ? req.body : [])
    .map(it => ({ userEmail: String(it.userEmail || '').toLowerCase(), rate: Number(it.rate) }))
    .filter(it => it.userEmail && Number.isFinite(it.rate) && it.rate > 0);
  const tx = db.transaction((items) => {
    db.prepare('DELETE FROM matter_rates WHERE matter_id = ?').run(req.params.id);
    const ins = db.prepare('INSERT INTO matter_rates (matter_id, user_email, rate) VALUES (?,?,?)');
    items.forEach(it => ins.run(req.params.id, it.userEmail, it.rate));
  });
  tx(list);
  res.json({ ok: true });
});

// Fetch fresh DT data for a linked matter and cache it in dt_data
app.post('/api/matters/:id/dt-sync', authRequired, verifyFirmMembership, requireCap('editContacts'), async (req, res) => {
  const matter = db.prepare('SELECT id, dt_matter_id FROM matters WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!matter)           return res.status(404).json({ error: 'Matter not found' });
  if (!matter.dt_matter_id) return res.status(400).json({ error: 'No DT matter linked' });
  try {
    const r = await fetch(`${DT_URL}/api/clients/export`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return res.status(502).json({ error: 'DT unreachable' });
    const clients = await r.json();
    const found = Array.isArray(clients) ? clients.find(c => String(c.id) === String(matter.dt_matter_id)) : null;
    if (!found) return res.status(404).json({ error: 'DT matter not found in export — ID may have changed' });
    db.prepare(`UPDATE matters SET dt_data = ?, updated_at = datetime('now') WHERE id = ?`)
      .run(JSON.stringify(found), matter.id);
    res.json({ ok: true, dt_matter_id: matter.dt_matter_id, dt_data: found });
  } catch(e) {
    res.status(502).json({ error: 'DT sync failed: ' + e.message });
  }
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

// ── Matter document attachments (Phase 5.3) ─────────────────────────────
const DOC_MIME_WHITELIST = new Set([
  'application/pdf',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/plain',
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
]);
const MAX_DOC_BYTES = 10 * 1024 * 1024; // 10 MB

function loadMatterForDoc(req, res) {
  const m = db.prepare('SELECT id FROM matters WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!m) { res.status(404).json({ error: 'Matter not found' }); return null; }
  return m;
}

app.get('/api/matters/:id/documents', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const m = loadMatterForDoc(req, res); if (!m) return;
  const rows = db.prepare(`SELECT id, filename, mime_type, size, uploaded_by, created_at
                           FROM matter_documents WHERE matter_id = ? ORDER BY created_at DESC`).all(m.id);
  res.json(rows);
});

app.post('/api/matters/:id/documents', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const m = loadMatterForDoc(req, res); if (!m) return;
  const { filename, mimeType, dataBase64 } = req.body || {};
  if (!filename || !mimeType || !dataBase64) return res.status(400).json({ error: 'filename, mimeType, dataBase64 required' });
  if (!DOC_MIME_WHITELIST.has(mimeType)) return res.status(400).json({ error: 'File type not allowed. Accepted: PDF, Word, Excel, plain text, and images.' });
  let buf;
  try { buf = Buffer.from(dataBase64, 'base64'); }
  catch { return res.status(400).json({ error: 'Invalid base64 data' }); }
  if (buf.length === 0) return res.status(400).json({ error: 'Empty file' });
  if (buf.length > MAX_DOC_BYTES) return res.status(413).json({ error: `File too large (max ${MAX_DOC_BYTES / 1024 / 1024} MB)` });
  const id = uid('doc_');
  const safeName = String(filename).slice(0, 255);
  db.prepare(`INSERT INTO matter_documents (id, matter_id, firm_id, filename, mime_type, size, data, uploaded_by)
              VALUES (?,?,?,?,?,?,?,?)`).run(id, m.id, req.user.firmId, safeName, mimeType, buf.length, buf, req.user.email);
  res.json({ id, filename: safeName, mime_type: mimeType, size: buf.length, uploaded_by: req.user.email });
});

app.get('/api/matters/:id/documents/:docId', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const m = loadMatterForDoc(req, res); if (!m) return;
  const doc = db.prepare('SELECT * FROM matter_documents WHERE id = ? AND matter_id = ?').get(req.params.docId, m.id);
  if (!doc) return res.status(404).json({ error: 'Document not found' });
  const disposition = req.query.download ? 'attachment' : 'inline';
  res.setHeader('Content-Type', doc.mime_type);
  res.setHeader('Content-Length', doc.size);
  res.setHeader('Content-Disposition', `${disposition}; filename="${doc.filename.replace(/"/g, '')}"`);
  res.send(doc.data);
});

app.delete('/api/matters/:id/documents/:docId', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const m = loadMatterForDoc(req, res); if (!m) return;
  const doc = db.prepare('SELECT uploaded_by FROM matter_documents WHERE id = ? AND matter_id = ?').get(req.params.docId, m.id);
  if (!doc) return res.status(404).json({ error: 'Document not found' });
  if (doc.uploaded_by !== req.user.email && !req.user.isAdmin) return res.status(403).json({ error: 'Only the uploader or an admin can delete' });
  db.prepare('DELETE FROM matter_documents WHERE id = ?').run(req.params.docId);
  res.json({ ok: true });
});

// ── Matter task tracking (Phase 5.5) ────────────────────────────────────
app.get('/api/matters/:id/tasks', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const m = loadMatterForDoc(req, res); if (!m) return;
  const rows = db.prepare(`SELECT * FROM matter_tasks WHERE matter_id = ? ORDER BY
    CASE WHEN status = 'open' THEN 0 ELSE 1 END,
    COALESCE(due_date, '9999-12-31'),
    created_at`).all(m.id);
  res.json(rows);
});

app.post('/api/matters/:id/tasks', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const m = loadMatterForDoc(req, res); if (!m) return;
  const { description, dueDate, assignedTo } = req.body || {};
  if (!description || !String(description).trim()) return res.status(400).json({ error: 'description required' });
  const id = uid('mt_');
  db.prepare(`INSERT INTO matter_tasks (id, matter_id, firm_id, description, due_date, assigned_to, created_by)
              VALUES (?,?,?,?,?,?,?)`)
    .run(id, m.id, req.user.firmId, String(description).trim().slice(0, 500),
         dueDate || null, assignedTo || null, req.user.email);
  res.json(db.prepare('SELECT * FROM matter_tasks WHERE id = ?').get(id));
});

app.patch('/api/matters/:id/tasks/:taskId', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const m = loadMatterForDoc(req, res); if (!m) return;
  const task = db.prepare('SELECT * FROM matter_tasks WHERE id = ? AND matter_id = ?').get(req.params.taskId, m.id);
  if (!task) return res.status(404).json({ error: 'Task not found' });
  const { description, dueDate, assignedTo, status } = req.body || {};
  const validStatuses = ['open', 'done'];
  if (status && !validStatuses.includes(status)) return res.status(400).json({ error: 'status must be open or done' });
  db.prepare(`UPDATE matter_tasks SET
    description = ?, due_date = ?, assigned_to = ?, status = ?, updated_at = datetime('now')
    WHERE id = ?`)
    .run(
      description != null ? String(description).trim().slice(0, 500) : task.description,
      dueDate !== undefined ? (dueDate || null) : task.due_date,
      assignedTo !== undefined ? (assignedTo || null) : task.assigned_to,
      status || task.status,
      task.id,
    );
  res.json(db.prepare('SELECT * FROM matter_tasks WHERE id = ?').get(task.id));
});

app.delete('/api/matters/:id/tasks/:taskId', authRequired, verifyFirmMembership, requireCap('editContacts'), (req, res) => {
  const m = loadMatterForDoc(req, res); if (!m) return;
  const task = db.prepare('SELECT created_by FROM matter_tasks WHERE id = ? AND matter_id = ?').get(req.params.taskId, m.id);
  if (!task) return res.status(404).json({ error: 'Task not found' });
  if (task.created_by !== req.user.email && !req.user.isAdmin) return res.status(403).json({ error: 'Only the creator or an admin can delete' });
  db.prepare('DELETE FROM matter_tasks WHERE id = ?').run(req.params.taskId);
  res.json({ ok: true });
});

// "My open tasks" — dashboard widget: tasks assigned to me, open, sorted by due date
app.get('/api/tasks/mine', authRequired, verifyFirmMembership, (req, res) => {
  const rows = db.prepare(`
    SELECT t.*, m.name AS matter_name, m.id AS matter_id,
           c.full_name AS client_name
      FROM matter_tasks t
      JOIN matters m ON m.id = t.matter_id
      LEFT JOIN contacts c ON c.id = m.client_contact_id
     WHERE t.firm_id = ? AND t.assigned_to = ? AND t.status = 'open'
     ORDER BY COALESCE(t.due_date, '9999-12-31'), t.created_at
     LIMIT 50
  `).all(req.user.firmId, req.user.email);
  res.json(rows);
});

// ═══════════════════════════════════════════════════════════════════════
// TIME ENTRIES
// ═══════════════════════════════════════════════════════════════════════

function effectiveRate(userEmail, matterId) {
  // A matter_rates row is treated as a real override only if its rate is > 0.
  // Stale/blank rows can sneak in (e.g. PUT round-trips that defaulted missing
  // values to 0); without this guard those silently zero out an entry's value.
  // Pro-bono should be expressed via billable=false on the entry, not a 0 rate.
  const override = db.prepare('SELECT rate FROM matter_rates WHERE matter_id = ? AND user_email = ?').get(matterId, userEmail);
  if (override && override.rate > 0) return override.rate;
  const u = db.prepare('SELECT default_rate FROM users WHERE email = ?').get(userEmail);
  return u?.default_rate || 0;
}

const DEFAULT_INCREMENT_MIN = 6;  // fallback when a firm hasn't set its own default
const VALID_INCREMENTS = [6, 15];

// The firm-level default increment is stored on firms.settings JSON under
// `defaultIncrementMinutes`. Falls back to 6 (0.1 hr) if unset or invalid.
function firmDefaultIncrementMinutes(firmId) {
  if (!firmId) return DEFAULT_INCREMENT_MIN;
  const row = db.prepare('SELECT settings FROM firms WHERE id = ?').get(firmId);
  const s = parseJSON(row?.settings, {});
  const v = parseInt(s.defaultIncrementMinutes, 10);
  return VALID_INCREMENTS.includes(v) ? v : DEFAULT_INCREMENT_MIN;
}

// Resolve the billing increment in minutes for a matter: matter → client → firm default.
function effectiveIncrementMinutes(matterId) {
  const m = db.prepare('SELECT billing_increment_minutes, client_contact_id, firm_id FROM matters WHERE id = ?').get(matterId);
  if (!m) return DEFAULT_INCREMENT_MIN;
  if (m.billing_increment_minutes) return m.billing_increment_minutes;
  if (m.client_contact_id) {
    const c = db.prepare('SELECT billing_increment_minutes FROM contacts WHERE id = ?').get(m.client_contact_id);
    if (c?.billing_increment_minutes) return c.billing_increment_minutes;
  }
  return firmDefaultIncrementMinutes(m.firm_id);
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

app.post('/api/time/import', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const rows = Array.isArray(req.body?.rows) ? req.body.rows : [];
  if (!rows.length) return res.json({ inserted: 0, skipped: 0, errors: [] });
  let inserted = 0, skipped = 0;
  const errors = [];
  const tx = db.transaction(() => {
    rows.forEach((row, i) => {
      const m = db.prepare('SELECT id FROM matters WHERE id = ? AND firm_id = ?').get(row.matterId, req.user.firmId);
      if (!m) { errors.push({ index: i, error: 'Matter not found' }); skipped++; return; }
      if (!row.date || !/^\d{4}-\d{2}-\d{2}$/.test(String(row.date))) { errors.push({ index: i, error: 'Invalid date' }); skipped++; return; }
      const mins = parseInt(row.minutes, 10);
      if (!mins || mins <= 0) { errors.push({ index: i, error: 'Invalid minutes' }); skipped++; return; }
      const targetUser = (row.userEmail && CAPS.manageBilling(req.user))
        ? String(row.userEmail).toLowerCase()
        : req.user.email;
      const rate = effectiveRate(targetUser, row.matterId);
      const billable = row.billable === false || row.billable === 0 ? 0 : 1;
      db.prepare(`INSERT INTO time_entries (id, firm_id, user_email, matter_id, date, minutes, rate, description, billable) VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(uid('t_'), req.user.firmId, targetUser, row.matterId, row.date, mins, rate, row.description || null, billable);
      inserted++;
    });
  });
  try {
    tx();
    res.json({ inserted, skipped, errors });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
  // Inline matter_number + client_number so the SPA detail view can render the
  // "{client#}-{matter#}" identifier without a second round-trip. Also lazily
  // backfills matter_number for old rows that missed the boot migration.
  const matter = fetchMatterForInvoice(inv.matter_id, req.user.firmId);
  const payments = db.prepare(`SELECT id, amount, method, status, occurred_at, reference, notes, destination,
                                      stripe_payment_intent_id, trust_ledger_id, created_by, created_at
                               FROM invoice_payments WHERE invoice_id = ? AND firm_id = ?
                               ORDER BY occurred_at DESC, created_at DESC`).all(req.params.id, req.user.firmId);
  const adjustments = db.prepare(`SELECT * FROM invoice_adjustments
                                  WHERE invoice_id = ? AND firm_id = ?
                                  ORDER BY occurred_at DESC, created_at DESC`).all(req.params.id, req.user.firmId);
  res.json({
    ...inv, lines, payments, adjustments,
    matter_number: matter?.matter_number ?? null,
    client_number: matter?.client_number ?? null,
    matter_name:   matter?.name ?? null,
  });
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
  // plus the matter's flat fee whenever flat_fee > 0 (independent of billing_type
  // — so the flat fee always appears in the total even if hourly entries are
  // also coded against the matter), plus any b.extraLines provided.
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
    }
    if (matter.flat_fee > 0) {
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

  // Compute tax against the raw (unrounded) subtotal so fractional cents from
  // each line don't drop before the multiplication. Subtotal and tax are then
  // each rounded independently; total is the sum of the two rounded values so
  // the UI's "subtotal + tax = total" always reconciles exactly.
  const rawSubtotal = lines.reduce((s, l) => s + (l.amount || 0), 0);
  const subtotal = +rawSubtotal.toFixed(2);
  const taxRate  = Number(b.taxRate) || 0;
  const tax      = +(rawSubtotal * taxRate).toFixed(2);
  const total    = +(subtotal + tax).toFixed(2);

  const tx = db.transaction(() => {
    db.prepare(`INSERT INTO invoices (id, firm_id, number, client_contact_id, client_name, matter_id, issued_at, due_at, subtotal, tax, total, status, notes, created_by)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      id, req.user.firmId, number, clientContactId, clientName, matter?.id || null,
      b.issuedAt || now, b.dueAt || null, subtotal, tax, total, 'draft', b.notes || null, req.user.email);
    const ins = db.prepare(`INSERT INTO invoice_lines (id, invoice_id, kind, description, time_entry_id, quantity, rate, amount, sort_order) VALUES (?,?,?,?,?,?,?,?,?)`);
    lines.forEach(l => ins.run(l.id, id, l.kind, l.description, l.time_entry_id, l.quantity, l.rate, l.amount, l.sort_order));
    // Mark time entries as billed against this invoice. The WHERE clause requires
    // status='draft' so an entry that's already on another invoice can't be silently
    // re-bound — if a row didn't update, it was already billed and we abort.
    const markTime = db.prepare(`UPDATE time_entries SET invoice_id = ?, status = 'billed', updated_at = datetime('now') WHERE id = ? AND firm_id = ? AND status = 'draft'`);
    lines.filter(l => l.time_entry_id).forEach(l => {
      const info = markTime.run(id, l.time_entry_id, req.user.firmId);
      if (info.changes === 0) throw new Error(`Time entry ${l.time_entry_id} is already billed or not in this firm`);
    });
    // Mark expenses as billed too — same guard.
    const markExp = db.prepare(`UPDATE expenses SET invoice_id = ?, status = 'billed', updated_at = datetime('now') WHERE id = ? AND firm_id = ? AND status = 'draft'`);
    lines.filter(l => l._expense_id).forEach(l => {
      const info = markExp.run(id, l._expense_id, req.user.firmId);
      if (info.changes === 0) throw new Error(`Expense ${l._expense_id} is already billed or not in this firm`);
    });
  });
  try { tx(); }
  catch(e) { return res.status(409).json({ error: e.message || 'Could not create invoice' }); }

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
    const rawSubtotal = rows.reduce((s, r) => s + (Number(r.amount) || 0), 0);
    const subtotal = +rawSubtotal.toFixed(2);
    const currentRate = inv.subtotal > 0 ? inv.tax / inv.subtotal : 0;
    const taxRate = (b.taxRate === undefined || b.taxRate === null || b.taxRate === '') ? currentRate : Number(b.taxRate);
    const tax = +(rawSubtotal * (Number.isFinite(taxRate) ? taxRate : 0)).toFixed(2);
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
  db.prepare(`UPDATE invoices SET status = ?, amount_paid = CASE ? WHEN 'paid' THEN total WHEN 'void' THEN 0 ELSE amount_paid END, updated_at = datetime('now') WHERE id = ?`)
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

// ═══════════════════════════════════════════════════════════════════════
// MANUAL PAYMENTS + ADJUSTMENTS (per invoice)
// ═══════════════════════════════════════════════════════════════════════
// Source of truth for cash on an invoice is invoice_payments. Stripe writes
// rows via webhook; this section lets a partner/admin record off-channel
// receipts (check, wire, ach, cash) and apply trust-on-deposit to a bill.
// Adjustments table tracks write-downs (and the rare write-up) without
// mutating invoices.total — original gross is preserved for realization
// reporting.

const PAYMENT_METHODS = ['check', 'wire', 'ach', 'cash', 'trust', 'manual'];
const ADJUSTMENT_KINDS = ['writedown', 'writeup', 'courtesy', 'bad_debt'];

app.get('/api/invoices/:id/payments', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const inv = db.prepare('SELECT id FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  const rows = db.prepare(`SELECT id, amount, method, status, occurred_at, reference, notes, destination,
                                  trust_ledger_id, stripe_payment_intent_id, created_by, created_at
                           FROM invoice_payments WHERE invoice_id = ? AND firm_id = ?
                           ORDER BY occurred_at DESC, created_at DESC`).all(req.params.id, req.user.firmId);
  res.json(rows);
});

// Record a manual payment against a specific invoice. method='trust' also
// posts a fee-applied trust_ledger row in the same transaction so the IOLTA
// audit trail stays in sync. Refuses to overpay (amount > balance + 0.005).
app.post('/api/invoices/:id/payments', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const b = req.body || {};
  const amount = Number(b.amount);
  if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'Positive amount required' });
  const method = String(b.method || '').toLowerCase();
  if (!PAYMENT_METHODS.includes(method)) return res.status(400).json({ error: `Invalid method (use: ${PAYMENT_METHODS.join(', ')})` });

  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  if (inv.status === 'void') return res.status(400).json({ error: 'Cannot record payment on a void invoice' });

  const writedown = Number(inv.amount_writedown || 0);
  const balance = +(Number(inv.total || 0) + writedown - Number(inv.amount_paid || 0)).toFixed(2);
  if (amount > balance + 0.005) {
    return res.status(400).json({ error: `Amount exceeds balance due (${fmtMoney(balance)}). Adjust or void first.` });
  }

  const occurredAt = b.occurredAt || new Date().toISOString();
  const reference  = b.reference || null;
  const notes      = b.notes || null;
  const id         = uid('pay_');

  try {
    const result = db.transaction(() => {
      let trustLedgerId = null;
      if (method === 'trust') {
        if (!inv.client_contact_id) throw new Error('Trust-applied payments require an invoice with a client');
        const cur = db.prepare('SELECT COALESCE(SUM(amount),0) AS bal FROM trust_ledger WHERE firm_id = ? AND client_contact_id = ?')
          .get(req.user.firmId, inv.client_contact_id).bal;
        if (cur < amount - 0.001) throw new Error(`Insufficient trust balance for client (${fmtMoney(cur)})`);
        trustLedgerId = uid('tr_');
        db.prepare(`INSERT INTO trust_ledger (id, firm_id, client_contact_id, client_name, matter_id, kind, amount, reference, occurred_at, notes, created_by)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
          trustLedgerId, req.user.firmId, inv.client_contact_id, inv.client_name, inv.matter_id,
          'fee-applied', -amount, inv.number || inv.id, occurredAt,
          `Applied to invoice ${inv.number || inv.id}`, req.user.email);
      }

      db.prepare(`INSERT INTO invoice_payments
                    (id, firm_id, invoice_id, client_contact_id, destination, amount, currency,
                     method, status, occurred_at, reference, notes, trust_ledger_id, created_by)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        id, req.user.firmId, inv.id, inv.client_contact_id, 'operating',
        amount, 'usd', method, 'succeeded', occurredAt, reference, notes, trustLedgerId, req.user.email);

      return recomputeInvoiceTotals(inv.id, req.user.firmId);
    })();
    res.json({ id, ...result });
  } catch (e) {
    res.status(400).json({ error: e.message || 'Could not record payment' });
  }
});

// Reverse a payment. Trust-method payments also reverse the matching trust
// ledger row (append-only invariant — posts a refund entry, not a delete).
// Stripe payments are not deletable here — refund them via Stripe.
app.delete('/api/invoices/:id/payments/:pid', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const pay = db.prepare('SELECT * FROM invoice_payments WHERE id = ? AND firm_id = ? AND invoice_id = ?')
    .get(req.params.pid, req.user.firmId, req.params.id);
  if (!pay) return res.status(404).json({ error: 'Payment not found' });
  if (pay.stripe_payment_intent_id) return res.status(400).json({ error: 'Refund Stripe payments via Stripe — they sync back through the webhook' });
  if (pay.status !== 'succeeded') return res.status(400).json({ error: 'Only succeeded payments can be reversed' });

  try {
    const result = db.transaction(() => {
      db.prepare(`UPDATE invoice_payments SET status = 'refunded' WHERE id = ?`).run(pay.id);
      if (pay.method === 'trust' && pay.trust_ledger_id) {
        const orig = db.prepare('SELECT * FROM trust_ledger WHERE id = ? AND firm_id = ?')
          .get(pay.trust_ledger_id, req.user.firmId);
        if (orig) {
          db.prepare(`INSERT INTO trust_ledger (id, firm_id, client_contact_id, client_name, matter_id, kind, amount, reference, occurred_at, notes, created_by)
                      VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
            uid('tr_'), req.user.firmId, orig.client_contact_id, orig.client_name, orig.matter_id,
            'refund', -orig.amount, `REVERSE ${orig.id}`, new Date().toISOString(),
            `Reversal of payment ${pay.id}`, req.user.email);
        }
      }
      return recomputeInvoiceTotals(pay.invoice_id, req.user.firmId);
    })();
    res.json({ ok: true, ...result });
  } catch (e) {
    res.status(400).json({ error: e.message || 'Could not reverse payment' });
  }
});

// ───────────────────── Adjustments (write-downs / write-ups) ─────────────
app.get('/api/invoices/:id/adjustments', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const inv = db.prepare('SELECT id FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  const rows = db.prepare(`SELECT * FROM invoice_adjustments
                           WHERE invoice_id = ? AND firm_id = ?
                           ORDER BY occurred_at DESC, created_at DESC`).all(req.params.id, req.user.firmId);
  res.json(rows);
});

app.post('/api/invoices/:id/adjustments', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const b = req.body || {};
  const kind = String(b.kind || '').toLowerCase();
  if (!ADJUSTMENT_KINDS.includes(kind)) return res.status(400).json({ error: `Invalid kind (use: ${ADJUSTMENT_KINDS.join(', ')})` });
  const raw = Number(b.amount);
  if (!Number.isFinite(raw) || raw <= 0) return res.status(400).json({ error: 'Positive amount required (sign is set by kind)' });

  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Not found' });
  if (inv.status === 'void') return res.status(400).json({ error: 'Cannot adjust a void invoice' });

  // writeup adds to billed total; everything else reduces it
  const signed = kind === 'writeup' ? +raw : -raw;
  const id = uid('adj_');
  const occurredAt = b.occurredAt || new Date().toISOString();

  try {
    const result = db.transaction(() => {
      db.prepare(`INSERT INTO invoice_adjustments (id, firm_id, invoice_id, amount, kind, occurred_at, reason, created_by)
                  VALUES (?,?,?,?,?,?,?,?)`).run(
        id, req.user.firmId, inv.id, signed, kind, occurredAt, b.reason || null, req.user.email);
      return recomputeInvoiceTotals(inv.id, req.user.firmId);
    })();
    res.json({ id, ...result });
  } catch (e) {
    res.status(400).json({ error: e.message || 'Could not record adjustment' });
  }
});

app.delete('/api/invoices/:id/adjustments/:aid', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const adj = db.prepare('SELECT * FROM invoice_adjustments WHERE id = ? AND firm_id = ? AND invoice_id = ?')
    .get(req.params.aid, req.user.firmId, req.params.id);
  if (!adj) return res.status(404).json({ error: 'Not found' });
  db.transaction(() => {
    db.prepare('DELETE FROM invoice_adjustments WHERE id = ?').run(adj.id);
    recomputeInvoiceTotals(adj.invoice_id, req.user.firmId);
  })();
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════
// PAYMENT LINKS (admin-created, public-consumable)
// ═══════════════════════════════════════════════════════════════════════
// Step 2 constraints: operating destination only; link amount is always the
// full current balance (partial payment is not offered in the public page).
// Trust-destination links land in step 3.
app.post('/api/invoices/:id/payment-link', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Invoice not found' });
  if (inv.status === 'void') return res.status(400).json({ error: 'Invoice is void' });
  if (inv.status === 'paid') return res.status(400).json({ error: 'Invoice is already paid' });

  const cfg = readPaymentConfig(req.user.firmId);
  if (!cfg || !cfg.stripe_secret_key) {
    return res.status(503).json({ error: 'Stripe is not connected. Configure it in Settings → Payments.' });
  }

  const balanceDue = Math.max(0, Math.round(((inv.total || 0) - (inv.amount_paid || 0)) * 100));
  if (balanceDue <= 0) return res.status(400).json({ error: 'Nothing left to pay on this invoice' });

  const expiresInDays = Math.max(1, Math.min(365, parseInt(req.body?.expiresInDays ?? 30, 10)));
  const token = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + expiresInDays * 86400000).toISOString();

  db.prepare(`INSERT INTO payment_links
              (token, firm_id, invoice_id, destination, amount_cents, expires_at, created_by)
              VALUES (?, ?, ?, 'operating', ?, ?, ?)`)
    .run(token, req.user.firmId, inv.id, balanceDue, expiresAt, req.user.email);

  const base = (req.headers['x-forwarded-proto'] || req.protocol) + '://' + req.get('host');
  res.json({ token, url: base + '/pay/' + token, expiresAt, amountCents: balanceDue });
});

// Lists prior pay links for an invoice so the UI can surface existing links
// rather than blindly creating duplicates. Returns status computed client-side-safe.
app.get('/api/invoices/:id/payment-links', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const inv = db.prepare('SELECT id FROM invoices WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Invoice not found' });
  const rows = db.prepare(`SELECT token, destination, amount_cents, expires_at, used_at, created_by, created_at
                           FROM payment_links WHERE invoice_id = ? AND firm_id = ?
                           ORDER BY created_at DESC LIMIT 20`).all(req.params.id, req.user.firmId);
  const base = (req.headers['x-forwarded-proto'] || req.protocol) + '://' + req.get('host');
  res.json(rows.map(r => ({
    ...r,
    url: base + '/pay/' + r.token,
    expired: r.expires_at && new Date(r.expires_at) < new Date(),
  })));
});

// ── Payment reminder email (Phase 5.4) ──────────────────────────────────
app.post('/api/invoices/:id/reminder', authRequired, verifyFirmMembership, requireCap('manageBilling'), async (req, res) => {
  if (!mailer) return res.status(503).json({ error: 'Email sending is not configured (SMTP env vars missing)' });

  const inv = db.prepare(`SELECT i.*, c.email AS contact_email, c.full_name AS contact_full_name, c.id AS cid,
                                 f.name AS firm_name, f.settings AS firm_settings
                            FROM invoices i
                            LEFT JOIN contacts c ON c.id = i.client_contact_id
                            LEFT JOIN firms f ON f.id = i.firm_id
                           WHERE i.id = ? AND i.firm_id = ?`).get(req.params.id, req.user.firmId);
  if (!inv) return res.status(404).json({ error: 'Invoice not found' });
  if (inv.status !== 'sent') return res.status(400).json({ error: 'Reminders can only be sent for invoices with status "sent"' });
  if (!inv.contact_email) return res.status(400).json({ error: 'Client has no email address on file' });

  const paidAmt  = +(Number(inv.amount_paid || 0)).toFixed(2);
  const balance  = +(Number(inv.total || 0) - paidAmt).toFixed(2);
  if (balance <= 0.005) return res.status(400).json({ error: 'Invoice is fully paid' });

  const firmSettings = parseJSON(inv.firm_settings, {});
  const firmPhone  = firmSettings.phone  || '';
  const firmEmail  = firmSettings.email  || '';
  const issuedFmt  = inv.issued_at ? inv.issued_at.slice(0, 10) : '—';
  const dueFmt     = inv.due_at    ? inv.due_at.slice(0, 10)    : '—';
  const balFmt     = '$' + balance.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const clientName = inv.contact_full_name || inv.client_name || 'Client';
  const firmName   = inv.firm_name || 'Our firm';

  const subject = `Payment reminder: Invoice ${inv.number || inv.id} — ${balFmt} due`;
  const textBody = [
    `Dear ${clientName},`,
    '',
    `This is a friendly reminder that the following invoice remains outstanding:`,
    '',
    `  Invoice:  ${inv.number || inv.id}`,
    `  Issued:   ${issuedFmt}`,
    `  Due:      ${dueFmt}`,
    `  Balance:  ${balFmt}`,
    '',
    `Please remit payment at your earliest convenience. If you believe this has already been paid or have any questions, please contact our office.`,
    '',
    ...(firmPhone ? [`Phone: ${firmPhone}`] : []),
    ...(firmEmail ? [`Email: ${firmEmail}`] : []),
    '',
    `Thank you,`,
    firmName,
  ].join('\n');

  const fromAddr = process.env.SMTP_FROM || process.env.SMTP_USER;
  try {
    await mailer.sendMail({
      from: fromAddr,
      replyTo: req.user.email,
      to: sanitizeEmailHeader(inv.contact_email),
      subject: sanitizeEmailHeader(subject),
      text: textBody,
    });
  } catch (err) {
    console.error('[reminder] SMTP error:', err.message);
    return res.status(502).json({ error: 'Failed to send reminder: ' + err.message });
  }

  if (inv.cid) {
    const iid = uid('i_');
    db.prepare(`INSERT INTO interactions (id, firm_id, contact_id, kind, subject, body, occurred_at, created_by)
                VALUES (?,?,?,'email',?,?,datetime('now'),?)`)
      .run(iid, req.user.firmId, inv.cid, subject, textBody, req.user.email);
    db.prepare(`UPDATE contacts SET last_activity_at = datetime('now'), updated_at = datetime('now') WHERE id = ? AND firm_id = ?`)
      .run(inv.cid, req.user.firmId);
  }

  console.log(`[reminder] ${inv.number || inv.id} → ${inv.contact_email} (${balFmt})`);
  res.json({ ok: true, sentTo: inv.contact_email });
});

// ── PUBLIC PAY PAGE (no auth; token proves authorization) ───────────────
// Rate limiter shared across pay routes to blunt token-guessing attempts.
const payLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, max: 60,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many requests. Try again shortly.' },
});

function escHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

function renderSimplePayPage(title, message) {
  return `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escHtml(title)}</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif;background:#f6f4ef;margin:0;padding:40px 20px;color:#222}
.card{max-width:460px;margin:40px auto;background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.06)}
h1{font-size:20px;margin:0 0 12px;color:#0f1f3d}
p{line-height:1.55;margin:0;color:#555}</style>
</head><body><div class="card"><h1>${escHtml(title)}</h1><p>${escHtml(message)}</p></div></body></html>`;
}

app.get('/pay/:token', payLimiter, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const link = db.prepare('SELECT * FROM payment_links WHERE token = ?').get(req.params.token);
  if (!link) return res.status(404).type('html').send(renderSimplePayPage('Link not found', 'This payment link is invalid or has been removed.'));
  if (link.expires_at && new Date(link.expires_at) < new Date()) {
    return res.status(410).type('html').send(renderSimplePayPage('Link expired', 'This payment link has expired. Please contact the firm for a new one.'));
  }

  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(link.invoice_id, link.firm_id);
  if (!inv || inv.status === 'void') {
    return res.status(404).type('html').send(renderSimplePayPage('Invoice unavailable', 'This invoice is no longer available.'));
  }
  if (inv.status === 'paid' || (inv.total && (inv.amount_paid || 0) >= inv.total - 0.005)) {
    return res.type('html').send(renderSimplePayPage('Already paid', 'This invoice has already been paid in full. Thank you!'));
  }

  const firm = db.prepare('SELECT name FROM firms WHERE id = ?').get(link.firm_id);
  const cfg  = readPaymentConfig(link.firm_id);
  const pub  = cfg?.stripe_publishable || '';
  if (!pub || !cfg?.stripe_secret_key) {
    return res.status(503).type('html').send(renderSimplePayPage('Payments unavailable',
      'This firm has not finished connecting Stripe. Please contact them to arrange payment another way.'));
  }

  const amount = (link.amount_cents / 100).toLocaleString('en-US', { style: 'currency', currency: 'usd' });
  res.type('html').send(`<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pay ${escHtml(firm.name)} — Invoice ${escHtml(inv.number || inv.id)}</title>
<script src="https://js.stripe.com/v3/"></script>
<style>
  :root{--navy:#0f1f3d;--gold:#c9a227;--cream:#f6f4ef;--muted:#666}
  *{box-sizing:border-box}
  body{font-family:system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif;background:var(--cream);margin:0;padding:32px 16px;color:#222}
  .card{max-width:480px;margin:20px auto;background:#fff;padding:28px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.06)}
  h1{font-size:18px;margin:0 0 4px;color:var(--navy)}
  .firm{font-size:13px;color:var(--muted);margin-bottom:20px}
  .row{display:flex;justify-content:space-between;padding:10px 0;font-size:14px;border-top:1px solid #eee}
  .row:first-of-type{border-top:none}
  .row .lbl{color:var(--muted)}
  .total{font-size:22px;font-weight:700;color:var(--navy);margin:18px 0 22px;display:flex;justify-content:space-between;align-items:baseline}
  .total .lbl{font-size:13px;color:var(--muted);font-weight:400}
  #payment-element{margin-bottom:18px}
  button{width:100%;padding:13px;font-size:15px;font-weight:600;background:var(--gold);color:var(--navy);border:0;border-radius:6px;cursor:pointer}
  button:disabled{opacity:.5;cursor:not-allowed}
  #msg{margin-top:14px;padding:10px 12px;border-radius:6px;font-size:13px;display:none}
  #msg.err{background:#fbe9e9;color:#8a1c1c;display:block}
  #msg.ok{background:#e6f5ea;color:#1a5c2e;display:block}
  .footnote{font-size:11px;color:var(--muted);margin-top:16px;text-align:center}
  .spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.2);border-top-color:var(--navy);border-radius:50%;animation:sp 0.8s linear infinite;vertical-align:middle;margin-right:6px}
  @keyframes sp{to{transform:rotate(360deg)}}
</style>
</head><body>
<div class="card">
  <h1>Invoice ${escHtml(inv.number || inv.id)}</h1>
  <div class="firm">Payable to ${escHtml(firm.name)}</div>

  <div class="row"><span class="lbl">Invoice #</span><span>${escHtml(inv.number || inv.id)}</span></div>
  <div class="row"><span class="lbl">Billed to</span><span>${escHtml(inv.client_name || '—')}</span></div>
  ${inv.issued_at ? `<div class="row"><span class="lbl">Issued</span><span>${escHtml(new Date(inv.issued_at).toLocaleDateString())}</span></div>` : ''}
  <div class="total"><span class="lbl">Amount due</span><span>${escHtml(amount)}</span></div>

  <form id="payment-form">
    <div id="payment-element"><div style="padding:20px;text-align:center;color:var(--muted);font-size:13px"><span class="spinner"></span>Loading payment form…</div></div>
    <button type="submit" id="submit-btn" disabled>Pay ${escHtml(amount)}</button>
    <div id="msg"></div>
  </form>
  <div class="footnote">Secured by Stripe. Card details never touch this firm's servers.</div>
</div>

<script>
(function(){
  var PUB = ${JSON.stringify(pub)};
  var TOKEN = ${JSON.stringify(req.params.token)};
  var RETURN_URL = window.location.origin + '/pay/' + TOKEN + '/complete';
  var stripe = Stripe(PUB);
  var elements;
  var msg = document.getElementById('msg');
  var submitBtn = document.getElementById('submit-btn');
  var form = document.getElementById('payment-form');

  function showMsg(text, kind){ msg.textContent = text; msg.className = kind || ''; }

  // Create a PaymentIntent, then mount the Payment Element bound to it.
  fetch('/api/pay/' + TOKEN + '/intent', { method:'POST', headers:{'Content-Type':'application/json'}, body:'{}' })
    .then(function(r){ return r.json().then(function(j){ if (!r.ok) throw new Error(j.error || 'init failed'); return j; }); })
    .then(function(j){
      elements = stripe.elements({ clientSecret: j.clientSecret, appearance: { theme: 'stripe', variables: { colorPrimary: '#0f1f3d' } } });
      var pe = elements.create('payment', { layout: 'tabs' });
      document.getElementById('payment-element').innerHTML = '';
      pe.mount('#payment-element');
      pe.on('ready', function(){ submitBtn.disabled = false; });
    })
    .catch(function(e){
      document.getElementById('payment-element').innerHTML = '';
      showMsg(e.message || 'Could not start payment', 'err');
    });

  form.addEventListener('submit', function(ev){
    ev.preventDefault();
    if (!elements) return;
    submitBtn.disabled = true;
    showMsg('Processing…');
    stripe.confirmPayment({ elements: elements, confirmParams: { return_url: RETURN_URL } })
      .then(function(result){
        // Only reached if there was an immediate error (no redirect).
        if (result.error) {
          showMsg(result.error.message || 'Payment failed', 'err');
          submitBtn.disabled = false;
        }
      });
  });
})();
</script>
</body></html>`);
});

// After redirect back from 3DS / ACH, Stripe appends query params we can use
// to display a success screen. The webhook is the source of truth for invoice
// state — this screen is cosmetic.
app.get('/pay/:token/complete', payLimiter, (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const status = String(req.query.redirect_status || '').toLowerCase();
  if (status === 'succeeded') {
    return res.type('html').send(renderSimplePayPage('Payment received',
      'Thank you — your payment has been submitted. The firm will send a confirmation once the funds clear. You can close this window.'));
  }
  if (status === 'processing') {
    return res.type('html').send(renderSimplePayPage('Payment processing',
      'Your payment is being processed. ACH payments typically settle in 3–5 business days. You will receive a confirmation from the firm once it clears.'));
  }
  return res.type('html').send(renderSimplePayPage('Payment not completed',
    'The payment was not completed. You can return to the pay link and try again.'));
});

// Creates (or reuses) a Stripe PaymentIntent for the pay link. One pending
// invoice_payments row is inserted on first call; subsequent calls for the
// same link return the same PI's client_secret so re-renders don't duplicate.
app.post('/api/pay/:token/intent', payLimiter, async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const link = db.prepare('SELECT * FROM payment_links WHERE token = ?').get(req.params.token);
  if (!link) return res.status(404).json({ error: 'Invalid link' });
  if (link.expires_at && new Date(link.expires_at) < new Date()) return res.status(410).json({ error: 'Link expired' });

  const inv = db.prepare('SELECT * FROM invoices WHERE id = ? AND firm_id = ?').get(link.invoice_id, link.firm_id);
  if (!inv || inv.status === 'void') return res.status(400).json({ error: 'Invoice not available' });
  if (inv.status === 'paid' || (inv.total && (inv.amount_paid || 0) >= inv.total - 0.005)) {
    return res.status(400).json({ error: 'Invoice is already paid' });
  }

  let bits;
  try { bits = getStripeClient(link.firm_id); }
  catch (e) { return res.status(e.status || 500).json({ error: e.message }); }

  const cfg = readPaymentConfig(link.firm_id);
  const methods = [];
  if (cfg.card_enabled) methods.push('card');
  if (cfg.ach_enabled)  methods.push('us_bank_account');
  if (!methods.length) return res.status(503).json({ error: 'No payment methods are enabled' });

  // If a pending PI already exists for this link, reuse it to avoid creating
  // orphaned intents when the customer reloads the page.
  const existing = db.prepare(`SELECT * FROM invoice_payments
                               WHERE firm_id=? AND invoice_id=? AND status='pending'
                                 AND stripe_payment_intent_id IS NOT NULL
                               ORDER BY created_at DESC LIMIT 1`)
    .get(link.firm_id, link.invoice_id);
  if (existing) {
    try {
      const pi = await bits.client.paymentIntents.retrieve(existing.stripe_payment_intent_id);
      if (pi && (pi.status === 'requires_payment_method' || pi.status === 'requires_confirmation' || pi.status === 'requires_action')) {
        return res.json({ clientSecret: pi.client_secret });
      }
    } catch { /* fall through and create a new one */ }
  }

  try {
    const pi = await bits.client.paymentIntents.create({
      amount:   link.amount_cents,
      currency: 'usd',
      payment_method_types: methods,
      description: `Invoice ${inv.number || inv.id}`,
      metadata: {
        firm_id:            link.firm_id,
        invoice_id:         link.invoice_id,
        payment_link_token: link.token,
        destination:        link.destination,
      },
    });
    const rowId = '_' + crypto.randomBytes(8).toString('hex');
    db.prepare(`INSERT INTO invoice_payments
                (id, firm_id, invoice_id, client_contact_id, destination, amount, currency, status, stripe_payment_intent_id)
                VALUES (?, ?, ?, ?, ?, ?, 'usd', 'pending', ?)`)
      .run(rowId, link.firm_id, link.invoice_id, inv.client_contact_id,
           link.destination, link.amount_cents / 100, pi.id);
    res.json({ clientSecret: pi.client_secret });
  } catch (e) {
    console.error('[stripe] paymentIntents.create failed:', e.stack || e.message);
    // Don't forward the raw Stripe error message — it can include account/key
    // fragments or internal URLs. Client gets a generic message; ops can find
    // the detailed error in the server log.
    res.status(500).json({ error: 'Could not start payment. Please try again or contact support.' });
  }
});

// Default font family for invoice PDFs. Shadowed inside renderInvoicePdf when
// firmSettings.invoiceFontFamily === 'serif'. Keep these module-scoped so the
// preview watermark (outside renderInvoicePdf) can reference F_BOLD too.
const F_REGULAR_DEFAULT = 'Helvetica';
const F_BOLD_DEFAULT    = 'Helvetica-Bold';
const F_ITALIC_DEFAULT  = 'Helvetica-Oblique';
const F_REGULAR = F_REGULAR_DEFAULT;
const F_BOLD    = F_BOLD_DEFAULT;
const F_ITALIC  = F_ITALIC_DEFAULT;

// Render an invoice PDF into the supplied PDFDocument. Shared between the real
// PDF route and the settings-page preview so both stay visually identical.
function renderInvoicePdf(doc, { firm, firmSettings, inv, lines, matter, client, timeEntries, outstanding, logoBuffer }) {
  // Map extended client-side font names onto one of the three PDFKit builtin
  // font packs (PDFKit ships Helvetica / Times / Courier by default; other
  // families would require registering TTF files).
  const FAMILY_MAP = {
    helvetica: 'helvetica', arial: 'helvetica', verdana: 'helvetica', trebuchet: 'helvetica',
    sans: 'helvetica',
    times: 'times', georgia: 'times', palatino: 'times', garamond: 'times',
    serif: 'times',
    courier: 'courier', monaco: 'courier',
  };
  const FONT_PACKS = {
    helvetica: { regular: 'Helvetica',   bold: 'Helvetica-Bold', italic: 'Helvetica-Oblique' },
    times:     { regular: 'Times-Roman', bold: 'Times-Bold',     italic: 'Times-Italic' },
    courier:   { regular: 'Courier',     bold: 'Courier-Bold',   italic: 'Courier-Oblique' },
  };
  const mapFamily = (f) => FAMILY_MAP[f] || 'helvetica';
  const fontKey = mapFamily(firmSettings.invoiceFontFamily);
  const F_REGULAR = FONT_PACKS[fontKey].regular;
  const F_BOLD    = FONT_PACKS[fontKey].bold;
  const F_ITALIC  = FONT_PACKS[fontKey].italic;
  doc.font(F_REGULAR); // default for branches (e.g. simple template) that don't set font explicitly

  // Per-label overrides: { [key]: { family?, size?, color? } }.
  const labelStyles = firmSettings.labelStyles || {};
  // Apply a label's style (font family + size). `weight` selects 'regular' /
  // 'bold' / 'italic' within the chosen pack. `defaultSize` is the hardcoded
  // size used when the label has no per-label size override. Returns the
  // rendered text so callers can chain `.text(forLabel(...), ...)`.
  const forLabel = (key, defaultSize, weight = 'regular') => {
    const s = labelStyles[key] || {};
    const pack = FONT_PACKS[mapFamily(s.family) || fontKey];
    const size = (s.size != null && Number(s.size) > 0) ? Number(s.size) : defaultSize;
    doc.font(pack[weight] || pack.regular).fontSize(size);
    return labels[key];
  };
  // Per-label color override. Caller passes the hardcoded fallback color;
  // returns the user override (if any valid hex was set) else the fallback.
  // Use as: doc.fillColor(colorFor('myKey', accent)).text(labels.myKey, ...)
  const colorFor = (key, fallback) => {
    const c = (labelStyles[key] || {}).color;
    return (typeof c === 'string' && /^#[0-9a-fA-F]{6}$/.test(c)) ? c : fallback;
  };

  // Logo scale — clamp to [0.5, 2.0] to avoid layout blowups.
  const logoScale = Math.max(0.5, Math.min(2.0, Number(firmSettings.invoiceLogoScale) || 1));
  // "Invoice" heading scale — independent of the logo so users can tune the
  // heading size without distorting the firm mark. Clamped to the same range.
  const titleScale = Math.max(0.5, Math.min(2.0, Number(firmSettings.invoiceTitleScale) || 1));

  // Per-block layout offsets — { [blockId]: { dx, dy, w, h } } in editor pixels.
  // The editor renders the page at 96 DPI / 816px wide; PDFKit uses 72pt /
  // 612pt wide. Both ratios reduce to 0.75. We honor only `dx`/`dy` here —
  // resize (`w`/`h`) is preview-only since most block content reflows
  // automatically in the PDF. `currentPageId` lets `drawHeader` (which is
  // shared across all four pages) pick up the right per-page offset.
  const blockLayout = (firmSettings.blockLayout && typeof firmSettings.blockLayout === 'object') ? firmSettings.blockLayout : {};
  const hiddenBlocks = new Set(Array.isArray(firmSettings.hiddenBlocks) ? firmSettings.hiddenBlocks : ['p1-custom-text']);
  const isHidden = (id) => hiddenBlocks.has(id);
  const PX_TO_PT = 0.75;
  const blockOff = (id) => {
    const lay = blockLayout[id];
    if (!lay) return { dx: 0, dy: 0 };
    return {
      dx: (Number(lay.dx) || 0) * PX_TO_PT,
      dy: (Number(lay.dy) || 0) * PX_TO_PT,
    };
  };
  const withOffset = (id, draw) => {
    const off = blockOff(id);
    if (!off.dx && !off.dy) { draw(); return; }
    doc.save();
    doc.translate(off.dx, off.dy);
    try { draw(); } finally { doc.restore(); }
  };
  let currentPageId = 'p1';

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

  // Firm-internal "{client#}-{matter#}" identifier (e.g. "42-00001"). Shared by
  // both templates so the invoice carries the same matter number the firm uses
  // elsewhere. Falls back to the linked DealTracker id; if neither exists we
  // intentionally show '—' rather than the raw internal uuid (matter ids look
  // like "m_<hex>", which leaks an implementation detail onto the invoice).
  const fmtMatNo = (n) => (n == null || n === '') ? '' : String(n).padStart(5, '0');
  let matterLabel = '—';
  if (matter?.matter_number != null) {
    const mn = fmtMatNo(matter.matter_number);
    matterLabel = matter.client_number != null ? `${matter.client_number}-${mn}` : mn;
  } else if (matter?.dt_matter_id) {
    matterLabel = matter.dt_matter_id;
  }
  const matterDesc = matter?.name || matter?.description || '';

  // Customizable text labels. Every string the PDF prints that isn't data is
  // overridable via firmSettings.labels so admins can tweak wording (e.g.
  // rename "BILLING SUMMARY" to "STATEMENT OF ACCOUNT") without code edits.
  const labels = Object.assign({
    invoiceHeading:          'INVOICE',
    invoiceNumberLabel:      'Invoice No.',
    matterNumberLabel:       'Matter No.',
    dueLabelPrefix:          'Due:',
    billingSummaryTitle:     'BILLING SUMMARY',
    servicesSubtitlePrefix:  'For Professional Services Rendered as of',
    paymentDetailsNote:      'Payment Details on Last Page',
    professionalServicesTitle: 'Summary of Professional Services',
    totalServicesLabel:      'Total Professional Services Rendered',
    summaryByTimekeeperTitle:'Summary by Timekeeper',
    costsTitle:              'Summary of Costs',
    totalCostsLabel:         'Total Costs',
    remittanceTitle:         'REMITTANCE',
    currentDueLabel:         'Current Balance Due This Invoice',
    outstandingLabel:        'Outstanding Balance',
    totalBalanceDueLabel:    'TOTAL BALANCE DUE',
    checksPayableLabel:      'All checks should be made payable to:',
    wireHeadingLabel:        'For payment by wire or ACH in USD:',
    notesHeadingLabel:       'Notes',
    invoiceTotalLabel:       'Invoice Total',
    taxLabel:                'Tax',
    subtotalLabel:           'Subtotal',
    colMatter:    'Matter #',
    colDescription: 'Description',
    colFees:      'Fees',
    colCosts:     'Costs',
    colTotal:     'Total',
    colDate:      'Date',
    colTimekeeper:'Timekeeper',
    colHours:     'Hours',
    colRate:      'Rate',
    colAmount:    'Amount',
    wireBeneficiaryNameLabel:    'Beneficiary Name',
    wireBeneficiaryAddressLabel: 'Beneficiary Address',
    wireAccountNumberLabel:      'Account Number',
    wireRoutingNumberLabel:      'ABA Routing Number',
    wireBankNameLabel:           'Bank Name',
    wireBankAddressLabel:        'Bank Address',
    customTextBlock:             '',
  }, firmSettings.labels || {});

  // Fallback to the original simple format if the firm prefers it
  if (template === 'simple') {
    doc.fontSize(20).fillColor(accent).text(firm.name, 50, 50);
    if (firmAddr) doc.fontSize(10).fillColor(muted).text(firmAddr);
    doc.fontSize(24 * titleScale).fillColor(accent).text(labels.invoiceHeading, 400, 50, { align: 'right' });
    doc.fontSize(10).fillColor('#333').text(inv.number || '', 400, 80, { align: 'right' });
    if (matter && matterLabel && matterLabel !== '—') {
      doc.fontSize(9).fillColor(muted)
         .text(`${labels.matterNumberLabel} ${matterLabel}`, 400, 96, { align: 'right' });
    }
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
    doc.text(String(labels.colDescription).toUpperCase(), 50, y);
    doc.text('QTY', 340, y, { width: 50, align: 'right' });
    doc.text(String(labels.colRate).toUpperCase(), 400, y, { width: 70, align: 'right' });
    doc.text(String(labels.colAmount).toUpperCase(), 480, y, { width: 80, align: 'right' });
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
    doc.text(labels.subtotalLabel || 'Subtotal', 340, y, { width: 140, align: 'right' });
    doc.text(fmtMoney(inv.subtotal), 480, y, { width: 80, align: 'right' });
    y += 16;
    if (inv.tax > 0) {
      doc.text(labels.taxLabel, 340, y, { width: 140, align: 'right' });
      doc.text(fmtMoney(inv.tax), 480, y, { width: 80, align: 'right' });
      y += 16;
    }
    doc.fontSize(12).fillColor(accent);
    doc.text(String(labels.colTotal || 'Total').toUpperCase(), 340, y, { width: 140, align: 'right' });
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
    const headerId = currentPageId + '-header';
    if (short) {
      const topY = 40;
      const logoH = 26 * logoScale;
      let endY = topY + logoH + 8;
      // The whole short-header block — logo, INVOICE heading, short meta line,
      // client lines, and divider — translates as one unit, mirroring the
      // single `data-block-id` wrapper in the editor.
      withOffset(headerId, () => {
        if (!tryImage(PAGE_LEFT, topY, { fit: [180 * logoScale, logoH] })) {
          doc.font(F_BOLD).fontSize(12).fillColor(accent)
             .text(logoText, PAGE_LEFT, topY + 4, { width: 260, lineBreak: false, ellipsis: true });
        }
        forLabel('invoiceHeading', 16 * titleScale, 'bold');
        doc.fillColor(colorFor('invoiceHeading', accent))
           .text(labels.invoiceHeading, PAGE_LEFT, topY, { width: PAGE_WIDTH, align: 'right' });
        const shortMeta = matter && matterLabel && matterLabel !== '—'
          ? `${inv.number || ''}  ·  ${labels.matterNumberLabel} ${matterLabel}  ·  ${longDate(inv.issued_at)}`
          : `${inv.number || ''}  ·  ${longDate(inv.issued_at)}`;
        doc.font(F_REGULAR).fontSize(9).fillColor(muted)
           .text(shortMeta, PAGE_LEFT, topY + 18, { width: PAGE_WIDTH, align: 'right' });

        let cy = topY + logoH + 8;
        doc.font(F_REGULAR).fontSize(9).fillColor('#222');
        for (const line of clientLines) {
          doc.text(line, PAGE_LEFT, cy, { width: PAGE_WIDTH * 0.6 });
          cy += 11;
        }
        cy = Math.max(cy, topY + logoH + 8);
        doc.moveTo(PAGE_LEFT, cy + 6).lineTo(PAGE_RIGHT, cy + 6).strokeColor(accent).lineWidth(0.5).stroke();
        endY = cy;
      });
      // Subsequent content lays out from the natural endY — drag offsets only
      // shift the header itself, not the content beneath it.
      return endY + 22;
    }

    // Full header (cover page)
    const topY = 50;
    const logoMaxH = 60 * logoScale, logoMaxW = 280 * logoScale;
    let logoBottom = topY;
    withOffset(headerId, () => {
      if (tryImage(PAGE_LEFT, topY, { fit: [logoMaxW, logoMaxH] })) {
        logoBottom = topY + logoMaxH;
      } else {
        doc.font(F_BOLD).fontSize(24).fillColor(accent)
           .text(logoText, PAGE_LEFT, topY + 10, { width: logoMaxW, lineBreak: false, ellipsis: true });
        logoBottom = topY + 44;
      }
      forLabel('invoiceHeading', 28 * titleScale, 'bold');
      doc.fillColor(colorFor('invoiceHeading', accent))
         .text(labels.invoiceHeading, PAGE_LEFT, topY + 12, { width: PAGE_WIDTH, align: 'right' });
    });

    const dividerY = Math.max(logoBottom + 6, topY + 58);
    doc.moveTo(PAGE_LEFT, dividerY).lineTo(PAGE_RIGHT, dividerY).strokeColor(accent).lineWidth(1.5).stroke();

    // Bill-to (left) and invoice meta (right) — independent drag targets.
    const blockTop = dividerY + 16;
    let ly = blockTop;
    withOffset('p1-client', () => {
      doc.font(F_REGULAR).fontSize(10).fillColor('#111');
      for (const line of clientLines) {
        doc.text(line, PAGE_LEFT, ly, { width: PAGE_WIDTH * 0.55 });
        ly += 13;
      }
    });

    const metaX = PAGE_LEFT + PAGE_WIDTH * 0.58;
    const metaW = PAGE_WIDTH - PAGE_WIDTH * 0.58;
    let metaY = blockTop + 14;
    withOffset('p1-meta', () => {
      forLabel('invoiceNumberLabel', 10, 'bold');
      doc.fillColor(colorFor('invoiceNumberLabel', '#111'))
         .text(`${labels.invoiceNumberLabel} ${inv.number || ''}`, metaX, blockTop, { width: metaW, align: 'right' });
      if (matter && matterLabel && matterLabel !== '—') {
        forLabel('matterNumberLabel', 10, 'bold');
        doc.fillColor(colorFor('matterNumberLabel', '#111'))
           .text(`${labels.matterNumberLabel} ${matterLabel}`, metaX, metaY, { width: metaW, align: 'right' });
        metaY += 14;
      }
      doc.font(F_REGULAR).fontSize(10).fillColor('#333')
         .text(longDate(inv.issued_at), metaX, metaY, { width: metaW, align: 'right' });
      metaY += 14;
      if (inv.due_at) {
        const prevFont = doc._font && doc._font.name;
        const prevSize = doc._fontSize;
        forLabel('dueLabelPrefix', 10, 'regular');
        doc.fillColor(colorFor('dueLabelPrefix', '#333')).text(labels.dueLabelPrefix + ' ' + longDate(inv.due_at), metaX, metaY, { width: metaW, align: 'right' });
        if (prevFont) doc.font(prevFont);
        if (prevSize) doc.fontSize(prevSize);
        metaY += 14;
      }
    });

    return Math.max(ly, metaY) + 6;
  };

  // Render a table (header + rows). Handles auto-sized header and rows, and
  // page-breaks while preserving the short header and the table head.
  const renderTable = (cols, rows, opts = {}) => {
    const headerPad = 6;
    const cellPad = 5;
    const headerFontSize = opts.headerFontSize || 9;
    const bodyFontSize   = opts.bodyFontSize   || 9.5;

    const setColHeaderStyle = (c) => {
      if (c.key) forLabel(c.key, headerFontSize, 'bold');
      else doc.font(F_BOLD).fontSize(headerFontSize);
    };
    const drawHeaderRow = () => {
      let maxH = 0;
      for (const c of cols) {
        setColHeaderStyle(c);
        const h = doc.heightOfString(c.label, { width: c.w - cellPad * 2, align: c.align || 'left' });
        if (h > maxH) maxH = h;
      }
      const rowH = maxH + headerPad * 2;
      doc.save().rect(PAGE_LEFT, y, PAGE_WIDTH, rowH).fill(accent).restore();
      for (const c of cols) {
        setColHeaderStyle(c);
        doc.fillColor(c.key ? colorFor(c.key, '#fff') : '#fff');
        doc.text(c.label, c.x + cellPad, y + headerPad, { width: c.w - cellPad * 2, align: c.align || 'left' });
      }
      y += rowH;
    };

    drawHeaderRow();

    doc.font(F_REGULAR).fontSize(bodyFontSize).fillColor('#111');
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
        doc.font(F_REGULAR).fontSize(bodyFontSize).fillColor('#111')
           .text(cell, cols[i].x + cellPad, y + 4, { width: cols[i].w - cellPad * 2, align: cols[i].align || 'left' });
      }
      doc.moveTo(PAGE_LEFT, y + rowH).lineTo(PAGE_RIGHT, y + rowH).strokeColor(border).lineWidth(0.3).stroke();
      y += rowH;
    }
  };

  // Write a title, advancing y by the measured height. If `key` is supplied,
  // the title adopts per-label family + size from labelStyles. If `blockId`
  // is supplied, the title shifts by that block's drag offset (without
  // disturbing the natural y advance for following content).
  const writeTitle = (text, size, align = 'left', key = null, blockId = null) => {
    if (key) forLabel(key, size, 'bold');
    else doc.font(F_BOLD).fontSize(size);
    doc.fillColor(key ? colorFor(key, accent) : accent);
    const h = doc.heightOfString(text, { width: PAGE_WIDTH, align });
    if (blockId) withOffset(blockId, () => doc.text(text, PAGE_LEFT, y, { width: PAGE_WIDTH, align }));
    else doc.text(text, PAGE_LEFT, y, { width: PAGE_WIDTH, align });
    y += h + 8;
  };

  // ═══ Page 1: Cover + Billing Summary ════════════════════════════════════
  currentPageId = 'p1';
  let y = drawHeader(false);

  writeTitle(labels.billingSummaryTitle, 14, 'center', 'billingSummaryTitle', 'p1-summary-title');
  forLabel('servicesSubtitlePrefix', 10, 'italic');
  doc.fillColor(colorFor('servicesSubtitlePrefix', '#333'));
  const subtitleText = `${labels.servicesSubtitlePrefix} ${longDate(inv.issued_at)}`;
  const subtitleH = doc.heightOfString(subtitleText, { width: PAGE_WIDTH, align: 'center' });
  withOffset('p1-subtitle', () => doc.text(subtitleText, PAGE_LEFT, y, { width: PAGE_WIDTH, align: 'center' }));
  y += subtitleH + 16;

  // Totals
  const servicesTotal = lines.filter(l => l.kind === 'time' || l.kind === 'flat').reduce((s, l) => s + (Number(l.amount) || 0), 0);
  const costsTotal    = lines.filter(l => l.kind === 'expense').reduce((s, l) => s + (Number(l.amount) || 0), 0);

  // Summary table: balanced columns so no header wraps awkwardly
  const sumCols = [
    { key: 'colMatter',      label: labels.colMatter,      x: PAGE_LEFT,       w: 64,  align: 'left'  },
    { key: 'colDescription', label: labels.colDescription, x: PAGE_LEFT + 64,  w: 216, align: 'left'  },
    { key: 'colFees',        label: labels.colFees,        x: PAGE_LEFT + 280, w: 80,  align: 'right' },
    { key: 'colCosts',       label: labels.colCosts,       x: PAGE_LEFT + 360, w: 76,  align: 'right' },
    { key: 'colTotal',       label: labels.colTotal,       x: PAGE_LEFT + 436, w: 76,  align: 'right' },
  ];
  renderTable(sumCols, [
    [matterLabel, matterDesc, fmtMoney(servicesTotal), fmtMoney(costsTotal), fmtMoney(inv.subtotal)],
  ], { headerFontSize: 9, bodyFontSize: 10 });

  // Totals row — manually styled (shaded)
  const totalsH = 24;
  doc.save().rect(PAGE_LEFT, y, PAGE_WIDTH, totalsH).fill('#eef2f7').restore();
  forLabel('colTotal', 10, 'bold');
  doc.fillColor(colorFor('colTotal', '#111'))
     .text(labels.colTotal, sumCols[0].x + 5, y + 7, { width: sumCols[1].x + sumCols[1].w - sumCols[0].x - 10 });
  doc.text(fmtMoney(servicesTotal), sumCols[2].x + 5, y + 7, { width: sumCols[2].w - 10, align: 'right' });
  doc.text(fmtMoney(costsTotal),    sumCols[3].x + 5, y + 7, { width: sumCols[3].w - 10, align: 'right' });
  doc.text(fmtMoney(inv.subtotal),  sumCols[4].x + 5, y + 7, { width: sumCols[4].w - 10, align: 'right' });
  y += totalsH + 8;

  if (inv.tax > 0) {
    forLabel('taxLabel', 10, 'regular');
    doc.fillColor(colorFor('taxLabel', '#333'));
    doc.text(labels.taxLabel, sumCols[3].x - 80, y, { width: 140 + 80, align: 'right' });
    doc.text(fmtMoney(inv.tax), sumCols[4].x + 5, y, { width: sumCols[4].w - 10, align: 'right' });
    y += 16;
    forLabel('invoiceTotalLabel', 11, 'bold');
    doc.fillColor(colorFor('invoiceTotalLabel', accent));
    doc.text(labels.invoiceTotalLabel || 'Invoice Total', sumCols[3].x - 80, y, { width: 140 + 80, align: 'right' });
    doc.text(fmtMoney(inv.total), sumCols[4].x + 5, y, { width: sumCols[4].w - 10, align: 'right' });
    y += 20;
  }

  const customText = String(labels.customTextBlock || '').trim();
  if (customText && !isHidden('p1-custom-text')) {
    y += 12;
    doc.font(F_REGULAR).fontSize(10).fillColor('#333');
    const ctLines = customText.split(/\r?\n/);
    withOffset('p1-custom-text', () => {
      let cy = y;
      for (const line of ctLines) {
        doc.text(line || ' ', PAGE_LEFT, cy, { width: PAGE_WIDTH });
        cy += doc.heightOfString(line || ' ', { width: PAGE_WIDTH }) + 2;
      }
    });
    const ctH = ctLines.reduce((h, l) => h + doc.heightOfString(l || ' ', { width: PAGE_WIDTH }) + 2, 0);
    y += ctH + 8;
  }

  forLabel('paymentDetailsNote', 10, 'italic');
  doc.fillColor(colorFor('paymentDetailsNote', muted));
  withOffset('p1-payment-note', () => doc.text(labels.paymentDetailsNote, PAGE_LEFT, PAGE_BOTTOM - 20, { width: PAGE_WIDTH, align: 'center', lineBreak: false }));

  // ═══ Professional Services detail ═══════════════════════════════════════
  if (timeEntries.length > 0 && !isHidden('p2-services')) {
    doc.addPage();
    currentPageId = 'p2';
    y = drawHeader(true);
    writeTitle(`${labels.professionalServicesTitle} — ${matterDesc || matterLabel}`, 12, 'left', 'professionalServicesTitle', 'p2-services-title');

    const tCols = [
      { key: 'colDate',        label: labels.colDate,        x: PAGE_LEFT,       w: 58,  align: 'left'  },
      { key: 'colTimekeeper',  label: labels.colTimekeeper,  x: PAGE_LEFT + 58,  w: 100, align: 'left'  },
      { key: 'colDescription', label: labels.colDescription, x: PAGE_LEFT + 158, w: 198, align: 'left'  },
      { key: 'colHours',       label: labels.colHours,       x: PAGE_LEFT + 356, w: 46,  align: 'right' },
      { key: 'colRate',        label: labels.colRate,        x: PAGE_LEFT + 402, w: 54,  align: 'right' },
      { key: 'colAmount',      label: labels.colAmount,      x: PAGE_LEFT + 456, w: 56,  align: 'right' },
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
    forLabel('totalServicesLabel', 10, 'bold');
    doc.fillColor(colorFor('totalServicesLabel', accent))
       .text(labels.totalServicesLabel, PAGE_LEFT, y, { width: tCols[3].x - PAGE_LEFT - 5, align: 'right' });
    doc.text(totalHours.toFixed(2), tCols[3].x + 5, y, { width: tCols[3].w - 10, align: 'right' });
    doc.text(fmtMoney(total),       tCols[5].x + 5, y, { width: tCols[5].w - 10, align: 'right' });
    y += 24;

    // Summary by timekeeper
    if (byTimekeeper.size > 0 && !isHidden('p2-timekeeper')) {
      // Page-break if this section wouldn't have room for a title + at least
      // a header row and one data row (~80pt).
      if (y + 80 > PAGE_BOTTOM) {
        doc.addPage();
        y = drawHeader(true);
      }
      writeTitle(labels.summaryByTimekeeperTitle, 12, 'left', 'summaryByTimekeeperTitle', 'p2-timekeeper-title');
      const tkCols = [
        { key: 'colTimekeeper', label: labels.colTimekeeper, x: PAGE_LEFT,       w: 300, align: 'left'  },
        { key: 'colHours',      label: labels.colHours,      x: PAGE_LEFT + 300, w: 100, align: 'right' },
        { key: 'colAmount',     label: labels.colAmount,     x: PAGE_LEFT + 400, w: 112, align: 'right' },
      ];
      const tkRows = [...byTimekeeper.entries()]
        .sort((a, b) => b[1].amount - a[1].amount)
        .map(([name, v]) => [name, v.hours.toFixed(2), fmtMoney(v.amount)]);
      renderTable(tkCols, tkRows);

      y += 4;
      doc.moveTo(PAGE_LEFT, y).lineTo(PAGE_RIGHT, y).strokeColor(accent).lineWidth(1).stroke();
      y += 8;
      forLabel('colTotal', 10, 'bold');
      doc.fillColor(colorFor('colTotal', accent))
         .text(labels.colTotal, PAGE_LEFT, y, { width: tkCols[1].x - PAGE_LEFT - 5, align: 'right' });
      doc.text(totalHours.toFixed(2), tkCols[1].x + 5, y, { width: tkCols[1].w - 10, align: 'right' });
      doc.text(fmtMoney(total),       tkCols[2].x + 5, y, { width: tkCols[2].w - 10, align: 'right' });
      y += 20;
    }
  }

  // ═══ Expense detail ═════════════════════════════════════════════════════
  const expenseLines = lines.filter(l => l.kind === 'expense');
  if (expenseLines.length > 0 && !isHidden('p3-costs')) {
    doc.addPage();
    currentPageId = 'p3';
    y = drawHeader(true);
    writeTitle(`${labels.costsTitle} — ${matterDesc || matterLabel}`, 12, 'left', 'costsTitle', 'p3-costs-title');

    const eCols = [
      { key: 'colDescription', label: labels.colDescription, x: PAGE_LEFT,       w: 400, align: 'left'  },
      { key: 'colAmount',      label: labels.colAmount,      x: PAGE_LEFT + 400, w: 112, align: 'right' },
    ];
    renderTable(eCols, expenseLines.map(l => [l.description || '', fmtMoney(l.amount)]));

    y += 4;
    doc.moveTo(PAGE_LEFT, y).lineTo(PAGE_RIGHT, y).strokeColor(accent).lineWidth(1).stroke();
    y += 8;
    forLabel('totalCostsLabel', 10, 'bold');
    doc.fillColor(colorFor('totalCostsLabel', accent))
       .text(labels.totalCostsLabel, PAGE_LEFT, y, { width: eCols[0].w + eCols[0].x - PAGE_LEFT, align: 'right' });
    doc.text(fmtMoney(costsTotal), eCols[1].x + 5, y, { width: eCols[1].w - 10, align: 'right' });
    y += 20;
  }

  // ═══ Remittance page ════════════════════════════════════════════════════
  doc.addPage();
  currentPageId = 'p4';
  y = drawHeader(true);
  writeTitle(labels.remittanceTitle, 16, 'center', 'remittanceTitle', 'p4-remittance-title');
  y += 4;

  const currentDue = +(Number(inv.total) - Number(inv.amount_paid || 0)).toFixed(2);
  const totalDue = +(currentDue + outstanding).toFixed(2);

  const bal = (key, amount, emphasize, blockId) => {
    const label = labels[key];
    const draw = () => {
      if (emphasize) {
        const h = 28;
        doc.save().rect(PAGE_LEFT, y, PAGE_WIDTH, h).fill(accent).restore();
        forLabel(key, 12, 'bold');
        doc.fillColor(colorFor(key, '#fff'));
        doc.text(label, PAGE_LEFT + 14, y + 8, { width: PAGE_WIDTH * 0.65 });
        doc.text(fmtMoney(amount), PAGE_LEFT, y + 8, { width: PAGE_WIDTH - 14, align: 'right' });
      } else {
        const h = 22;
        forLabel(key, 11, 'regular');
        doc.fillColor(colorFor(key, '#222'));
        doc.text(label, PAGE_LEFT + 14, y + 6, { width: PAGE_WIDTH * 0.65 });
        doc.text(fmtMoney(amount), PAGE_LEFT, y + 6, { width: PAGE_WIDTH - 14, align: 'right' });
        doc.moveTo(PAGE_LEFT, y + h).lineTo(PAGE_RIGHT, y + h).strokeColor(border).lineWidth(0.5).stroke();
      }
    };
    if (blockId) withOffset(blockId, draw);
    else draw();
    y += (emphasize ? 28 + 6 : 22 + 2);
  };
  bal('currentDueLabel',      currentDue,  false, 'p4-current-due');
  bal('outstandingLabel',     outstanding, false, 'p4-outstanding');
  bal('totalBalanceDueLabel', totalDue,    true,  'p4-total-due');

  y += 18;
  const block = (key, textLines, headingId, contentId) => {
    if (!textLines.filter(Boolean).length) return;
    const headingY = y;
    forLabel(key, 11, 'bold');
    doc.fillColor(colorFor(key, accent));
    if (headingId) withOffset(headingId, () => doc.text(labels[key], PAGE_LEFT, headingY, { width: PAGE_WIDTH }));
    else doc.text(labels[key], PAGE_LEFT, headingY, { width: PAGE_WIDTH });
    y += 16;
    const filtered = textLines.filter(Boolean);
    const contentY0 = y;
    const drawContent = () => {
      doc.font(F_REGULAR).fontSize(10).fillColor('#111');
      let cy = contentY0;
      for (const line of filtered) {
        doc.text(line, PAGE_LEFT + 14, cy, { width: PAGE_WIDTH - 14 });
        cy += 13;
      }
    };
    if (contentId) withOffset(contentId, drawContent);
    else drawContent();
    y += 13 * filtered.length + 14;
  };

  if (remitName || remitAddr) {
    block('checksPayableLabel', [remitName, ...(remitAddr ? String(remitAddr).split(/\r?\n/) : [])], 'p4-checks-heading', 'p4-checks-info');
  }

  if ((wire.accountNumber || wire.routingNumber || wire.bankName) && !isHidden('p4-wire')) {
    const wireHeadingY = y;
    forLabel('wireHeadingLabel', 11, 'bold');
    doc.fillColor(colorFor('wireHeadingLabel', accent));
    withOffset('p4-wire-heading', () => doc.text(labels.wireHeadingLabel, PAGE_LEFT, wireHeadingY, { width: PAGE_WIDTH }));
    y += 18;
    const wireRows = [
      ['wireBeneficiaryNameLabel',    wire.beneficiaryName],
      ['wireBeneficiaryAddressLabel', wire.beneficiaryAddress],
      ['wireAccountNumberLabel',      wire.accountNumber],
      ['wireRoutingNumberLabel',      wire.routingNumber],
      ['wireBankNameLabel',           wire.bankName],
      ['wireBankAddressLabel',        wire.bankAddress],
    ].filter(([, v]) => v);
    const labelW = 150;
    for (const [key, value] of wireRows) {
      const valLines = String(value).split(/\r?\n/).filter(Boolean);
      doc.font(F_REGULAR).fontSize(10);
      const valH = valLines.reduce((h, line) => h + doc.heightOfString(line, { width: PAGE_WIDTH - labelW - 20 }), 0) + 6;
      const rh = Math.max(22, valH);
      const rowY = y;
      withOffset('p4-' + key, () => {
        doc.save().rect(PAGE_LEFT, rowY, PAGE_WIDTH, rh).fill('#f5f7fb').restore();
        doc.rect(PAGE_LEFT, rowY, PAGE_WIDTH, rh).strokeColor(border).lineWidth(0.5).stroke();
        forLabel(key, 10, 'bold');
        doc.fillColor(colorFor(key, '#222')).text(labels[key], PAGE_LEFT + 10, rowY + 6, { width: labelW - 10 });
        doc.font(F_REGULAR).fontSize(10).fillColor('#111').text(valLines.join('\n'), PAGE_LEFT + labelW + 4, rowY + 6, { width: PAGE_WIDTH - labelW - 14 });
      });
      y += rh;
    }
    y += 18;
  }

  if (inv.notes) {
    const notesHeadY = y;
    forLabel('notesHeadingLabel', 10, 'bold');
    doc.fillColor(colorFor('notesHeadingLabel', accent));
    withOffset('p4-notes-heading', () => doc.text(labels.notesHeadingLabel, PAGE_LEFT, notesHeadY, { width: PAGE_WIDTH }));
    y += 14;
    const notesY = y;
    withOffset('p4-notes-info', () => doc.font(F_REGULAR).fontSize(10).fillColor('#333').text(inv.notes, PAGE_LEFT, notesY, { width: PAGE_WIDTH }));
    y += doc.heightOfString(inv.notes, { width: PAGE_WIDTH }) + 14;
  }

  if (footerText) {
    doc.font(F_BOLD).fontSize(11).fillColor(accent);
    withOffset('p4-footer', () => doc.text(footerText, PAGE_LEFT, PAGE_BOTTOM - 16, { width: PAGE_WIDTH, align: 'center', lineBreak: false }));
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
  const matter = fetchMatterForInvoice(inv.matter_id, req.user.firmId);
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
  // If the client disconnects or the stream errors, tear the doc down so PDFKit
  // doesn't keep writing to a dead socket (memory + fd leak).
  doc.on('error', (e) => { console.error('Invoice PDF stream error:', e); try { res.end(); } catch {} });
  res.on('close', () => { if (!res.writableEnded) doc.destroy(); });
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
    client_number: 42,
    matter_number: 1,
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
  doc.on('error', (e) => { console.error('Invoice preview PDF stream error:', e); try { res.end(); } catch {} });
  res.on('close', () => { if (!res.writableEnded) doc.destroy(); });
  doc.pipe(res);
  renderInvoicePdf(doc, { firm, firmSettings, inv, lines, matter, client, timeEntries, outstanding, logoBuffer });
  // Diagonal "PREVIEW" watermark on every page (requires bufferPages).
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i++) {
    doc.switchToPage(i);
    doc.save();
    doc.fillColor('#d0d7e2').opacity(0.35).fontSize(90).font(F_BOLD);
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
// CASHFLOW REPORT
// ═══════════════════════════════════════════════════════════════════════
// Three independent series rolled up by issued_at / occurred_at:
//   billed   — sum of invoices.total (status != 'void')
//   adjusts  — sum of signed invoice_adjustments.amount
//   cash     — sum of succeeded invoice_payments.amount (broken out by method)
// Realization = cash / (billed + adjustments) over the window. manageBilling
// gates this — Partners and Admins only, per CLAUDE.md role table.
app.get('/api/reports/cashflow', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const granularity = ['day','month','year'].includes(req.query.granularity) ? req.query.granularity : 'month';
  const fmt = granularity === 'day' ? '%Y-%m-%d' : granularity === 'year' ? '%Y' : '%Y-%m';
  const from = req.query.from || null;  // YYYY-MM-DD inclusive
  const to   = req.query.to   || null;  // YYYY-MM-DD inclusive (interpreted as end-of-day)
  const toEnd = to ? to + 'T23:59:59.999Z' : null;
  const f = resolveCashflowFilters(req);

  const dateClause = (col) => {
    const parts = [];
    const params = [];
    if (from) { parts.push(`${col} >= ?`); params.push(from); }
    if (toEnd){ parts.push(`${col} <= ?`); params.push(toEnd); }
    return { sql: parts.length ? ' AND ' + parts.join(' AND ') : '', params };
  };

  // Adjustments link via invoice_id; cash and billed have client_contact_id +
  // matter_id directly. We pre-resolved attorney→client list in resolveCashflowFilters
  // so each downstream query just uses an IN (...) clause.
  const billedClient = inClause('client_contact_id', f.clientIdIn);
  const billedMatter = inClause('matter_id',         f.matterIdIn);
  const cashClient   = inClause('client_contact_id', f.clientIdIn);
  const cashMatter   = inClause('matter_id',         f.matterIdIn);

  const billedDate = dateClause('issued_at');
  const billed = db.prepare(`
    SELECT strftime('${fmt}', issued_at) AS period, COALESCE(SUM(total),0) AS amount, COUNT(*) AS n
    FROM invoices WHERE firm_id = ? AND status != 'void' AND issued_at IS NOT NULL
    ${billedDate.sql}${billedClient.sql}${billedMatter.sql}
    GROUP BY period ORDER BY period
  `).all(req.user.firmId, ...billedDate.params, ...billedClient.params, ...billedMatter.params);

  const adjDate = dateClause('occurred_at');
  // Adjustments are filtered to the same invoice universe (client + matter) via a join.
  const adjJoinNeeded = f.clientIdIn || f.matterIdIn;
  const adjJoinClient = inClause('iv.client_contact_id', f.clientIdIn);
  const adjJoinMatter = inClause('iv.matter_id',         f.matterIdIn);
  const adjJoin = adjJoinNeeded
    ? `JOIN invoices iv ON iv.id = a.invoice_id ${adjJoinClient.sql}${adjJoinMatter.sql}`
    : '';
  const adjJoinParams = adjJoinNeeded ? [...adjJoinClient.params, ...adjJoinMatter.params] : [];
  const adjustments = db.prepare(`
    SELECT strftime('${fmt}', a.occurred_at) AS period,
           COALESCE(SUM(a.amount),0) AS amount,
           COALESCE(SUM(CASE WHEN a.amount < 0 THEN -a.amount ELSE 0 END),0) AS writedowns,
           COALESCE(SUM(CASE WHEN a.amount > 0 THEN  a.amount ELSE 0 END),0) AS writeups,
           COUNT(*) AS n
    FROM invoice_adjustments a ${adjJoin}
    WHERE a.firm_id = ? ${adjDate.sql.replace(/occurred_at/g, 'a.occurred_at')}
    GROUP BY period ORDER BY period
  `).all(...adjJoinParams, req.user.firmId, ...adjDate.params);

  const payDate = dateClause('occurred_at');
  const cash = db.prepare(`
    SELECT strftime('${fmt}', occurred_at) AS period,
           COALESCE(method,'unknown') AS method,
           COALESCE(SUM(amount),0) AS amount, COUNT(*) AS n
    FROM invoice_payments
    WHERE firm_id = ? AND status = 'succeeded' AND occurred_at IS NOT NULL
    ${payDate.sql}${cashClient.sql}${cashMatter.sql}
    GROUP BY period, method ORDER BY period
  `).all(req.user.firmId, ...payDate.params, ...cashClient.params, ...cashMatter.params);

  // Stitch the three series into one period→row map.
  const periods = new Map();
  const ensure = (p) => {
    if (!periods.has(p)) periods.set(p, { period: p, billed_gross: 0, adjustments: 0, writedowns: 0, writeups: 0, cash_received: 0, cash_by_method: {} });
    return periods.get(p);
  };
  for (const r of billed)      ensure(r.period).billed_gross  = +Number(r.amount).toFixed(2);
  for (const r of adjustments) {
    const row = ensure(r.period);
    row.adjustments = +Number(r.amount).toFixed(2);
    row.writedowns  = +Number(r.writedowns).toFixed(2);
    row.writeups    = +Number(r.writeups).toFixed(2);
  }
  for (const r of cash) {
    const row = ensure(r.period);
    row.cash_received = +(row.cash_received + Number(r.amount)).toFixed(2);
    row.cash_by_method[r.method] = +(Number(r.amount)).toFixed(2);
  }

  const rows = [...periods.values()].sort((a, b) => a.period < b.period ? -1 : a.period > b.period ? 1 : 0);
  const totals = rows.reduce((t, r) => ({
    billed_gross:  +(t.billed_gross  + r.billed_gross).toFixed(2),
    adjustments:   +(t.adjustments   + r.adjustments).toFixed(2),
    writedowns:    +(t.writedowns    + r.writedowns).toFixed(2),
    writeups:      +(t.writeups      + r.writeups).toFixed(2),
    cash_received: +(t.cash_received + r.cash_received).toFixed(2),
  }), { billed_gross: 0, adjustments: 0, writedowns: 0, writeups: 0, cash_received: 0 });
  const netBilled = +(totals.billed_gross + totals.adjustments).toFixed(2);
  totals.net_billed = netBilled;
  totals.realization_rate = netBilled > 0 ? +(totals.cash_received / netBilled).toFixed(4) : null;

  res.json({
    granularity, from, to,
    clientId: f.clientId, matterId: f.matterId,
    attorneyEmail: f.attorneyEmail, attorneyRole: f.attorneyRole,
    periods: rows, totals,
  });
});

// Shared helper: parse and validate the attorney/matter/client filter set used
// by the cashflow tab's three reports. Returns { clientIdIn, matterIdIn,
// attorneyEmail, attorneyRole } where the *In arrays are either null (no
// filter) or the resolved id list. Pre-resolving the client list lets each
// downstream query filter via "client_contact_id IN (?, ?, …)" without joining
// contacts repeatedly.
function resolveCashflowFilters(req) {
  const firmId = req.user.firmId;
  const attorneyEmail = (req.query.attorneyEmail || '').toLowerCase().trim() || null;
  const attorneyRole  = ['originating', 'billing', 'either'].includes(req.query.attorneyRole) ? req.query.attorneyRole : 'either';
  const clientId = req.query.clientId || null;
  const matterId = req.query.matterId || null;

  let clientIdIn = clientId ? [clientId] : null;
  if (attorneyEmail) {
    let csql = 'SELECT id FROM contacts WHERE firm_id = ?';
    const cp  = [firmId];
    if (attorneyRole === 'originating')   { csql += ' AND originating_attorney_email = ?'; cp.push(attorneyEmail); }
    else if (attorneyRole === 'billing')  { csql += ' AND billing_attorney_email = ?';     cp.push(attorneyEmail); }
    else                                  { csql += ' AND (originating_attorney_email = ? OR billing_attorney_email = ?)'; cp.push(attorneyEmail, attorneyEmail); }
    if (clientIdIn) { csql += ' AND id = ?'; cp.push(clientIdIn[0]); }
    clientIdIn = db.prepare(csql).all(...cp).map(r => r.id);
  }
  return { clientIdIn, matterIdIn: matterId ? [matterId] : null, attorneyEmail, attorneyRole, clientId, matterId };
}

function inClause(col, ids) {
  if (!ids) return { sql: '', params: [] };
  if (ids.length === 0) return { sql: ' AND 1=0', params: [] };  // empty list = match nothing
  return { sql: ` AND ${col} IN (${ids.map(() => '?').join(',')})`, params: ids };
}

function periodFmtJs(iso, granularity) {
  if (!iso) return '';
  const m = String(iso).match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return '';
  if (granularity === 'year')  return m[1];
  if (granularity === 'month') return `${m[1]}-${m[2]}`;
  return `${m[1]}-${m[2]}-${m[3]}`;
}

// AR aging — outstanding balance on issued invoices, bucketed by days since
// issued_at. Status='sent' is the AR universe; 'paid' and 'void' are excluded
// because their balance is zero (or nullified). Balance is computed from
// invoice_payments (succeeded), not invoices.amount_paid, since that field is
// a stale denormalization that the payments table is the source of truth for.
app.get('/api/reports/ar-aging', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const f = resolveCashflowFilters(req);
  const asOfStr = req.query.asOf || new Date().toISOString().slice(0, 10);
  const today = new Date(asOfStr + 'T00:00:00');
  today.setHours(0, 0, 0, 0);
  const todayMs = today.getTime();

  const cIn = inClause('i.client_contact_id', f.clientIdIn);
  const mIn = inClause('i.matter_id',         f.matterIdIn);
  const sql = `
    SELECT i.id, i.number, i.client_contact_id, i.client_name, i.matter_id,
           i.issued_at, i.due_at, i.total,
           (SELECT COALESCE(SUM(p.amount), 0) FROM invoice_payments p
              WHERE p.invoice_id = i.id AND p.status = 'succeeded') AS paid,
           m.name AS matter_name, m.matter_number,
           c.client_number, c.originating_attorney_email, c.billing_attorney_email
      FROM invoices i
      LEFT JOIN matters  m ON m.id = i.matter_id
      LEFT JOIN contacts c ON c.id = i.client_contact_id
     WHERE i.firm_id = ? AND i.status = 'sent' AND i.issued_at IS NOT NULL
     ${cIn.sql}${mIn.sql}
     ORDER BY i.issued_at
  `;
  const invoices = db.prepare(sql).all(req.user.firmId, ...cIn.params, ...mIn.params);

  const buckets = {
    '0-30':  { count: 0, amount: 0 },
    '31-60': { count: 0, amount: 0 },
    '61-90': { count: 0, amount: 0 },
    '90+':   { count: 0, amount: 0 },
  };
  const rows = [];
  for (const inv of invoices) {
    const balance = +(Number(inv.total || 0) - Number(inv.paid || 0)).toFixed(2);
    if (balance <= 0.005) continue;
    const issuedDate = String(inv.issued_at).slice(0, 10);
    const issuedMs = new Date(issuedDate + 'T00:00:00').getTime();
    const days = Math.max(0, Math.floor((todayMs - issuedMs) / 86400000));
    const bucket = days <= 30 ? '0-30' : days <= 60 ? '31-60' : days <= 90 ? '61-90' : '90+';
    buckets[bucket].count  += 1;
    buckets[bucket].amount = +(buckets[bucket].amount + balance).toFixed(2);
    rows.push({
      invoice_id: inv.id, number: inv.number,
      client_contact_id: inv.client_contact_id, client_name: inv.client_name, client_number: inv.client_number,
      matter_id: inv.matter_id, matter_name: inv.matter_name, matter_number: inv.matter_number,
      issued_at: inv.issued_at, due_at: inv.due_at,
      total: +Number(inv.total || 0).toFixed(2),
      paid:  +Number(inv.paid  || 0).toFixed(2),
      balance, days_overdue: days, bucket,
      originating_attorney_email: inv.originating_attorney_email,
      billing_attorney_email: inv.billing_attorney_email,
    });
  }
  rows.sort((a, b) => b.days_overdue - a.days_overdue);
  const totals = { count: rows.length, balance: +rows.reduce((s, r) => s + r.balance, 0).toFixed(2) };
  res.json({ asOf: asOfStr, buckets, rows, totals });
});

// Cash receipts — succeeded payments rolled up by period, with method
// breakdown and individual rows for the detail table.
app.get('/api/reports/cash-receipts', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const granularity = ['day','month','year'].includes(req.query.granularity) ? req.query.granularity : 'month';
  const from = req.query.from || null;
  const to   = req.query.to   || null;
  const toEnd = to ? to + 'T23:59:59.999Z' : null;
  const f = resolveCashflowFilters(req);

  const cIn = inClause('i.client_contact_id', f.clientIdIn);
  const mIn = inClause('i.matter_id',         f.matterIdIn);
  let sql = `
    SELECT p.id, p.invoice_id, p.amount, p.method, p.occurred_at, p.destination,
           p.reference, p.notes,
           i.number AS invoice_number, i.client_contact_id, i.client_name, i.matter_id,
           m.name AS matter_name, m.matter_number,
           c.client_number, c.originating_attorney_email, c.billing_attorney_email
      FROM invoice_payments p
      LEFT JOIN invoices i ON i.id = p.invoice_id
      LEFT JOIN matters  m ON m.id = i.matter_id
      LEFT JOIN contacts c ON c.id = i.client_contact_id
     WHERE p.firm_id = ? AND p.status = 'succeeded' AND p.occurred_at IS NOT NULL
     ${cIn.sql}${mIn.sql}
  `;
  const params = [req.user.firmId, ...cIn.params, ...mIn.params];
  if (from)  { sql += ' AND p.occurred_at >= ?'; params.push(from); }
  if (toEnd) { sql += ' AND p.occurred_at <= ?'; params.push(toEnd); }
  sql += ' ORDER BY p.occurred_at DESC';
  const payments = db.prepare(sql).all(...params);

  const periodMap = new Map();
  const methodTotals = {};
  for (const p of payments) {
    const period = periodFmtJs(p.occurred_at, granularity);
    if (!periodMap.has(period)) periodMap.set(period, { period, total: 0, count: 0, by_method: {} });
    const row = periodMap.get(period);
    const amt = Number(p.amount || 0);
    const method = p.method || 'unknown';
    row.total = +(row.total + amt).toFixed(2);
    row.count += 1;
    row.by_method[method] = +((row.by_method[method] || 0) + amt).toFixed(2);
    methodTotals[method]  = +((methodTotals[method]  || 0) + amt).toFixed(2);
  }
  const periods = [...periodMap.values()].sort((a, b) => a.period < b.period ? -1 : 1);
  const totals = {
    amount: +payments.reduce((s, p) => s + Number(p.amount || 0), 0).toFixed(2),
    count: payments.length,
    by_method: methodTotals,
  };
  const rows = payments.map(p => ({
    id: p.id, invoice_id: p.invoice_id, invoice_number: p.invoice_number,
    occurred_at: p.occurred_at, amount: +Number(p.amount || 0).toFixed(2),
    method: p.method || 'unknown', destination: p.destination,
    reference: p.reference, notes: p.notes,
    client_contact_id: p.client_contact_id, client_name: p.client_name, client_number: p.client_number,
    matter_id: p.matter_id, matter_name: p.matter_name, matter_number: p.matter_number,
    originating_attorney_email: p.originating_attorney_email,
    billing_attorney_email: p.billing_attorney_email,
  }));
  res.json({ granularity, from, to, periods, rows, totals });
});

app.get('/api/reports/origination', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const rows = db.prepare(`
    SELECT c.originating_attorney_email AS attorney_email,
           c.origination_split_pct      AS split_pct,
           c.id                         AS client_id,
           c.full_name                  AS client_name,
           c.client_number,
           COALESCE(SUM(CASE WHEN i.status IS NOT NULL AND i.status != 'void' THEN i.total       ELSE 0 END), 0) AS fees_billed,
           COALESCE(SUM(CASE WHEN i.status IS NOT NULL AND i.status != 'void' THEN i.amount_paid ELSE 0 END), 0) AS fees_collected
    FROM contacts c
    LEFT JOIN invoices i ON i.client_contact_id = c.id AND i.firm_id = c.firm_id
    WHERE c.firm_id = ? AND c.originating_attorney_email IS NOT NULL AND c.originating_attorney_email != ''
    GROUP BY c.id
    ORDER BY c.originating_attorney_email, fees_billed DESC
  `).all(req.user.firmId);

  const attorneyMap = new Map();
  for (const row of rows) {
    const email = row.attorney_email;
    if (!attorneyMap.has(email)) attorneyMap.set(email, { email, total_billed: 0, total_share: 0, clients: [] });
    const a = attorneyMap.get(email);
    const splitPct = Number(row.split_pct || 0);
    const billed   = Number(row.fees_billed   || 0);
    const share    = +(billed * splitPct / 100).toFixed(2);
    a.total_billed = +(a.total_billed + billed).toFixed(2);
    a.total_share  = +(a.total_share  + share).toFixed(2);
    a.clients.push({
      client_id:      row.client_id,
      client_name:    row.client_name,
      client_number:  row.client_number,
      split_pct:      splitPct,
      fees_billed:    +billed.toFixed(2),
      fees_collected: +Number(row.fees_collected || 0).toFixed(2),
      share,
    });
  }
  res.json({ attorneys: [...attorneyMap.values()] });
});

// ═══════════════════════════════════════════════════════════════════════
// BANK RECONCILIATION
// Mercury auto-sync + OFX/QFX file import, shared reconciliation table
// ═══════════════════════════════════════════════════════════════════════

const timedFetch = async (url, init = {}, ms = 15000) => {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { ...init, signal: ctrl.signal }); }
  finally { clearTimeout(t); }
};

// Sync transactions from Mercury for both configured accounts
app.post('/api/bank/sync', authRequired, verifyFirmMembership, requireCap('manageBilling'), async (req, res) => {
  if (!paymentsEnabled) return res.status(503).json({ error: 'PAYMENTS_KEK not configured' });
  const cfg = readPaymentConfig(req.user.firmId);
  const token = cfg ? decryptSecret(cfg.mercury_token) : null;
  if (!token) return res.status(400).json({ error: 'Mercury token not configured' });

  const accounts = [];
  if (cfg.mercury_operating_account_id) accounts.push({ id: cfg.mercury_operating_account_id, role: 'operating' });
  if (cfg.mercury_trust_account_id)     accounts.push({ id: cfg.mercury_trust_account_id,     role: 'trust' });
  if (!accounts.length) return res.status(400).json({ error: 'No Mercury account IDs configured' });

  const firmId = req.user.firmId;
  const syncState = db.prepare('SELECT last_synced_at FROM mercury_sync_state WHERE firm_id = ?').get(firmId);
  // Fetch from last sync date, or 90 days back on first run
  const since = syncState?.last_synced_at
    ? syncState.last_synced_at.slice(0, 10)
    : new Date(Date.now() - 90 * 86400e3).toISOString().slice(0, 10);

  const upsert = db.prepare(`
    INSERT INTO bank_transactions
      (id, firm_id, account_id, account_role, amount, posted_at, counterparty, memo, raw_json, source)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'mercury')
    ON CONFLICT(id) DO UPDATE SET
      amount       = excluded.amount,
      posted_at    = excluded.posted_at,
      counterparty = excluded.counterparty,
      memo         = excluded.memo,
      raw_json     = excluded.raw_json,
      fetched_at   = datetime('now')
  `);

  let totalFetched = 0;
  try {
    for (const acct of accounts) {
      let offset = 0;
      const limit = 500;
      while (true) {
        const url = `https://api.mercury.com/api/v1/account/${acct.id}/transactions` +
          `?limit=${limit}&offset=${offset}&status=sent&start=${since}`;
        const r = await timedFetch(url, {
          headers: { Authorization: 'Bearer ' + token, Accept: 'application/json' },
        });
        if (!r.ok) {
          const j = await r.json().catch(() => ({}));
          return res.status(502).json({ error: 'Mercury API error: ' + (j.message || j.error || `HTTP ${r.status}`) });
        }
        const j = await r.json();
        const txns = Array.isArray(j.transactions) ? j.transactions : [];
        db.transaction(() => {
          for (const t of txns) {
            upsert.run(
              t.id, firmId, acct.id, acct.role,
              Number(t.amount || 0),
              t.postedAt || t.createdAt || null,
              t.counterpartyName || (t.counterparty && t.counterparty.name) || null,
              t.note || t.bankDescription || null,
              JSON.stringify(t),
            );
          }
        })();
        totalFetched += txns.length;
        if (txns.length < limit) break;
        offset += limit;
      }
    }
  } catch (e) {
    return res.status(502).json({ error: 'Mercury sync failed: ' + e.message });
  }

  const now = new Date().toISOString();
  db.prepare(`INSERT INTO mercury_sync_state (firm_id, last_synced_at) VALUES (?, ?)
              ON CONFLICT(firm_id) DO UPDATE SET last_synced_at = excluded.last_synced_at`)
    .run(firmId, now);

  res.json({ ok: true, fetched: totalFetched, syncedAt: now });
});

// List bank transactions (reconciled + unreconciled)
app.get('/api/bank/transactions', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const firmId = req.user.firmId;
  const { unreconciled, accountRole, from, to } = req.query;
  let sql = `
    SELECT bt.*,
           ip.invoice_id    AS payment_invoice_id,
           ip.amount        AS payment_amount,
           ip.method        AS payment_method,
           i.number         AS invoice_number,
           i.client_name
    FROM bank_transactions bt
    LEFT JOIN invoice_payments ip ON ip.id  = bt.reconciled_payment_id
    LEFT JOIN invoices         i  ON i.id   = ip.invoice_id
    WHERE bt.firm_id = ?
  `;
  const params = [firmId];
  if (unreconciled === '1') { sql += ' AND bt.reconciled_payment_id IS NULL'; }
  if (accountRole) { sql += ' AND bt.account_role = ?'; params.push(accountRole); }
  if (from) { sql += ' AND bt.posted_at >= ?'; params.push(from); }
  if (to)   { sql += ' AND bt.posted_at <= ?'; params.push(to + 'T23:59:59'); }
  sql += ' ORDER BY bt.posted_at DESC LIMIT 500';

  const syncState = db.prepare('SELECT last_synced_at FROM mercury_sync_state WHERE firm_id = ?').get(firmId);
  res.json({
    transactions: db.prepare(sql).all(...params),
    lastSyncedAt: syncState?.last_synced_at || null,
  });
});

// Invoice payments not yet matched to any bank transaction
app.get('/api/bank/unreconciled-payments', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const payments = db.prepare(`
    SELECT ip.id, ip.invoice_id, ip.amount, ip.method, ip.occurred_at, ip.destination,
           ip.reference, ip.notes,
           i.number AS invoice_number, i.client_name, i.matter_id,
           m.name   AS matter_name
    FROM invoice_payments ip
    LEFT JOIN invoices i ON i.id = ip.invoice_id
    LEFT JOIN matters  m ON m.id = i.matter_id
    WHERE ip.firm_id = ? AND ip.status = 'succeeded'
      AND NOT EXISTS (
        SELECT 1 FROM bank_transactions bt
        WHERE bt.reconciled_payment_id = ip.id AND bt.firm_id = ip.firm_id
      )
    ORDER BY ip.occurred_at DESC
    LIMIT 300
  `).all(req.user.firmId);
  res.json(payments);
});

// Import OFX/QFX rows parsed client-side
app.post('/api/bank/import', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const { transactions, accountRole } = req.body;
  if (!Array.isArray(transactions)) return res.status(400).json({ error: 'transactions must be an array' });
  const role = ['operating', 'trust'].includes(accountRole) ? accountRole : 'operating';
  const firmId = req.user.firmId;
  const upsert = db.prepare(`
    INSERT INTO bank_transactions
      (id, firm_id, account_id, account_role, amount, posted_at, counterparty, memo, source)
    VALUES (?, ?, 'ofx', ?, ?, ?, ?, ?, 'ofx')
    ON CONFLICT(id) DO NOTHING
  `);
  let inserted = 0;
  db.transaction(() => {
    for (const t of transactions) {
      if (!t.id) continue;
      const r = upsert.run(t.id, firmId, role, Number(t.amount || 0), t.posted_at || null, t.counterparty || null, t.memo || null);
      inserted += r.changes;
    }
  })();
  res.json({ ok: true, inserted, total: transactions.length });
});

// Link a bank transaction to an invoice payment
app.patch('/api/bank/transactions/:id/reconcile', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const { paymentId } = req.body;
  if (!paymentId) return res.status(400).json({ error: 'paymentId required' });
  const tx = db.prepare('SELECT id FROM bank_transactions WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!tx) return res.status(404).json({ error: 'Transaction not found' });
  const pmt = db.prepare('SELECT id FROM invoice_payments WHERE id = ? AND firm_id = ?').get(paymentId, req.user.firmId);
  if (!pmt) return res.status(404).json({ error: 'Payment not found' });
  db.prepare('UPDATE bank_transactions SET reconciled_payment_id = ? WHERE id = ? AND firm_id = ?')
    .run(paymentId, req.params.id, req.user.firmId);
  res.json({ ok: true });
});

// Clear a reconciliation link
app.patch('/api/bank/transactions/:id/unreconcile', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  const tx = db.prepare('SELECT id FROM bank_transactions WHERE id = ? AND firm_id = ?').get(req.params.id, req.user.firmId);
  if (!tx) return res.status(404).json({ error: 'Transaction not found' });
  db.prepare('UPDATE bank_transactions SET reconciled_payment_id = NULL WHERE id = ? AND firm_id = ?')
    .run(req.params.id, req.user.firmId);
  res.json({ ok: true });
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
        normalizeEmail(r.ownerEmail || r.owner_email) || req.user.email,
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
    // Aging slice — uses the same per-matter aging logic as the WIP report so
    // the dashboard nudge and the report card always match.
    const wip = computeUnbilledWipReport(firmId);
    const over60Amount  = +(wip.summary['61-90'].amount + wip.summary['90+'].amount).toFixed(2);
    const over60Matters = wip.summary['61-90'].count + wip.summary['90+'].count;
    billing = {
      unbilledWip: unbilled,
      outstandingAR: outstanding,
      trustBalance: trustTotal,
      unbilledWipOver60: over60Amount,
      unbilledWipOver60Matters: over60Matters,
    };
  }
  res.json({ totalContacts, byType, overdue, thisWeek, recent, billing });
});

// ═══════════════════════════════════════════════════════════════════════
// REPORTS
// ═══════════════════════════════════════════════════════════════════════

// Unbilled WIP grouped by matter, with aging buckets based on the oldest
// draft entry's work date. Time is included only for hourly matters (flat-fee
// draft time is bookkeeping, not WIP). Expenses are included for hourly and
// flat matters since advanced costs leak regardless of billing type.
// Closed matters are included — stale draft time on a closed matter is exactly
// the leakage this report exists to catch.
//
// Extracted as a function so the dashboard can reuse the same logic for its
// "$X older than 60 days" nudge — guarantees the dashboard number and the
// report agree.
function computeUnbilledWipReport(firmId) {
  const timeAgg = db.prepare(`
    SELECT t.matter_id,
           MIN(t.date) AS oldest_time_date,
           SUM(t.minutes) / 60.0 AS time_hours,
           SUM(t.minutes * t.rate / 60.0) AS time_amount,
           COUNT(*) AS entry_count
      FROM time_entries t
      JOIN matters m ON m.id = t.matter_id
     WHERE t.firm_id = ?
       AND t.status = 'draft'
       AND t.billable = 1
       AND m.billing_type = 'hourly'
     GROUP BY t.matter_id
  `).all(firmId);

  const expenseAgg = db.prepare(`
    SELECT e.matter_id,
           MIN(e.date) AS oldest_expense_date,
           SUM(e.amount * (1 + COALESCE(e.markup_pct, 0))) AS expense_amount,
           COUNT(*) AS expense_count
      FROM expenses e
      JOIN matters m ON m.id = e.matter_id
     WHERE e.firm_id = ?
       AND e.status = 'draft'
       AND e.billable = 1
       AND m.billing_type IN ('hourly','flat')
     GROUP BY e.matter_id
  `).all(firmId);

  const byMatter = new Map();
  for (const r of timeAgg) {
    byMatter.set(r.matter_id, {
      matter_id: r.matter_id,
      oldest_time_date: r.oldest_time_date,
      oldest_expense_date: null,
      time_hours: r.time_hours || 0,
      time_amount: r.time_amount || 0,
      expense_amount: 0,
      entry_count: r.entry_count || 0,
      expense_count: 0,
    });
  }
  for (const r of expenseAgg) {
    const cur = byMatter.get(r.matter_id);
    if (cur) {
      cur.oldest_expense_date = r.oldest_expense_date;
      cur.expense_amount = r.expense_amount || 0;
      cur.expense_count = r.expense_count || 0;
    } else {
      byMatter.set(r.matter_id, {
        matter_id: r.matter_id,
        oldest_time_date: null,
        oldest_expense_date: r.oldest_expense_date,
        time_hours: 0,
        time_amount: 0,
        expense_amount: r.expense_amount || 0,
        entry_count: 0,
        expense_count: r.expense_count || 0,
      });
    }
  }

  const summary = {
    '0-30':  { count: 0, amount: 0 },
    '31-60': { count: 0, amount: 0 },
    '61-90': { count: 0, amount: 0 },
    '90+':   { count: 0, amount: 0 },
  };

  if (byMatter.size === 0) {
    return { rows: [], summary, totals: { matters: 0, amount: 0 } };
  }

  const ids = [...byMatter.keys()];
  const placeholders = ids.map(() => '?').join(',');
  const matters = db.prepare(`
    SELECT id, name, client_name, client_contact_id, status, billing_type
      FROM matters
     WHERE firm_id = ? AND id IN (${placeholders})
  `).all(firmId, ...ids);
  const matterMap = new Map(matters.map(m => [m.id, m]));

  // Aging anchor: midnight today, local time. Date-only strings parse as local
  // when no Z suffix is present, so the diff is in calendar days.
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const todayMs = today.getTime();

  const rows = [];
  for (const r of byMatter.values()) {
    const m = matterMap.get(r.matter_id);
    if (!m) continue; // matter deleted out from under the entries — skip
    const candidates = [r.oldest_time_date, r.oldest_expense_date].filter(Boolean).sort();
    const oldest = candidates[0];
    const days = oldest
      ? Math.max(0, Math.floor((todayMs - new Date(oldest + 'T00:00:00').getTime()) / 86400000))
      : 0;
    const bucket = days <= 30 ? '0-30' : days <= 60 ? '31-60' : days <= 90 ? '61-90' : '90+';
    const time_amount    = +(r.time_amount || 0).toFixed(2);
    const expense_amount = +(r.expense_amount || 0).toFixed(2);
    const total_amount   = +(time_amount + expense_amount).toFixed(2);
    rows.push({
      matter_id:           m.id,
      matter_name:         m.name,
      matter_status:       m.status,
      billing_type:        m.billing_type,
      client_name:         m.client_name,
      client_contact_id:   m.client_contact_id,
      oldest_entry_date:   oldest,
      days_since_oldest:   days,
      bucket,
      time_hours:          +(r.time_hours || 0).toFixed(2),
      time_amount,
      expense_amount,
      total_amount,
      entry_count:         r.entry_count,
      expense_count:       r.expense_count,
    });
    summary[bucket].count  += 1;
    summary[bucket].amount += total_amount;
  }
  for (const k of Object.keys(summary)) summary[k].amount = +summary[k].amount.toFixed(2);

  rows.sort((a, b) => b.days_since_oldest - a.days_since_oldest);

  const totalsAmount = +rows.reduce((s, r) => s + r.total_amount, 0).toFixed(2);
  return { rows, summary, totals: { matters: rows.length, amount: totalsAmount } };
}

app.get('/api/reports/unbilled-wip', authRequired, verifyFirmMembership, requireCap('manageBilling'), (req, res) => {
  res.json(computeUnbilledWipReport(req.user.firmId));
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
// TIMERS (live stopwatches — users may run several concurrently)
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
    id: t.id,
    matterId: t.matter_id,
    matterName: matter?.name || null,
    clientName: matter?.client_name || null,
    description: t.description,
    running: !!t.started_at,
    elapsedSeconds: timerElapsedSeconds(t),
    startedAt: t.started_at,
    incrementMinutes: t.matter_id ? effectiveIncrementMinutes(t.matter_id) : firmDefaultIncrementMinutes(t.firm_id),
  };
}

function getTimerById(id, userEmail, firmId) {
  // firmId is optional for backward compat, but always pass it from a route so a
  // timer row left over from a prior firm membership can't be acted on.
  if (firmId) {
    return db.prepare('SELECT * FROM timers WHERE id = ? AND user_email = ? AND firm_id = ?').get(id, userEmail, firmId);
  }
  return db.prepare('SELECT * FROM timers WHERE id = ? AND user_email = ?').get(id, userEmail);
}

// Pauses every running timer for a user except optionally one (the one we're
// about to start/resume). Keeps accumulated_seconds correct for each paused row.
function pauseOtherRunningTimers(userEmail, exceptId = null) {
  const rows = db.prepare('SELECT * FROM timers WHERE user_email = ? AND started_at IS NOT NULL').all(userEmail);
  const upd = db.prepare('UPDATE timers SET started_at = NULL, accumulated_seconds = ? WHERE id = ?');
  for (const t of rows) {
    if (exceptId != null && String(t.id) === String(exceptId)) continue;
    upd.run(timerElapsedSeconds(t), t.id);
  }
}

// List all timers for the current user, newest first.
app.get('/api/timers', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const rows = db.prepare('SELECT * FROM timers WHERE user_email = ? ORDER BY created_at DESC, id DESC').all(req.user.email);
  res.json(rows.map(timerToJSON));
});

// Create a new timer. Users may hold several concurrent timer rows, but only
// one runs at a time — any others that were running get paused. matterId is
// optional: a timer can start with no client/matter and have one assigned later
// via PATCH (so users can hit "Start" and decide what they're working on after).
app.post('/api/timers', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const { matterId, description } = req.body || {};
  if (matterId) {
    const m = db.prepare('SELECT id FROM matters WHERE id = ? AND firm_id = ?').get(matterId, req.user.firmId);
    if (!m) return res.status(404).json({ error: 'Matter not found' });
  }
  const now = new Date().toISOString();
  const info = db.transaction(() => {
    pauseOtherRunningTimers(req.user.email);
    return db.prepare(`INSERT INTO timers (user_email, firm_id, matter_id, description, started_at, accumulated_seconds)
                       VALUES (?, ?, ?, ?, ?, 0)`)
      .run(req.user.email, req.user.firmId, matterId || null, description || null, now);
  })();
  res.json(timerToJSON(getTimerById(info.lastInsertRowid, req.user.email, req.user.firmId)));
});

app.post('/api/timers/:id/pause', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const t = getTimerById(req.params.id, req.user.email, req.user.firmId);
  if (!t) return res.status(404).json({ error: 'Timer not found' });
  if (!t.started_at) return res.json(timerToJSON(t));
  const elapsed = timerElapsedSeconds(t);
  db.prepare('UPDATE timers SET started_at = NULL, accumulated_seconds = ? WHERE id = ?').run(elapsed, t.id);
  res.json(timerToJSON(getTimerById(t.id, req.user.email, req.user.firmId)));
});

// Resume a paused timer — auto-pauses every other running timer so only one
// stopwatch ticks at a time.
app.post('/api/timers/:id/resume', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const t = getTimerById(req.params.id, req.user.email, req.user.firmId);
  if (!t) return res.status(404).json({ error: 'Timer not found' });
  if (t.started_at) return res.json(timerToJSON(t));
  db.transaction(() => {
    pauseOtherRunningTimers(req.user.email, t.id);
    db.prepare('UPDATE timers SET started_at = ? WHERE id = ?').run(new Date().toISOString(), t.id);
  })();
  res.json(timerToJSON(getTimerById(t.id, req.user.email, req.user.firmId)));
});

app.patch('/api/timers/:id', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const t = getTimerById(req.params.id, req.user.email, req.user.firmId);
  if (!t) return res.status(404).json({ error: 'Timer not found' });
  const { matterId, description } = req.body || {};
  if (matterId) {
    const m = db.prepare('SELECT id FROM matters WHERE id = ? AND firm_id = ?').get(matterId, req.user.firmId);
    if (!m) return res.status(404).json({ error: 'Matter not found' });
  }
  db.prepare('UPDATE timers SET matter_id = COALESCE(?, matter_id), description = COALESCE(?, description) WHERE id = ?')
    .run(matterId || null, description ?? null, t.id);
  res.json(timerToJSON(getTimerById(t.id, req.user.email, req.user.firmId)));
});

// Stop — commits the elapsed time as a time_entry and deletes the timer row.
// Rounds up to the nearest 6 minutes (0.1 hr) by default, which is standard legal billing increment.
app.post('/api/timers/:id/stop', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const t = getTimerById(req.params.id, req.user.email, req.user.firmId);
  if (!t) return res.status(404).json({ error: 'Timer not found' });
  if (!t.matter_id) return res.status(400).json({ error: 'Timer has no matter — set one first' });
  // Defense-in-depth: re-verify the matter still belongs to this firm. The timer
  // row was firm-scoped at create/patch time, but matters in theory could have
  // been moved; we don't want to commit a time entry against a foreign matter.
  const matter = db.prepare('SELECT id FROM matters WHERE id = ? AND firm_id = ?').get(t.matter_id, req.user.firmId);
  if (!matter) return res.status(404).json({ error: 'Matter not found' });
  const elapsed = timerElapsedSeconds(t);
  const rawMinutes = elapsed / 60;
  const inc = effectiveIncrementMinutes(t.matter_id);
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
    db.prepare('DELETE FROM timers WHERE id = ?').run(t.id);
  })();

  res.json({
    ok: true,
    entry: db.prepare('SELECT * FROM time_entries WHERE id = ?').get(entryId),
    rawSeconds: elapsed,
  });
});

app.delete('/api/timers/:id', authRequired, verifyFirmMembership, requireCap('logTime'), (req, res) => {
  const t = getTimerById(req.params.id, req.user.email, req.user.firmId);
  if (!t) return res.status(404).json({ error: 'Timer not found' });
  db.prepare('DELETE FROM timers WHERE id = ?').run(t.id);
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
    console.error('Receipt extract error:', e.stack || e.message);
    // Don't forward the raw upstream error — it can include Anthropic account
    // metadata or prompt fragments. Generic user-facing message; details in logs.
    res.status(502).json({ error: 'Receipt reading failed. Please try again or enter the expense manually.' });
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

scheduleBackups();
scheduleRecurringBilling();

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
