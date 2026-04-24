# Payments & Bank Reconciliation — Design Reference

Draft design for accepting client payments against invoices and reconciling
them against Mercury bank activity. Not yet implemented — this document is
the blueprint to build against.

## Goals

- Let clients pay an invoice via a hosted link (ACH preferred, card optional).
- Route earned-fee payments to the **operating** account and retainers to the
  **IOLTA trust** account — correctly, every time.
- Track every payment event against a specific invoice (and the corresponding
  `trust_ledger` row for retainers).
- Reconcile what actually hit Mercury against what the CRM thinks was paid,
  catching wires/checks that bypass Stripe entirely.

## Why this shape

Mercury itself is not a payment processor — its public API is primarily
read-only (accounts, transactions, statements). So the flow is:

```
Stripe (accept payment)  ─►  Mercury (funds land here)  ─►  CRM (reconcile)
```

Mercury's role is **confirmation of funds** and **catching non-Stripe
payments**, not acceptance.

## Schema additions

All new tables. `invoices.amount_paid` already exists and stays as the
denormalized sum, recomputed on every `invoice_payments` insert/refund.

```sql
-- Per-firm credentials. Tokens encrypted at rest with PAYMENTS_KEK (new env var).
CREATE TABLE IF NOT EXISTS firm_payment_config (
  firm_id               TEXT PRIMARY KEY REFERENCES firms(id) ON DELETE CASCADE,
  stripe_account_id     TEXT,              -- acct_xxx (Connect) or null for direct
  stripe_secret_key     TEXT,              -- encrypted
  stripe_publishable    TEXT,              -- plain; safe client-side
  stripe_webhook_secret TEXT,              -- encrypted
  mercury_token         TEXT,              -- encrypted; read-only API key
  mercury_operating_account_id TEXT,       -- Mercury accountId for operating
  mercury_trust_account_id     TEXT,       -- Mercury accountId for IOLTA
  ach_enabled           INTEGER DEFAULT 1,
  card_enabled          INTEGER DEFAULT 1,
  updated_at            TEXT DEFAULT (datetime('now'))
);

-- One row per payment event against an invoice OR trust deposit.
CREATE TABLE IF NOT EXISTS invoice_payments (
  id                       TEXT PRIMARY KEY,
  firm_id                  TEXT NOT NULL REFERENCES firms(id) ON DELETE CASCADE,
  invoice_id               TEXT REFERENCES invoices(id) ON DELETE SET NULL,  -- null for retainer-only deposits
  client_contact_id        TEXT REFERENCES contacts(id) ON DELETE SET NULL,
  destination              TEXT NOT NULL,     -- 'operating' | 'trust'
  amount                   REAL NOT NULL,
  currency                 TEXT DEFAULT 'usd',
  method                   TEXT,              -- 'stripe_card' | 'stripe_ach' | 'wire' | 'check' | 'manual'
  status                   TEXT NOT NULL,     -- 'pending' | 'succeeded' | 'failed' | 'refunded'
  stripe_payment_intent_id TEXT UNIQUE,
  stripe_charge_id         TEXT,
  mercury_txn_id           TEXT UNIQUE,       -- set when matched to a Mercury transaction
  trust_ledger_id          TEXT REFERENCES trust_ledger(id) ON DELETE SET NULL,
  occurred_at              TEXT,
  raw_json                 TEXT,              -- full Stripe/Mercury payload for audit
  created_at               TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_invpay_invoice ON invoice_payments(invoice_id);
CREATE INDEX IF NOT EXISTS idx_invpay_firm    ON invoice_payments(firm_id, status);

-- Public pay-links. Random token, no auth required to view.
CREATE TABLE IF NOT EXISTS payment_links (
  token        TEXT PRIMARY KEY,      -- 32-byte urlsafe random
  firm_id      TEXT NOT NULL,
  invoice_id   TEXT REFERENCES invoices(id) ON DELETE CASCADE,
  destination  TEXT NOT NULL,         -- 'operating' | 'trust'
  amount_cents INTEGER NOT NULL,      -- frozen at link creation
  expires_at   TEXT,
  used_at      TEXT,
  created_by   TEXT,
  created_at   TEXT DEFAULT (datetime('now'))
);

-- Mirror of Mercury transactions we've pulled. Idempotent via the mercury id as PK.
CREATE TABLE IF NOT EXISTS bank_transactions (
  id                    TEXT PRIMARY KEY,      -- Mercury's transaction id
  firm_id               TEXT NOT NULL,
  account_id            TEXT NOT NULL,         -- Mercury accountId
  account_role          TEXT,                  -- 'operating' | 'trust'
  amount                REAL NOT NULL,         -- signed; positive = credit
  posted_at             TEXT,
  counterparty          TEXT,
  memo                  TEXT,
  external_id           TEXT,                  -- Mercury externalMemo / wire ref
  reconciled_payment_id TEXT REFERENCES invoice_payments(id) ON DELETE SET NULL,
  raw_json              TEXT,
  fetched_at            TEXT DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_banktx_firm  ON bank_transactions(firm_id, posted_at);
CREATE INDEX IF NOT EXISTS idx_banktx_unrec ON bank_transactions(firm_id)
  WHERE reconciled_payment_id IS NULL;

-- Cursor for incremental Mercury pulls.
CREATE TABLE IF NOT EXISTS mercury_sync_state (
  firm_id        TEXT PRIMARY KEY,
  last_synced_at TEXT,
  last_cursor    TEXT
);
```

## Endpoints

### Admin config — `requireCap('manageFirm')`

| Method | Path                          | Purpose                                                       |
|--------|-------------------------------|---------------------------------------------------------------|
| GET    | `/api/firm/payments`          | Config with secrets redacted; `connected: {stripe, mercury}`. |
| PUT    | `/api/firm/payments`          | Upsert Stripe keys + Mercury token. Encrypt before storing.   |
| POST   | `/api/firm/payments/test`     | Ping Stripe + Mercury, report which work.                     |

### Pay links — `requireCap('manageBilling')`

| Method | Path                                    | Purpose                                                    |
|--------|-----------------------------------------|------------------------------------------------------------|
| POST   | `/api/invoices/:id/payment-link`        | Body `{destination, amount?, expiresInDays?}` → `{url}`.   |

Include the link automatically in the invoice PDF footer and send-email flow.
Reject creation if the invoice is `void` or already `paid`.

### Public pay page — no auth

| Method | Path                            | Purpose                                                          |
|--------|---------------------------------|------------------------------------------------------------------|
| GET    | `/pay/:token`                   | Minimal HTML: firm, client, invoice #, amount, destination label, Stripe Elements iframe. |
| POST   | `/api/pay/:token/intent`        | Creates a Stripe PaymentIntent; returns `client_secret`; inserts `pending` row in `invoice_payments`. |
| POST   | `/api/pay/stripe-webhook`       | Raw-body signature verification; handles `payment_intent.succeeded`. |

**Webhook success logic**:
1. Mark `invoice_payments.status = 'succeeded'`.
2. If `destination = 'operating'`: bump `invoices.amount_paid`; flip invoice
   `status → 'paid'` when `amount_paid >= total`.
3. If `destination = 'trust'`: insert a `trust_ledger` row with
   `kind = 'deposit'`; store its id on the payment row.

### Mercury sync — admin-triggered + cron

| Method | Path                                         | Purpose                                                  |
|--------|----------------------------------------------|----------------------------------------------------------|
| POST   | `/api/firm/mercury/sync`                     | Pull transactions since `last_synced_at` for both accounts, upsert, run matcher. |
| GET    | `/api/bank-transactions?status=unreconciled` | Feeds the reconcile inbox UI.                            |
| POST   | `/api/bank-transactions/:id/reconcile`       | Body `{invoice_id, destination}`. Manual match.          |

**Auto-match rules** (run inside the sync endpoint):
- Candidate = unreconciled credit where `abs(amount - txn.amount) < 0.01`
  AND (`memo` or `externalMemo` contains the invoice number)
  AND `posted_at` within 14 days of invoice `issued_at`.
- Exact single match → auto-reconcile. If a matching Stripe `succeeded`
  payment already exists, link `bank_transactions.reconciled_payment_id` to
  it. Otherwise create a new `invoice_payments` row with `method = 'wire'`
  (or `'check'` if counterparty suggests it).
- Zero or multiple matches → leave unreconciled; surface in the inbox.

### Background cron

On Render, add a cron service that hits
`/api/internal/mercury/sync-all` (protected by a shared-secret header) every
6 hours. The endpoint iterates every `firm_payment_config` row with a
`mercury_token` set.

## Flow summary

```
Client clicks pay link
  └─► Stripe Elements
        └─► PaymentIntent (destination tagged in metadata)
              └─► webhook → invoice_payments.status = succeeded
                      ├── destination=operating → invoices.amount_paid++,
                      │                           status → paid when full
                      └── destination=trust     → trust_ledger deposit row

Nightly (or manual) sync:
  Mercury API → bank_transactions (upsert)
              → matcher → link to invoice_payments
                        (catches wires/checks that bypassed Stripe;
                         double-confirms Stripe deposits)
```

## Security

- **`PAYMENTS_KEK`** — new required env var, 32-byte base64. Used with
  `crypto.createCipheriv('aes-256-gcm', …)` for the encrypted columns. Never
  log decrypted values. Rotate by re-encrypting all rows on key change.
- **Stripe webhook** — route needs `express.raw({type:'application/json'})`,
  mounted **before** the global `express.json()` middleware or signature
  verification will fail.
- **Pay-link tokens** — `crypto.randomBytes(32).toString('base64url')`.
  Rate-limit `/pay/:token` attempts per IP.
- **IOLTA invariant** — never auto-sweep from trust to operating. "Apply
  retainer to invoice" is a deliberate `manageBilling` action that posts a
  `trust_ledger` withdrawal AND an `invoice_payments` row (`method='manual'`,
  `destination='operating'`). Keep this as its own endpoint, not part of the
  Stripe flow.
- **Refunds** — inserting a refund payment (negative amount, status
  `refunded`) must decrement `invoices.amount_paid`; if it goes below
  `total`, flip status back to `sent`.

## Build order (smallest useful slice first)

1. Schema migration + `firm_payment_config` admin UI.
2. Stripe-only path, operating destination only: pay link → Elements →
   webhook → `amount_paid`.
3. Trust destination (writes to `trust_ledger`).
4. Mercury read-only sync + reconcile inbox.
5. Manual wire/check entry (for clients who refuse online payment).
6. Refund flow.

## Open questions

- Stripe **Connect** (each firm onboards their own Stripe account) vs
  **direct** (you hold the keys for your firm only)? Single-firm deployment
  → direct is simpler. Revisit if the CRM ever goes multi-tenant for real.
- Surcharge card fees back to client? Stripe supports it but some states
  restrict it for legal services — check jurisdiction before enabling.
- ACH returns can arrive days after `succeeded`. Handle `charge.refunded`
  and `charge.dispute.*` webhooks to roll back `amount_paid`.
