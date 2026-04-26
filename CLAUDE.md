# CLAUDE.md

This file provides guidance to Claude Code when working with this repository.

## Project Overview

CRM is a legal-firm CRM that tracks clients, prospects, and industry contacts (opposing counsel, judges, experts, referral sources, vendors), with a prospect pipeline (kanban), interaction log, matter management, conflict checking, time tracking, billing (PDF invoices, hourly + flat-fee), and IOLTA trust accounting. Single-firm deployment on `crm.phillipacevedo.com`. Integrates with DealTracker (DT), SPV-Tracker (SPVT), and Leaderboard (LB) via shared JWT exchange and public exports.

## Commands

```bash
npm start           # Start server — requires JWT_SECRET env var
node reset-password.js <email> <new-password>   # Reset a user's password locally
```

**Required env vars:** `JWT_SECRET` (min 32 chars).
**First-boot seed:** set `SEED_ADMIN_PASSWORD` and (optionally) `SEED_ADMIN_EMAIL`, `SEED_FIRM_NAME`. These create the first admin + firm on initial deploy; remove after first boot.
**Optional env vars:** `DB_PATH`, `ALLOWED_ORIGIN`, `DT_URL`, `SPV_URL`, `LB_URL`, `PORT`, SMTP vars (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`), `ANTHROPIC_API_KEY` (enables the "Read receipt to autofill" button on expenses — without it, `POST /api/expenses/extract` returns 503), `PAYMENTS_KEK` (32-byte base64; encrypts Stripe/Mercury credentials in `firm_payment_config`. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`. Without it, the Payments settings tab loads read-only and `PUT /api/firm/payments` returns 503 — the rest of the app runs normally). See `PAYMENTS_DESIGN.md` for the full payments architecture.

### Receipt Reader — Prefer pdf.js for PDFs

The "Read receipt to autofill" flow must try **pdf.js first** for any uploaded PDF before falling back to `ANTHROPIC_API_KEY`. pdf.js runs in the browser, extracts embedded text for free, and handles digitally-generated receipts (the common case). Only when pdf.js returns no text (i.e. scanned-image PDFs or non-PDF images like JPG/PNG) should the request hit `POST /api/expenses/extract` and burn API credits. Goal: don't charge the API key for receipts we can parse locally.

## Architecture

**Single-server monolith** — `server.js` handles Express REST API, JWT auth, SQLite, static file serving, and PDF generation. Matches the DealTracker pattern.

- **Backend:** Node.js + Express. CommonJS, no build step, no bundler.
- **Database:** SQLite via `better-sqlite3`. Local `./data/crm.db`, Render `/data/crm.db` (1 GB disk). WAL mode. Migrations are inline try/catch `ALTER TABLE` blocks.
- **Frontend:** Vanilla HTML/CSS/JS. `public/app.html` is the main SPA (single file with inline CSS and JS). `public/index.html` is the login landing page. `public/inactivity.js` is 30-min auto-logout.
- **Auth:** JWT in HttpOnly cookies (Bearer fallback). Token denylist in SQLite for logout/revocation. Bcrypt 12 rounds.
- **PDF invoices:** `pdfkit`, streamed via `/api/invoices/:id/pdf`.
- **Deployment:** Render (`render.yaml`). `better-sqlite3` needs `--build-from-source`.

### Data Model

Relational tables for core entities (concurrent writes, referential integrity):
`firms`, `users`, `companies`, `contacts`, `interactions`, `matters`, `matter_rates`, `time_entries`, `invoices`, `invoice_lines`, `trust_ledger`, plus auth-support tables (`password_resets`, `invites`, `token_denylist`).

Firm-level JSON blob in `firm_data` (pipeline stages, tag list, custom fields). Per-user JSON in `user_profiles` for UI preferences.

### Role & Permission Model

Single source of truth is the `CAPS` object in `server.js`. Rank-based:

| Role               | Rank | Can log time | Can see rates | Can manage billing | Admin mgmt |
|--------------------|------|--------------|---------------|--------------------|------------|
| Admin              | 100  | yes          | yes           | yes                | yes        |
| Partner            | 90   | yes          | yes           | yes                | no         |
| Associate          | 70   | yes          | no            | no                 | no         |
| Project Assistant  | 60   | yes          | no            | no                 | no         |
| Paralegal          | 55   | yes          | no            | no                 | no         |
| Secretary          | 40   | no           | no            | no                 | no         |
| Staff              | 20   | no           | no            | no                 | no         |

Secretary sees all contacts but can't log time. Staff sees only contacts they own.

### Cross-App Integration (phillipacevedo.com ecosystem)

- `/api/auth/dt-exchange`  — accept a DealTracker JWT, issue a CRM session.
- `/api/auth/spv-exchange` — accept an SPV Tracker JWT.
- `/api/contacts/export`   — public endpoint for Leaderboard (name, company, type).
- `/api/staff/export`      — public endpoint for Leaderboard (active users).
- `/api/dt/matters`        — proxy pull from DT (used to autofill matter pickers).

### API Route Groups

All routes live in `server.js`:
- `/api/auth/*` — login, logout, forgot/reset password, change password, refresh, dt-exchange, spv-exchange, invite-info, accept-invite
- `/api/me`, `/api/me/profile` — current user info & UI prefs
- `/api/seats/*` — invite, edit, deactivate, admin-toggle, reset-password (admin only)
- `/api/firm` — firm settings, pipeline stages, tags
- `/api/contacts` + `/api/contacts/:id` + `/api/contacts/:id/stage`, `/api/contacts/import`, `/api/contacts/export.csv`
- `/api/conflict-check`
- `/api/companies`
- `/api/interactions`
- `/api/matters` + `/api/matters/:id/rates`
- `/api/time`
- `/api/invoices` + `/api/invoices/:id/pdf` + `/api/invoices/:id/status`
- `/api/trust`
- `/api/dashboard`
- Public: `/api/contacts/export`, `/api/staff/export`
- `/api/stream` (reserved; SSE not yet wired to UI)

### Invariants

- Time entries with `status = 'billed'` are locked (can't be edited/deleted except by admin). If an invoice is voided, its time entries are released back to `draft`.
- Trust ledger is append-only. "Delete" posts a reversing entry rather than hard-deleting, to preserve IOLTA audit trail.
- `owner_email` on contacts is lowercased on write. Staff role can only see/edit contacts where `owner_email = their email`.
- Privileged contacts (`privilege = 1`) are still visible to everyone at or above Secretary rank — the flag is informational, not access-gating. If stricter confidentiality is needed later, extend `visibleContactWhere()`.

## Deployment

See `DEPLOY.md` for the Render + Namecheap DNS walkthrough.
