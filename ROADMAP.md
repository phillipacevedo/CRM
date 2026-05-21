# CRM Roadmap

Based on a structural audit of `app.html` and `server.js` as of April 2026.
Ordered by phase: quick wins first, then workflow depth, then larger features.

---

## Phase 1 — Quick Wins ✅ COMPLETE

### 1.1 Empty-state action buttons ✅
- Expenses empty state → "Record an expense" button (or hint to create a matter first)
- Time list/month view empty state → "+ Log time" button for users with `logTime` cap
- Matters tab empty state → "+ New matter" button

### 1.2 Cross-module links ✅

| From | Fix shipped |
|------|------------|
| Invoice detail | `client_name` → `openContact(client_contact_id)` |
| Invoice detail | `matter_name` / matter ID → opens matter detail |
| Matter detail | "Invoices" mini-table added (below rates section, billing-cap users only) |
| Contact detail | "Trust ledger" button in footer (clients + billing-cap users) navigates to Trust tab pre-filtered |
| Time entry — Status column | Billed entries show badge + "Invoice ↗" link to `openInvoiceDetail` |

### 1.3 Permission hint in sidebar ✅
Restricted tabs (Time, Expenses, Invoices, Cashflow, Trust) now render for all users but appear dimmed (`.nav-locked` — 45% opacity, non-clickable) with a tooltip "Requires [cap] access". No navigation to a permission wall.

### 1.4 Invoice status confirmation ✅
Void button now requires: "Void this invoice? This cannot be undone. Billed time entries will be released back to draft." Sent/Paid remain single-click (low stakes).

### 1.5 Interaction editing from contact detail ✅
- Added `PUT /api/interactions/:id` server route (author or admin only)
- `openInteractionForm` now accepts an optional `existing` interaction — pre-fills all fields and switches modal title / save label
- Each timeline item has an edit pencil (✎) that opens the form pre-filled
- Edit modal includes a Delete button with confirmation

---

## Phase 2 — Workflow Depth (1 week each)

### 2.1 Generate invoice shortcut path ✅
- **Matter detail footer** — "Generate invoice" button (billing-cap users, existing matters only). Confirms, calls `POST /api/invoices` with the matter pre-set, toasts, navigates to Invoices tab.
- **Time entries bulk toolbar** — when all selected draft-billable entries share a single matter, a "Generate invoice" button appears in the bulk toolbar (before Delete). Clicking it invoices that matter directly and clears the selection.

### 2.2 Contact form cleanup ✅
Reorganized `openContactForm` from a flat 20+ field list into three sections:
- **Always visible** — type, owner, name, email, phone, title, company, next action + date, pipeline stage, tags (~10 fields)
- **Client details** (`<details>`, auto-open when editing a client) — client since, DOB, tax ID, billing increment, originating attorney + split %, billing attorney, main contact for entity clients
- **More details** (`<details>`, auto-open when editing a contact with any of those fields populated) — secondary email/phone, industry, preferred contact, address, mailing address, LinkedIn, notes, privilege flag

Fields and `name` attributes are unchanged — save handler required no edits.

### 2.3 Unsaved-changes guard ✅
Added `_modalDirty` flag (module-level, next to `_modalPreviousFocus`):
- Reset to `false` in `openModal`; set to `true` on any `input` or `change` event inside the modal
- Reset to `false` in `closeModal`
- Escape key, overlay click-outside, and sidebar `navigate()` each confirm "Discard unsaved changes?" before proceeding when the flag is set

### 2.4 Trust-destination payment completion
The Stripe webhook handler logs a warning and stops at the trust ledger write (server.js, marked "step 3 not implemented"). Complete the flow:
- On `charge.succeeded` where `destination = trust`, automatically post a `trust_ledger` deposit entry
- Match `contact_id` from invoice → contact chain
- Add a `reconciled_payment_id` back-link so the ledger entry is traceable to the payment

This is the only known data-integrity gap in the current app.

### 2.5 Filter persistence ✅
Audit found most tabs already persisted filters via `viewState` or `profile.*View`. Two real gaps fixed:
- **Contacts**: added `sort`/`dir` to viewState initialization; added a `#contacts-clear` slot to the filter bar that `applyContactFilters` populates with a red "× Clear filters" button whenever `search` or `type` is non-default
- **Clients**: same — `#clients-clear` slot, "× Clear" button appears when search is active
- Both buttons reset the relevant viewState keys and call `navigate()` to rebuild the view clean

---

## Phase 3 — Feature Additions (2–4 weeks each)

### 3.1 Bank reconciliation UI ✅
Added "Reconciliation" sub-tab to Cashflow. Bank-agnostic design — two sync paths:

**Mercury auto-sync** (`POST /api/bank/sync`): fetches transactions from both operating and trust accounts using stored Mercury credentials, upserts into `bank_transactions` with incremental date tracking via `mercury_sync_state`. "Sync Mercury" button in the panel header.

**OFX/QFX file import** (`POST /api/bank/import`): client-side `parseOFX()` handles both SGML and XML OFX variants (US Bank, Chase, Wells Fargo, etc.). User selects operating or trust account role on import. Duplicate-safe (`ON CONFLICT DO NOTHING` on FITID-based IDs).

**Reconciliation UI**: table of bank transactions (unreconciled by default, toggle to show all). Each row shows date, description, amount (green/red), account role, and reconciliation status. "Match" button opens an inline payment picker showing unreconciled invoice payments sorted by amount proximity. One click matches; "Clear" unmatches. Backed by `PATCH /api/bank/transactions/:id/reconcile` and `/unreconcile`.

Added `source TEXT DEFAULT 'mercury'` column to `bank_transactions` to distinguish Mercury vs. OFX-imported rows.

### 3.2 Matter-level billing dashboard ✅
Added `renderMatterBillingSummary(wrap, matter)` — rendered at the top of the matter detail modal (before rates, before invoices) for billing-capable users. Fetches time entries, invoices, trust ledger, and expenses in parallel, then shows a 4-stat grid:
- **Unbilled WIP** — draft billable time (hrs × rate) + draft billable expenses (with markup); sub-line shows entry/expense count
- **Outstanding** — open invoice balances (draft + sent, net of write-downs and partial payments)
- **Collected** — sum of `amount_paid` on non-void invoices; sub-line shows paid invoice count
- **Trust held** — net trust ledger balance for this matter; colored red if negative

### 3.3 Custom expense categories ✅
Added "Expense categories" card to Settings → Firm (parallel to pipeline stages editor): admins edit a monospace textarea (`id | label` format, one per line), saved to `firm_data.expenseCategories` via `PUT /api/firm`. `GET /api/firm` now returns `expenseCategories`. The expense form reads `state.firm.expenseCategories` when available and falls back to the hardcoded 8-item `EXPENSE_CATEGORIES` default for firms that haven't customized yet.

### 3.4 Contact deduplication ✅
- **Warn on save**: before `POST`/`PUT /api/contacts`, the form calls `GET /api/contacts/dedup-check?email=&excludeId=`. If another contact with that email exists, a confirm dialog warns the user (non-blocking — they can save anyway).
- **Find Duplicates tool**: new card in Settings → Firm with a "Find duplicates" button. Calls `GET /api/contacts/duplicates` (groups contacts by shared email). Each duplicate group renders with a "Merge into [Name]" button per contact. Merge calls `POST /api/contacts/:primaryId/merge/:otherId`, which transfers all interactions, matters, invoices, and trust ledger entries to the primary then deletes the secondary.

### 3.5 Origination split report ✅
Added "Origination" sub-tab to Cashflow. Calls `GET /api/reports/origination`, which groups clients by `originating_attorney_email`, computes `fees_billed × origination_split_pct / 100` per client, and aggregates by attorney. Panel shows a 3-stat summary (attorney count, total billed, total credit) and a per-attorney table: client, split %, fees billed, collected, and credit share.

---

## Phase 4 — Larger Initiatives (1 month+)

### 4.1 DealTracker matter sync ✅
**Subscription gate:** Added `dt_subscriber` boolean to `users` table. Admin toggles it per user in Settings → Team (Edit modal). DT subscriber users show a "DT" badge in the team table. Only DT subscribers see the DT linking UI in the matter form; non-subscribers get a hidden input that preserves any existing link.

**Matter form DT field (DT subscribers only):**
- Unlinked: "Link to DT matter" button → fetches `/api/dt/matters` (DT public export) → inline searchable list → click to link
- If DT is unreachable: falls back to a manual ID text input
- Linked: shows DT matter name, stage, status badges; "Sync" button calls `POST /api/matters/:id/dt-sync` to refresh cached data; "Unlink" clears the link

**Server:**
- `dt_subscriber INTEGER DEFAULT 0` migration on `users`; `dt_data TEXT` migration on `matters`
- `GET /api/me` and `GET /api/seats` return `dtSubscriber`; `PUT /api/seats/:email` accepts `dtSubscriber`
- `POST /api/matters/:id/dt-sync` — fetches DT public export, finds matching matter by ID, caches JSON in `dt_data`

### 4.2 Invoice layout editor: block add/remove ✅
The current layout editor lets users reposition and resize existing blocks but not add new ones or delete unwanted ones. Extend it to support:
- Add a custom text block (firm tagline, payment instructions)
- Toggle visibility of optional blocks (e.g., hide the "Hours × Rate" breakdown for flat-fee clients)
- Persist block list alongside existing label styles in `invoice_layout`

**Shipped:** "Blocks" button in the layout editor toolbar opens a slide-in panel with visibility toggles for 5 sections: Professional Services detail (page 2), Timekeeper summary (page 2), Costs page (page 3), Wire/ACH instructions (page 4), and Custom text block (page 1). Custom text block is a multi-line contenteditable div on page 1 (between billing summary and payment note) — hidden by default, shown once enabled. Visibility state persisted as `hiddenBlocks[]` in `firm.settings`; the PDF renderer honors all toggles. Custom text content stored as `labels.customTextBlock`.

### 4.3 Bulk time/expense import ✅
Large matters accumulate time from multiple attorneys. Support a CSV import on the Time tab (parallel to contact CSV import) with columns: `matter_name`, `date`, `description`, `minutes`, `user_email`, `billable`. Show a preview table with validation errors before committing.

**Shipped:** "Import CSV" button on Time tab (all `logTime` users). Modal accepts file upload or paste. Required columns: `matter_name`, `date` (YYYY-MM-DD), `minutes` (or `hours`). Optional: `description`, `user_email` (honored for `manageBilling` users only), `billable` (yes/no, default yes). Preview table shows per-row validation with color-coded status before committing. Server: `POST /api/time/import` — resolves matters by `id` (client-resolved), inserts in a transaction, returns `{ inserted, skipped, errors }`.

### 4.4 Email-linked interaction logging ✅
When an outgoing email is BCC'd to the logging address, an inbound email webhook auto-creates an interaction log entry for every matching CRM contact.

**Shipped:** `POST /api/webhooks/inbound-email` — public webhook endpoint secured by `X-Webhook-Secret` header (or `?secret=` query param). Normalizes fields from Mailgun (`sender`/`body-plain`), SendGrid (`from`/`text`), and Postmark (`From`/`TextBody`). Extracts all email addresses from From/To/Cc, looks up matching contacts, inserts a `kind='email'` interaction per match, and touches `last_activity_at`. Returns `{ matched, contacts[] }`. Requires `INBOUND_EMAIL_SECRET` env var (returns 503 if unset). Optional `INBOUND_EMAIL_ADDRESS` env var is surfaced in `GET /api/firm` and shown in the Settings → Firm "Inbound email logging" card with copy buttons for both the BCC address and webhook URL, plus per-provider setup instructions (Mailgun/SendGrid/Postmark).

---

## Phase 5 — Polish & Collections (next up)

The core is solid. Phase 5 fills the gaps that matter most for a working law firm: collecting money, managing deadlines, and communicating without leaving the CRM.

### 5.1 AR aging report ✅
Already shipped prior to Phase 5 write-up. `GET /api/reports/ar-aging` buckets open `sent` invoices by days since issuance (0–30, 31–60, 61–90, 90+), computes per-row balance net of payments, and returns bucket totals + a full row list sorted by days overdue. `renderCashflowAgingPanel` is the second sub-tab in Cashflow (after Activity), supports the same date/client/matter filters as the rest of the tab.

### 5.2 Outbound email from contact view ✅
"✉ Send email" button appears in the contact Activity section when the contact has an email address, the user has `editContacts`, and SMTP is configured (`state.firm.smtpConfigured`). Opens `openEmailCompose` modal with To (pre-filled), CC, Subject, Message fields. Server: `POST /api/contacts/:id/email` — sends via nodemailer (from firm address, replyTo = sender's CRM email), then inserts an `email` interaction and touches `last_activity_at` in one step. Returns 503 if SMTP not configured, 502 on SMTP delivery failure. `smtpConfigured` added to `GET /api/firm` response.

### 5.3 Matter document attachments ✅
New `matter_documents` table (matter_id, firm_id, filename, mime_type, size, data BLOB, uploaded_by). Four routes under `GET|POST /api/matters/:id/documents` and `GET|DELETE /api/matters/:id/documents/:docId`. Accepted types: PDF, Word (.doc/.docx), Excel (.xls/.xlsx), plain text, JPEG/PNG/GIF/WebP. Max 10 MB. `renderMatterDocuments` section added to the matter detail modal (below invoices, for all `editContacts` users). File picked via hidden `<input type="file">`, read as base64 DataURL client-side, POSTed as JSON. Documents list shows filename (inline view link), size, uploader email, date, and Delete button (uploader or admin only).

### 5.4 Payment reminder emails ✅
**Invoice detail:** "Send reminder" button appears in the footer when `status = 'sent'`, balance > 0, `manageBilling`, SMTP configured, and client has an email. Confirms before sending. Server: `POST /api/invoices/:id/reminder` — validates status/balance/email, composes a professional reminder (invoice #, issued, due, balance, firm phone/email), sends via nodemailer, logs as an `email` interaction on the contact. Returns 503 if SMTP unconfigured.

**Bulk reminders:** "Send reminders" extra action in the Invoices selection toolbar (SMTP + `manageBilling` gated). Filters selection to `sent` invoices, confirms, fires `/reminder` for each in sequence, reports sent/failed counts. `selectionToolbar` extended to accept `extraActions: [{label, onclick}]` rendered between Export and Delete.

### 5.5 Task / deadline tracking on matters ✅
New `matter_tasks` table (matter_id, firm_id, description, due_date, assigned_to, status open|done, created_by). Four routes: `GET|POST /api/matters/:id/tasks`, `PATCH /api/matters/:id/tasks/:taskId` (any field), `DELETE /api/matters/:id/tasks/:taskId` (creator or admin). Bonus: `GET /api/tasks/mine` returns open tasks assigned to the current user across all matters (used by dashboard widget).

**Matter detail:** "Tasks" section (above Documents, for all `editContacts` users). Inline add form with description, due date picker, and assignee select (populated from team roster). Tasks listed with checkbox to toggle open/done, description, due date (red if overdue), assigned email, and delete button. Open tasks float above done tasks; done tasks are 50% opacity.

**Dashboard:** "My open tasks" widget (below overdue/week grid, for `editContacts` users). Shows tasks assigned to the current user sorted by due date. Each row shows description, matter name, client name, and due date (red if overdue). Clicking navigates to the matter detail.

---

## Phase 6 — Recurring Revenue, Compliance, Quality of Life (next up)

Phases 1–5 closed the core workflow gaps. Phase 6 focuses on three themes: making recurring revenue easy to run, hardening the firm's compliance posture (trust funds + audit trail + auth), and removing friction from everyday use.

### 6.1 Recurring invoices + trust auto-replenishment ✅
**Schema:** added `billing_schedule TEXT` (JSON), `trust_min_balance REAL DEFAULT 0`, `trust_replenish_to REAL` columns on `matters`.

**Server:**
- `createRecurringInvoice(firmId, matter, amount, description, notes)` — single-line flat-fee invoice (no time/expense sweep, intentionally separate from manual `POST /api/invoices` so attorneys' time on the same matter still bills normally).
- `runRecurringForMatter()` — for one matter, generates a scheduled invoice if `next_run_at <= today` and advances `next_run_at` by month/quarter; separately checks trust balance and creates a "Trust replenishment" invoice for the shortfall when below floor (dedup via `notes LIKE 'Trust replenishment%'` + `status IN ('draft','sent')` so consecutive cron runs don't pile up duplicate replenishments).
- `runRecurringBilling()` — sweeps all active matters with a schedule or trust floor. Scheduled hourly via `scheduleRecurringBilling()` (idempotent: same-day re-runs are no-ops because `next_run_at` advances).
- `POST /api/matters/:id/billing-schedule/run-now` — manual trigger (`manageBilling` gated).
- `PUT /api/matters/:id` extended to accept `billingSchedule` (JSON), `trustMinBalance`, `trustReplenishTo`.

**UI:** "Recurring billing" card on the matter detail modal (`manageBilling` users). Active toggle, frequency (Monthly/Quarterly), day of period (1–28, clamped to avoid Feb skip), amount, next run date, invoice line description. Trust replenishment subsection with floor + optional replenish-to target. Save and "Run now" buttons.

**Edge cases:** voided invoice in current cycle — `next_run_at` already advanced; manual "Run now" can regenerate. Matter closed mid-cycle — sweep filters `status = 'active'`. Schedule edit mid-cycle — user provides the new `next_run_at` directly. Email-on-generate deferred (SMTP wiring can be added by calling existing nodemailer transport).

### 6.2 Client portal (read-only, magic-link first)
Lowest-cost version that still saves real time: per-invoice tokenized share link, no client account required.
- `invoice_share_tokens` table: `(token, invoice_id, expires_at, revoked_at)` — token is a 32-byte URL-safe random string
- `POST /api/invoices/:id/share-link` (billing-cap) returns the URL + expiration
- Public route `GET /portal/invoice/:token` renders a read-only HTML view (mirrors the PDF layout) + a "Download PDF" link + (once Stripe lands) a Pay button that hands off to the existing Stripe Checkout session
- Invoice detail footer: "Copy share link" button next to "Send reminder"
- Future expansion path: same token table can serve matter-level portals (documents, trust balance) without restructuring

### 6.3 Global search
The app is now big enough that menu-hunting is the main friction.
- SQLite FTS5 virtual tables shadowing `contacts`, `matters`, `interactions`, `invoices` — populated on insert/update via existing routes
- Cmd-K opens a search palette overlay; results grouped by type with keyboard nav; Enter routes to the relevant detail modal
- Scope respects existing `visibleContactWhere()` and matter visibility — Staff doesn't see contacts they don't own through search either

### 6.4 Audit log (trust + billing + admin actions) ✅
**Schema:** `audit_log (id AUTOINCREMENT, firm_id, actor_email, action, entity_type, entity_id, before_json, after_json, at)` with indexes on `(firm_id, at DESC)`, `(firm_id, entity_type, entity_id)`, `(firm_id, actor_email)`. Append-only — same invariant as `trust_ledger`.

**Server:** `logAudit(req, action, entityType, entityId, before, after)` helper wraps the routes that matter — never throws, logs on failure so audit gaps surface. Wired into:
- `PATCH /api/invoices/:id/status` — `invoice.status_change` (skipped when status unchanged)
- `PUT /api/time/:id`, `DELETE /api/time/:id` — `time_entry.admin_override` / `admin_delete` (only when admin acts on someone else's entry or on a billed/locked entry)
- `PUT /api/matters/:id/rates` — `matter.rates_change` (full before/after rate list)
- `DELETE /api/trust/:id` — `trust.reversal` (with reversal entry id)
- `PUT /api/seats/:email`, `PATCH /api/seats/:email`, `DELETE /api/seats/:email` — `seat.update` / `seat.admin_toggle` / `seat.deactivate`
- `PUT /api/firm/payments` — `payments.config_update` (secrets redacted to `[set]`/`null`)

**Read routes:** `GET /api/audit-log` (paginated JSON; filters: actor, action, entityType, entityId, from, to; returns distinct actions/entityTypes for filter dropdowns) and `GET /api/audit-log.csv` (10k row cap, same filters). Both `manageFirm` gated and `firm_id`-scoped.

**UI:** Settings → Firm → "Audit log" card (admin only) with filter row (actor email substring, action dropdown, entity-type dropdown, from/to dates), Apply/Clear/Export CSV buttons, paginated table showing time/actor/action/entity/before+after JSON (each in a collapsible `<details>`), and Prev/Next pager.

### 6.5 Automated nightly DB backup ✅
**Server:** `runBackup()` uses `db.backup()` to write `./data/backups/crm-YYYY-MM-DD.db` (overridable via `BACKUP_DIR`). Retention keeps newest `BACKUP_RETAIN` (default 14). Hourly idempotency tick: only writes today's stamped file if it doesn't exist yet. Routes: `GET /api/admin/backups`, `POST /api/admin/backups/run` (manual, timestamp-suffixed filename so it doesn't collide with the daily), `GET /api/admin/backups/:filename/download`, `DELETE /api/admin/backups/:filename`. All `manageFirm` gated. S3/R2 upload deferred — local backups + manual downloads cover the immediate "one bad deploy from disaster" risk.

**UI:** "Backups" card in Settings → Firm. Shows last successful backup time and last error if any. Table of backup files with size, created date, Download/Delete buttons. "Backup now" + "Refresh" buttons.

### 6.6 Two-factor auth (TOTP)
A firm holding trust funds should offer this even if not required.
- `users.totp_secret` (encrypted with `PAYMENTS_KEK` or a dedicated `AUTH_KEK`), `totp_enabled` boolean
- `otplib` for verification, QR generation via `qrcode` (server-side, no extra dependency on a renderer)
- Profile settings: "Enable 2FA" → show QR + manual key → confirm with a 6-digit code before flipping `totp_enabled`
- Login flow: after password success, if `totp_enabled`, prompt for code before issuing the JWT
- Admin override: admin can disable 2FA for a seat (logged to audit log) in case a user loses their device

### 6.7 Calendar feed (iCal)
Surface deadlines without building an integration.
- `GET /api/calendar/:userToken.ics` — signed per-user URL, returns an ICS feed of (a) `matter_tasks` assigned to that user where `status='open'`, (b) interactions with `next_action_date` set
- Profile settings: "Calendar feed" card with the URL + copy button + revoke/regenerate
- Each task event includes matter name + client in the description and a deep link back to the matter detail

### 6.8 Document templates with merge fields
Engagement letters and fee agreements get generated over and over.
- `document_templates` table per firm: name, body (HTML or a simple `{{client.name}}`-style placeholder DSL), output_type (pdf/html)
- Available merge fields: `client.*`, `matter.*`, `firm.*`, `today`
- Settings → Firm → "Document templates" editor (admin)
- Matter detail: "Generate document" → pick template → preview → download PDF (reuses the `pdfkit` pipeline) or copy HTML

### 6.9 Persistent time-entry widget ✅
Shipped earlier as a topbar widget (better visibility than a bottom-right floater) with multi-timer support. Server-backed `timers` table is the source of truth — survives page reloads *and* device switches. This pass added a localStorage fallback (`crm_timers_cache_v1`): every successful timer fetch/mutation snapshots the list with `cachedAt` so `initTimer()` can display cached running clocks (with elapsed-since-cache advanced) when the server is briefly unreachable during a reload. Cache is cleared on logout. Toast tells the user when they're on cached data and again when reconnected.

---

## Phase 7 — Multi-tenant SaaS (next major initiative)

Promoting "multi-firm support" out of the parking lot. The schema is already `firm_id`-scoped end-to-end and per-firm secret encryption exists (`PAYMENTS_KEK` + `firm_payment_config`), so the gap is mostly tenant lifecycle, routing, and self-service billing — not data-model rework.

**Locked architectural decisions** (see `SAAS_PLAN.md` for the full discussion):
- **Routing:** subdomains only (`acme.yourapp.com`). Wildcard DNS + wildcard Let's Encrypt cert. Custom domains deferred to "later premium tier" — not part of v1.
- **Database:** shared SQLite (current state). Ceiling is ~50–100 firms; revisit (likely Postgres) once contention bites. Per-tenant SQLite rejected — Postgres is the better destination for that isolation pattern.
- **Hosting:** stay on Render. Cost delta vs. a VPS doesn't justify the ops overhead at single-digit-tenant scale.

**Still open** (decide before Phase 7B):
- **Billing model** — per-user/month vs. flat tier vs. feature tiers vs. hybrid
- **Your-firm strategy** — whether your firm becomes Tenant 1 with DT/SPVT/LB integrations gated to your `firm_id` only, or whether you fork the codebase

### 7.A Per-tenant connections (1–2 days)
The smallest useful slice — extends the existing `firm_payment_config` encryption pattern to email. Useful even if you never go SaaS.
- `firm_email_config` table: encrypted SMTP host/port/user/pass/from per firm (reuse `PAYMENTS_KEK` or introduce `EMAIL_KEK`)
- Replace the module-level `nodemailer.createTransport()` singleton with `getTransporterForFirm(firmId)` that builds (and caches) a transport from decrypted config
- Settings → Email tab with test-connection button (mirrors the Payments tab pattern)
- Per-tenant inbound email: route on recipient subdomain (e.g. `log@acme.crmapp.com` → firm Acme) instead of the global `INBOUND_EMAIL_ADDRESS` env var

### 7.B Tenant signup + subdomain routing + your billing (3–5 days)
- Public signup page (collects firm name, admin email, password, slug); current landing is login-only
- Email-verification gate before firm is created
- Trial period (14 days) — `firms.trial_ends_at`, `subscription_status` columns
- Subdomain routing middleware: `req.hostname.split('.')[0]` → `firms.slug` lookup → set `req.tenant`; login/signup pages read tenant slug from the URL
- Wildcard DNS (`*.yourapp.com` → Render) + wildcard LE cert (Render supports this on paid plans, or use Caddy in front)
- **Your billing of firms**: separate Stripe integration from the existing per-firm "Stripe for collecting from clients." Tenants pay you via a Stripe Checkout subscription. Webhook → `firms.subscription_status` (active / past_due / canceled). Past_due puts the firm in read-only.

### 7.C Hardening + super-admin (1 week)
- **Query audit**: grep every `db.prepare()` for missing `firm_id` filters. One miss = cross-tenant data leak. Build a test that runs as Firm A and asserts it cannot see Firm B's rows for each tenant-scoped table.
- **Per-tenant backups**: extend the Phase 6.5 backup helper to produce per-firm exports (a firm holding IOLTA may need to extract their data for a compliance audit). Or: keep the single shared backup and add an `/api/admin/export-firm/:id` route that produces a SQLite file containing only that firm's rows.
- **Super-admin panel**: tab visible only to a hardcoded super-admin email (`SUPER_ADMIN_EMAIL` env var). Lists all firms with subscription status, last login, user count, MRR. Suspend / unsuspend / impersonate / delete.
- **ToS + Privacy Policy + DPA**: required before taking real customers. Templates exist (Termly, iubenda); plug in firm name dynamically.
- **Cross-app integrations**: DT/SPVT/LB endpoints today assume a single firm. Decide per the "your-firm strategy" question — most likely gate them to your firm's `firm_id` only.

### 7.D Custom domains (deferred premium tier)
Not part of v1. When you have tenants asking: add `firm_domains` table mapping hostnames → firm_id, verification flow (DNS TXT record), and either Caddy in front (auto-cert per domain) or Cloudflare for SaaS ($0–$2/hostname/mo). ~1 day on top of 7.B.

---

## Deferred / Parking Lot

- **Partial refund flow** — Stripe webhook handler has a `// revisit` comment; defer until manual refund UI lands (payments step 6)
- **Custom contact/matter fields** — `firm_data` schema could support arbitrary field definitions; high effort for uncertain payoff at single-firm scale
- **Mobile-native layout** — current responsive CSS handles tablets well but small phones are serviceable at best; low priority for a desktop-primary tool

---

## Suggested Sequencing

```
April 2026       Phase 1 ✅ complete
April–May 2026   Phase 2.1–2.3, 2.5, 3.2 ✅ complete (invoice shortcut, form cleanup, dirty guard, filter persistence, matter billing dashboard)
June 2026        Phase 2.4 (trust payment completion — deferred until payments go live)
May 2026         Phase 3.1, 3.3–3.5 ✅ complete (bank reconciliation, custom expense categories, contact dedup, origination report)
April–May 2026   Phase 4.1 ✅ complete (DealTracker matter sync with per-user subscription gate)
May 2026         Phase 4.3 ✅ complete (bulk time/expense import via CSV)
May 2026         Phase 4.2 ✅ complete (invoice layout block visibility + custom text block)
May 2026         Phase 4.4 ✅ complete (email-linked interaction logging via inbound webhook)
May 2026         Phase 5.1 ✅ already shipped (AR aging report)
May 2026         Phase 5.2 ✅ complete (outbound email from contact view)
May 2026         Phase 5.3 ✅ complete (matter document attachments)
May 2026         Phase 5.4 ✅ complete (payment reminder emails + bulk send)
May 2026         Phase 5.5 ✅ complete (matter task tracking + dashboard widget)
June 2026        Phase 2.4 (trust payment completion — revisit once Stripe goes live)
May 2026         Phase 6.5 ✅ complete (automated nightly DB backup)
May 2026         Phase 6.9 ✅ complete (time-entry widget — localStorage fallback layered on existing topbar timer)
May 2026         Phase 6.1 ✅ complete (recurring invoices + trust auto-replenishment)
May 2026         Phase 6.4 ✅ complete (audit log: helper + 6 mutating routes + admin UI + CSV export)
July 2026        Phase 6.6 (2FA — second half of compliance bundle)
July 2026        Phase 6.2 (client portal v1: tokenized invoice share links)
Aug  2026        Phase 6.3, 6.7 (global search, calendar feed — quality of life)
Aug  2026        Phase 6.8 (document templates)
TBD              Phase 7.A (per-tenant SMTP + inbound email routing — useful even if SaaS slips)
TBD              Phase 7.B (tenant signup + subdomain routing + your Stripe billing)
TBD              Phase 7.C (hardening: query audit, per-tenant backups, super-admin, ToS/Privacy)
Later            Phase 7.D (custom domains as premium tier)
```
