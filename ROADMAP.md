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

### 4.1 DealTracker matter sync
`matters.dt_matter_id` is schema-ready but has no UI. Build a "Link to DT matter" picker on matter create/edit (calls the existing `/api/dt/matters` proxy). Once linked, sync matter name and status bidirectionally and surface DT-sourced fields (deal stage, counterparty) in a read-only panel on matter detail.

### 4.2 Invoice layout editor: block add/remove
The current layout editor lets users reposition and resize existing blocks but not add new ones or delete unwanted ones. Extend it to support:
- Add a custom text block (firm tagline, payment instructions)
- Toggle visibility of optional blocks (e.g., hide the "Hours × Rate" breakdown for flat-fee clients)
- Persist block list alongside existing label styles in `invoice_layout`

### 4.3 Bulk time/expense import
Large matters accumulate time from multiple attorneys. Support a CSV import on the Time tab (parallel to contact CSV import) with columns: `matter_name`, `date`, `description`, `minutes`, `user_email`, `billable`. Show a preview table with validation errors before committing.

### 4.4 Email-linked interaction logging
When SMTP is configured, add an optional BCC address (e.g., `log@crm.phillipacevedo.com`) that, when included on an outgoing email, auto-creates an interaction log entry. Requires an inbound email parser (Mailgun inbound routes or similar) but would close the loop between communication and the CRM record without manual entry.

---

## Deferred / Parking Lot

- **Multi-firm support** — schema is ready (`firm_id` everywhere) but single-firm deployment is the target for now; revisit only if the app is offered as SaaS
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
Q4 2026+         Phase 4 as needed
```
