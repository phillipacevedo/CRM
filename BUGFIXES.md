# CRM Bug Fixes & Improvements

Tracking list from code review on 2026-04-23. Check off items as they're resolved.

---

## Backend (`server.js`)

### Critical — fix first

- [x] **1. Email casing inconsistency** (`server.js:1878-1882`, `1434`, `1519`, `1581-1582`) ✅ 2026-04-23
      Normalized `req.user.email` to lowercase+trim in `authRequired` middleware (`server.js:881-883`).
  - `owner_email` is lowercased on write, but `req.user.email` from the JWT isn't normalized on read.
  - Impact: A user whose email was stored mixed-case sees no contacts/time entries.
  - Fix: Normalize at token creation **or** lowercase `req.user.email` in auth middleware on every request.

- [x] **2. PDF routes don't handle client disconnect** (`server.js:3014`, `3096`) ✅ 2026-04-23
      Added `doc.on('error', ...)` (logs + closes response) and `res.on('close', () => doc.destroy())`
      to both the invoice PDF route and the invoice preview route, so a client disconnect stops the
      PDF writer instead of leaking memory/fd.

- [x] **3. Invoice creation doesn't verify time-entry locking succeeded** (`server.js:2035-2049`) ✅ 2026-04-23
      The UPDATE statements on both `time_entries` and `expenses` now include `AND firm_id = ? AND
      status = 'draft'` so an already-billed row can't be silently rebound. Each UPDATE's `info.changes`
      is checked; a 0 throws inside the transaction (rolls back the whole invoice) and returns a
      409 Conflict with the offending id. This also adds a firm-scoping check that was previously
      missing — a forged time_entry_id from a different firm would have been accepted before.

- [x] **4. Timer-stop doesn't verify matter belongs to firm** (`server.js:3356`, `3359`) ✅ 2026-04-23
      `getTimerById` now accepts a `firmId` arg and scopes the SELECT by `firm_id`, so a timer row
      left over from a prior firm membership can't be acted on. All 9 call sites updated to pass
      `req.user.firmId`. Timer-stop additionally re-validates that `t.matter_id` belongs to the user's
      firm before committing the time_entry (defense-in-depth; the matter could have been moved).

- [x] **5. Migration `try/catch` swallows everything** (`server.js:582-584`) ✅ 2026-04-23
      The catch now only swallows `/duplicate column name/i` errors — anything else re-throws so a
      broken migration fails boot loudly instead of leaving the schema half-applied. After each
      `ALTER TABLE ... ADD COLUMN`, a `pragma_table_info` post-check verifies the column actually
      landed and throws if it didn't. Existing DB boots cleanly under the new checks.

- [x] **6. Void invoice doesn't reset `amount_paid`** (`server.js:2094-2098`) ✅ 2026-04-23
      Status UPDATE now uses `CASE ? WHEN 'paid' THEN total WHEN 'void' THEN 0 ELSE amount_paid END`,
      so voiding always resets `amount_paid` to 0.

### High — fix soon

- [x] **7. Stripe webhook decryption errors are silent** (`server.js:203-206`, `740-747`) ✅ 2026-04-23
      Replaced the swallowing `try/catch/return null` in the per-firm webhook-secret decryption
      loop with a `RECONCILE NEEDED` error log that names the firm id and nudges the admin to
      re-enter the secret in Settings → Payments. If PAYMENTS_KEK gets rotated, webhooks won't
      silently vanish any more.

- [x] **8. Tax rounds twice** (`server.js:2030-2033`) ✅ 2026-04-23
      Invoice create and invoice edit both now keep a `rawSubtotal` (unrounded) and compute tax
      against it. `subtotal` and `tax` are each rounded independently; `total = subtotal + tax`
      uses the rounded values so the UI's "subtotal + tax = total" always reconciles exactly.
      In practice the line amounts are already 2dp so the delta is tiny, but the code's intent is
      now unambiguous and future unrounded-line scenarios are covered.

- [x] **9. Refund amount isn't bounded** (`server.js:828-843`) ✅ 2026-04-23
      `handleChargeRefunded` now clamps the refund to `row.amount` (the original payment) via
      `Math.min`. If the webhook's `amount_refunded` exceeds the original, a warning logs with
      the charge/payment ids. Stripe's API already enforces this, so the clamp is defense-in-depth
      against replayed/mangled webhooks.

- [x] **10. 500 handler on webhooks makes Stripe retry forever** (`server.js:767`) ✅ 2026-04-23
      Handler errors now return 202 with a loud `RECONCILE NEEDED` log that includes the event id,
      firm id, and stack. Signature verification failures still return 400 (those should fail loudly).
      Trade-off acknowledged in code comments: transient DB failures no longer auto-retry, but the
      log makes manual replay straightforward for a single-firm deployment.

- [x] **11. Trust payments are a stub** (`server.js:776-815`) ✅ 2026-04-23
      `handlePaymentIntentSucceeded` now explicitly throws on `destination='trust'` instead of
      silently falling through. Because the webhook handler was recently switched to return 202
      on errors (#10), the throw surfaces a `RECONCILE NEEDED` log line with the payment id —
      payment is already marked succeeded; a human posts the trust_ledger entry manually until
      step 3 ships. The link-creation route hardcodes `destination='operating'`, so no trust
      links can be created from the UI today; the guard protects against future paths or manual
      DB inserts.

- [x] **12. `ownerEmail` vs `originatingAttorneyEmail` normalized differently** (`server.js:1502`, `1508`) ✅ 2026-04-23
      All three contact-write paths (create, update, CSV import) now use `normalizeEmail()` for
      `ownerEmail` instead of raw `.toLowerCase()`. Consistent with how originating/billing attorney
      fields were already normalized, and handles `null`/`undefined` safely. Query-coercion
      callsites (where the helper's null-return semantics would change behavior) left alone.

### Medium — cleanup

- [x] **13. N+1 in PDF invoice outstanding balance** (`server.js:3005-3008`) ✅ 2026-04-23
      Added `idx_invoices_client_status` covering `(firm_id, client_contact_id, status)` — the
      outstanding-balance subquery is now an index-covered scan instead of falling through one of
      the two single-column indexes. Caching at firm level was rejected: invalidation on every
      payment event is fragile for a modest performance win.

- [x] **14. owner_email has no NOT NULL constraint** ✅ 2026-04-23
      Two-part fix without rebuilding the table:
      - **Backfill migration** at boot: any contact with NULL/empty `owner_email` gets
        its `created_by`, falling back to the firm's first active admin. Logs the count.
      - **Write-path guard**: the contact PUT route now does
        `normalizeEmail(b.ownerEmail ?? existing.owner_email) || req.user.email`, so an
        update on a legacy NULL row (or a PUT with no ownerEmail) always lands non-null.
        POST and CSV import were already safe after #12.
      Skipped the schema-level `NOT NULL` — SQLite requires a table rebuild to add it and
      the app-level guard provides the same invariant. Revisit if we add a richer migration
      framework.

- [x] **15. Stack traces in 500 errors** (`server.js:3613-3615`) ✅ 2026-04-23
      Global error handler was already safe — logs stack server-side, returns generic
      `'Internal server error'` to clients. Audited individual 500 responders: the Stripe
      `paymentIntents.create` handler and the `/api/expenses/extract` (Claude receipt OCR) route
      both interpolated raw upstream error messages into the client response, which could leak
      API account fragments or prompt/URL internals. Both now log the full stack to the server
      and return a generic user-facing message. Validation 400s (contact/matter/invoice) still
      surface their intentional user-facing messages — those are safe.

---

## Frontend (`public/app.html`)

### Real bugs users will hit

- [x] **16. View-switch race condition** (`app.html:805-826`) ✅ 2026-04-23
      Added `state._renderVersion` counter + `isStaleRender(v)` helper. `navigate()` bumps the counter
      and passes `v` to each top-level render function, which bails after its initial `await` if a newer
      navigate has superseded it. Settings tab-switch and invoice filter-clear also bump the version.

- [x] **17. Silent save failures on contact/matter forms** (`app.html:1436`) ✅ 2026-04-23
      Restructured contact form, matter form, and change-password save handlers: API errors now log
      to console and `return` (leaving modal open for retry — `api()` already toasted). Post-save
      `navigate()` wrapped in its own try/catch so a navigation bug doesn't look like a save failure.
      **Follow-up:** other save handlers (trust, time, expense, invoice edit) have no try/catch at all
      and could use the same pattern — not urgent because `api()` already surfaces the error, but the
      modal closes and navigates regardless of outcome.

- [x] **18. Date parsing isn't centralized** (`app.html:701`, `1363`, `4318`) ✅ 2026-04-23
      Added `toDateInput(d)` and `todayDateInput()` near the `fmt` helpers. `toDateInput` handles
      YYYY-MM-DD prefixes (the common case) and falls back to `new Date(s)` for full ISO strings,
      so API responses with a time component still produce a valid `<input type="date">` value.
      Replaced scattered `.slice(0,10)` / `new Date().toISOString().slice(0,10)` patterns across the
      contact, time-entry, expense, invoice, and trust forms. Internal date-math helpers in the time
      module left alone (they operate on `Date` objects, not possibly-null strings).

- [x] **19. Toasts overwrite each other** (`app.html:721-727`) ✅ 2026-04-23
      Rewrote `toast()` as a tiny FIFO queue with dedup. Consecutive identical messages collapse
      (so a flurry of "Request failed" from one broken panel shows once, not 10 times); distinct
      messages play sequentially with a short gap between them. Same 2.4s visible time each.

- [x] **20. Spinners have no timeout** (`app.html:811`) ✅ 2026-04-23
      `navigate()` now arms a 15s fallback that replaces the spinner with "Request is taking
      longer than expected. [Retry]" and bumps `_renderVersion` so the late-arriving render is
      discarded on return. Cleared in a `finally` so normal fast renders never see it.

- [x] **21. Form serialization picks up all `[name]` inputs** (`app.html:1419`) ✅ 2026-04-23
      Added a `CONTACT_FORM_FIELDS` Set right above the contact form definition, and the save
      handler now filters by `CONTACT_FORM_FIELDS.has(i.name)` before reading values. If an
      autocomplete or embedded search adds a named input to the modal body, it can't smuggle data
      into the save payload. Adding a new field requires touching the whitelist — intentional, so
      payload contents stay auditable.

- [x] **22. Promise.all without error boundaries** (`app.html:2382`) ✅ 2026-04-23
      `renderExpenses`, `renderInvoices`, and `renderTrust` now attach `.catch(() => [])` (or `{}`
      for object responses) to each fetch in their opening `Promise.all`. A failed secondary fetch
      (e.g. matters) degrades gracefully — the "+New" button loses its dropdown but the primary list
      still renders. `api()` already surfaces the error via toast, so no extra messaging needed.
      **Not touched:** `renderMatterRates` uses an inline side-effect pattern in its `Promise.all`
      that would need a small restructure; it's a sub-component (not a top-level view) and a
      failure already degrades gracefully to an empty rates panel.

### Layout / responsive

- [x] **23. Tables overflow on narrow screens** (`app.html:126`) ✅ 2026-04-23
      Added a `@media (max-width:768px)` rule that sets `table.data { display:block;
      overflow-x:auto; white-space:nowrap }`. No JS changes needed — existing table render
      sites become horizontally scrollable on narrow viewports; desktop layout untouched.

- [x] **24. Kanban forces horizontal scroll on mobile** (`app.html:199`) ✅ 2026-04-23
      Same media query: `.kanban { flex-direction:column; overflow-x:visible; min-height:auto }`
      and `.kanban-col { width:100%; max-height:none }`. `.kanban-cards { max-height:50vh }` keeps
      each stacked column from taking over the whole screen when it has many cards.

- [x] **25. Topbar wrap is ugly** (`app.html:58`) ✅ 2026-04-26
      Added a `@media (max-width:900px)` rule that stacks the topbar as a column,
      drops `margin-left:auto` on `.actions` (it pushes nothing in a column), and
      removes the search's `max-width:420px` so it fills the row when stacked.
      Desktop layout unchanged.

- [x] **26. Modal awkward on short screens** (`app.html:185`) ✅ 2026-04-26
      Inside the existing `(max-width:768px)` block, added
      `font-size:clamp(12px,3vw,13.5px)` on `.modal-body input/select/textarea`
      and `clamp(10px,2.5vw,11.5px)` on `.modal-body label`. Clamp ceilings match
      current desktop sizes (13.5/11.5px) so wider screens are unaffected; the
      floors keep text legible at ~320px.

### Event wiring / state

- [x] **27. Per-row event listeners on table re-render** (`app.html:1262-1294`, `2815`) ✅ 2026-04-23
      Contact table switched to a single delegated click handler on `<tbody>`. Rows carry
      `data-contact-id`; the Edit cell is tagged `data-row-action="edit"` so clicks on it skip
      the row-open. Kills one closure per row (×N rows per render) plus the per-cell
      `stopPropagation` wiring on the mailto link (now handled by an `a[href^="mailto:"]` check
      in the delegate). Matter table and dashboard summaries left alone — tables there are
      always small, so the closure overhead isn't worth the restructure.

- [x] **28. Schedule drag listeners leak on navigate** (`app.html:2739-2863`) ✅ 2026-04-23
      Added a `state._viewCleanups` Set + `registerViewCleanup(fn) → unregister` helpers.
      `navigate()` runs cleanups at the top so a mid-drag nav can't leave stale
      document-level `mousemove`/`mouseup` handlers. All three schedule drag handlers (create,
      move, resize-untimed) register their teardown on mousedown and unregister on mouseup.
      Normal completed drags don't grow the registry; only mid-drag navigations trigger the
      force-release.

- [x] **29. View state scattered across `state._*`** (`app.html:1063`, `1103`, `4368`) ✅ 2026-04-26
      Added `viewState: {}` to the central `state` initializer and migrated the five
      view-scoped fields: `_contactsView` → `viewState.contacts`, `_clientsView` →
      `viewState.clients`, `_timeView` → `viewState.time`, `_trustView` →
      `viewState.trust`, `_settingsTab` → `viewState.settingsTab`.
      **Intentionally left as `state._*`:** `_renderVersion` and `_viewCleanups` are
      navigation control-flow (not per-view UI), `_pendingSearch` is a cross-view
      handoff, and `_users` is a server-data cache. None belong under `viewState`.

- [x] **30. Timer widget late-initializes** (`app.html:839`) ✅ 2026-04-23
      `boot()` now awaits `initTimer()` before calling `navigate('dashboard')`, so the dashboard's
      first render sees a populated `Timer.list`. Previously a slow `/api/timers` fetch meant the
      dashboard could render with an empty timer state and a flash-update when it resolved.

### CSS organization

- [x] **31. Invoice CSS leaks** (`app.html:475-555`) ✅ 2026-04-23
      Audited the concern first: all `.inv-*` rules already use the prefix, and the CSS custom
      properties (`--inv-font`, `--inv-logo-scale`, `--inv-font-scale`, `--inv-accent`) are
      declared on `.inv-editor-body` — NOT `:root` — and set via element-scoped `style.setProperty`
      in `openInvoiceLayoutEditor`. So they don't actually leak when the overlay closes. The real
      risk was maintenance: adding an unprefixed rule inside the invoice block would silently
      become global. Added prominent START/END banner comments delineating the block and documenting
      the scoping invariant, so future changes here stay scoped. Full rename to `.invoice-*` or
      wrapping 87 rules in a parent selector was rejected as churn for no runtime benefit.

- [x] **32. Repeated badge/tag color definitions** (`app.html:142-165`) ✅ 2026-04-23
      Collapsed 14 badge rules into 5 color groups (green/gold/red/blue/gray) + 4 unique badges
      (judge/expert/referral/vendor). `.badge-client`, `.badge-status-active`, `.badge-status-paid`
      now share one rule. Adding a new badge means picking the right color group or defining a
      new unique rule — no more near-duplicate declarations to keep in sync.

- [x] **33. Button CSS specificity cascade** (`app.html:76-106`) ✅ 2026-04-26
      Wrapped `.btn-cluster` in `:where()` on the descendant rules so they sit at
      single-class specificity (0,1,0 / 0,1,1) — matching `.btn-ghost:hover` etc.
      instead of escalating via the descendant-selector boost. Behavior is
      identical because source order still favors the cluster rules; the win is
      that any future per-button override only needs a single modifier class
      instead of a specificity arms race.

### Accessibility / polish

- [x] **34. No back/forward history** (`app.html:805-826`) ✅ 2026-04-23
      `navigate()` now `pushState`s the view to `?view=xxx` on a distinct view change; same-view
      refreshes (save, retry) and popstate-driven navs skip the push via a `skipPush` opt, so
      history doesn't fill with no-ops. `boot()` honors an initial `?view=` param (validated
      against `NAV_ITEMS` + capability), and `popstate` drives `navigate(..., { skipPush: true })`.
      Users can now deep-link to `/app?view=contacts` and browser back/forward works as expected.

- [x] **35. Modal focus trap missing** (`app.html:743`) ✅ 2026-04-23
      `openModal` now stores `document.activeElement`, focuses the first focusable in the modal,
      and installs a document-level `keydown` listener that traps `Tab`/`Shift+Tab` inside the
      modal. `closeModal` removes the listener and restores focus to wherever it was before the
      modal opened. Escape also closes the modal now. Added `aria-label="Close"` on the ×
      button as a bonus (partial credit toward #36).

- [x] **36. Icon-only buttons lack `aria-label`** (`app.html:640-642`, `2815`) ✅ 2026-04-23
      All 13 `.icon`-class SVGs now carry `aria-hidden="true" focusable="false"` (bulk perl
      substitution across nav, topbar, and icon library). The logout button has visible "Log out"
      text alongside its SVG, so the icon itself is correctly marked decorative rather than given
      a redundant aria-label. Also added `aria-label="Search contacts, companies, notes"` to the
      global search input and `aria-label="Close"` to modal × (from #35). Drag-to-schedule rows
      already expose click-to-edit fallback via their buttons; not touched — a full keyboard
      replacement for drag would be its own feature.

- [x] **37. Conflict check visual feedback subtle** (`app.html:294`) ✅ 2026-04-23
      `.cc-result` now has a 6px (up from 3px) gold left border, inset 1px ring, and soft drop
      shadow — reads clearly against the gold bg. Hover state darkens the border and deepens
      the shadow. Since the result card is only rendered when `hits > 0`, this is a
      load-bearing visual for "potential conflict" — worth making unmissable.

- [x] **38. Global search debounce wrong** (`app.html:847-853`) ✅ 2026-04-23
      `onGlobalSearch` now short-circuits when the user is already on the contacts view: updates
      `state._contactsView.search` in place and re-runs the filter, skipping the full
      `navigate()` → `/api/contacts` re-fetch. Clearing the search input also resets the filter
      (previously ignored). First-time jump-to-contacts from another view still works the old
      way. Debounce on the input remains 300ms; the core change is what happens after it fires.

---

## Suggested attack order

1. **Email normalization in auth middleware** (#1) — one change, kills a class of silent-visibility bugs.
2. **Render version counter** (#16) — one helper, kills a class of stale-data bugs.
3. **Date helper + centralized API error handler** (#17, #18) — small, pays off across every form.
4. **PDF stream cleanup + invoice row-count check + void reset** (#2, #3, #6) — billing correctness.
5. **Table scroll wrapper + kanban mobile stack** (#23, #24) — one media query, big UX win.
