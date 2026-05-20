# SaaS Plan & Architectural Decisions

Working document for the multi-tenant SaaS direction. Captures the decisions made, the options considered, the reasoning, and the open questions still to resolve.

Date opened: 2026-05-19.

---

## TL;DR

The CRM is already ~80% multi-tenant at the schema layer — every tenant-scoped table carries `firm_id`, JWTs include `firmId`, `verifyFirmMembership` middleware gates every route, and per-firm secrets (Stripe/Mercury credentials) are already encrypted via `PAYMENTS_KEK` in `firm_payment_config`. Going SaaS is mostly about adding tenant lifecycle, subdomain routing, and self-service billing — **not** rewriting the data model.

**Locked decisions:**
- Routing: subdomains only (e.g. `acme.yourapp.com`)
- Database: shared SQLite (current state); revisit when write contention bites
- Hosting: stay on Render

**Open decisions** (defer until Phase 7.B planning):
- Billing model (per-user vs. flat tier vs. feature tiers)
- Your-firm strategy (your firm = Tenant 1 vs. fork codebase)

**Phased rollout:** see `ROADMAP.md` Phase 7 — A (per-tenant SMTP), B (signup + billing), C (hardening), D (custom domains, deferred).

---

## Why this discussion happened

Original prompt was about per-tenant SMTP for invoice email auto-send. That widened to "make this a multi-tenant app." Recognizing the size, we paused to lock architectural decisions before any code was written, so the implementation phases (in `ROADMAP.md`) can proceed against a known shape.

---

## Decision 1: Routing — Subdomains

### Options considered

| Option | Description |
|---|---|
| **1. Subdomains** ✅ chosen | `acme.yourapp.com` per firm. Wildcard DNS + wildcard TLS cert. |
| 2. Path prefix | `yourapp.com/t/acme/...`. No DNS work but shared cookies across tenants (risky), uglier URLs. |
| 3. Subdomains + custom domains as premium | Start with subdomains, add `crm.acmelaw.com` as upsell. Per-domain TLS provisioning needed. |

### Why #1

- Cleanest URLs, isolates cookies per tenant (security win — a compromised tenant subdomain can't read another tenant's cookies)
- One-time setup: wildcard A/CNAME record for `*.yourapp.com`, one wildcard Let's Encrypt cert via DNS-01 challenge (auto-renews)
- Tenant identification: `const slug = req.hostname.split('.')[0]; const firm = lookupFirmBySlug(slug);`
- **Cost:** $0 setup, $0 ongoing
- **Effort:** ~half day (cert + middleware + tenant-slug lookup)

### Why not #3 (yet)

Custom domains (`crm.acmelaw.com` CNAME'd to your service) are a real upsell *after* you have ~10 paying firms asking for it. Adding it later is a ~1-day delta on top of #1, not a rewrite. Implementation when needed: either Caddy in front of Node (auto-issues per-domain LE certs) or Cloudflare for SaaS (~$0.10/hostname/mo at scale, free up to 200 hostnames).

### What this implies for code

- New middleware reads `req.hostname`, extracts slug, looks up firm, sets `req.tenant` for downstream routes
- Login + signup pages need to know which tenant the URL refers to (slug in URL)
- The "share contacts/staff" public endpoints (`/api/contacts/export`, `/api/staff/export` used by Leaderboard) need scoping or removal for SaaS — see "Your-firm strategy" open question

---

## Decision 2: Database — Shared SQLite

### Options considered

| Option | Description |
|---|---|
| **1. Shared SQLite** ✅ chosen | One file, all tenants share, `firm_id` scopes everything. Current state. |
| 2. Postgres | No ceiling, real concurrent writes. But rewriting every `db.prepare()` call, losing synchronous queries (everything becomes async), more ops, more cash. |
| 3. SQLite per tenant | One DB file per firm. Strong isolation but super-admin views are painful, backups multiply, uncommon pattern. |

### Why #1

- Zero code change — current state already works
- Backup helper (Phase 6.5) is one-file simple
- Operational simplicity matches the current single-server, no-build-step monolith
- Sufficient for the first ~50–100 firms (write contention is the practical ceiling on a shared SQLite file)

### Why not #3

The isolation benefits of per-tenant SQLite are real (a bug that drops `WHERE firm_id = ?` can't leak across firms), but the operational costs are worse than the alternative migration path: when contention does bite, **Postgres is the better destination than per-tenant SQLite**, because it offers similar isolation via row-level security *and* keeps super-admin queries simple. Spending 2–3 days now on per-tenant SQLite would buy isolation we'd then throw away on the next migration.

### Mitigations for the shared-SQLite leak risk

Phase 7.C includes a "query audit" task: grep every `db.prepare()` for the presence of `firm_id` in the WHERE clause, and add an integration test that runs as Firm A and asserts it cannot see any of Firm B's rows for each tenant-scoped table.

### When to revisit

Signals that say "time to move to Postgres":
- Write throughput becomes a problem (SQLite WAL still has a single-writer lock)
- More than ~50 active firms
- A second app instance is needed for HA / blue-green deploys
- You hit a real cross-tenant query bottleneck (analytics, super-admin reporting)

---

## Decision 3: Hosting — Render

### Options considered

| Option | Monthly | Notes |
|---|---|---|
| **Stay on Render** ✅ chosen | $7 web + $1/GB persistent disk | Already working. Zero ops. Auto-deploys from git. |
| Hetzner VPS (CX11) | ~$4 | Cheapest credible. You manage OS, TLS, deploys yourself. |
| DigitalOcean / Linode | $4–6 | Similar to Hetzner, slightly more polished UI. |
| Fly.io | Free tier → ~$5–10 | Closer-to-edge if global latency matters. |
| Local (home server) | $0 hardware | Residential ISPs block 80/443, uptime on you, offsite backups still needed. **Not viable for SaaS.** |

### Why Render

For year 1 of SaaS at single-digit-tenant scale: cost delta to a VPS is ~$3–5/month; ops delta (TLS provisioning, backups, deploys, monitoring) is many hours/month. Not a close call.

### Local is fine for one thing

Running the dev copy. Keep that as-is. Production must be on managed infra.

### When to revisit

If Render pricing becomes the bottleneck (typically around the time the SQLite ceiling forces a Postgres migration anyway), revisit. Likely successor: Hetzner VPS + Caddy + Postgres on the same box, or a small managed Postgres + Render or Fly.io for the app.

---

## Open Decisions

These are deferred to the start of Phase 7.B planning. Locking them now would be premature — the right answers depend on how Phase 7.A goes and what early-tenant conversations reveal.

### Billing model

| Option | Notes |
|---|---|
| Per-user/month | e.g. $30/user/month. Standard for legal-tech (Clio, MyCase). Predictable, scales with firm size. |
| Flat tier per firm | e.g. $99/firm/month unlimited users. Simpler pricing but leaves money on the table for larger firms. |
| Feature tiers (Solo/Pro/Firm) | Trust accounting, custom invoice layouts, etc. gated behind higher tiers. More upsell levers but every cap check gets a tier check too. |
| Per-user + feature tiers | Hybrid. Standard but most complex to implement and communicate. |

**Initial lean:** per-user/month. Decide for real after talking to 2–3 prospect firms.

### Your-firm strategy

| Option | Notes |
|---|---|
| Your firm = Tenant 1, integrations firm-scoped | Cleanest. DT/SPVT/LB endpoints filter by `firm_id = your-firm`. Other tenants don't see those features. |
| Your firm = Tenant 1, integrations opt-in for any tenant | More product surface area. DT/SPVT/LB are *your* apps — probably not useful to others. |
| Split: keep current single-firm app for you, fork to SaaS | Two codebases to maintain. Most isolation, most ongoing cost. |

**Initial lean:** Tenant 1 with firm-scoped integrations. Decide for real once we have a concrete second tenant in mind.

---

## Cost Summary

| | Setup labor | Setup cash | Monthly cash |
|---|---|---|---|
| **Routing (subdomains only)** | ~half day | $0 | $0 |
| **Database (stay on SQLite)** | $0 | $0 | $0 |
| **Hosting (Render, current)** | $0 | $0 | ~$8 (existing) |
| **Phase 7.A (per-tenant SMTP)** | 1–2 days | $0 | $0 (tenants pay their own email providers) |
| **Phase 7.B (signup + billing)** | 3–5 days | $0 | Stripe fees on your subscription revenue (2.9% + 30¢) |
| **Phase 7.C (hardening)** | ~1 week | $0 | $0 |
| **Phase 7.D (custom domains, later)** | ~1 day | $0 | $0 with Caddy, or ~$0–$2/domain with Cloudflare for SaaS |

Effectively: SaaS infrastructure costs $0/month above the current Render bill. The labor is the cost.

---

## Risks & Open Questions

1. **Cross-tenant data leak.** Single biggest risk on shared SQLite. Mitigation: Phase 7.C query audit + integration tests. Treat any new route that touches a tenant-scoped table as a code-review checkpoint for `firm_id` filter presence.
2. **Trust accounting compliance.** IOLTA rules vary by state. If marketing this for SaaS, marketing claims must be careful — say "trust ledger" not "IOLTA-compliant" unless you've actually validated against your bar association's rules.
3. **Backups for tenants.** Phase 6.5 covers the platform-level backup. Tenants in regulated industries may want their own export — `GET /api/admin/export-firm/:id` producing a single-tenant SQLite file is the lightest answer.
4. **Email deliverability.** If you operate the SMTP relay on behalf of tenants (instead of having each tenant configure their own SMTP), bounces from one tenant degrade deliverability for all. **Strong reason to land 7.A — per-tenant SMTP — before opening signup.**
5. **DT/SPVT/LB integration scope.** Currently `dt-exchange` and `spv-exchange` routes will trust any DT/SPVT JWT. Multi-tenant means deciding whether those handshakes create new firms, link to existing firms by email match, or are gated to your firm only.
6. **Sign-up abuse.** Open signup → bot signups → wasted resources, potential reputation damage. Mitigation: email verification before first login, rate-limit signup endpoint, hCaptcha or similar on the signup form.
7. **Migration of your existing firm.** Your current data needs to become Tenant 1 cleanly. Likely a one-shot migration script that assigns a slug, sets subscription status to "exempt" (so you don't bill yourself), and verifies all your contacts/matters/invoices still load correctly through the tenant-routing middleware.

---

## Implementation Order (cross-reference)

See `ROADMAP.md` Phase 7 for the canonical phased plan. Summary:

- **7.A** Per-tenant SMTP + inbound email routing (1–2 days). Useful even if SaaS slips.
- **7.B** Signup + subdomain routing + your Stripe billing (3–5 days). Locks in billing model.
- **7.C** Hardening: query audit, per-tenant backups, super-admin, ToS/Privacy (~1 week).
- **7.D** Custom domains as premium tier (~1 day, deferred until tenants ask).
