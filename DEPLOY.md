# Deployment Guide — CRM

Deploys to `crm.phillipacevedo.com` on Render, matching the DealTracker / SPV-Tracker pattern.

## 1. Push to GitHub

```bash
cd ~/Desktop/Projects/CRM
git init
git add .
git commit -m "Initial CRM scaffold"
gh repo create pacevedo67/CRM --private --source=. --push
```

## 2. Create the Render service

1. Go to https://dashboard.render.com → **New +** → **Web Service** → pick the `CRM` repo.
2. Render auto-detects `render.yaml` and pre-fills most settings. Confirm:
   - **Build command:** `npm install --build-from-source`
   - **Start command:** `node server.js`
   - **Plan:** Starter (or higher). The persistent disk is required — don't choose Free.
3. **Environment variables** (set in the Render dashboard):

   | Key | Value | Notes |
   |---|---|---|
   | `JWT_SECRET` | *(auto-generated)* | `render.yaml` generates this; don't overwrite |
   | `SEED_ADMIN_EMAIL` | `pacevedo67@gmail.com` | first admin account |
   | `SEED_ADMIN_PASSWORD` | *(pick a strong temp password)* | **DELETE this env var after first deploy completes** |
   | `SEED_FIRM_NAME` | *(your firm name)* | used on the login page header; can be changed in Settings |
   | `NODE_ENV` | `production` | enables HSTS + secure cookies |
   | `ALLOWED_ORIGIN` | `https://crm.phillipacevedo.com` | set after DNS is live |
   | `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | *(your SMTP)* | enables outgoing reset & invite emails |

4. Click **Deploy**. First build takes 3–5 min (native `better-sqlite3` compile).

## 3. Log in once, then remove the seed password env var

1. Open the default Render URL (e.g. `crm-abc.onrender.com`) to verify it boots.
2. Log in as `pacevedo67@gmail.com` with your seed password.
3. **Change the password immediately** (Settings → Change password).
4. Delete the `SEED_ADMIN_PASSWORD` env var in Render. Restart the service.

## 4. Point `crm.phillipacevedo.com` at Render

1. In Render: your service → **Settings** → **Custom Domains** → **Add Custom Domain** → enter `crm.phillipacevedo.com`. Render will show you a target like `crm-abc.onrender.com`.
2. In your DNS provider for `phillipacevedo.com` (this should be wherever DT and SPVT already point — check the existing DT entries for the pattern):
   - Add a **CNAME** record: name = `crm`, value = the Render target from step 1.
3. Wait 5–30 min for DNS + Render's automatic TLS issuance.
4. Set `ALLOWED_ORIGIN=https://crm.phillipacevedo.com` in Render env and restart.

## 5. Enable SSO from DealTracker & SPV Tracker

To make "Open CRM" links from DT/SPVT flow through with no second login:

- In DealTracker, add a link like `https://crm.phillipacevedo.com/?ssoToken=<jwt>&src=dt` and have DT's frontend set that JWT on click. The CRM landing page already accepts `?ssoToken=…&src=dt|spv` and calls the matching `/api/auth/*-exchange` endpoint.
- Same approach works from SPVT (`src=spv`).

No code change needed in CRM — the exchange endpoints are live.

## 6. Invite your team

1. Log into CRM as admin.
2. Settings → Users → **+ Invite user**. Enter email + role. An invite email is sent (if SMTP is configured) with a 72-hour link. Without SMTP, the link is printed to Render logs — copy it from there.
3. The invitee sets their own password on the accept-invite page.

## 7. Optional: Outlook / Microsoft 365 integration

Phase-3 feature. Requires:
- Azure AD app registration in your M365 tenant (Client ID, Tenant ID, client secret, redirect URI = `https://crm.phillipacevedo.com/api/outlook/callback`).
- Delegated Graph API permissions: `Mail.Read`, `Calendars.ReadWrite` (at minimum).
- New env vars in Render: `MS_CLIENT_ID`, `MS_TENANT_ID`, `MS_CLIENT_SECRET`.

The code for Outlook sync isn't in Phase 1 — tell me when you're ready and I'll add it.

## 8. Backup strategy

Render's persistent disk snapshots daily. For extra safety, set up a weekly cron that runs `sqlite3 /data/crm.db '.backup /data/crm-backup.db'` and pushes to S3 or similar. Ask when you want this wired up.

## Local development

```bash
npm install
JWT_SECRET=$(openssl rand -hex 32) SEED_ADMIN_PASSWORD=testpass1234 npm start
# Visit http://localhost:3000
```

Database lives at `./data/crm.db`. Delete it to start fresh (drops the firm + all users).

## Troubleshooting

- **"JWT_SECRET is too short"** — must be at least 32 chars.
- **Invite email not arriving** — check Render logs; if SMTP isn't configured, the link is printed there.
- **`better-sqlite3` build fails on Render** — ensure build command is `npm install --build-from-source`.
- **401 loop after login** — `ALLOWED_ORIGIN` doesn't match your actual domain, or cookies are being blocked by cross-origin policy. Match it exactly.
