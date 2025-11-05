# Campus Cart Lite

A simplified, production‑ish Node/Express app that serves static HTML/CSS/JS and provides APIs + WebSockets for auth, posts, requests, notifications, and chat.

- Server: Express + lowdb (JSON file) + JWT cookies + WebSocket
- Frontend: Static HTML + Tailwind CDN + small vanilla JS

## Run locally

```bash
corepack enable
pnpm install
pnpm run dev
# open http://localhost:8080 (or set PORT)
```

Optional:
- `PORT`: override the port (default 8080)
- Storage (choose one):
	- `DATA_DIR`: directory where `data.json` is stored (default: app folder)
	- or MongoDB: `MONGODB_URI` (plus optional `MONGODB_DB`, `MONGODB_COLLECTION`)
- Admin:
	- `ADMIN_CODE`: code used to elevate an account to ADMIN via `/admin-setup.html`

Health check:
- `GET /health` → `{ "status": "ok" }`

## Deploy

Use the included `render.yaml` for Render Blueprint deploys.
- JSON disk mode: attach a persistent disk and set `DATA_DIR=/data`.
- MongoDB mode (recommended on free tiers): set `MONGODB_URI` and skip disk.
- WebSockets supported.

Alternative: build container with `Dockerfile` and deploy to Fly.io/Railway/Azure.

## Admin + diagnostics

- Elevate to admin: visit `/admin-setup.html` and enter your `ADMIN_CODE`.
- Check admin presence: `GET /api/v1/admin/state`.
- Check storage mode and counts: `GET /api/v1/sys/info` (shows `storage: "mongo" | "json"`).

## Security note

This is a simplified stack to run quickly without external DB. For multi‑instance scaling and stronger auth/session features, migrate to a managed database and/or your preferred identity provider later.
