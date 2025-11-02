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
- `DATA_DIR`: directory where `data.json` is stored (default: app folder)

Health check:
- `GET /health` → `{ "status": "ok" }`

## Deploy

Use the included `render.yaml` for Render Blueprint deploys.
- Persistent disk mounted at `/data`; app writes `data.json` there via `DATA_DIR=/data`.
- WebSockets supported.

Alternative: build container with `Dockerfile` and deploy to Fly.io/Railway/Azure.

## Security note

This is a simplified stack to run quickly without external DB. For multi‑instance scaling and stronger auth/session features, migrate to a managed database and/or your preferred identity provider later.
