# Deploy Campus Cart Lite

This guide gets you a hosted URL your team can use. We’ll use Render (simple, supports WebSockets and a persistent disk for `data.json`).

## What you’ll need
- A GitHub repo with this project
- A free Render account (https://render.com)

## 1) Push this project to GitHub
You can create a new repo and push the folder `Campus_Cart-master` as the repo root.

> The blueprint file `render.yaml` is already included at the repo root. It tells Render how to build and run the app.

## 2) Create the Render service (Blueprint)
1. In Render, click New → Blueprint.
2. Pick your GitHub repo that contains `render.yaml` at the root (next to `Campus_Cart-master`).
3. Review the plan and click Apply. Render will provision:
   - A Web Service (Node.js) at `Campus_Cart-master/lite` (via `rootDir: lite`)
   - A persistent Disk mounted at `/data`
   - Environment variables:
     - `DATA_DIR=/data` (so your data.json persists)
     - `SECRET` (auto-generated)
4. Wait for the first deploy to finish. You’ll get a live URL like `https://campus-cart-lite.onrender.com`.

## 3) Share the link
Give your team the Render URL. Your laptop doesn’t need to stay on—Render hosts it for you.

## Notes
- Health check: `GET /health` returns `{ status: "ok" }`.
- Port: Render sets `PORT` automatically; the app uses it.
- Persistence: Data is stored in the Render Disk at `/data/data.json`.
- Scale: Keep 1 instance for now since JSON storage isn’t multi-writer safe.

## Alternatives
- Railway/Fly.io/Azure App Service: use the `lite/Dockerfile` included to deploy as a container. Mount a volume and set `DATA_DIR` accordingly.
- Vercel split: host static on Vercel and API/WebSockets on Render. Requires small cookie/CORS changes—ask before switching.
