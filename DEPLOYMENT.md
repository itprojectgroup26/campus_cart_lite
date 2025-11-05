# Deploy Campus Cart Lite

This guide gets you a hosted URL your team can use. We’ll use Render (simple, supports WebSockets). You can persist data either on a disk (JSON file) or in MongoDB.

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
   - Environment variables declared in `lite/render.yaml`:
     - `SECRET` (auto-generated)
     - `ADMIN_CODE` (you set this; used to elevate an account to admin)
     - Optional JSON-file storage:
       - `DATA_DIR=/data` and attach a persistent Disk mounted at `/data`
     - Optional MongoDB storage (recommended on free plans where disks aren’t available):
       - `MONGODB_URI` (connection string)
       - `MONGODB_DB` (default: `campus_cart`)
       - `MONGODB_COLLECTION` (default: `lite_db`)
4. Wait for the first deploy to finish. You’ll get a live URL like `https://campus-cart-lite.onrender.com`.

## 3) First-time admin setup

1. After the first deploy, go to your live URL and sign up your account.
2. In Render → your service → Environment, set `ADMIN_CODE` to a secret string (e.g., `SECRET`).
3. On the live site, open `/admin-setup.html`, enter the same code, and submit to elevate your account to admin.
4. You can now approve posts/requests and manage users via the admin pages.

Endpoint helpers:
- `GET /api/v1/admin/state` → shows whether an admin exists and your current role.
- `GET /api/v1/sys/info` → shows storage mode (`mongo` or `json`) and basic counts.

## 4) Share the link
Give your team the Render URL. Your laptop doesn’t need to stay on—Render hosts it for you.

## Notes
- Health check: `GET /health` returns `{ status: "ok" }`.
- Port: Render sets `PORT` automatically; the app uses it.
- Persistence options:
  - JSON file: attach a Disk and set `DATA_DIR=/data` (data at `/data/data.json`).
  - MongoDB: set `MONGODB_URI` and omit the Disk; great for free tiers.
- Scale: Keep 1 instance for JSON storage. MongoDB supports scaling beyond 1 instance.

## Alternatives
- Railway/Fly.io/Azure App Service: use the `lite/Dockerfile` included to deploy as a container. Mount a volume and set `DATA_DIR` accordingly, or inject `MONGODB_URI`.
- Vercel split: host static on Vercel and API/WebSockets on Render. Requires small cookie/CORS changes—ask before switching.
