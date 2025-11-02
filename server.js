import express from 'express';
import http from 'node:http';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { WebSocketServer } from 'ws';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;
const SECRET = process.env.SECRET || 'devsecret-lite';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || '';
const ADMIN_CODE = process.env.ADMIN_CODE || SECRET; // fallback to SECRET if no explicit code

// DB init (JSON file; allow overriding directory for writable/persistent volumes in hosting)
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch {}
const adapter = new JSONFile(path.join(DATA_DIR, 'data.json'));
const db = new Low(adapter, { users: [], posts: [], requests: [], notifications: [], chats: [], messages: [] });

// Helpers
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function uid() { return randomUUID(); }

function authMiddleware(req, res, next) {
  const token = req.cookies?.session;
  if (!token) return res.status(401).json({ msg: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ msg: 'Unauthorized' });
  }
}

function adminMiddleware(req, res, next) {
  if (!req.user) return res.status(401).json({ msg: 'Unauthorized' });
  if (req.user.role !== 'ADMIN') return res.status(403).json({ msg: 'Forbidden' });
  next();
}

// Zod schemas (mirroring original)
const emailPattern = /^[^\s@]+@(my\.richfield\.ac\.za|gmail\.com)$/i;
const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{6,10}$/;

const SignupSchema = z.object({
  email: z
    .string()
    .email({ message: "Please provide a valid @my.richfield.ac.za or @gmail.com email" })
    .regex(emailPattern, {
      message: "Email must be a valid @my.richfield.ac.za or @gmail.com address",
    }),
  name: z.string().min(5, { message: "Name must be minimum 5 characters long" }),
  password: z
    .string()
    .refine(
      (val) => {
        if (typeof val !== "string") return false;
        if (val.length < 6 || val.length > 10) return false;
        return passwordPattern.test(val);
      },
      {
        message:
          "Password must be 6–10 characters and include at least one uppercase letter, one lowercase letter, one number, and one special character.",
      }
    ),
  college: z.string().min(5, { message: "College name must be minimum 5 characters long" }),
  phoneNo: z.coerce.string().refine((val) => /^\d{10}$/.test(val), {
    message: "Phone no. must be exactly 10 digits and contain only numbers",
  }),
  image: z.string().optional().default("")
});

const LoginSchema = z.object({
  email: z
    .string()
    .email({ message: "Please provide a valid email" }),
  password: z.string(),
});

// Routes (pages)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/home', (req, res) => {
  try {
    const token = req.cookies?.session;
    if (!token) return res.redirect('/login');
    jwt.verify(token, SECRET);
    return res.sendFile(path.join(__dirname, 'public', 'home.html'));
  } catch {
    return res.redirect('/login');
  }
});

// API: auth
app.post('/api/v1/auth/signup', async (req, res) => {
  const result = SignupSchema.safeParse(req.body || {});
  if (!result.success) {
    const errors = result.error.format();
    const errorMessages = {};
    for (const [field, error] of Object.entries(errors)) {
      if (field === "_errors") continue;
      if (Array.isArray(error)) {
        errorMessages[field] = error.join(', ');
      } else if (error && "_errors" in error) {
        errorMessages[field] = error._errors.join(', ');
      }
    }
    return res.status(400).json({ msg: errorMessages });
  }

  const { email, name, password, college, phoneNo, image } = result.data;
  const emailNorm = String(email).trim().toLowerCase();
  const exists = db.data.users.find(u => String(u.email || '').trim().toLowerCase() === emailNorm);
  if (exists) return res.status(400).json({ msg: 'Account already exists. Please login!' });

  const hash = await bcrypt.hash(password, 10);
  const id = uid();
  const user = { id, email: emailNorm, name, password: hash, college, phoneNo, image: image ?? null, role: 'USER', createdAt: new Date().toISOString() };
  db.data.users.push(user);
  // If no admins exist yet, promote the first registrant to ADMIN
  const hasAdmin = (db.data.users || []).some(u => u.role === 'ADMIN');
  if (!hasAdmin) {
    user.role = 'ADMIN';
  }
  await db.write();

  const token = jwt.sign({ id, email: user.email, role: user.role }, SECRET);
  const cookieOpts = { httpOnly: true, sameSite: 'lax', path: '/' };
  res.cookie('session', token, cookieOpts);
  res.cookie('uid', id, { ...cookieOpts, httpOnly: false });
  return res.status(201).json({ msg: 'Account created!', token, uid: id });
});

app.post('/api/v1/auth/login', async (req, res) => {
  const result = LoginSchema.safeParse(req.body || {});
  if (!result.success) {
    const errors = result.error.format();
    const errorMessages = {};
    for (const [field, error] of Object.entries(errors)) {
      if (field === "_errors") continue;
      if (Array.isArray(error)) {
        errorMessages[field] = error.join(', ');
      } else if (error && "_errors" in error) {
        errorMessages[field] = error._errors.join(', ');
      }
    }
    return res.status(400).json({ msg: errorMessages });
  }

  const { email, password } = result.data;
  const emailNorm = String(email).trim().toLowerCase();
  const user = db.data.users.find(u => String(u.email || '').trim().toLowerCase() === emailNorm);
  if (!user) return res.status(400).json({ msg: 'Please create an account!' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ msg: 'Incorrect credentials!' });
  const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET);
  const cookieOpts = { httpOnly: true, sameSite: 'lax', path: '/' };
  res.cookie('session', token, cookieOpts);
  res.cookie('uid', user.id, { ...cookieOpts, httpOnly: false });
  return res.status(200).json({ msg: 'Credentials verified!', token, uid: user.id });
});

app.post('/api/v1/auth/logout', (req, res) => {
  const opts = { path: '/' };
  res.clearCookie('session', opts);
  res.clearCookie('uid', opts);
  return res.status(200).json({ msg: 'Logging out!' });
});

// API: posts (basic)
app.get('/api/v1/posts', authMiddleware, (req, res) => {
  const isAdmin = req.user.role === 'ADMIN';
  const posts = [...db.data.posts]
    .filter(p => isAdmin || p.status === 'APPROVED')
    .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ posts });
});

app.post('/api/v1/posts', authMiddleware, async (req, res) => {
  const { title, category, price, description, images } = req.body || {};
  if (!title) return res.status(400).json({ msg: 'Title required' });
  const id = uid();
  db.data.posts.push({ id, userId: req.user.id, title, category: category ?? null, price: price ?? null, description: description ?? null, images: images ?? [], sold: 0, status: 'PENDING', createdAt: new Date().toISOString() });
  await db.write();
  res.status(201).json({ msg: 'Post created (pending approval)', id });
});

// Posts: detail, edit, mark-sold
app.get('/api/v1/posts/:id', authMiddleware, (req, res) => {
  const isAdmin = req.user.role === 'ADMIN';
  const p = db.data.posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ msg: 'Not found' });
  if (p.status !== 'APPROVED' && !(isAdmin || p.userId === req.user.id)) {
    return res.status(403).json({ msg: 'Forbidden' });
  }
  res.json({ post: p });
});

app.patch('/api/v1/posts/:id', authMiddleware, async (req, res) => {
  const p = db.data.posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ msg: 'Not found' });
  const isAdmin = req.user.role === 'ADMIN';
  if (!(isAdmin || p.userId === req.user.id)) return res.status(403).json({ msg: 'Forbidden' });
  const { title, category, price, description } = req.body || {};
  if (title !== undefined) p.title = title;
  if (category !== undefined) p.category = category;
  if (price !== undefined) p.price = price;
  if (description !== undefined) p.description = description;
  await db.write();
  res.json({ msg: 'Updated' });
});

app.post('/api/v1/posts/:id/mark-sold', authMiddleware, async (req, res) => {
  const p = db.data.posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ msg: 'Not found' });
  const isAdmin = req.user.role === 'ADMIN';
  if (!(isAdmin || p.userId === req.user.id)) return res.status(403).json({ msg: 'Forbidden' });
  p.sold = 1;
  await db.write();
  res.json({ msg: 'Marked as sold' });
});

// My posts (all statuses)
app.get('/api/v1/posts/mine', authMiddleware, (req, res) => {
  const mine = [...db.data.posts].filter(p => p.userId === req.user.id).sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ posts: mine });
});

  // API: requests (basic)
  app.get('/api/v1/requests', authMiddleware, (req, res) => {
    const requests = [...(db.data.requests || [])]
      .filter(r => r.status === 'APPROVED')
      .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json({ requests });
  });

  app.post('/api/v1/requests/create', authMiddleware, async (req, res) => {
    const { title, description } = req.body || {};
    if (!title) return res.status(400).json({ msg: 'Title required' });
    const id = uid();
    db.data.requests ||= [];
    db.data.requests.push({ id, userId: req.user.id, title, description: description ?? null, upvotes: 0, status: 'PENDING', createdAt: new Date().toISOString() });
    await db.write();
    res.status(201).json({ msg: 'Request created (pending approval)', id });
  });

  app.post('/api/v1/requests/upvote/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const r = (db.data.requests || []).find(x => x.id === id);
    if (!r) return res.status(404).json({ msg: 'Not found' });
    // Ensure unique upvotes per user (toggle behavior)
    r.voters ||= [];
    const i = r.voters.indexOf(req.user.id);
    if (i === -1) {
      r.voters.push(req.user.id);
      r.upvotes = (r.upvotes || 0) + 1;
    } else {
      r.voters.splice(i, 1);
      r.upvotes = Math.max(0, (r.upvotes || 0) - 1);
    }
    await db.write();
    // Notify request owner
    if (r.userId !== req.user.id) {
      db.data.notifications.push({ id: uid(), userId: r.userId, type: 'REQUEST_UPVOTE', text: `Your request "${r.title}" received an upvote`, read: false, createdAt: new Date().toISOString() });
      await db.write();
    }
    res.json({ msg: 'Upvoted' });
  });

  app.delete('/api/v1/requests/:id', authMiddleware, async (req, res) => {
    const { id } = req.params;
    const list = db.data.requests || [];
    const idx = list.findIndex(x => x.id === id && (x.userId === req.user.id || req.user.role === 'ADMIN'));
    if (idx === -1) return res.status(404).json({ msg: 'Not found' });
    list.splice(idx, 1);
    await db.write();
    res.json({ msg: 'Deleted' });
  });

// Admin endpoints
// Elevate a user to admin in a controlled way
// Options:
// - Provide { code: ADMIN_CODE, userId?: string } to elevate any user (secure bootstrap)
// - If caller is already ADMIN, they can elevate others without code by passing { userId }
app.post('/api/v1/admin/elevate', authMiddleware, async (req, res) => {
  const { code, userId } = req.body || {};
  const caller = db.data.users.find(x => x.id === req.user.id);
  if (!caller) return res.status(404).json({ msg: 'User not found' });

  const hasCode = typeof code === 'string' && code && code === ADMIN_CODE;
  const isAdmin = caller.role === 'ADMIN';
  if (!hasCode && !isAdmin) return res.status(403).json({ msg: 'Forbidden' });

  const targetId = userId || caller.id;
  const target = db.data.users.find(x => x.id === targetId);
  if (!target) return res.status(404).json({ msg: 'Target user not found' });
  target.role = 'ADMIN';
  await db.write();

  // If caller elevated self, refresh their cookie to reflect new role
  if (target.id === caller.id) {
    const token = jwt.sign({ id: caller.id, email: caller.email, role: 'ADMIN' }, SECRET);
    const cookieOpts = { httpOnly: true, sameSite: 'lax', path: '/' };
    res.cookie('session', token, cookieOpts);
  }
  res.json({ msg: `Elevated ${target.email} to admin` });
});

// List users (admin only, no passwords)
app.get('/api/v1/admin/users', authMiddleware, adminMiddleware, (req, res) => {
  const users = (db.data.users || []).map(u => ({ id: u.id, email: u.email, name: u.name, role: u.role, createdAt: u.createdAt }));
  res.json({ users });
});

app.get('/api/v1/admin/posts', authMiddleware, adminMiddleware, (req, res) => {
  const { status } = req.query;
  let posts = [...db.data.posts];
  if (status) posts = posts.filter(p => p.status === String(status));
  posts.sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ posts });
});

app.post('/api/v1/admin/posts/:id/approve', authMiddleware, adminMiddleware, async (req, res) => {
  const p = db.data.posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ msg: 'Not found' });
  p.status = 'APPROVED';
  await db.write();
  // Notify owner
  db.data.notifications.push({ id: uid(), userId: p.userId, type: 'POST_APPROVED', text: `Your post "${p.title}" was approved`, read: false, createdAt: new Date().toISOString() });
  await db.write();
  res.json({ msg: 'Approved' });
});

app.post('/api/v1/admin/posts/:id/reject', authMiddleware, adminMiddleware, async (req, res) => {
  const p = db.data.posts.find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ msg: 'Not found' });
  p.status = 'REJECTED';
  await db.write();
  // Notify owner
  db.data.notifications.push({ id: uid(), userId: p.userId, type: 'POST_REJECTED', text: `Your post "${p.title}" was rejected`, read: false, createdAt: new Date().toISOString() });
  await db.write();
  res.json({ msg: 'Rejected' });
});

app.get('/api/v1/admin/requests', authMiddleware, adminMiddleware, (req, res) => {
  const { status } = req.query;
  let requests = [...(db.data.requests || [])];
  if (status) requests = requests.filter(r => r.status === String(status));
  requests.sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ requests });
});

app.post('/api/v1/admin/requests/:id/approve', authMiddleware, adminMiddleware, async (req, res) => {
  const r = (db.data.requests || []).find(x => x.id === req.params.id);
  if (!r) return res.status(404).json({ msg: 'Not found' });
  r.status = 'APPROVED';
  await db.write();
  // Notify owner
  db.data.notifications.push({ id: uid(), userId: r.userId, type: 'REQUEST_APPROVED', text: `Your request "${r.title}" was approved`, read: false, createdAt: new Date().toISOString() });
  await db.write();
  res.json({ msg: 'Approved' });
});

app.post('/api/v1/admin/requests/:id/reject', authMiddleware, adminMiddleware, async (req, res) => {
  const r = (db.data.requests || []).find(x => x.id === req.params.id);
  if (!r) return res.status(404).json({ msg: 'Not found' });
  r.status = 'REJECTED';
  await db.write();
  // Notify owner
  db.data.notifications.push({ id: uid(), userId: r.userId, type: 'REQUEST_REJECTED', text: `Your request "${r.title}" was rejected`, read: false, createdAt: new Date().toISOString() });
  await db.write();
  res.json({ msg: 'Rejected' });
});

// Notifications
app.get('/api/v1/notifications', authMiddleware, (req, res) => {
  const items = [...(db.data.notifications || [])]
    .filter(n => n.userId === req.user.id)
    .sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ notifications: items });
});

app.post('/api/v1/notifications/:id/read', authMiddleware, async (req, res) => {
  const n = (db.data.notifications || []).find(x => x.id === req.params.id && x.userId === req.user.id);
  if (!n) return res.status(404).json({ msg: 'Not found' });
  n.read = true;
  await db.write();
  res.json({ msg: 'Marked as read' });
});

app.post('/api/v1/notifications/read-all', authMiddleware, async (req, res) => {
  (db.data.notifications || []).forEach(n => {
    if (n.userId === req.user.id) n.read = true;
  });
  await db.write();
  res.json({ msg: 'All marked as read' });
});

  // API: profile
app.get('/api/v1/user', authMiddleware, (req, res) => {
  const { id } = req.user;
  const u = db.data.users.find(x => x.id === id);
  if (!u) return res.status(404).json({ msg: 'User not found' });
  const { password, ...safe } = u;
  res.json({ user: safe });
});

// User lookup for display names/images
app.post('/api/v1/users/lookup', authMiddleware, (req, res) => {
  const ids = Array.isArray(req.body?.ids) ? req.body.ids : [];
  const users = (db.data.users || [])
    .filter(u => ids.includes(u.id))
    .map(u => ({ id: u.id, name: u.name || u.email, email: u.email, image: u.image || '' }));
  res.json({ users });
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Sys info to help verify persistence on hosts
app.get('/api/v1/sys/info', (req, res) => {
  try {
    const dataFile = path.join(DATA_DIR, 'data.json');
    const exists = fs.existsSync(dataFile);
    const size = exists ? (fs.statSync(dataFile).size) : 0;
    const users = (db.data?.users || []).length;
    const posts = (db.data?.posts || []).length;
    res.json({ dataDir: DATA_DIR, dataFile, exists, size, counts: { users, posts } });
  } catch (e) {
    res.json({ dataDir: DATA_DIR, error: String(e) });
  }
});

// Stats for dashboard widgets
app.get('/api/v1/stats', authMiddleware, (req, res) => {
  const me = req.user.id;
  const myPosts = (db.data.posts || []).filter(p => p.userId === me).length;
  const approvedPosts = (db.data.posts || []).filter(p => p.status === 'APPROVED').length;
  const myRequests = (db.data.requests || []).filter(r => r.userId === me).length;
  const unreadNotifications = (db.data.notifications || []).filter(n => n.userId === me && !n.read).length;
  const myChats = (db.data.chats || []).filter(c => (c.participants || []).includes(me)).length;
  res.json({ myPosts, approvedPosts, myRequests, unreadNotifications, myChats });
});

async function bootstrap() {
  await db.read();
  db.data ||= { users: [], posts: [], requests: [], notifications: [], chats: [], messages: [] };
  // Ensure required collections always exist (handles older data.json without new keys)
  db.data.users ||= [];
  db.data.posts ||= [];
  db.data.requests ||= [];
  db.data.notifications ||= [];
  db.data.chats ||= [];
  db.data.messages ||= [];
  // Migrate legacy posts/requests fields for consistency
  (db.data.posts || []).forEach(p => {
    if (!('status' in p)) p.status = 'APPROVED';
    if (!('sold' in p)) p.sold = 0;
    if (!('images' in p) || !Array.isArray(p.images)) p.images = [];
  });
  (db.data.requests || []).forEach(r => {
    if (!('status' in r)) r.status = 'APPROVED';
    if (!('upvotes' in r)) r.upvotes = 0;
    if (!('voters' in r)) r.voters = [];
  });
  // Normalize user emails to lowercase (login is case-insensitive)
  (db.data.users || []).forEach(u => {
    if (u && typeof u.email === 'string') {
      u.email = u.email.trim().toLowerCase();
    }
  });
  // Ensure users have roles
  (db.data.users || []).forEach(u => {
    if (!('role' in u)) u.role = 'USER';
  });

  // Guarantee at least one admin exists for moderation
  try {
    const admins = (db.data.users || []).filter(u => u.role === 'ADMIN');
    if (admins.length === 0 && (db.data.users || []).length > 0) {
      let promote = null;
      if (ADMIN_EMAIL) {
        promote = db.data.users.find(u => (u.email || '').toLowerCase() === ADMIN_EMAIL.toLowerCase());
      }
      if (!promote) {
        // Oldest by createdAt
        promote = [...db.data.users].sort((a,b) => new Date(a.createdAt || 0) - new Date(b.createdAt || 0))[0];
      }
      if (promote) {
        promote.role = 'ADMIN';
        await db.write();
        console.log(`Bootstrap: Promoted ${promote.email} to ADMIN`);
      }
    }
  } catch (e) {
    console.warn('Bootstrap admin check failed:', e?.message || e);
  }
  const server = http.createServer(app);

  // WebSocket Chat Server
  const wss = new WebSocketServer({ server, path: '/ws' });
  const socketsByUser = new Map();
  wss.on('connection', (ws) => {
    ws.meta = { id: uid(), userId: null, name: 'Guest' };
    ws.on('message', async (raw) => {
      try {
        const msg = JSON.parse(raw.toString());
        if (msg.type === 'hello') {
          ws.meta.userId = msg.uid || null;
          ws.meta.name = msg.name || 'Guest';
          if (ws.meta.userId) socketsByUser.set(ws.meta.userId, ws);
          return;
        }
        if (msg.type === 'chat' && typeof msg.text === 'string' && msg.text.trim()) {
          // Per-chat message
          const { chatId } = msg;
          const chat = (db.data.chats || []).find(c => c.id === chatId);
          if (!chat) return;
          if (!chat.participants.includes(ws.meta.userId)) return; // not a participant
          const entry = { id: uid(), chatId, senderId: ws.meta.userId, text: msg.text.trim(), ts: Date.now() };
          chat.messages ||= [];
          chat.messages.push(entry);
          await db.write();
          const out = JSON.stringify({ type: 'chat', ...entry });
          // broadcast to participants only
          chat.participants.forEach((uid) => {
            const s = socketsByUser.get(uid);
            if (s) {
              try { s.send(out); } catch {}
            }
          });
        }
      } catch {}
    });
    ws.on('close', () => {
      if (ws.meta.userId) socketsByUser.delete(ws.meta.userId);
    });
  });

  // Chat endpoints (conversations)
  app.post('/api/v1/chats', authMiddleware, async (req, res) => {
    const { withUserId } = req.body || {};
    if (!withUserId || withUserId === req.user.id) return res.status(400).json({ msg: 'Invalid user' });
    const me = req.user.id;
    let chat = (db.data.chats || []).find(c => c.participants.length === 2 && c.participants.includes(me) && c.participants.includes(withUserId));
    if (!chat) {
      chat = { id: uid(), participants: [me, withUserId], messages: [], createdAt: new Date().toISOString() };
      db.data.chats ||= [];
      db.data.chats.push(chat);
      await db.write();
      return res.status(201).json({ msg: 'Initiated chat', chatId: chat.id });
    }
    return res.status(200).json({ msg: 'Chat already exists', chatId: chat.id });
  });

  app.get('/api/v1/chats', authMiddleware, (req, res) => {
    const me = req.user.id;
    const chats = (db.data.chats || [])
      .filter(c => c.participants.includes(me))
      .map(c => ({ id: c.id, participants: c.participants, lastTs: c.messages?.length ? c.messages[c.messages.length-1].ts : 0 }))
      .sort((a,b) => (b.lastTs||0) - (a.lastTs||0));
    res.json({ chats });
  });

  app.get('/api/v1/chats/:id', authMiddleware, (req, res) => {
    const me = req.user.id;
    const chat = (db.data.chats || []).find(c => c.id === req.params.id);
    if (!chat) return res.status(404).json({ msg: 'Chat not found' });
    if (!chat.participants.includes(me)) return res.status(403).json({ msg: 'Forbidden' });
    res.json({ chat: { id: chat.id, participants: chat.participants, messages: chat.messages || [] } });
  });

  app.post('/api/v1/chats/:id/messages', authMiddleware, async (req, res) => {
    const me = req.user.id;
    const chat = (db.data.chats || []).find(c => c.id === req.params.id);
    if (!chat) return res.status(404).json({ msg: 'Chat not found' });
    if (!chat.participants.includes(me)) return res.status(403).json({ msg: 'Forbidden' });
    const { text } = req.body || {};
    if (!text || !String(text).trim()) return res.status(400).json({ msg: 'Text required' });
    const entry = { id: uid(), chatId: chat.id, senderId: me, text: String(text).trim(), ts: Date.now() };
    chat.messages ||= [];
    chat.messages.push(entry);
    await db.write();
    // Try to emit via WS if possible
    try {
      const out = JSON.stringify({ type: 'chat', ...entry });
      chat.participants.forEach((uid) => {
        const s = (wss && wss.clients) ? Array.from(wss.clients).find(c => c.meta && c.meta.userId === uid) : null;
        if (s) { try { s.send(out); } catch {} }
      });
    } catch {}
    res.status(201).json({ msg: 'Sent', id: entry.id });
  });

  server.listen(PORT, () => {
    console.log(`Lite server listening on http://localhost:${PORT}`);
  });
}

// Global error safety nets to avoid full process crashes
process.on('unhandledRejection', (err) => {
  console.error('UnhandledRejection:', err);
});
process.on('uncaughtException', (err) => {
  console.error('UncaughtException:', err);
});

bootstrap().catch((e) => {
  console.error('Failed to start server:', e);
  process.exit(1);
});
