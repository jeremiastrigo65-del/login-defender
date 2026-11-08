import express from 'express';
import session from 'express-session';
import bcrypt from 'bcryptjs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pool, initDb } from './db.js';
import { getClientIp, logAttempt } from './helpers.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

// Clean URLs for pages
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'views', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'views', 'register.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'views', 'dashboard.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'views', 'admin.html')));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 },
}));
app.use(express.static(path.join(__dirname, 'views')));

// Config
const MAX_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

// Init DB once per cold start
let initialized = false;
app.use(async (req, res, next) => {
  if (!initialized) {
    try { await initDb(); initialized = true; }
    catch (e) { return res.status(500).send('DB init failed: ' + e.message); }
  }
  next();
});

// Middleware
async function currentUser(req) {
  if (!req.session?.userId) return null;
  const { rows } = await pool.query(
    `SELECT id, username, role FROM users WHERE id=$1`, [req.session.userId]
  );
  return rows[0] || null;
}

function requireAuth(role) {
  return async (req, res, next) => {
    const u = await currentUser(req);
    if (!u) return res.redirect('/login'); // FIXED: Removed .html
    if (role && u.role !== role) return res.status(403).send('Forbidden');
    req.user = u;
    next();
  };
}

// ---- Routes ----

app.get('/', (req, res) => res.redirect('/login'));

// Register
app.post('/api/register', async (req, res) => {
  const { username = '', password = '' } = req.body;
  if (username.length < 3 || password.length < 5)
    return res.status(400).send('Username min 3, password min 5 chars.');
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO users (username, password_hash) VALUES ($1,$2)`,
      [username.trim(), hash]
    );
    res.redirect('/login?registered=1'); // FIXED: Removed .html
  } catch {
    res.status(400).send('Username already taken.');
  }
});

// Login (the defender)
app.post('/api/login', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const ip = getClientIp(req);

  // 1) Lockout check
  const { rows: urows } = await pool.query(
    `SELECT * FROM users WHERE username=$1`, [username]
  );
  const user = urows[0];

  if (user?.locked_until && new Date(user.locked_until) > new Date()) {
    await logAttempt(username, ip, false, 'Locked out - rejected');
    const mins = Math.ceil((new Date(user.locked_until) - Date.now()) / 60000);
    return res.status(429).send(`⛔ Account locked. Try again in ${mins} minute(s).`);
  }

  // 2) Verify
  if (user && await bcrypt.compare(password, user.password_hash)) {
    await pool.query(
      `UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=$1`,
      [user.id]
    );
    await logAttempt(username, ip, true, 'Login success');
    req.session.userId = user.id;
    req.session.role = user.role;
    return res.redirect(user.role === 'admin' ? '/admin' : '/dashboard'); // FIXED: Removed .html
  }

  // 3) Fail path
  await logAttempt(username, ip, false, 'Wrong credentials');
  if (!user) return res.status(401).send('❌ Wrong username/password.');

  const fails = user.failed_attempts + 1;
  if (fails >= MAX_ATTEMPTS) {
    const until = new Date(Date.now() + LOCKOUT_MINUTES * 60000);
    await pool.query(
      `UPDATE users SET failed_attempts=$1, locked_until=$2 WHERE id=$3`,
      [fails, until, user.id]
    );
    return res.status(429).send(`⛔ Too many failed attempts. Locked for ${LOCKOUT_MINUTES} min.`);
  }
  await pool.query(`UPDATE users SET failed_attempts=$1 WHERE id=$2`, [fails, user.id]);
  res.status(401).send(`❌ Wrong credentials. ${MAX_ATTEMPTS - fails} attempt(s) left.`);
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login')); // FIXED: Removed .html
});

// Admin data (JSON, fetched by admin.html)
app.get('/api/admin/attempts', requireAuth('admin'), async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM login_attempts ORDER BY attempted_at DESC LIMIT 100`
  );
  res.json(rows);
});

// Session probe for frontend
app.get('/api/me', async (req, res) => {
  const u = await currentUser(req);
  res.json(u || null);
});

// Local dev server (Vercel uses the exported app)
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`http://localhost:${PORT}`));
}

export default app;