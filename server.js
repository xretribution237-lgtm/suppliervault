require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme123';

// ─── DATABASE ─────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS suppliers (
      id            SERIAL PRIMARY KEY,
      name          TEXT        NOT NULL,
      product       TEXT        NOT NULL,
      status        TEXT        NOT NULL DEFAULT 'on_hold',
      note          TEXT        DEFAULT '',
      est_delivery  DATE        DEFAULT NULL,
      added_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS delivery_history (
      id            SERIAL PRIMARY KEY,
      name          TEXT        NOT NULL,
      product       TEXT        NOT NULL,
      note          TEXT        DEFAULT '',
      est_delivery  DATE        DEFAULT NULL,
      added_at      TIMESTAMPTZ,
      delivered_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS announcements (
      id         SERIAL PRIMARY KEY,
      message    TEXT        NOT NULL,
      active     BOOLEAN     NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await pool.query(`ALTER TABLE suppliers ADD COLUMN IF NOT EXISTS est_delivery DATE DEFAULT NULL`);

  console.log('✅ Database ready');
}

initDB().catch(err => console.error('❌ DB init failed:', err.message));

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── RATE LIMITER ─────────────────────────────────────────────────────────────
const MAX_ATTEMPTS = 5;
const WINDOW_MS    = 15 * 60 * 1000;
const LOCKOUT_MS   = 30 * 60 * 1000;
const loginAttempts = new Map();

function getRealIP(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
}

function checkRateLimit(ip) {
  const now  = Date.now();
  const data = loginAttempts.get(ip) || { count: 0, firstAttempt: now, lockedUntil: 0 };
  if (data.lockedUntil && now < data.lockedUntil) {
    return { allowed: false, minutesLeft: Math.ceil((data.lockedUntil - now) / 60000) };
  }
  if (now - data.firstAttempt > WINDOW_MS) {
    loginAttempts.set(ip, { count: 0, firstAttempt: now, lockedUntil: 0 });
    return { allowed: true };
  }
  if (data.count >= MAX_ATTEMPTS) {
    data.lockedUntil = now + LOCKOUT_MS;
    loginAttempts.set(ip, data);
    return { allowed: false, minutesLeft: 30 };
  }
  return { allowed: true };
}

function recordFailedAttempt(ip) {
  const now  = Date.now();
  const data = loginAttempts.get(ip) || { count: 0, firstAttempt: now, lockedUntil: 0 };
  data.count++;
  loginAttempts.set(ip, data);
}

function clearAttempts(ip) { loginAttempts.delete(ip); }

// ─── AUTH ─────────────────────────────────────────────────────────────────────
const activeSessions = new Set();

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || !activeSessions.has(token)) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

app.post('/api/login', (req, res) => {
  const ip = getRealIP(req);
  const rl = checkRateLimit(ip);
  if (!rl.allowed) {
    return res.status(429).json({ error: `Too many attempts. Try again in ${rl.minutesLeft} min.` });
  }
  const { password } = req.body;
  if (!password || password !== ADMIN_PASSWORD) {
    recordFailedAttempt(ip);
    const data = loginAttempts.get(ip);
    const left = MAX_ATTEMPTS - (data?.count || 0);
    const warn = left > 0 ? ` ${left} attempt${left !== 1 ? 's' : ''} left.` : '';
    return res.status(401).json({ error: `Wrong password.${warn}` });
  }
  clearAttempts(ip);
  const token = crypto.randomBytes(32).toString('hex');
  activeSessions.add(token);
  res.json({ token });
});

app.post('/api/logout', requireAdmin, (req, res) => {
  activeSessions.delete(req.headers['x-admin-token']);
  res.json({ ok: true });
});

// ─── PUBLIC ───────────────────────────────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  const query = (req.query.q || '').trim();
  if (!query) return res.json([]);
  try {
    const { rows } = await pool.query(
      `SELECT name, product, status, note, est_delivery, added_at FROM suppliers WHERE LOWER(name) LIKE LOWER($1) ORDER BY added_at DESC`,
      [`%${query}%`]
    );
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Search failed' }); }
});

app.get('/api/announcements', async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT id, message, created_at FROM announcements WHERE active = true ORDER BY created_at DESC`);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// ─── ADMIN: SUPPLIERS ─────────────────────────────────────────────────────────
app.get('/api/admin/suppliers', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM suppliers ORDER BY added_at DESC`);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/suppliers', requireAdmin, async (req, res) => {
  const { name, product, note = '', est_delivery = null } = req.body;
  if (!name || !product) return res.status(400).json({ error: 'name and product required' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO suppliers (name, product, note, est_delivery) VALUES ($1,$2,$3,$4) RETURNING *`,
      [name.trim(), product.trim(), note.trim(), est_delivery || null]
    );
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed to add' }); }
});

app.patch('/api/admin/suppliers/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, product, note, est_delivery, status } = req.body;
  try {
    const { rows } = await pool.query(`SELECT * FROM suppliers WHERE id=$1`, [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const s = rows[0];
    await pool.query(
      `UPDATE suppliers SET name=$1,product=$2,note=$3,est_delivery=$4,status=$5 WHERE id=$6`,
      [name??s.name, product??s.product, note??s.note, est_delivery!==undefined?(est_delivery||null):s.est_delivery, status??s.status, id]
    );
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed to update' }); }
});

app.delete('/api/admin/suppliers/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const { rows } = await pool.query(`SELECT * FROM suppliers WHERE id=$1`, [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    const s = rows[0];
    await pool.query(
      `INSERT INTO delivery_history (name,product,note,est_delivery,added_at) VALUES ($1,$2,$3,$4,$5)`,
      [s.name, s.product, s.note, s.est_delivery, s.added_at]
    );
    await pool.query(`DELETE FROM suppliers WHERE id=$1`, [id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// ─── ADMIN: HISTORY ───────────────────────────────────────────────────────────
app.get('/api/admin/history', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM delivery_history ORDER BY delivered_at DESC LIMIT 100`);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/history/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query(`DELETE FROM delivery_history WHERE id=$1`, [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// ─── ADMIN: ANNOUNCEMENTS ─────────────────────────────────────────────────────
app.get('/api/admin/announcements', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(`SELECT * FROM announcements ORDER BY created_at DESC`);
    res.json(rows);
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/announcements', requireAdmin, async (req, res) => {
  const { message } = req.body;
  if (!message) return res.status(400).json({ error: 'message required' });
  try {
    const { rows } = await pool.query(`INSERT INTO announcements (message) VALUES ($1) RETURNING *`, [message.trim()]);
    res.json(rows[0]);
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.patch('/api/admin/announcements/:id', requireAdmin, async (req, res) => {
  const { active, message } = req.body;
  try {
    if (active !== undefined) await pool.query(`UPDATE announcements SET active=$1 WHERE id=$2`, [active, req.params.id]);
    if (message !== undefined) await pool.query(`UPDATE announcements SET message=$1 WHERE id=$2`, [message, req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/announcements/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query(`DELETE FROM announcements WHERE id=$1`, [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => console.log(`✅ Supplier Vault running on port ${PORT}`));
