require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme123';

// ─── DATABASE SETUP (PostgreSQL) ─────────────────────────────────────────────
// Railway automatically sets DATABASE_URL when you add a Postgres plugin
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS suppliers (
      id         SERIAL PRIMARY KEY,
      name       TEXT        NOT NULL,
      product    TEXT        NOT NULL,
      status     TEXT        NOT NULL DEFAULT 'on_hold',
      note       TEXT        DEFAULT '',
      added_at   TIMESTAMPTZ DEFAULT NOW()
    )
  `);
  console.log('✅ Database ready');
}

initDB().catch(err => {
  console.error('❌ DB init failed:', err.message);
});

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Simple in-memory token store (resets on redeploy — just re-login)
const activeSessions = new Set();

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || !activeSessions.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Wrong password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  activeSessions.add(token);
  res.json({ token });
});

app.post('/api/logout', requireAdmin, (req, res) => {
  activeSessions.delete(req.headers['x-admin-token']);
  res.json({ ok: true });
});

// ─── PUBLIC ROUTES ────────────────────────────────────────────────────────────

// GET /api/search?q=john
app.get('/api/search', async (req, res) => {
  const query = (req.query.q || '').trim();
  if (!query) return res.json([]);

  try {
    const { rows } = await pool.query(
      `SELECT name, product, status, note, added_at
       FROM suppliers
       WHERE LOWER(name) LIKE LOWER($1)
       ORDER BY added_at DESC`,
      [`%${query}%`]
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Search failed' });
  }
});

// ─── ADMIN ROUTES (protected) ─────────────────────────────────────────────────

app.get('/api/admin/suppliers', requireAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM suppliers ORDER BY added_at DESC`
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: 'Failed to load suppliers' });
  }
});

app.post('/api/admin/suppliers', requireAdmin, async (req, res) => {
  const { name, product, note = '' } = req.body;
  if (!name || !product) {
    return res.status(400).json({ error: 'name and product are required' });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO suppliers (name, product, note)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [name.trim(), product.trim(), note.trim()]
    );
    res.json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Failed to add supplier' });
  }
});

app.patch('/api/admin/suppliers/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  const { status, note } = req.body;
  try {
    const { rows } = await pool.query(`SELECT * FROM suppliers WHERE id = $1`, [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });

    const newStatus = status ?? rows[0].status;
    const newNote   = note   ?? rows[0].note;

    await pool.query(
      `UPDATE suppliers SET status = $1, note = $2 WHERE id = $3`,
      [newStatus, newNote, id]
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update supplier' });
  }
});

// DELETE = mark as delivered (removes record)
app.delete('/api/admin/suppliers/:id', requireAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`DELETE FROM suppliers WHERE id = $1`, [id]);
    if (result.rowCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ ok: true, deleted: id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete supplier' });
  }
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Supplier Vault running on port ${PORT}`);
});
