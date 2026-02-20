require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme123';

// ─── DATABASE SETUP ──────────────────────────────────────────────────────────
const db = new Database('vault.db');

// Create suppliers table if it doesn't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS suppliers (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL,
    product   TEXT    NOT NULL,
    status    TEXT    NOT NULL DEFAULT 'on_hold',
    note      TEXT    DEFAULT '',
    added_at  DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Simple token store (in-memory, resets on server restart — fine for personal use)
const activeSessions = new Set();

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token || !activeSessions.has(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// ─── AUTH ROUTES ─────────────────────────────────────────────────────────────

// POST /api/login  { password: "..." }
// Returns: { token: "..." } or 401
app.post('/api/login', (req, res) => {
  const { password } = req.body;
  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Wrong password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  activeSessions.add(token);
  res.json({ token });
});

// POST /api/logout
app.post('/api/logout', requireAdmin, (req, res) => {
  activeSessions.delete(req.headers['x-admin-token']);
  res.json({ ok: true });
});

// ─── PUBLIC ROUTES ────────────────────────────────────────────────────────────

// GET /api/search?q=john
// Returns matching suppliers (name, product, status, note, added_at) — no IDs exposed to public
app.get('/api/search', (req, res) => {
  const query = (req.query.q || '').trim();
  if (!query) return res.json([]);

  const rows = db.prepare(`
    SELECT name, product, status, note, added_at
    FROM suppliers
    WHERE LOWER(name) LIKE LOWER(?)
    ORDER BY added_at DESC
  `).all(`%${query}%`);

  res.json(rows);
});

// ─── ADMIN ROUTES (protected) ─────────────────────────────────────────────────

// GET /api/admin/suppliers  — list all suppliers
app.get('/api/admin/suppliers', requireAdmin, (req, res) => {
  const rows = db.prepare(`
    SELECT * FROM suppliers ORDER BY added_at DESC
  `).all();
  res.json(rows);
});

// POST /api/admin/suppliers  — add a supplier
// Body: { name, product, note? }
app.post('/api/admin/suppliers', requireAdmin, (req, res) => {
  const { name, product, note = '' } = req.body;
  if (!name || !product) {
    return res.status(400).json({ error: 'name and product are required' });
  }
  const result = db.prepare(`
    INSERT INTO suppliers (name, product, note) VALUES (?, ?, ?)
  `).run(name.trim(), product.trim(), note.trim());

  res.json({ id: result.lastInsertRowid, name, product, note, status: 'on_hold' });
});

// PATCH /api/admin/suppliers/:id  — update a supplier (status, note, etc.)
// Body: { status?, note? }
app.patch('/api/admin/suppliers/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { status, note } = req.body;

  const supplier = db.prepare('SELECT * FROM suppliers WHERE id = ?').get(id);
  if (!supplier) return res.status(404).json({ error: 'Supplier not found' });

  const newStatus = status ?? supplier.status;
  const newNote   = note   ?? supplier.note;

  db.prepare(`
    UPDATE suppliers SET status = ?, note = ? WHERE id = ?
  `).run(newStatus, newNote, id);

  res.json({ ok: true });
});

// DELETE /api/admin/suppliers/:id  — mark as delivered (deletes the record)
app.delete('/api/admin/suppliers/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const info = db.prepare('DELETE FROM suppliers WHERE id = ?').run(id);
  if (info.changes === 0) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true, deleted: id });
});

// ─── START ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ Supplier Vault running on port ${PORT}`);
  console.log(`   Public  → http://localhost:${PORT}`);
  console.log(`   Admin   → http://localhost:${PORT}/admin.html`);
});
