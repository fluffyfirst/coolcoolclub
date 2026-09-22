'use strict';
/**
 * COOL COOL CLUB - ระบบจัดคิวสนามแบด
 * Node.js + Express + SQLite (better-sqlite3)
 *
 *  /            บอร์ดสำหรับผู้เล่น (ดูอย่างเดียว ไม่ต้องล็อกอิน)
 *  /staff       หน้าเจ้าหน้าที่ (ต้องใส่ PIN) จัดคิว จบเกม เก็บเงิน
 *  /api/*       API (เขียนข้อมูลต้องมี token จากการล็อกอิน)
 */
const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const os = require('os');

const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'club.db');
const TZ_NAME = process.env.TZ_NAME || 'Asia/Bangkok';
const CLUB_NAME = process.env.CLUB_NAME || 'COOL COOL CLUB';
const STAFF_PIN = process.env.STAFF_PIN || '';
const TOKEN_DAYS = Number(process.env.TOKEN_DAYS || 30);
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(path.dirname(DB_PATH), 'backups');
const BACKUP_KEEP = Number(process.env.BACKUP_KEEP || 14);

if (STAFF_PIN.length < 4) {
  console.error('ต้องตั้งค่า STAFF_PIN (อย่างน้อย 4 ตัวอักษร) ก่อนรันเซิร์ฟเวอร์ เช่น STAFF_PIN=482913 npm start');
  process.exit(1);
}

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS live_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL,
  state TEXT,
  updated_at TEXT NOT NULL
);
INSERT OR IGNORE INTO live_state (id, version, state, updated_at) VALUES (1, 1, NULL, datetime('now'));
CREATE TABLE IF NOT EXISTS sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  day TEXT NOT NULL,
  archived_at TEXT NOT NULL,
  players INTEGER NOT NULL,
  games INTEGER NOT NULL,
  shuttles INTEGER NOT NULL,
  court_fee INTEGER NOT NULL,
  shuttle_fee INTEGER NOT NULL,
  total INTEGER NOT NULL,
  paid INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS session_players (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  rank TEXT NOT NULL,
  games INTEGER NOT NULL,
  shuttles INTEGER NOT NULL,
  court_fee INTEGER NOT NULL,
  shuttle_fee INTEGER NOT NULL,
  total INTEGER NOT NULL,
  paid INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS session_games (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  ended_at TEXT NOT NULL,
  court INTEGER NOT NULL,
  team1 TEXT NOT NULL,
  team2 TEXT NOT NULL,
  winner INTEGER,
  score1 INTEGER,
  score2 INTEGER,
  shuttles INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_day ON sessions(day);
CREATE TABLE IF NOT EXISTS members (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  rank INTEGER NOT NULL DEFAULT 3,
  phone TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_members_active_name ON members(lower(name)) WHERE active = 1;
`);
if (!db.prepare('PRAGMA table_info(session_players)').all().some((c) => c.name === 'member_id')) {
  db.exec('ALTER TABLE session_players ADD COLUMN member_id TEXT');
}
db.exec('CREATE INDEX IF NOT EXISTS idx_sp_member ON session_players(member_id)');

const RANKS = ['หน้าบ้าน', 'BG', 'N', 'S', 'P', 'C'];

/* ---------- secret + tokens ---------- */
function getSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  const row = db.prepare("SELECT value FROM meta WHERE key='secret'").get();
  if (row) return row.value;
  const s = crypto.randomBytes(32).toString('hex');
  db.prepare("INSERT INTO meta (key, value) VALUES ('secret', ?)").run(s);
  return s;
}
const SECRET = getSecret();
const hmac = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');
function makeToken() {
  const exp = Date.now() + TOKEN_DAYS * 86400000;
  return `${exp}.${hmac(String(exp))}`;
}
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
function tokenValid(tok) {
  if (typeof tok !== 'string') return false;
  const i = tok.indexOf('.');
  if (i < 1) return false;
  const exp = tok.slice(0, i);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  return safeEqual(tok.slice(i + 1), hmac(exp));
}
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : '';
  if (!tokenValid(tok)) return res.status(401).json({ error: 'ต้องเข้าสู่ระบบ' });
  next();
}

/* ---------- login rate limit ---------- */
const attempts = new Map();
function limited(ip) {
  const now = Date.now();
  const a = attempts.get(ip);
  if (!a || a.reset < now) return false;
  return a.n >= 10;
}
function noteFail(ip) {
  const now = Date.now();
  const a = attempts.get(ip);
  if (!a || a.reset < now) attempts.set(ip, { n: 1, reset: now + 10 * 60000 });
  else a.n++;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of attempts) if (v.reset < now) attempts.delete(k);
}, 60000).unref();

/* ---------- live state ---------- */
const getRow = () => db.prepare('SELECT version, state, updated_at FROM live_state WHERE id=1').get();
const getVersion = () => getRow().version;

function validState(s) {
  return (
    s && typeof s === 'object' &&
    Array.isArray(s.players) && s.players.length <= 500 &&
    Array.isArray(s.courts) && s.courts.length >= 1 && s.courts.length <= 30 &&
    Array.isArray(s.history)
  );
}

/* ---------- SSE ---------- */
const clients = new Set();
function broadcast(version) {
  const msg = `data: ${JSON.stringify({ version })}\n\n`;
  for (const c of clients) c.write(msg);
}

/* ---------- board (public, sanitized: no money, no ids) ---------- */
function buildBoard() {
  const row = getRow();
  const S = row.state ? JSON.parse(row.state) : null;
  const base = { version: row.version, now: Date.now(), club: CLUB_NAME, size: 2, courts: [], queue: [], resting: 0 };
  if (!S) return base;
  const byId = new Map(S.players.map((p) => [p.id, p]));
  const pv = (id) => {
    const p = byId.get(id);
    return p ? { n: p.n, lv: p.lv } : null;
  };
  const busy = new Set();
  const sz = S.size === 1 ? 1 : 2;
  const courts = S.courts.map((c) => {
    if (c.m) {
      c.m.t.flat().forEach((id) => busy.add(id));
      return { no: c.no, status: 'playing', start: c.m.start, teams: c.m.t.map((t) => t.map(pv)) };
    }
    if (c.draft && c.draft.some(Boolean)) {
      c.draft.filter(Boolean).forEach((id) => busy.add(id));
      return { no: c.no, status: 'draft', teams: [c.draft.slice(0, sz).map(pv), c.draft.slice(sz).map(pv)] };
    }
    return { no: c.no, status: 'empty' };
  });
  const queue = S.players
    .filter((p) => p.st === 'in' && !busy.has(p.id))
    .sort((a, b) => a.g - b.g || a.ws - b.ws)
    .map((p) => ({ n: p.n, lv: p.lv, g: p.d ?? (p.w || 0) + (p.l || 0), ws: p.ws }));
  return {
    ...base,
    size: sz,
    courts,
    queue,
    resting: S.players.filter((p) => p.st === 'rest').length,
  };
}

/* ---------- billing archive ---------- */
function dayString(ts = Date.now()) {
  return new Date(ts).toLocaleDateString('sv-SE', { timeZone: TZ_NAME }); // YYYY-MM-DD
}
function archiveLive() {
  const row = getRow();
  if (!row.state) return { skipped: true };
  const S = JSON.parse(row.state);
  const fee = Number(S.fee) || 0;
  const shp = Number(S.shp) || 0;
  const lines = [];
  for (const p of S.players) {
    const games = p.d ?? (p.w || 0) + (p.l || 0);
    const pays = p.g > 0 || (S.feeAll && p.st !== 'out');
    const courtFee = pays ? fee : 0;
    const shutFee = (p.sh || 0) * shp;
    const total = courtFee + shutFee;
    if (total > 0) {
      lines.push({
        name: p.n, rank: RANKS[(p.lv || 3) - 1] || '', games, shuttles: p.sh || 0,
        courtFee, shutFee, total, paid: p.paid ? 1 : 0, mid: p.mid || null,
      });
    }
  }
  const hist = Array.isArray(S.history) ? S.history : [];
  if (!lines.length && !hist.length) return { skipped: true };

  const sum = (k) => lines.reduce((s, l) => s + l[k], 0);
  const tx = db.transaction(() => {
    const r = db.prepare(
      `INSERT INTO sessions (day, archived_at, players, games, shuttles, court_fee, shuttle_fee, total, paid)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      dayString(), new Date().toISOString(), lines.length, hist.length, S.shTotal || 0,
      sum('courtFee'), sum('shutFee'), sum('total'),
      lines.filter((l) => l.paid).reduce((s, l) => s + l.total, 0)
    );
    const sid = r.lastInsertRowid;
    const ip = db.prepare(
      `INSERT INTO session_players (session_id, name, rank, games, shuttles, court_fee, shuttle_fee, total, paid, member_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const l of lines) ip.run(sid, l.name, l.rank, l.games, l.shuttles, l.courtFee, l.shutFee, l.total, l.paid, l.mid);
    const ig = db.prepare(
      `INSERT INTO session_games (session_id, ended_at, court, team1, team2, winner, score1, score2, shuttles)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );
    for (const h of [...hist].reverse()) {
      ig.run(
        sid, new Date(h.t).toISOString(), h.court, (h.teams?.[0] || []).join(' + '), (h.teams?.[1] || []).join(' + '),
        h.win === 0 || h.win === 1 ? h.win : null, h.score ? h.score[0] : null, h.score ? h.score[1] : null, h.sh || 1
      );
    }
    return sid;
  });
  return { id: Number(tx()) };
}

/* ---------- app ---------- */
const app = express();
app.set('trust proxy', Number(process.env.TRUST_PROXY ?? 1));
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'same-origin');
  next();
});
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  if (req.method !== 'GET' && req.path.startsWith('/api/') && req.path !== '/api/login') backupDirty = true;
  next();
});

app.get('/healthz', (req, res) => res.json({ ok: true, version: getVersion() }));

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  if (limited(ip)) return res.status(429).json({ error: 'ใส่ PIN ผิดหลายครั้ง กรุณารอสักครู่แล้วลองใหม่' });
  const pin = req.body && req.body.pin;
  if (typeof pin !== 'string' || !safeEqual(pin, STAFF_PIN)) {
    noteFail(ip);
    return res.status(401).json({ error: 'PIN ไม่ถูกต้อง' });
  }
  res.json({ token: makeToken() });
});

app.get('/api/version', (req, res) => res.json({ version: getVersion() }));
app.get('/api/board', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json(buildBoard());
});

app.get('/api/events', (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  res.write('retry: 3000\n\n');
  res.write(`data: ${JSON.stringify({ version: getVersion() })}\n\n`);
  clients.add(res);
  const ka = setInterval(() => res.write(': keepalive\n\n'), 25000);
  req.on('close', () => {
    clearInterval(ka);
    clients.delete(res);
  });
});

app.get('/api/state', auth, (req, res) => {
  res.set('Cache-Control', 'no-store');
  const r = getRow();
  res.json({ version: r.version, state: r.state ? JSON.parse(r.state) : null });
});

app.put('/api/state', auth, (req, res) => {
  const { baseVersion, state } = req.body || {};
  if (!Number.isInteger(baseVersion) || !validState(state)) {
    return res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง' });
  }
  const tx = db.transaction(() => {
    const cur = getRow();
    if (cur.version !== baseVersion) {
      return { conflict: true, version: cur.version, state: cur.state ? JSON.parse(cur.state) : null };
    }
    const nv = cur.version + 1;
    db.prepare('UPDATE live_state SET version=?, state=?, updated_at=? WHERE id=1')
      .run(nv, JSON.stringify(state), new Date().toISOString());
    return { conflict: false, version: nv };
  });
  const r = tx();
  if (r.conflict) return res.status(409).json({ version: r.version, state: r.state });
  res.json({ version: r.version });
  broadcast(r.version);
});

app.post('/api/archive', auth, (req, res) => {
  try {
    const r = archiveLive();
    res.json(r);
    if (!r.skipped) setTimeout(autoBackup, 500).unref();
  } catch (e) {
    console.error('archive failed', e);
    res.status(500).json({ error: 'บันทึกประวัติรายวันไม่สำเร็จ' });
  }
});

app.get('/api/sessions', auth, (req, res) => {
  const rows = db.prepare(
    `SELECT id, day, archived_at, players, games, shuttles, court_fee, shuttle_fee, total, paid
     FROM sessions ORDER BY id DESC LIMIT 200`
  ).all();
  res.json({ sessions: rows });
});

app.get('/api/sessions/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  const s = db.prepare('SELECT * FROM sessions WHERE id=?').get(id);
  if (!s) return res.status(404).json({ error: 'ไม่พบข้อมูล' });
  const players = db.prepare('SELECT id, member_id, name, rank, games, shuttles, court_fee, shuttle_fee, total, paid FROM session_players WHERE session_id=? ORDER BY id').all(id);
  const games = db.prepare('SELECT ended_at, court, team1, team2, winner, score1, score2, shuttles FROM session_games WHERE session_id=? ORDER BY id').all(id);
  res.json({ session: s, players, games });
});

const csvCell = (v) => {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
app.get('/api/sessions/:id/csv', auth, (req, res) => {
  const id = Number(req.params.id);
  const s = db.prepare('SELECT * FROM sessions WHERE id=?').get(id);
  if (!s) return res.status(404).json({ error: 'ไม่พบข้อมูล' });
  const rows = db.prepare('SELECT name, rank, games, shuttles, court_fee, shuttle_fee, total, paid FROM session_players WHERE session_id=? ORDER BY id').all(id);
  const head = ['ชื่อ', 'ระดับ', 'เกม', 'ลูก', 'ค่าสนาม', 'ค่าลูก', 'รวม', 'จ่ายแล้ว'];
  const lines = [head.join(',')].concat(
    rows.map((r) => [r.name, r.rank, r.games, r.shuttles, r.court_fee, r.shuttle_fee, r.total, r.paid ? 'จ่ายแล้ว' : 'ยังไม่จ่าย'].map(csvCell).join(','))
  );
  res.set({
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="cool-cool-club-${s.day}.csv"`,
  });
  res.send('\ufeff' + lines.join('\r\n'));
});

app.get('/api/backup', auth, async (req, res) => {
  const tmp = path.join(os.tmpdir(), `ccc-backup-${Date.now()}.db`);
  try {
    await db.backup(tmp);
    res.download(tmp, `cool-cool-club-${dayString()}.db`, () => fs.unlink(tmp, () => {}));
  } catch (e) {
    console.error('backup failed', e);
    fs.unlink(tmp, () => {});
    res.status(500).json({ error: 'สำรองข้อมูลไม่สำเร็จ' });
  }
});


/* ---------- members (permanent roster) ---------- */
const cleanName = (v) => (typeof v === 'string' ? v.trim().replace(/\s+/g, ' ').slice(0, 40) : '');
const cleanRank = (v) => { const n = Number(v); return Number.isInteger(n) && n >= 1 && n <= 6 ? n : null; };
const cleanPhone = (v) => (typeof v === 'string' ? v.replace(/[^0-9+\-\s]/g, '').trim().slice(0, 20) : '');
const cleanNote = (v) => (typeof v === 'string' ? v.trim().slice(0, 200) : '');
const newMid = () => 'm_' + crypto.randomBytes(5).toString('hex');
const nowIso = () => new Date().toISOString();

const MEMBER_SELECT = `
SELECT m.id, m.name, m.rank, m.phone, m.note, m.active, m.created_at,
       COALESCE(s.visits, 0) AS visits, COALESCE(s.games, 0) AS games,
       COALESCE(s.spent, 0) AS spent, COALESCE(s.unpaid, 0) AS unpaid, s.last_day
FROM members m
LEFT JOIN (
  SELECT sp.member_id AS mid, COUNT(*) AS visits, SUM(sp.games) AS games, SUM(sp.total) AS spent,
         SUM(CASE WHEN sp.paid = 0 THEN sp.total ELSE 0 END) AS unpaid, MAX(se.day) AS last_day
  FROM session_players sp JOIN sessions se ON se.id = sp.session_id
  WHERE sp.member_id IS NOT NULL GROUP BY sp.member_id
) s ON s.mid = m.id`;
const memberRow = (id) => db.prepare(MEMBER_SELECT + ' WHERE m.id = ?').get(id);
const activeByName = (name) => db.prepare('SELECT * FROM members WHERE active = 1 AND lower(name) = lower(?)').get(name);

function ensureMember({ name, rank, phone, note }) {
  const n = cleanName(name);
  if (!n) return { error: 'ต้องใส่ชื่อ' };
  const found = activeByName(n);
  if (found) return { member: memberRow(found.id), created: false };
  const hidden = db.prepare('SELECT id FROM members WHERE active = 0 AND lower(name) = lower(?) ORDER BY updated_at DESC').get(n);
  if (hidden) {
    db.prepare('UPDATE members SET active = 1, updated_at = ? WHERE id = ?').run(nowIso(), hidden.id);
    return { member: memberRow(hidden.id), created: false, restored: true };
  }
  const id = newMid();
  const t = nowIso();
  db.prepare('INSERT INTO members (id, name, rank, phone, note, active, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)')
    .run(id, n, cleanRank(rank) || 3, cleanPhone(phone), cleanNote(note), t, t);
  return { member: memberRow(id), created: true };
}

app.get('/api/members', auth, (req, res) => {
  const where = req.query.hidden === '1' ? '' : ' WHERE m.active = 1';
  const rows = db.prepare(MEMBER_SELECT + where).all();
  res.set('Cache-Control', 'no-store');
  res.json({ members: rows });
});

app.get('/api/members.csv', auth, (req, res) => {
  const rows = db.prepare(MEMBER_SELECT + ' ORDER BY m.active DESC, m.name').all();
  const head = ['ชื่อ', 'ระดับ', 'เบอร์โทร', 'หมายเหตุ', 'สถานะ', 'มาแล้ว(ครั้ง)', 'เกมรวม', 'ยอดใช้จ่ายรวม', 'ค้างจ่าย', 'มาล่าสุด'];
  const lines = [head.join(',')].concat(rows.map((r) => [
    r.name, RANKS[r.rank - 1], r.phone, r.note, r.active ? 'ใช้งาน' : 'ซ่อนไว้', r.visits, r.games, r.spent, r.unpaid, r.last_day || '',
  ].map(csvCell).join(',')));
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="cool-cool-club-members-${dayString()}.csv"` });
  res.send('\ufeff' + lines.join('\r\n'));
});

app.post('/api/members/ensure', auth, (req, res) => {
  const r = ensureMember(req.body || {});
  if (r.error) return res.status(400).json({ error: r.error });
  res.json(r);
});

app.post('/api/members/bulk', auth, (req, res) => {
  const rows = Array.isArray(req.body && req.body.rows) ? req.body.rows.slice(0, 300) : null;
  if (!rows) return res.status(400).json({ error: 'ข้อมูลไม่ถูกต้อง' });
  const out = { members: [], created: 0, existing: 0, skipped: 0 };
  db.transaction(() => {
    for (const row of rows) {
      const r = ensureMember(typeof row === 'string' ? { name: row } : row || {});
      if (r.error) { out.skipped++; continue; }
      out.members.push(r.member);
      if (r.created) out.created++; else out.existing++;
    }
  })();
  res.json(out);
});

app.get('/api/members/:id', auth, (req, res) => {
  const m = memberRow(req.params.id);
  if (!m) return res.status(404).json({ error: 'ไม่พบสมาชิก' });
  const sessions = db.prepare(
    `SELECT sp.id, sp.session_id, se.day, sp.games, sp.shuttles, sp.total, sp.paid
     FROM session_players sp JOIN sessions se ON se.id = sp.session_id
     WHERE sp.member_id = ? ORDER BY se.day DESC, sp.id DESC LIMIT 60`
  ).all(req.params.id);
  res.json({ member: m, sessions });
});

app.put('/api/members/:id', auth, (req, res) => {
  const cur = db.prepare('SELECT * FROM members WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'ไม่พบสมาชิก' });
  const b = req.body || {};
  const next = { ...cur };
  if (b.name !== undefined) { next.name = cleanName(b.name); if (!next.name) return res.status(400).json({ error: 'ต้องใส่ชื่อ' }); }
  if (b.rank !== undefined) { const r = cleanRank(b.rank); if (!r) return res.status(400).json({ error: 'ระดับไม่ถูกต้อง' }); next.rank = r; }
  if (b.phone !== undefined) next.phone = cleanPhone(b.phone);
  if (b.note !== undefined) next.note = cleanNote(b.note);
  if (b.active !== undefined) next.active = b.active ? 1 : 0;
  if (next.active) {
    const clash = db.prepare('SELECT id FROM members WHERE active = 1 AND lower(name) = lower(?) AND id <> ?').get(next.name, cur.id);
    if (clash) return res.status(409).json({ error: 'มีสมาชิกชื่อนี้อยู่แล้ว ลองเติมนามสกุลหรือเลขต่อท้ายให้ต่างกัน' });
  }
  db.prepare('UPDATE members SET name=?, rank=?, phone=?, note=?, active=?, updated_at=? WHERE id=?')
    .run(next.name, next.rank, next.phone, next.note, next.active, nowIso(), cur.id);
  res.json({ member: memberRow(cur.id) });
});

app.delete('/api/members/:id', auth, (req, res) => {
  const cur = db.prepare('SELECT * FROM members WHERE id = ?').get(req.params.id);
  if (!cur) return res.status(404).json({ error: 'ไม่พบสมาชิก' });
  if (req.query.permanent !== '1') {
    db.prepare('UPDATE members SET active = 0, updated_at = ? WHERE id = ?').run(nowIso(), cur.id);
    return res.json({ hidden: true });
  }
  // ลบถาวร (ขอลบข้อมูลตาม PDPA): ยอดเงินในประวัติยังอยู่ แต่ชื่อถูกแทนที่
  const GONE = '(ลบข้อมูลแล้ว)';
  db.transaction(() => {
    const names = db.prepare('SELECT DISTINCT name FROM session_players WHERE member_id = ?').all(cur.id).map((r) => r.name);
    names.push(cur.name);
    db.prepare('UPDATE session_players SET name = ?, member_id = NULL WHERE member_id = ?').run(GONE, cur.id);
    const upd = db.prepare('UPDATE session_games SET team1 = ?, team2 = ? WHERE id = ?');
    const swap = (txt) => txt.split(' + ').map((n) => (names.includes(n) ? GONE : n)).join(' + ');
    for (const g of db.prepare('SELECT id, team1, team2 FROM session_games').all()) {
      const a = swap(g.team1), b2 = swap(g.team2);
      if (a !== g.team1 || b2 !== g.team2) upd.run(a, b2, g.id);
    }
    db.prepare('DELETE FROM members WHERE id = ?').run(cur.id);
  })();
  res.json({ deleted: true });
});

app.put('/api/session-players/:id', auth, (req, res) => {
  const id = Number(req.params.id);
  const row = db.prepare('SELECT * FROM session_players WHERE id = ?').get(id);
  if (!row) return res.status(404).json({ error: 'ไม่พบข้อมูล' });
  const paid = req.body && req.body.paid ? 1 : 0;
  db.transaction(() => {
    db.prepare('UPDATE session_players SET paid = ? WHERE id = ?').run(paid, id);
    db.prepare('UPDATE sessions SET paid = (SELECT COALESCE(SUM(total), 0) FROM session_players WHERE session_id = ? AND paid = 1) WHERE id = ?')
      .run(row.session_id, row.session_id);
  })();
  res.json({ ok: true, paid });
});

/* ---------- automatic backups ---------- */
let backupDirty = true;
let backupRunning = false;
function pruneBackups() {
  const files = fs.readdirSync(BACKUP_DIR).filter((n) => /^club-\d{4}-\d{2}-\d{2}\.db$/.test(n)).sort();
  while (files.length > BACKUP_KEEP) fs.unlinkSync(path.join(BACKUP_DIR, files.shift()));
}
async function autoBackup() {
  if (backupRunning || !backupDirty) return;
  backupRunning = true;
  backupDirty = false;
  try {
    fs.mkdirSync(BACKUP_DIR, { recursive: true });
    const f = path.join(BACKUP_DIR, `club-${dayString()}.db`);
    await db.backup(f + '.tmp');
    fs.renameSync(f + '.tmp', f);
    pruneBackups();
  } catch (e) {
    backupDirty = true;
    console.error('สำรองอัตโนมัติไม่สำเร็จ', e);
  } finally {
    backupRunning = false;
  }
}
app.get('/api/backup/status', auth, (req, res) => {
  let files = [];
  try {
    files = fs.readdirSync(BACKUP_DIR).filter((n) => /^club-\d{4}-\d{2}-\d{2}\.db$/.test(n)).sort().reverse()
      .map((n) => { const st = fs.statSync(path.join(BACKUP_DIR, n)); return { name: n, size: st.size, at: st.mtime.toISOString() }; });
  } catch {}
  res.json({ keep: BACKUP_KEEP, count: files.length, latest: files[0] || null });
});

/* ---------- seed members from an existing live board (first run after upgrade) ---------- */
function seedMembersFromLive() {
  if (db.prepare('SELECT COUNT(*) AS c FROM members').get().c > 0) return;
  const row = getRow();
  if (!row.state) return;
  const S = JSON.parse(row.state);
  let changed = false;
  db.transaction(() => {
    for (const p of S.players) {
      if (p.mid) continue;
      const r = ensureMember({ name: p.n, rank: p.lv });
      if (r.member) { p.mid = r.member.id; changed = true; }
    }
    if (changed) db.prepare('UPDATE live_state SET version = version + 1, state = ?, updated_at = ? WHERE id = 1').run(JSON.stringify(S), nowIso());
  })();
}

const pub = path.join(__dirname, 'public');
app.get('/', (req, res) => res.sendFile(path.join(pub, 'board.html')));
app.get('/board', (req, res) => res.redirect('/'));
app.get('/staff', (req, res) => res.sendFile(path.join(pub, 'staff.html')));
app.use(express.static(pub, { index: false, maxAge: '1h' }));
app.use('/api', (req, res) => res.status(404).json({ error: 'ไม่พบ API นี้' }));

seedMembersFromLive();
autoBackup();
setInterval(autoBackup, 30 * 60000).unref();

const server = app.listen(PORT, () => {
  console.log(`${CLUB_NAME} พร้อมใช้งานที่พอร์ต ${PORT}`);
  console.log(`  บอร์ดผู้เล่น:   http://localhost:${PORT}/`);
  console.log(`  หน้าเจ้าหน้าที่: http://localhost:${PORT}/staff`);
  console.log(`  ฐานข้อมูล:      ${DB_PATH}`);
});

function shutdown() {
  console.log('กำลังปิดเซิร์ฟเวอร์...');
  for (const c of clients) c.end();
  server.close(() => {
    db.close();
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

module.exports = { app, server };
