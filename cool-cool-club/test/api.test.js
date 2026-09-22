'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');

const PORT = 3900 + Math.floor(Math.random() * 90);
const BASE = `http://127.0.0.1:${PORT}`;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ccc-'));
let proc;
let token;

const j = (p, o = {}) =>
  fetch(BASE + p, {
    ...o,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}), ...(o.headers || {}) },
  });

function sampleState() {
  const now = Date.now();
  const mk = (id, n, lv, extra = {}) => ({ id, n, lv, st: 'in', g: 0, d: 0, w: 0, l: 0, sh: 0, ws: now, paid: false, pt: {}, op: {}, ...extra });
  return {
    players: [mk('a', 'โอ๊ต', 6, { g: 1, d: 1, w: 1, sh: 2 }), mk('b', 'เบิร์ด', 3, { g: 1, d: 1, sh: 2 }),
      mk('c', 'ต้น', 2, { g: 1, d: 1, l: 1, sh: 2 }), mk('d', 'แบงค์', 4, { g: 1, d: 1, l: 1, sh: 2 }), mk('e', 'มิว', 3), mk('f', 'ฝ้าย', 1, { st: 'rest' })],
    courts: [{ no: 5, m: null, draft: null }, { no: 6, m: { t: [['a', 'b'], ['c', 'd']], start: now, sh: 1, ws: {} }, draft: null }],
    size: 2, balance: true, fee: 95, shp: 26, feeAll: false, shTotal: 2,
    history: [{ t: now, court: 5, teams: [['โอ๊ต', 'เบิร์ด'], ['ต้น', 'แบงค์']], ids: ['a', 'b', 'c', 'd'], score: [21, 15], win: 0, sh: 2 }],
  };
}

before(async () => {
  proc = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
    env: { ...process.env, PORT: String(PORT), STAFF_PIN: '2468', DB_PATH: path.join(dir, 'test.db'), TRUST_PROXY: '0' },
    stdio: 'ignore',
  });
  for (let i = 0; i < 50; i++) {
    try { if ((await fetch(BASE + '/healthz')).ok) return; } catch {}
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('server did not start');
});
after(() => { proc && proc.kill(); fs.rmSync(dir, { recursive: true, force: true }); });

test('public pages are served', async () => {
  assert.equal((await fetch(BASE + '/')).status, 200);
  assert.equal((await fetch(BASE + '/staff')).status, 200);
});

test('state endpoints require login', async () => {
  assert.equal((await j('/api/state')).status, 401);
  assert.equal((await j('/api/state', { method: 'PUT', body: '{}' })).status, 401);
  assert.equal((await j('/api/sessions')).status, 401);
  assert.equal((await j('/api/backup')).status, 401);
});

test('wrong PIN rejected, right PIN returns token', async () => {
  assert.equal((await j('/api/login', { method: 'POST', body: JSON.stringify({ pin: '0000' }) })).status, 401);
  const r = await j('/api/login', { method: 'POST', body: JSON.stringify({ pin: '2468' }) });
  assert.equal(r.status, 200);
  token = (await r.json()).token;
  assert.ok(token.includes('.'));
});

test('forged token rejected', async () => {
  const saved = token;
  token = '9999999999999.forged';
  assert.equal((await j('/api/state')).status, 401);
  token = saved;
});

test('empty state, then save and optimistic concurrency', async () => {
  let r = await (await j('/api/state')).json();
  assert.equal(r.state, null);
  const v0 = r.version;
  const put = await j('/api/state', { method: 'PUT', body: JSON.stringify({ baseVersion: v0, state: sampleState() }) });
  assert.equal(put.status, 200);
  const v1 = (await put.json()).version;
  assert.equal(v1, v0 + 1);
  const stale = await j('/api/state', { method: 'PUT', body: JSON.stringify({ baseVersion: v0, state: sampleState() }) });
  assert.equal(stale.status, 409);
  const body = await stale.json();
  assert.equal(body.version, v1);
  assert.equal(body.state.players.length, 6);
  const bad = await j('/api/state', { method: 'PUT', body: JSON.stringify({ baseVersion: v1, state: { nope: 1 } }) });
  assert.equal(bad.status, 400);
});

test('public board hides money and ids', async () => {
  const raw = await (await fetch(BASE + '/api/board')).text();
  const b = JSON.parse(raw);
  assert.equal(b.courts.length, 2);
  assert.equal(b.courts[1].status, 'playing');
  assert.equal(b.courts[1].teams[0][0].n, 'โอ๊ต');
  assert.equal(b.queue.length, 1);          // เฉพาะ "มิว" (ฝ้ายพัก, 4 คนกำลังเล่น)
  assert.equal(b.queue[0].n, 'มิว');
  assert.equal(b.resting, 1);
  for (const key of ['fee', 'shp', 'paid', '"sh"', '"id"', 'shTotal']) assert.ok(!raw.includes(key), 'leaked ' + key);
});

test('SSE announces new versions', async () => {
  const ctrl = new AbortController();
  const res = await fetch(BASE + '/api/events', { signal: ctrl.signal });
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let text = '';
  const first = await reader.read();
  text += dec.decode(first.value);
  assert.ok(/"version":\d+/.test(text));
  const cur = (await (await j('/api/state')).json());
  const put = await j('/api/state', { method: 'PUT', body: JSON.stringify({ baseVersion: cur.version, state: cur.state }) });
  const nv = (await put.json()).version;
  let seen = false;
  const t0 = Date.now();
  while (!seen && Date.now() - t0 < 3000) {
    const { value } = await reader.read();
    text += dec.decode(value);
    seen = text.includes(`"version":${nv}`);
  }
  ctrl.abort();
  assert.ok(seen, 'no SSE event for version ' + nv);
});

test('archive day, list, detail, csv, backup', async () => {
  const a = await (await j('/api/archive', { method: 'POST', body: '{}' })).json();
  assert.ok(a.id > 0);
  const list = (await (await j('/api/sessions')).json()).sessions;
  assert.equal(list.length, 1);
  // 4 players x (95 + 2*26) = 4 x 147 = 588
  assert.equal(list[0].players, 4);
  assert.equal(list[0].court_fee, 380);
  assert.equal(list[0].shuttle_fee, 208);
  assert.equal(list[0].total, 588);
  const d = await (await j('/api/sessions/' + a.id)).json();
  assert.equal(d.players.length, 4);
  assert.equal(d.games.length, 1);
  assert.equal(d.games[0].score1, 21);
  const csv = await j('/api/sessions/' + a.id + '/csv');
  assert.equal(csv.status, 200);
  const csvText = await csv.text();
  assert.ok(csvText.includes('โอ๊ต'));
  const bk = await j('/api/backup');
  assert.equal(bk.status, 200);
  const buf = Buffer.from(await bk.arrayBuffer());
  assert.equal(buf.slice(0, 15).toString(), 'SQLite format 3');
});

test('login is rate limited after repeated failures', async () => {
  let last;
  for (let i = 0; i < 12; i++) last = await j('/api/login', { method: 'POST', body: JSON.stringify({ pin: 'wrong' + i }) });
  assert.equal(last.status, 429);
});

/* ---------- members (permanent roster) ---------- */
let mA, mB;
test('members: ensure creates, repeats return the same person', async () => {
  const r1 = await (await j('/api/members/ensure', { method: 'POST', body: JSON.stringify({ name: '  โอ๊ต  ', rank: 6 }) })).json();
  assert.equal(r1.created, true);
  assert.equal(r1.member.name, 'โอ๊ต');
  assert.equal(r1.member.rank, 6);
  mA = r1.member;
  const r2 = await (await j('/api/members/ensure', { method: 'POST', body: JSON.stringify({ name: 'โอ๊ต' }) })).json();
  assert.equal(r2.created, false);
  assert.equal(r2.member.id, mA.id);
  assert.equal((await j('/api/members/ensure', { method: 'POST', body: JSON.stringify({ name: '   ' }) })).status, 400);
});

test('members: bulk import with rank and phone, duplicates skipped', async () => {
  const r = await (await j('/api/members/bulk', { method: 'POST', body: JSON.stringify({ rows: [
    { name: 'เบิร์ด', rank: 3, phone: '081-234-5678', note: 'มาทุกวันพุธ' }, 'ต้น', { name: 'โอ๊ต' }, { name: '' },
  ] }) })).json();
  assert.equal(r.created, 2);
  assert.equal(r.existing, 1);
  assert.equal(r.skipped, 1);
  mB = r.members.find((m) => m.name === 'เบิร์ด');
  assert.equal(mB.phone, '081-234-5678');
  const list = (await (await j('/api/members')).json()).members;
  assert.equal(list.length, 3);
});

test('members: edit, name clash, hide and restore', async () => {
  let r = await j('/api/members/' + mB.id, { method: 'PUT', body: JSON.stringify({ rank: 4, note: 'ย้ายมือ' }) });
  assert.equal((await r.json()).member.rank, 4);
  r = await j('/api/members/' + mB.id, { method: 'PUT', body: JSON.stringify({ name: 'โอ๊ต' }) });
  assert.equal(r.status, 409);
  assert.equal((await j('/api/members/' + mB.id, { method: 'PUT', body: JSON.stringify({ rank: 9 }) })).status, 400);
  await j('/api/members/' + mB.id, { method: 'DELETE' });
  let list = (await (await j('/api/members')).json()).members;
  assert.equal(list.length, 2);
  list = (await (await j('/api/members?hidden=1')).json()).members;
  assert.equal(list.length, 3);
  r = await (await j('/api/members/' + mB.id, { method: 'PUT', body: JSON.stringify({ active: true }) })).json();
  assert.equal(r.member.active, 1);
});

test('members: archive links visits, spending and unpaid to the person; paid can be ticked later', async () => {
  const cur = await (await j('/api/state')).json();
  const st = cur.state;
  st.players[0].mid = mA.id; // โอ๊ต
  st.players[1].mid = mB.id; // เบิร์ด
  st.history = st.history.length ? st.history : [];
  const put = await j('/api/state', { method: 'PUT', body: JSON.stringify({ baseVersion: cur.version, state: st }) });
  assert.equal(put.status, 200);
  const a = await (await j('/api/archive', { method: 'POST', body: '{}' })).json();
  assert.ok(a.id);
  let m = (await (await j('/api/members/' + mA.id)).json());
  assert.equal(m.member.visits, 1);
  assert.equal(m.member.spent, 147);        // 95 + 2 x 26
  assert.equal(m.member.unpaid, 147);
  assert.equal(m.sessions.length, 1);
  const rowId = m.sessions[0].id;
  assert.equal((await j('/api/session-players/' + rowId, { method: 'PUT', body: JSON.stringify({ paid: true }) })).status, 200);
  m = await (await j('/api/members/' + mA.id)).json();
  assert.equal(m.member.unpaid, 0);
  const sess = (await (await j('/api/sessions')).json()).sessions.find((s) => s.id === a.id);
  assert.equal(sess.paid, 147);
});

test('members: csv export includes phone and stats', async () => {
  const r = await j('/api/members.csv');
  assert.equal(r.status, 200);
  const t = await r.text();
  assert.ok(t.includes('081-234-5678'));
  assert.ok(t.includes('โอ๊ต'));
});

test('members: permanent delete keeps money history but removes the name', async () => {
  const before = await (await j('/api/members/' + mB.id)).json();
  assert.equal(before.sessions.length, 1);
  assert.equal((await j('/api/members/' + mB.id + '?permanent=1', { method: 'DELETE' })).status, 200);
  assert.equal((await j('/api/members/' + mB.id)).status, 404);
  const sid = before.sessions[0].session_id;
  const d = await (await j('/api/sessions/' + sid)).json();
  const raw = JSON.stringify(d);
  assert.ok(!raw.includes('เบิร์ด'), 'name still present in history');
  assert.ok(raw.includes('(ลบข้อมูลแล้ว)'));
  assert.equal(d.players.length, 4);       // ยอดเงินยังอยู่ครบ
});

test('automatic backup file is created and reported', async () => {
  let st;
  for (let i = 0; i < 30; i++) {
    st = await (await j('/api/backup/status')).json();
    if (st.count > 0) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  assert.ok(st.count >= 1);
  assert.ok(/^club-\d{4}-\d{2}-\d{2}\.db$/.test(st.latest.name));
  const f = path.join(dir, 'backups', st.latest.name);
  assert.equal(fs.readFileSync(f).slice(0, 15).toString(), 'SQLite format 3');
});
