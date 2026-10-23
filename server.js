"use strict";
const express = require("express");
const { density15, daysOfMonth, buildStockRegister, buildDensityRegister, buildMeterRegister, daysBetween } = require("./registers");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const path = require("path");

const PORT = +process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";
const TZ = process.env.TZ_NAME || "Asia/Kolkata";
const db = new Database(process.env.DB_PATH || path.join(__dirname, "data.db"));
db.pragma("journal_mode = WAL");
db.exec(`
create table if not exists users(
  id integer primary key, name text not null, mobile text unique not null,
  hash text not null, role text not null check(role in ('owner','manager','worker')),
  active integer not null default 1);
create table if not exists sessions(token text primary key, user_id integer not null, exp integer not null);
create table if not exists state(id integer primary key check(id = 1), ver integer not null, json text not null);
create table if not exists credit_sales(
  id integer primary key, cust_id text not null, d text not null, n text not null,
  a real not null, veh text, worker_id integer not null, created integer not null,
  status text not null default 'ok');
`);
if (!db.prepare("pragma table_info(credit_sales)").all().some((c) => c.name === "status"))
  db.exec("alter table credit_sales add column status text not null default 'ok'");

addColLang();
function addColLang() { if (!db.prepare("pragma table_info(users)").all().some((c) => c.name === "lang")) db.exec("alter table users add column lang text not null default 'en'"); }
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use((q, s, n) => {
  s.set({
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Content-Security-Policy":
      "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob: https:; connect-src 'self' *;",
  });
  n();
});
app.use(express.json({ limit: "8mb" }));
// CSRF guard: every state-changing call must carry a custom header a cross-site form cannot send.
app.use((q, s, n) => {
  if (q.method !== "GET" && q.method !== "HEAD" && q.get("x-app") !== "1") return s.status(403).json({ error: "Forbidden." });
  n();
});
// Every successful change is recorded, with who did it (AUD is defined further down).
app.use((q, s, n) => {
  if (q.method !== "GET") s.on("finish", () => {
    const f = AUD[q.method + " " + (q.route && q.route.path)];
    if (f && s.statusCode < 400 && q.user) audit(q.user, "action", f(q));
  });
  n();
});


const now = () => Math.floor(Date.now() / 1000);
const DAY = 86400;
const hs = (t) => crypto.createHash("sha256").update(t).digest("hex");
const mob = (x) => String(x || "").replace(/\D/g, "").slice(-10);
const pub = (u) => ({ id: u.id, name: u.name, mobile: u.mobile, role: u.role, lang: u.lang || "en" });
const today = () => new Date().toLocaleDateString("en-CA", { timeZone: TZ });
const usersCount = () => db.prepare("select count(*) n from users").get().n;

function cookie(q, k) {
  const m = (q.headers.cookie || "").split(";").map((x) => x.trim()).find((x) => x.startsWith(k + "="));
  return m ? decodeURIComponent(m.slice(k.length + 1)) : null;
}
function getSessionToken(q) {
  const auth = q.headers.authorization;
  if (auth && auth.startsWith("Bearer ")) {
    return auth.slice(7).trim();
  }
  const xToken = q.headers["x-session-token"] || q.headers["x-token"];
  if (xToken) return String(xToken).trim();
  return cookie(q, "sid");
}
function getUser(q) {
  const t = getSessionToken(q);
  if (!t) return null;
  const r = db.prepare("select u.id,u.name,u.mobile,u.role,u.lang,u.active,s.exp from sessions s join users u on u.id=s.user_id where s.token=?").get(hs(t));
  return r && r.active && r.exp >= now() ? r : null;
}
const need = (...roles) => (q, s, n) => {
  const u = getUser(q);
  if (!u) return s.status(401).json({ error: "Please log in." });
  if (roles.length && !roles.includes(u.role)) return s.status(403).json({ error: "You do not have access to this." });
  q.user = u;
  n();
};
function startSession(q, s, uid) {
  const t = crypto.randomBytes(32).toString("hex");
  db.prepare("insert into sessions values(?,?,?)").run(hs(t), uid, now() + 7 * DAY);
  const isSecure = q.secure || q.headers["x-forwarded-proto"] === "https";
  const cookieOpts = isSecure ? "SameSite=None; Secure; Partitioned" : "SameSite=Lax";
  s.setHeader("Set-Cookie", `sid=${t}; HttpOnly; ${cookieOpts}; Path=/; Max-Age=${7 * DAY}`);
  return t;
}
function checkUser(name, m, pw) {
  if (!String(name || "").trim() || String(name).length > 60) return "Enter a name (up to 60 characters).";
  if (m.length !== 10) return "Enter a 10-digit mobile number.";
  if (typeof pw !== "string" || pw.length < 6 || pw.length > 100) return "Password must be at least 6 characters.";
  return null;
}

// Login throttle: 5 wrong tries per IP + mobile locks that pair for 15 minutes.
db.exec(`create table if not exists login_fails(k text primary key, n integer not null, t integer not null);`);
const failRow = (k) => db.prepare("select n,t from login_fails where k=?").get(k);
const blocked = (k) => { const f = failRow(k); return !!f && f.n >= 5 && Date.now() - f.t < 15 * 60e3; };
const addFail = (k) => { const f = failRow(k); const n = f && Date.now() - f.t <= 15 * 60e3 ? f.n + 1 : 1; db.prepare("insert into login_fails(k,n,t) values(?,?,?) on conflict(k) do update set n=excluded.n, t=excluded.t").run(k, n, Date.now()); };
const clearFail = (k) => db.prepare("delete from login_fails where k=?").run(k);

app.get("/api/me", (q, s) => {
  const u = getUser(q);
  s.json({ user: u ? pub(u) : null, setup: usersCount() === 0, biz: bizDate() });
});
app.post("/api/setup", (q, s) => {
  if (usersCount() > 0) return s.status(403).json({ error: "Setup is already done." });
  const { name, mobile, password } = q.body || {};
  const e = checkUser(name, mob(mobile), password);
  if (e) return s.status(400).json({ error: e });
  const id = db.prepare("insert into users(name,mobile,hash,role) values(?,?,?,'owner')").run(String(name).trim(), mob(mobile), bcrypt.hashSync(password, 10)).lastInsertRowid;
  const token = startSession(q, s, id);
  s.json({ user: { id, name: String(name).trim(), mobile: mob(mobile), role: "owner" }, token });
});
app.post("/api/reset-setup", (q, s) => {
  const dutiesCount = db.prepare("select count(*) n from duties").get().n;
  const salesCount = db.prepare("select count(*) n from shop_sales").get().n;
  if (dutiesCount === 0 && salesCount === 0) {
    db.prepare("delete from sessions").run();
    db.prepare("delete from users").run();
    db.prepare("delete from login_fails").run();
    return s.json({ ok: true });
  }
  return s.status(403).json({ error: "Cannot reset setup once duties or sales exist." });
});
app.post("/api/login", (q, s) => {
  const m = mob(q.body && q.body.mobile), p = String((q.body && q.body.password) || ""), k = q.ip + "|" + m;
  if (blocked(k)) return s.status(429).json({ error: "Too many wrong attempts. Try again in 15 minutes." });
  const u = db.prepare("select * from users where mobile=?").get(m);
  if (!u || !u.active || !bcrypt.compareSync(p, u.hash)) { addFail(k); return s.status(401).json({ error: "Wrong mobile number or password." }); }
  clearFail(k);
  const token = startSession(q, s, u.id);
  audit(u, "login", "Logged in");
  s.json({ user: pub(u), token });
});
app.post("/api/logout", (q, s) => {
  const t = getSessionToken(q);
  if (t) db.prepare("delete from sessions where token=?").run(hs(t));
  const isSecure = q.secure || q.headers["x-forwarded-proto"] === "https";
  const cookieOpts = isSecure ? "SameSite=None; Secure; Partitioned" : "SameSite=Lax";
  s.setHeader("Set-Cookie", `sid=; HttpOnly; ${cookieOpts}; Path=/; Max-Age=0`);
  s.json({ ok: true });
});
app.post("/api/lang", need(), (q, s) => {
  const lang = q.body && q.body.lang;
  if (!["en", "mr", "hi"].includes(lang)) return s.status(400).json({ error: "Unknown language." });
  db.prepare("update users set lang=? where id=?").run(lang, q.user.id);
  s.json({ ok: true });
});
app.post("/api/password", need(), (q, s) => {
  const { old, password } = q.body || {};
  const u = db.prepare("select * from users where id=?").get(q.user.id);
  if (!bcrypt.compareSync(String(old || ""), u.hash)) return s.status(400).json({ error: "Current password is wrong." });
  if (typeof password !== "string" || password.length < 6 || password.length > 100) return s.status(400).json({ error: "New password must be at least 6 characters." });
  db.prepare("update users set hash=? where id=?").run(bcrypt.hashSync(password, 10), u.id);
  const keep = hs(getSessionToken(q) || "");
  db.prepare("delete from sessions where user_id=? and token<>?").run(u.id, keep);
  s.json({ ok: true });
});

// ---- Team (owner only)
app.get("/api/users", need("owner", "manager"), (q, s) =>
  s.json(db.prepare(q.user.role === "owner" ? "select id,name,mobile,role,active from users order by id" : "select id,name,mobile,role,active from users where role='worker' order by id").all()));
app.post("/api/users", need("owner", "manager"), (q, s) => {
  const { name, mobile, password, role } = q.body || {};
  const m = mob(mobile);
  if (!["manager", "worker"].includes(role)) return s.status(400).json({ error: "Choose manager or worker." });
  if (q.user.role === "manager" && role !== "worker") return s.status(403).json({ error: "Managers can add workers only." });
  const e = checkUser(name, m, password);
  if (e) return s.status(400).json({ error: e });
  if (db.prepare("select 1 from users where mobile=?").get(m)) return s.status(409).json({ error: "This mobile number is already registered." });
  db.prepare("insert into users(name,mobile,hash,role) values(?,?,?,?)").run(String(name).trim(), m, bcrypt.hashSync(password, 10), role);
  s.json({ ok: true });
});
app.patch("/api/users/:id", need("owner", "manager"), (q, s) => {
  const id = +q.params.id, u = db.prepare("select * from users where id=?").get(id);
  if (!u) return s.status(404).json({ error: "User not found." });
  if (q.user.role === "manager" && u.role !== "worker") return s.status(403).json({ error: "Managers can change workers only." });
  const { active, password, name } = q.body || {};
  if (active !== undefined) {
    if (u.id === q.user.id) return s.status(400).json({ error: "You cannot deactivate your own account." });
    db.prepare("update users set active=? where id=?").run(active ? 1 : 0, id);
    if (!active) db.prepare("delete from sessions where user_id=?").run(id);
  }
  if (password !== undefined) {
    if (typeof password !== "string" || password.length < 6 || password.length > 100) return s.status(400).json({ error: "Password must be at least 6 characters." });
    db.prepare("update users set hash=? where id=?").run(bcrypt.hashSync(password, 10), id);
    db.prepare("delete from sessions where user_id=?").run(id);
  }
  if (name !== undefined && String(name).trim()) db.prepare("update users set name=? where id=?").run(String(name).trim().slice(0, 60), id);
  s.json({ ok: true });
});

// ---- Shared business data (owner and manager)
// ---- Shared business data, split into sections so edits rarely clash
db.exec(`
create table if not exists sections(name text primary key, ver integer not null, json text not null);
create table if not exists audit(id integer primary key, t integer not null, user_id integer, user_name text, action text not null, detail text);
`);
const SECTIONS = { c: ["c"], items: ["items", "itemcats"], sup: ["sup"], bk: ["bk", "ob", "cf"], biz: ["biz"], tanks: ["tanks", "deliv"], setup: ["nozzles", "rates", "expcats", "paymodes", "fuelprods"] };
const ARRAY_KEYS = new Set(["c", "shop", "items", "sup", "bk", "tanks", "deliv", "nozzles", "rates", "expcats", "paymodes", "fuelprods", "itemcats"]);
const LABEL = { c: "Customers", shop: "Shop sales", items: "Stock items", sup: "Suppliers", bk: "Book entries", ob: "Opening balances", cf: "Cash flow starting cash", biz: "Business details", tanks: "Tanks", deliv: "Fuel deliveries", nozzles: "Nozzles", rates: "Fuel rates", expcats: "Expense categories", paymodes: "Payment modes", fuelprods: "Fuel products", itemcats: "Product categories" };
function audit(u, action, detail) {
  try { db.prepare("insert into audit(t,user_id,user_name,action,detail) values(?,?,?,?,?)").run(now(), u ? u.id : null, u ? u.name : "", action, String(detail || "").slice(0, 600)); } catch (e) {
    console.error("Audit log failed:", e.message); /* never block the request */ }
}
db.exec(`create table if not exists atg_readings(id integer primary key, tank_id text not null, bd text not null, litres real not null, t integer not null, user_id integer, unique(tank_id, bd));`);
db.exec(`create table if not exists shop_sales(id integer primary key, d text not null, mode text not null, lines_json text not null, total real not null, note text, worker_id integer, created integer not null);`);
function shopRows() {
  return db.prepare("select * from shop_sales order by id").all().map((r) => ({ id: r.id, d: r.d, mode: r.mode, lines: JSON.parse(r.lines_json), total: r.total, note: r.note || "" }));
}
function readSections() {
  const state = {}, vers = {};
  db.prepare("select * from sections").all().forEach((r) => { vers[r.name] = r.ver; Object.assign(state, JSON.parse(r.json)); });
  state.shop = shopRows();
  return { state, vers };
}
const stateNow = () => readSections().state;
function writeSection(name, obj) {
  const r = db.prepare("select ver from sections where name=?").get(name), ver = (r ? r.ver : 0) + 1;
  db.prepare("insert into sections(name,ver,json) values(?,?,?) on conflict(name) do update set ver=excluded.ver, json=excluded.json").run(name, ver, JSON.stringify(obj));
  return ver;
}
// One-time move from the old single-record layout
(() => {
  if (db.prepare("select 1 from sections limit 1").get()) return;
  const old = db.prepare("select json from state where id=1").get();
  if (!old) return;
  const st = JSON.parse(old.json);
  db.transaction(() => {
    for (const [n, keys] of Object.entries(SECTIONS)) {
      const o = {};
      keys.forEach((k) => { if (st[k] !== undefined) o[k] = st[k]; });
      db.prepare("insert into sections values(?,?,?)").run(n, 1, JSON.stringify(o));
    }
  })();
})();
const hasId = (x) => x && typeof x === "object" && x.id !== undefined;
function diffSummary(before, after) {
  const out = [];
  for (const k of Object.keys(after)) {
    const b = after[k], a = before[k] === undefined && Array.isArray(b) ? [] : before[k];
    if (JSON.stringify(a) === JSON.stringify(b)) continue;
    const lab = LABEL[k] || k;
    if (Array.isArray(a) && Array.isArray(b) && a.every(hasId) && b.every(hasId)) {
      const am = new Map(a.map((x) => [String(x.id), x])), bm = new Map(b.map((x) => [String(x.id), x]));
      const nm = (x) => String(x.name || x.no || x.d || x.id).slice(0, 30);
      const added = b.filter((x) => !am.has(String(x.id))).map(nm), removed = a.filter((x) => !bm.has(String(x.id))).map(nm);
      const changed = b.filter((x) => am.has(String(x.id)) && JSON.stringify(am.get(String(x.id))) !== JSON.stringify(x)).map((x) => {
        const o = am.get(String(x.id));
        return nm(x) + (Array.isArray(x.e) && Array.isArray(o.e) && x.e.length !== o.e.length ? ` (entries ${o.e.length} to ${x.e.length})` : "");
      });
      const cut = (l) => l.slice(0, 4).join(", ") + (l.length > 4 ? ` +${l.length - 4} more` : "");
      if (added.length) out.push(`${lab} added: ${cut(added)}`);
      if (removed.length) out.push(`${lab} removed: ${cut(removed)}`);
      if (changed.length) out.push(`${lab} changed: ${cut(changed)}`);
      if (!added.length && !removed.length && !changed.length) out.push(`${lab} reordered`);
    } else out.push(`${lab} changed`);
  }
  return out.join("; ");
}
app.get("/api/state", need("owner", "manager"), (q, s) => {
  const { state, vers } = readSections();
  s.json(Object.keys(vers).length ? { vers, state } : { vers: {}, state: null });
});
app.put("/api/state", need("owner", "manager"), (q, s) => {
  const { vers, changes } = q.body || {};
  const names = changes && typeof changes === "object" ? Object.keys(changes) : [];
  const bad = () => s.status(400).json({ error: "Invalid data." });
  if (!names.length || names.some((n) => !SECTIONS[n])) return bad();
  for (const n of names) for (const k of SECTIONS[n]) {
    const v = changes[n] && changes[n][k];
    if (v === undefined && k === "cf") continue;
    if (ARRAY_KEYS.has(k) ? !Array.isArray(v) : v === null || typeof v !== "object" || Array.isArray(v)) return bad();
  }
  const res = db.transaction(() => {
    const conflicts = names.filter((n) => { const r = db.prepare("select ver from sections where name=?").get(n); return +((vers || {})[n] || 0) !== (r ? r.ver : 0); });
    if (conflicts.length) return { conflicts };
    const out = {};
    names.forEach((n) => {
      const prev = db.prepare("select json from sections where name=?").get(n), before = prev ? JSON.parse(prev.json) : {}, obj = {};
      SECTIONS[n].forEach((k) => (obj[k] = changes[n][k]));
      out[n] = writeSection(n, obj);
      const d = diffSummary(before, obj);
      if (d) audit(q.user, "data", d);
    });
    return { vers: out };
  })();
  if (res.conflicts) return s.status(409).json({ error: "Data was changed by someone else.", conflicts: res.conflicts });
  s.json(res);
});

// ---- Audit log (owner)
app.get("/api/audit", need("owner"), (q, s) => {
  const lim = Math.min(500, +q.query.limit || 200), t = String(q.query.q || "").trim(), like = `%${t}%`;
  s.json(t
    ? db.prepare("select * from audit where action like ? or detail like ? or user_name like ? order by id desc limit ?").all(like, like, like, lim)
    : db.prepare("select * from audit order by id desc limit ?").all(lim));
});
const money = (n) => "\u20b9" + Math.round(+n || 0);
const AUD = {
  "POST /api/users": (q) => `Added ${q.body.role} ${q.body.name}`,
  "PATCH /api/users/:id": (q) => `Changed user #${q.params.id}` + (q.body.active !== undefined ? (q.body.active ? " (activated)" : " (deactivated)") : "") + (q.body.password !== undefined ? " (password reset)" : ""),
  "POST /api/password": () => "Changed own password",
  "POST /api/credit-sales": (q) => `Credit sale ${money(q.body.a)} for customer #${q.body.cust_id}`,
  "POST /api/credit-sales/:id/approve": (q) => `Approved over-limit credit sale #${q.params.id}`,
  "POST /api/credit-sales/:id/reject": (q) => `Rejected credit sale #${q.params.id}`,
  "DELETE /api/credit-sales/:id": (q) => `Deleted credit sale #${q.params.id}`,
  "POST /api/duty/:id/submit": (q) => `Submitted duty #${q.params.id}`,
  "POST /api/duties/assign": (q) => `Assigned a ${q.body.shift} duty to worker #${q.body.worker_id}`,
  "DELETE /api/duties/:id": (q) => `Cancelled duty #${q.params.id}`,
  "POST /api/duties/:id/close": (q) => `Closed duty #${q.params.id}`,
  "POST /api/duties/:id/reopen": (q) => `Reopened duty #${q.params.id}`,
  "POST /api/days/:d/close": (q) => `Closed business day ${q.params.d}`,
  "POST /api/days/:d/approve": (q) => `Approved business day ${q.params.d}`,
  "POST /api/days/:d/reopen": (q) => `Reopened business day ${q.params.d}`,
  "PUT /api/payroll/rates": (q) => `Changed pay rates for worker #${q.body.worker_id}`,
  "POST /api/payroll/items": (q) => `Pay entry (${q.body.kind}) ${money(q.body.amount)} for worker #${q.body.worker_id}`,
  "DELETE /api/payroll/items/:id": (q) => `Deleted pay entry #${q.params.id}`,
  "POST /api/dips": (q) => `Tank dip reading for tank #${q.body.tank_id}` + (q.body.d15 || q.body.dens_obs ? " with density" : ""),
  "DELETE /api/dips/:id": (q) => `Deleted dip reading #${q.params.id}`,
};
// ---- Credit customers and worker credit sales
function customers() {
  const st = stateNow();
  const sums = {};
  db.prepare("select cust_id, sum(a) t from credit_sales where status='ok' group by cust_id").all().forEach((x) => (sums[x.cust_id] = x.t));
  return (st.c || []).map((c) => {
    const due = (c.e || []).reduce((a, x) => a + (x.t === "sale" ? x.a : -x.a), 0) + (sums[String(c.id)] || 0);
    return { id: c.id, name: c.name, active: c.active !== false, veh: c.veh || [], available: Math.round(((c.limit || 0) - due) * 100) / 100 };
  });
}
app.get("/api/fuels", need(), (q, s) => { const st = stateNow(); s.json([...new Set((st.nozzles || []).filter((n) => n.active !== false).map((n) => n.fuel))].map((name) => ({ name, unit: unitOf(st, name) }))); });
app.get("/api/customers", need(), (q, s) => s.json(customers().filter((c) => c.active)));
app.post("/api/credit-sales", need(), (q, s) => {
  const { cust_id, n, a, veh, force, fuel, litres } = q.body || {};
  const c = customers().find((x) => String(x.id) === String(cust_id));
  // A retried request (same client key) returns the entry already saved instead of saving it twice.
  const cid = String((q.body && q.body.cid) || "").slice(0, 40);
  if (cid) { const ex = db.prepare("select id,status from credit_sales where cid=? and worker_id=?").get(cid, q.user.id); if (ex) return s.json({ id: ex.id, pending: ex.status === "pending", available: c ? c.available : 0 }); }
  const fu = String(fuel || "").trim().slice(0, 30), lt = fu && litres !== "" && litres != null ? Math.round(+litres * 100) / 100 : null;
  const amt = Math.round(+a * 100) / 100, item = String(n || "").trim() || (fu && lt > 0 ? `${fu} ${lt} L` : "");
  if (!c) return s.status(400).json({ error: "Choose a customer from the list." });
  if (!c.active) return s.status(400).json({ error: "This customer is inactive." });
  if (fu && !(lt > 0 && lt <= 5000)) return s.status(400).json({ error: "Enter the litres." });
  if (!item || item.length > 100) return s.status(400).json({ error: "Enter the fuel or item and quantity." });
  if (!(amt > 0 && amt <= 1e7)) return s.status(400).json({ error: "Enter an amount above zero." });
  const over = amt > c.available, worker = q.user.role === "worker";
  // Workers cannot exceed a customer's limit: the sale waits for a manager or owner to approve it.
  if (over && !worker && !force) return s.status(409).json({ error: "over_limit", available: c.available });
  const status = over && worker ? "pending" : "ok";
  const id = db.prepare("insert into credit_sales(cust_id,d,n,a,veh,worker_id,created,status,fuel,litres,cid) values(?,?,?,?,?,?,?,?,?,?,?)")
    .run(String(c.id), bizDate(), item, amt, String(veh || "").trim().toUpperCase().slice(0, 20), q.user.id, now(), status, fu || null, lt, cid || null).lastInsertRowid;
  s.json({ id, pending: status === "pending", available: Math.round((status === "ok" ? c.available - amt : c.available) * 100) / 100 });
});
app.get("/api/credit-sales", need("owner", "manager"), (q, s) =>
  s.json(db.prepare("select cs.id,cs.cust_id,cs.d,cs.n,cs.a,cs.veh,cs.fuel,cs.litres,cs.status,u.name worker from credit_sales cs join users u on u.id=cs.worker_id where cs.status<>'rejected' order by cs.id").all()));
app.get("/api/my-credit-sales", need(), (q, s) => {
  const names = {};
  customers().forEach((c) => (names[String(c.id)] = c.name));
  const rows = db.prepare("select id,cust_id,d,n,a,veh,fuel,litres,status from credit_sales where worker_id=? order by id desc limit 50").all(q.user.id);
  s.json(rows.map((r) => ({ ...r, cname: names[r.cust_id] || "Customer" })));
});
const decide = (to) => (q, s) => {
  const r = db.prepare("update credit_sales set status=? where id=? and status='pending'").run(to, +q.params.id);
  if (!r.changes) return s.status(404).json({ error: "This sale is no longer waiting for approval." });
  s.json({ ok: true });
};
app.post("/api/credit-sales/:id/approve", need("owner", "manager"), decide("ok"));
app.post("/api/credit-sales/:id/reject", need("owner", "manager"), decide("rejected"));
app.delete("/api/credit-sales/:id", need("owner", "manager"), (q, s) => {
  db.prepare("delete from credit_sales where id=?").run(+q.params.id);
  s.json({ ok: true });
});

// ---- Duties and nozzle readings
db.exec(`
create table if not exists duties(
  id integer primary key, worker_id integer not null, d text not null, shift text not null,
  status text not null default 'open', cash real not null default 0, upi real not null default 0,
  card real not null default 0, note text, started integer not null, submitted integer,
  closed_by integer, closed_at integer);
create table if not exists duty_lines(
  id integer primary key, duty_id integer not null, nozzle_id text not null,
  opening real, closing real, testing real not null default 0, rate real);
create table if not exists duty_items(
  id integer primary key, duty_id integer not null, item_id text not null, name text not null, qty real not null, price real not null);
create table if not exists duty_expenses(
  id integer primary key, duty_id integer not null, cat text not null, note text, amount real not null);
create table if not exists days(
  d text primary key, status text not null, closed_by integer, closed_at integer, approved_by integer, approved_at integer);
`);
const addCol = (t, c, def) => { if (!db.prepare(`pragma table_info(${t})`).all().some((x) => x.name === c)) db.exec(`alter table ${t} add column ${c} ${def}`); };
addCol("duties", "pay_json", "text");
addCol("duties", "stock_done", "integer not null default 0");
addCol("duties", "assigned_by", "integer");
addCol("duties", "breakdown_json", "text");
addCol("duties", "handover_from", "integer");
db.exec(`create table if not exists day_checks(d text not null, mode text not null, expected real not null, counted real not null, diff real not null, note text, by integer, t integer, primary key(d, mode));`);
const DENOM_LIST = [500, 200, 100, 50, 20, 10, 5];
addCol("credit_sales", "fuel", "text");
addCol("credit_sales", "litres", "real");
addCol("credit_sales", "cid", "text");

const r2 = (x) => Math.round(x * 100) / 100;
const num = (x) => { if (x === "" || x === null || x === undefined) return NaN; const n = +x; return Number.isFinite(n) && n >= 0 && n < 1e9 ? n : NaN; };
// The business day starts at 6 AM: a night shift that runs past midnight belongs to the previous day.
const bizDate = () => new Date(Date.now() - 6 * 3600e3).toLocaleDateString("en-CA", { timeZone: TZ });
const DEFMODES = [{ key: "cash", name: "Cash", active: true }, { key: "upi", name: "UPI", active: true }, { key: "card", name: "Card", active: true }];
const allModes = (st) => (st.paymodes && st.paymodes.length ? st.paymodes : DEFMODES);
const activeModes = (st) => allModes(st).filter((m) => m.active !== false || m.key === "cash");
function nozzleMap(st = stateNow()) {
  const m = {};
  (st.nozzles || []).forEach((n) => (m[String(n.id)] = n));
  return m;
}
function rateFor(st, fuel, date) {
  let best = null;
  (st.rates || []).forEach((r) => {
    if (r.fuel === fuel && r.from <= date && (!best || r.from > best.from || (r.from === best.from && r.id > best.id))) best = r;
  });
  return best ? +best.rate : null;
}
const unitOf = (st, fuel) => { const p = (st.fuelprods || []).find((x) => x.name === fuel); return (p && p.unit) || "L"; };
function lastClose(nid) {
  return db.prepare("select dl.closing c from duty_lines dl join duties d on d.id=dl.duty_id where dl.nozzle_id=? and d.status in ('submitted','closed') and dl.closing is not null order by d.submitted desc, dl.id desc limit 1").get(String(nid)) || {};
}
const dayStatus = (d) => (db.prepare("select status from days where d=?").get(d) || { status: "open" }).status;
// A closing reading is locked while another worker holds the nozzle through a hand-over from this duty.
const tankDipOn = (tank_id, day) => !!db.prepare("select 1 from dips where tank_id=? and bd=?").get(String(tank_id), day);
const tankName = (st, tank_id) => ((st.tanks || []).find((t) => String(t.id) === String(tank_id)) || {}).name || "the tank";
const handoverLocked = (duty_id, nozzle_id) => !!db.prepare("select 1 from duty_lines dl join duties du on du.id=dl.duty_id where du.handover_from=? and dl.nozzle_id=? and du.status in ('open','returned') limit 1").get(duty_id, String(nozzle_id));
function detail(d) {
  const st = stateNow(), nm = nozzleMap(st);
  const lines = db.prepare("select * from duty_lines where duty_id=? order by id").all(d.id).map((l) => {
    const lt = l.closing == null ? 0 : r2(l.closing - l.opening - l.testing), n = nm[l.nozzle_id] || {};
    return { ...l, nozzle: n.name || "Nozzle", fuel: n.fuel || "", unit: unitOf(st, n.fuel), litres: lt, amount: r2(lt * (l.rate || 0)), locked: handoverLocked(d.id, l.nozzle_id) };
  });
  const items = db.prepare("select * from duty_items where duty_id=? order by id").all(d.id).map((i) => ({ ...i, amount: r2(i.qty * i.price) }));
  const expenses = db.prepare("select * from duty_expenses where duty_id=? order by id").all(d.id);
  const sales = r2(lines.reduce((a, l) => a + l.amount, 0)), litres = r2(lines.filter((l) => l.unit === "L").reduce((a, l) => a + l.litres, 0));
  const lube = r2(items.reduce((a, i) => a + i.amount, 0)), exp = r2(expenses.reduce((a, e) => a + e.amount, 0));
  const credit = r2(db.prepare("select coalesce(sum(a),0) t from credit_sales where worker_id=? and status='ok' and created>=? and created<=?").get(d.worker_id, d.started, d.submitted || now()).t);
  const creditSales = db.prepare("select id,cust_id,a,litres,fuel,n,veh,status,created from credit_sales where worker_id=? and created>=? and created<=? order by created").all(d.worker_id, d.started, d.submitted || now()).map((x) => ({ id: x.id, customer: ((st.c || []).find((c) => String(c.id) === String(x.cust_id)) || {}).name || "Customer", fuel: x.fuel || x.n || "", litres: x.litres || 0, amount: r2(x.a), vehicle: x.veh || "", status: x.status }));
  const pay = d.pay_json ? JSON.parse(d.pay_json) : { cash: d.cash, upi: d.upi, card: d.card };
  const collected = r2(Object.values(pay).reduce((a, x) => a + (+x || 0), 0));
  const expected = r2(sales + lube - credit - exp);
  const w = db.prepare("select name from users where id=?").get(d.worker_id);
  return {
    id: d.id, d: d.d, shift: d.shift, status: d.status, worker_id: d.worker_id, handover_from: d.handover_from || null, worker: w ? w.name : "", pay,
    cash: +pay.cash || 0, upi: +pay.upi || 0, card: +pay.card || 0, note: d.note || "", breakdown: d.breakdown_json ? JSON.parse(d.breakdown_json) : null,
    lines, items, expenses, creditSales, litres, sales, lube, exp, credit, expected, collected, diff: r2(collected - expected),
  };
}
// Updates a duty's nozzle readings, shop items, expenses and collections.
// Workers change closing/testing only; managers (full) can also change opening and rate.
function saveDuty(id, b, strict, full) {
  const st = stateNow(), nm = nozzleMap(st), cur = db.prepare("select * from duty_lines where duty_id=? order by id").all(id);
  const src = Array.isArray(b.lines) ? b.lines : [], ups = [];
  const rd = (v) => (v === "" || v === null || v === undefined ? null : num(v));
  for (const row of cur) {
    const l = src.find((x) => String(x.nozzle_id) === row.nozzle_id) || {}, nn = (nm[row.nozzle_id] || {}).name || "Nozzle";
    const o = { id: row.id, opening: row.opening, rate: row.rate, closing: row.closing, testing: row.testing };
    if (l.closing !== undefined) o.closing = rd(l.closing);
    const sameVal = (a, b) => (a == null && b == null) || (a != null && b != null && Math.abs(+a - +b) < 1e-9);
    if (l.closing !== undefined && !sameVal(o.closing, row.closing)) {
      if (full) return "Closing readings are corrected by the worker. Send the duty back instead.";
      if (handoverLocked(id, row.nozzle_id)) return `The closing reading for ${nn} is locked while the nozzle is handed over. The manager must cancel the handover first.`;
    }
    if (l.testing !== undefined) o.testing = rd(l.testing) ?? 0;
    if (full && l.opening !== undefined) o.opening = rd(l.opening);
    if (full && l.rate !== undefined) o.rate = rd(l.rate);
    if ([o.closing, o.testing, o.opening, o.rate].some((x) => Number.isNaN(x))) return `Check the numbers for ${nn}.`;
    if (strict) {
      if (o.opening == null) return `Enter the opening reading for ${nn}.`;
      if (o.closing == null) return `Enter the closing reading for ${nn}.`;
      if (o.rate == null || o.rate <= 0) return `The rate for ${nn} is missing. Ask the owner to set it in Pump setup.`;
      if (o.closing < o.opening) return `Closing is less than opening for ${nn}.`;
      if (o.testing > o.closing - o.opening) return `Testing litres are more than the fuel dispensed on ${nn}.`;
    }
    ups.push(o);
  }
  const items = [], need = {}, stItems = st.items || [], iSrc = Array.isArray(b.items) ? b.items : [];
  if (iSrc.length > 50) return "Too many shop items.";
  for (const x of iSrc) {
    if (x.item_id === "" || x.item_id == null) continue;
    const it = stItems.find((i) => String(i.id) === String(x.item_id));
    if (!it) return "Choose each lube or shop item from the stock list.";
    const q = num(x.qty);
    if (Number.isNaN(q) || q <= 0) { if (strict) return `Enter a quantity for ${it.name}.`; continue; }
    items.push({ item_id: String(it.id), name: it.name, qty: q, price: +it.sell });
    need[it.id] = (need[it.id] || 0) + q;
  }
  if (strict) for (const k in need) { const it = stItems.find((i) => String(i.id) === k); if (need[k] > +it.stock) return `Only ${it.stock} ${it.unit} of ${it.name} in stock.`; }
  const exps = [], eSrc = Array.isArray(b.expenses) ? b.expenses : [];
  if (eSrc.length > 50) return "Too many expense lines.";
  for (const x of eSrc) {
    const blank = (x.amount === "" || x.amount == null) && !String(x.note || "").trim();
    if (blank) continue;
    const a = num(x.amount);
    if (Number.isNaN(a) || a <= 0) { if (strict) return "Enter an amount above zero for every expense."; continue; }
    exps.push({ cat: String(x.cat || "Other").slice(0, 40), note: String(x.note || "").slice(0, 60), amount: r2(a) });
  }
  const pay = {};
  for (const m of activeModes(st)) {
    let raw = b.pay && b.pay[m.key] !== undefined ? b.pay[m.key] : b[m.key];
    const n = num(raw === undefined || raw === null || raw === "" ? 0 : raw);
    if (Number.isNaN(n)) return `Check the ${m.name} amount.`;
    pay[m.key] = n;
  }
  if (strict) {
    const nmx = nozzleMap(stateNow());
    for (const r of db.prepare("select nozzle_id from duty_lines where duty_id=?").all(id)) {
      const n = nmx[r.nozzle_id];
      if (n && n.tank_id && !tankDipOn(n.tank_id, bizDate())) return `Take today's 6 AM dip for ${tankName(stateNow(), n.tank_id)} before submitting this duty.`;
    }
  }
  // Notes and coins counted, and slips for each non-cash mode. On submit they must add up to what was collected.
  const bd = b.breakdown && typeof b.breakdown === "object" ? b.breakdown : {};
  const cashCount = {};
  let cashCoins = 0;
  if (bd.cash && typeof bd.cash === "object") {
    Object.keys(bd.cash).forEach((k) => { const d = +k, c = parseInt(bd.cash[k], 10) || 0; if (DENOM_LIST.includes(d) && c > 0 && c < 100000) cashCount[d] = c; });
    cashCoins = r2(Math.max(0, +bd.cash.coins || 0)); if (cashCoins >= 1e7) cashCoins = 0;
  }
  const slipsOut = {};
  if (bd.slips && typeof bd.slips === "object") Object.keys(bd.slips).forEach((k) => {
    if (!Array.isArray(bd.slips[k])) return;
    slipsOut[k] = bd.slips[k].slice(0, 50).map((x) => ({ ref: String((x && x.ref) || "").slice(0, 40), amt: r2(+((x && x.amt) || 0)) })).filter((x) => x.amt > 0 && x.amt < 1e8);
  });
  if (strict) {
    const cashSum = r2(Object.keys(cashCount).reduce((a, k) => a + (+k) * cashCount[k], 0) + cashCoins);
    if ((Object.keys(cashCount).length || cashCoins) && Math.abs(cashSum - (pay.cash || 0)) > 0.5) return `The notes you counted (${money(cashSum)}) do not match the cash collected (${money(pay.cash || 0)}).`;
    for (const k of Object.keys(slipsOut)) {
      const t = r2(slipsOut[k].reduce((a, x) => a + x.amt, 0));
      if (slipsOut[k].length && Math.abs(t - (pay[k] || 0)) > 0.5) return `The slips for ${k} (${money(t)}) do not match the amount collected (${money(pay[k] || 0)}).`;
    }
  }
  db.prepare("update duties set breakdown_json=? where id=?").run(JSON.stringify({ cash: Object.assign({}, cashCount, cashCoins ? { coins: cashCoins } : {}), slips: slipsOut }), id);
  db.transaction(() => {
    const u = db.prepare("update duty_lines set opening=?, closing=?, testing=?, rate=? where id=?");
    ups.forEach((o) => u.run(o.opening, o.closing, o.testing, o.rate, o.id));
    db.prepare("delete from duty_items where duty_id=?").run(id);
    items.forEach((x) => db.prepare("insert into duty_items(duty_id,item_id,name,qty,price) values(?,?,?,?,?)").run(id, x.item_id, x.name, x.qty, x.price));
    db.prepare("delete from duty_expenses where duty_id=?").run(id);
    exps.forEach((x) => db.prepare("insert into duty_expenses(duty_id,cat,note,amount) values(?,?,?,?)").run(id, x.cat, x.note, x.amount));
    db.prepare("update duties set pay_json=?, cash=?, upi=?, card=?, note=? where id=?").run(JSON.stringify(pay), pay.cash || 0, pay.upi || 0, pay.card || 0, String(b.note || "").slice(0, 200), id);
  })();
  return null;
}
// Lube and shop stock moves when a duty is closed (and comes back if the owner reopens it).
function adjustStock(duty, sign) {
  const items = db.prepare("select * from duty_items where duty_id=?").all(duty.id), r = db.prepare("select json from sections where name='items'").get();
  if (!items.length || !r) return;
  const o = JSON.parse(r.json);
  items.forEach((x) => { const it = (o.items || []).find((i) => String(i.id) === x.item_id); if (it) it.stock = Math.max(0, r2(+it.stock + sign * x.qty)); });
  writeSection("items", o);
  audit(null, "stock", `${sign < 0 ? "Deducted" : "Restored"} lube and shop stock for duty #${duty.id}`);
}
const openDuty = (uid) => db.prepare("select * from duties where worker_id=? and status in ('open','returned') order by id desc limit 1").get(uid);
const mine = (q, s, n) => {
  const d = db.prepare("select * from duties where id=? and worker_id=? and status in ('open','returned')").get(+q.params.id, q.user.id);
  if (!d) return s.status(404).json({ error: "This duty is not open." });
  q.duty = d; n();
};
const fillInfo = (st) => ({
  modes: activeModes(st).map((m) => ({ key: m.key, name: m.name })),
  cats: st.expcats && st.expcats.length ? st.expcats : ["Tea and food", "Repairs", "Electricity", "Transport", "Other"],
  items: (st.items || []).map((i) => ({ id: i.id, name: i.name, unit: i.unit, sell: i.sell, stock: i.stock })),
});
app.get("/api/duty/current", need(), (q, s) => {
  const d = openDuty(q.user.id), st = stateNow();
  const recent = db.prepare("select * from duties where worker_id=? and status<>'open' order by id desc limit 8").all(q.user.id).map(detail);
  const workers = db.prepare("select id,name from users where role='worker' and active=1 and id<>? order by name").all(q.user.id);
  s.json({ duty: d ? detail(d) : null, ...fillInfo(st), recent, workers });
});
app.get("/api/my-duties/:id", need(), (q, s) => {
  const d = db.prepare("select * from duties where id=? and worker_id=? and status<>'open'").get(+q.params.id, q.user.id);
  if (!d) return s.status(404).json({ error: "Duty not found." });
  s.json({ duty: detail(d), modes: allModes(stateNow()).map((m) => ({ key: m.key, name: m.name })) });
});
app.put("/api/duty/:id", need(), mine, (q, s) => {
  const e = saveDuty(q.duty.id, q.body || {}, false, false);
  if (e) return s.status(400).json({ error: e });
  s.json({ ok: true });
});
app.post("/api/duty/:id/submit", need(), mine, (q, s) => {
  const e = saveDuty(q.duty.id, q.body || {}, true, false);
  if (e) return s.status(400).json({ error: e });
  db.prepare("update duties set status='submitted', submitted=? where id=?").run(now(), q.duty.id);
  s.json({ ok: true });
});

// ---- Manager: assign nozzles, review, close
app.get("/api/assign-info", need("owner", "manager"), (q, s) => {
  const st = stateNow(), d = bizDate();
  const busy = {};
  db.prepare("select dl.nozzle_id n, u.name w from duty_lines dl join duties du on du.id=dl.duty_id join users u on u.id=du.worker_id where du.status in ('open','returned')").all().forEach((x) => (busy[x.n] = x.w));
  const workers = db.prepare("select id,name from users where role='worker' and active=1 order by name").all();
  const nozzles = (st.nozzles || []).filter((n) => n.active !== false).map((n) => {
    const lc = lastClose(n.id);
    return { id: n.id, name: n.name, fuel: n.fuel, busy_by: busy[String(n.id)] || null, rate: rateFor(st, n.fuel, d), opening: lc.c ?? (n.open ?? null) };
  });
  const open = db.prepare("select * from duties where status='open' order by id").all().map(detail);
  s.json({ date: d, day: dayStatus(d), workers, nozzles, open });
});
app.post("/api/duties/assign", need("owner", "manager"), (q, s) => {
  const { worker_id, shift, nozzle_ids } = q.body || {}, st = stateNow(), d = bizDate();
  const w = db.prepare("select * from users where id=? and active=1 and role='worker'").get(+worker_id);
  if (!w) return s.status(400).json({ error: "Choose a worker." });
  if (!SHIFTS.includes(shift)) return s.status(400).json({ error: "Choose a shift." });
  const ids = Array.isArray(nozzle_ids) ? [...new Set(nozzle_ids.map(String))] : [];
  if (!ids.length || ids.length > 30) return s.status(400).json({ error: "Choose at least one nozzle." });
  if (dayStatus(d) !== "open") return s.status(409).json({ error: "Today's business day is already closed. Ask the owner to reopen it." });
  if (openDuty(w.id)) return s.status(409).json({ error: `${w.name} already has a duty in progress.` });
  const nm = nozzleMap(st), lines = [];
  for (const id of ids) { const n = nm[id]; if (n && n.tank_id && !tankDipOn(n.tank_id, d)) return s.status(409).json({ error: `Take today's 6 AM dip for ${tankName(st, n.tank_id)} before assigning ${n.name}.` }); }
  for (const id of ids) {
    const n = nm[id];
    if (!n || n.active === false) return s.status(400).json({ error: "One of the nozzles is not available." });
    const b = db.prepare("select u.name w from duty_lines dl join duties du on du.id=dl.duty_id join users u on u.id=du.worker_id where dl.nozzle_id=? and du.status in ('open','returned') limit 1").get(id);
    if (b) return s.status(409).json({ error: `${n.name} is with ${b.w}. It is free once that duty is closed.` });
    const rate = rateFor(st, n.fuel, d);
    if (rate == null) return s.status(400).json({ error: `Set the ${n.fuel} rate in Pump setup first.` });
    const lc = lastClose(id), opening = lc.c ?? (n.open ?? null);
    if (opening == null) return s.status(400).json({ error: `Set the opening reading for ${n.name} in Pump setup first.` });
    lines.push({ id, opening, rate });
  }
  const dutyId = db.transaction(() => {
    const did = db.prepare("insert into duties(worker_id,d,shift,started,assigned_by) values(?,?,?,?,?)").run(w.id, d, shift, now(), q.user.id).lastInsertRowid;
    lines.forEach((l) => db.prepare("insert into duty_lines(duty_id,nozzle_id,opening,rate) values(?,?,?,?)").run(did, l.id, l.opening, l.rate));
    return did;
  })();
  s.json({ id: dutyId });
});
app.delete("/api/duties/:id", need("owner", "manager"), (q, s) => {
  const r = db.transaction(() => {
    const d = db.prepare("select * from duties where id=? and status='open'").get(+q.params.id);
    if (!d) return 0;
    db.prepare("delete from duty_lines where duty_id=?").run(d.id);
    db.prepare("delete from duty_items where duty_id=?").run(d.id);
    db.prepare("delete from duty_expenses where duty_id=?").run(d.id);
    db.prepare("delete from duties where id=?").run(d.id);
    return 1;
  })();
  if (!r) return s.status(404).json({ error: "Only a duty that has not been submitted can be cancelled." });
  s.json({ ok: true });
});
app.get("/api/duties", need("owner", "manager"), (q, s) => {
  const d = /^\d{4}-\d{2}-\d{2}$/.test(q.query.d || "") ? q.query.d : bizDate();
  s.json({
    day: db.prepare("select * from duties where d=? and status<>'open' order by id").all(d).map(detail),
    pending: db.prepare("select * from duties where status='submitted' order by id").all().map(detail),
    open: db.prepare("select * from duties where status in ('open','returned') order by id").all().map(detail),
    day_status: dayStatus(d),
  });
});
app.get("/api/duties/:id", need("owner", "manager"), (q, s) => {
  const d = db.prepare("select * from duties where id=? and status<>'open'").get(+q.params.id);
  if (!d) return s.status(404).json({ error: "Duty not found." });
  s.json(detail(d));
});
app.put("/api/duties/:id", need("owner", "manager"), (q, s) => {
  if (q.user.role === "manager") return s.status(403).json({ error: "A manager cannot change a duty. Send it back for correction, or close it as it stands." });
  const d = db.prepare("select * from duties where id=? and status='submitted'").get(+q.params.id);
  if (!d) return s.status(404).json({ error: "Only duties waiting to be closed can be changed." });
  const before = detail(d), e = saveDuty(d.id, q.body || {}, true, true);
  if (e) return s.status(400).json({ error: e });
  const after = detail(db.prepare("select * from duties where id=?").get(d.id)), bits = [];
  [["fuel sales", "sales"], ["lube sales", "lube"], ["expenses", "exp"], ["collected", "collected"]].forEach(([l, k]) => { if (before[k] !== after[k]) bits.push(`${l} ${money(before[k])} to ${money(after[k])}`); });
  if (JSON.stringify(before.lines.map((l) => [l.opening, l.closing, l.testing, l.rate])) !== JSON.stringify(after.lines.map((l) => [l.opening, l.closing, l.testing, l.rate]))) bits.push("nozzle readings changed");
  audit(q.user, "duty corrected", `Duty #${d.id} (${before.worker}, ${before.shift}): ${bits.length ? bits.join(", ") : "saved with no figure changes"}`);
  s.json({ ok: true });
});
app.post("/api/duties/:id/close", need("owner", "manager"), (q, s) => {
  const out = db.transaction(() => {
    const d = db.prepare("select * from duties where id=? and status='submitted'").get(+q.params.id);
    if (!d) return { code: 404, error: "This duty is not waiting to be closed." };
    if (dayStatus(d.d) !== "open") return { code: 409, error: "This business day is already closed." };
    db.prepare("update duties set status='closed', closed_by=?, closed_at=?, stock_done=1 where id=?").run(q.user.id, now(), d.id);
    if (!d.stock_done) adjustStock(d, -1);
    return { ok: true };
  })();
  if (out.error) return s.status(out.code).json({ error: out.error });
  s.json({ ok: true });
});
app.post("/api/duties/:id/reopen", need("owner"), (q, s) => {
  const out = db.transaction(() => {
    const d = db.prepare("select * from duties where id=? and status='closed'").get(+q.params.id);
    if (!d) return { code: 404, error: "This duty is not closed." };
    if (dayStatus(d.d) !== "open") return { code: 409, error: "Reopen the business day first." };
    db.prepare("update duties set status='submitted', stock_done=0 where id=?").run(d.id);
    if (d.stock_done) adjustStock(d, +1);
    return { ok: true };
  })();
  if (out.error) return s.status(out.code).json({ error: out.error });
  s.json({ ok: true });
});

// ---- Business day: manager closes, owner approves
const validDay = (d) => /^\d{4}-\d{2}-\d{2}$/.test(d || "");
app.post("/api/days/:d/close", need("owner", "manager"), (q, s) => {
  const d = q.params.d;
  if (!validDay(d)) return s.status(400).json({ error: "Invalid date." });
  if (dayStatus(d) !== "open") return s.status(409).json({ error: "This day is already closed." });
  const c = db.prepare("select sum(status='closed') done, sum(status<>'closed') wait from duties where d=?").get(d);
  if (!c.done) return s.status(400).json({ error: "There are no closed duties on this date." });
  if (c.wait) return s.status(400).json({ error: "Some duties on this date are still open or waiting to be closed." });
  db.prepare("insert into days(d,status,closed_by,closed_at) values(?,?,?,?) on conflict(d) do update set status='closed', closed_by=excluded.closed_by, closed_at=excluded.closed_at, approved_by=null, approved_at=null").run(d, "closed", q.user.id, now());
  s.json({ ok: true });
});
// ---- Collection check before the owner approves the day: every payment mode counted, ticked, and explained if different.
function dayExpected(d, st) {
  const exp = {}, add = (k, v) => (exp[k] = r2((exp[k] || 0) + (+v || 0)));
  db.prepare("select * from duties where d=? and status='closed'").all(d).map(detail).forEach((x) => Object.keys(x.pay || {}).forEach((k) => add(bookKeyOf(k, st), x.pay[k])));
  (st.shop || []).filter((x) => x.d === d).forEach((x) => add(bookKeyOf(x.mode, st), x.total));
  (st.c || []).forEach((c) => (c.e || []).forEach((x) => { if (x.t === "pay" && x.d === d) add(bookKeyOf(x.n, st), x.a); }));
  return exp;
}
function dayModes(st, exp) {
  const keys = activeModes(st).map((m) => m.key);
  Object.keys(exp).forEach((k) => { if (exp[k] > 0 && !keys.includes(k)) keys.push(k); });
  return keys.map((k) => ({ key: k, name: bookLabel(k, st) }));
}
function dayVerifyState(d, st) {
  const exp = dayExpected(d, st), modes = dayModes(st, exp);
  const checks = db.prepare("select * from day_checks where d=?").all(d);
  const missing = modes.filter((m) => {
    const c = checks.find((x) => x.mode === m.key);
    return !c || (Math.abs(c.diff) > 0.5 && !String(c.note || "").trim());
  });
  return { exp, modes, checks, missing };
}
app.get("/api/days/:d/verify", need("owner", "manager"), (q, s) => {
  const st = stateNow(), v = dayVerifyState(q.params.d, st);
  s.json({ d: q.params.d, expected: v.exp, modes: v.modes, checks: v.checks, complete: v.missing.length === 0 });
});
app.post("/api/days/:d/verify", need("owner", "manager"), (q, s) => {
  const d = q.params.d, row = db.prepare("select status from days where d=?").get(d) || { status: "open" };
  if (row.status !== "closed") return s.status(409).json({ error: "Verify the collections after the manager closes the day." });
  const st = stateNow(), exp = dayExpected(d, st), modes = dayModes(st, exp), list = Array.isArray((q.body || {}).lines) ? q.body.lines : [];
  const rows = [];
  for (const l of list) {
    if (!l || !l.tick) continue;
    const m = modes.find((x) => x.key === l.mode);
    if (!m) return s.status(400).json({ error: "Choose a payment mode." });
    const counted = l.counted === "" || l.counted == null ? NaN : +l.counted;
    if (!(counted >= 0)) return s.status(400).json({ error: `Enter the amount counted for ${m.name}.` });
    const e = exp[m.key] || 0, diff = r2(counted - e), note = String(l.note || "").slice(0, 200);
    if (Math.abs(diff) > 0.5 && !note.trim()) return s.status(400).json({ error: `Explain the difference for ${m.name} (counted ${money(counted)}, expected ${money(e)}).` });
    rows.push({ mode: m.key, expected: e, counted: r2(counted), diff, note });
  }
  db.transaction(() => {
    for (const r of rows) db.prepare("insert into day_checks(d,mode,expected,counted,diff,note,by,t) values(?,?,?,?,?,?,?,?) on conflict(d,mode) do update set expected=excluded.expected, counted=excluded.counted, diff=excluded.diff, note=excluded.note, by=excluded.by, t=excluded.t").run(d, r.mode, r.expected, r.counted, r.diff, r.note, q.user.id, now());
  })();
  audit(q.user, "day", `Collections verified for ${d}: ${rows.length} mode(s)`);
  s.json({ ok: true, saved: rows.length });
});
app.post("/api/days/:d/approve", need("owner"), (q, s) => {
  const vs = dayVerifyState(q.params.d, stateNow());
  if (vs.missing.length) return s.status(409).json({ error: "Verify the collection for every mode before approving: " + vs.missing.map((x) => x.name).join(", ") + "." });
  const r = db.prepare("update days set status='approved', approved_by=?, approved_at=? where d=? and status='closed'").run(q.user.id, now(), q.params.d);
  if (!r.changes) return s.status(409).json({ error: "Only a day closed by the manager can be approved." });
  s.json({ ok: true });
});
app.post("/api/days/:d/reopen", need("owner"), (q, s) => {
  db.prepare("update days set status='open', approved_by=null, approved_at=null where d=?").run(q.params.d);
  s.json({ ok: true });
});
// Day reports use closed duties only.
// Manager financial summary for a business day
function finDay(d, st, T, pay) {
  const shopSales = r2((st.shop || []).filter((x) => x.d === d).reduce((a, x) => a + (+x.total || 0), 0));
  const creditNew = r2(db.prepare("select coalesce(sum(a),0) t from credit_sales where d=? and status='ok'").get(d).t);
  let recovery = 0;
  (st.c || []).forEach((c) => (c.e || []).forEach((x) => { if (x.t === "pay" && x.d === d) recovery += +x.a || 0; }));
  const mgrExp = r2((st.bk || []).filter((b) => b.t === "out" && !b.dep && b.d === d).reduce((a, b) => a + (+b.a || 0), 0));
  const deposits = r2((st.bk || []).filter((b) => b.dep && b.d === d).reduce((a, b) => a + (+b.a || 0), 0));
  const cf = cashFlowRows(st, d).rows.find((x) => x.d === d);
  return { fuelSales: r2(T.sales), lubeSales: r2(T.lube), shopSales, totalSales: r2(T.sales + T.lube + shopSales), creditNew, creditRecovery: r2(recovery), collectedDuties: pay, dutyExpenses: r2(T.exp), managerExpenses: mgrExp, bankDeposits: deposits, cashInHand: cf ? cf.close : null };
}
app.get("/api/day-report", need("owner", "manager"), (q, s) => {
  const d = validDay(q.query.d) ? q.query.d : bizDate(), st = stateNow();
  const duties = db.prepare("select * from duties where d=? and status='closed' order by id").all(d).map(detail);
  const fuel = {}, shop = {}, exps = {}, pay = {};
  const T = { sales: 0, lube: 0, credit: 0, exp: 0, expected: 0, collected: 0, diff: 0, litres: 0 };
  duties.forEach((x) => {
    ["sales", "lube", "credit", "exp", "expected", "collected", "diff", "litres"].forEach((k) => (T[k] += x[k]));
    x.lines.forEach((l) => { const f = fuel[l.fuel || "Other"] || (fuel[l.fuel || "Other"] = { litres: 0, amount: 0 }); f.litres += l.litres; f.amount += l.amount; });
    x.items.forEach((i) => { const f = shop[i.name] || (shop[i.name] = { qty: 0, amount: 0 }); f.qty += i.qty; f.amount += i.amount; });
    x.expenses.forEach((e) => (exps[e.cat] = (exps[e.cat] || 0) + e.amount));
    Object.keys(x.pay).forEach((k) => (pay[k] = (pay[k] || 0) + (+x.pay[k] || 0)));
  });
  Object.keys(T).forEach((k) => (T[k] = r2(T[k])));
  const dd = db.prepare("select * from days where d=?").get(d) || { status: "open" };
  s.json({ d, financial: finDay(d, st, T, pay), day: dd, modes: allModes(st).map((m) => ({ key: m.key, name: m.name })), duties, summary: { ...T, total: r2(T.sales + T.lube), fuel, shop, exps, pay } });
});

// Money from closed business days: collections by mode, fuel and shop sales, expenses (for the Book and Reports)
app.get("/api/duty-money", need("owner", "manager"), (q, s) => {
  const f = validDay(q.query.from) ? q.query.from : "0000-01-01", t = validDay(q.query.to) ? q.query.to : "9999-12-31";
  const days = db.prepare("select distinct d from duties where status='closed' and d>=? and d<=? order by d").all(f, t);
  s.json(days.map(({ d }) => {
    const ds = db.prepare("select * from duties where d=? and status='closed' order by id").all(d).map(detail);
    const pay = {}, fuel = {}, lube = {}, exp = [];
    let fuelTotal = 0, lubeTotal = 0, credit = 0;
    ds.forEach((x) => {
      Object.keys(x.pay).forEach((k) => (pay[k] = r2((pay[k] || 0) + (+x.pay[k] || 0))));
      x.lines.forEach((l) => { const k = l.fuel || "Other", o = fuel[k] || (fuel[k] = { litres: 0, amount: 0 }); o.litres = r2(o.litres + l.litres); o.amount = r2(o.amount + l.amount); });
      x.items.forEach((i) => { const o = lube[i.item_id] || (lube[i.item_id] = { item_id: i.item_id, name: i.name, qty: 0, amount: 0 }); o.qty = r2(o.qty + i.qty); o.amount = r2(o.amount + i.amount); });
      x.expenses.forEach((e) => exp.push({ cat: e.cat, note: e.note, amount: e.amount, worker: x.worker }));
      fuelTotal += x.sales; lubeTotal += x.lube; credit += x.credit;
    });
    return { d, pay, fuel, lube: Object.values(lube), exp, fuelTotal: r2(fuelTotal), lubeTotal: r2(lubeTotal), credit: r2(credit), duties: ds.length };
  }));
});

// Closed duties with their sales and cash difference, for the shortage report
app.get("/api/shortage-data", need("owner", "manager"), (q, s) => {
  const f = validDay(q.query.from) ? q.query.from : "0000-01-01", t = validDay(q.query.to) ? q.query.to : "9999-12-31";
  s.json(db.prepare("select * from duties where status='closed' and d>=? and d<=? order by d,id").all(f, t).map(detail)
    .map((x) => ({ id: x.id, d: x.d, shift: x.shift, worker_id: x.worker_id, worker: x.worker, sales: r2(x.sales + x.lube), diff: x.diff })));
});

// ---- Fuel tanks: dip readings and stock check
db.exec(`
create table if not exists dips(
  id integer primary key, tank_id text not null, litres real not null, dip real,
  note text, user_id integer not null, t integer not null);
`);
addCol("dips", "dens_obs", "real");
addCol("dips", "temp", "real");
addCol("dips", "d15", "real");
addCol("dips", "cid", "text");
addCol("dips", "purpose", "text");
addCol("dips", "bd", "text");
db.prepare("select id,t from dips where bd is null").all().forEach((r) => db.prepare("update dips set bd=?, purpose=coalesce(purpose,'morning') where id=?").run(new Date(r.t * 1000 - 6 * 3600e3).toLocaleDateString("en-CA", { timeZone: TZ }), r.id));
function fromChart(chart, dip) {
  const c = (chart || []).map((x) => ({ cm: +x.cm, l: +x.l })).filter((x) => Number.isFinite(x.cm) && Number.isFinite(x.l)).sort((a, b) => a.cm - b.cm);
  if (c.length < 2) return { err: "This tank has no dip chart yet. Enter litres directly, or ask the manager to add the chart." };
  if (dip < c[0].cm || dip > c[c.length - 1].cm) return { err: "This dip is outside the tank's chart range. Check the reading." };
  for (let i = 1; i < c.length; i++) {
    if (dip <= c[i].cm) { const a = c[i - 1], b = c[i]; return { l: r2(b.cm === a.cm ? b.l : a.l + ((dip - a.cm) / (b.cm - a.cm)) * (b.l - a.l)) }; }
  }
  return { l: c[c.length - 1].l };
}
function tankChecks() {
  const st = stateNow(), tanks = st.tanks || [], dv = st.deliv || [], tankOf = {};
  (st.nozzles || []).forEach((n) => (tankOf[String(n.id)] = String(n.tank_id || "")));
  const sales = db.prepare("select d.submitted t, dl.nozzle_id n, dl.closing-dl.opening-dl.testing lt from duty_lines dl join duties d on d.id=dl.duty_id where d.status='closed'").all();
  const dips = db.prepare("select di.*, u.name by_name from dips di join users u on u.id=di.user_id order by di.t, di.id").all();
  const sold = (tid, a, b) => r2(sales.filter((x) => tankOf[x.n] === tid && x.t > a && x.t <= b).reduce((s, x) => s + x.lt, 0));
  const recv = (tid, a, b) => r2(dv.reduce((s, d) => s + (Math.floor(d.ts / 1000) > a && Math.floor(d.ts / 1000) <= b ? (d.lines || []).filter((l) => String(l.tank_id) === tid).reduce((q, l) => q + (+l.litres || 0), 0) : 0), 0));
  return tanks.map((tk) => {
    const tid = String(tk.id), ds = dips.filter((x) => x.tank_id === tid), checks = [];
    for (let i = 1; i < ds.length; i++) {
      const p = ds[i - 1], c = ds[i], so = sold(tid, p.t, c.t), re = recv(tid, p.t, c.t), exp = r2(p.litres + re - so);
      checks.push({ id: c.id, from: p.t, to: c.t, opening: p.litres, received: re, sold: so, expected: exp, actual: c.litres, variance: r2(c.litres - exp), by: c.by_name });
    }
    const last = ds[ds.length - 1] || null;
    const book = last ? r2(last.litres + recv(tid, last.t, now()) - sold(tid, last.t, now())) : null;
    return { id: tk.id, name: tk.name, fuel: tk.fuel, capacity: tk.capacity || 0, last: last ? { id: last.id, litres: last.litres, t: last.t, by: last.by_name } : null, book, checks: checks.slice(-8).reverse() };
  });
}
app.get("/api/tanks", need(), (q, s) => {
  const st = stateNow(), names = {};
  (st.tanks || []).forEach((t) => (names[String(t.id)] = t.name));
  const mine = db.prepare("select id,tank_id,litres,dip,dens_obs,temp,d15,purpose,note,t from dips where user_id=? order by id desc limit 10").all(q.user.id).map((d) => ({ ...d, tank: names[d.tank_id] || "Tank" }));
  const bookOf = {};
  tankChecks().forEach((t) => (bookOf[String(t.id)] = t.book));
  s.json({ tanks: (st.tanks || []).map((t) => ({ id: t.id, name: t.name, fuel: t.fuel, capacity: t.capacity || 0, book: bookOf[String(t.id)] ?? null })), mine });
});
// ---- Morning density (separate from the dip reading): one per tank per business day, after that tank's 6 AM dip.
// ---- Morning reading: every tank in one form. Dip and optional density per tank. All or nothing.
app.post("/api/morning-reading", need(), (q, s) => {
  const b = q.body || {}, st = stateNow(), list = Array.isArray(b.tanks) ? b.tanks.slice(0, 30) : [];
  if (!list.length) return s.status(400).json({ error: "Enter the reading for at least one tank." });
  let bd = bizDate();
  if (/^\d{4}-\d{2}-\d{2}$/.test(b.date || "") && q.user.role !== "worker") bd = b.date;
  const seen = new Set(), prep = [];
  // Every tank needs its stock reading and its density, unless its 6 AM reading is already saved today.
  const allTanks = st.tanks || [];
  if (!allTanks.length) return s.status(400).json({ error: "No tanks are set up yet." });
  const taken = new Set(db.prepare("select tank_id from dips where bd=?").all(bd).map((r) => String(r.tank_id)));
  const missing = allTanks.filter((t) => !taken.has(String(t.id)) && !list.some((e) => String(e.tank_id) === String(t.id) && (e.litres !== "" && e.litres != null || (e.dip !== "" && e.dip != null)) && e.dens_obs !== "" && e.dens_obs != null && e.temp !== "" && e.temp != null && e.atg !== "" && e.atg != null));
  if (missing.length) return s.status(400).json({ error: `Enter the stock reading and the density for: ${missing.map((t) => t.name).join(", ")}. Nothing was saved.` });
  for (const e of list) {
    const tank = (st.tanks || []).find((t) => String(t.id) === String(e.tank_id));
    if (!tank) return s.status(400).json({ error: "Choose a tank for every line." });
    if (seen.has(String(tank.id))) return s.status(400).json({ error: `${tank.name} appears twice.` });
    seen.add(String(tank.id));
    const cid = String(e.cid || "").slice(0, 60);
    if (cid && db.prepare("select id from dips where cid=? and user_id=?").get(cid, q.user.id)) continue; // already saved (a retry)
    let litres = num(e.litres);
    const dip = e.dip === "" || e.dip == null ? null : num(e.dip);
    if (dip !== null && (Number.isNaN(dip) || dip < 0)) return s.status(400).json({ error: `The dip reading for ${tank.name} cannot be negative.` });
    if (Number.isNaN(litres)) {
      if (dip === null || Number.isNaN(dip)) return s.status(400).json({ error: `Enter the litres or the dip reading for ${tank.name}.` });
      const r = fromChart(tank.chart, dip);
      if (r.err) return s.status(400).json({ error: `${tank.name}: ${r.err}` });
      litres = r.l;
    }
    if (tank.capacity && litres > tank.capacity * 1.02) return s.status(400).json({ error: `${tank.name}: that is more than the tank capacity (${tank.capacity} L). Check the reading.` });
    if (taken.has(String(tank.id))) continue; // already read today: nothing to change
    const hasDens = e.dens_obs !== "" && e.dens_obs != null;
    const dobs = hasDens ? +e.dens_obs : null, tmp = e.temp === "" || e.temp == null ? null : +e.temp;
    if (hasDens) {
      if (!(dobs >= 500 && dobs <= 1200)) return s.status(400).json({ error: `${tank.name}: the density should be between 500 and 1200 kg/m3.` });
      if (!(tmp >= -10 && tmp <= 90)) return s.status(400).json({ error: `${tank.name}: enter the temperature for the density.` });
    }
    let d15 = e.d15 === "" || e.d15 == null ? null : +e.d15;
    if (hasDens && d15 == null) d15 = density15(dobs, tmp);
    const atgL = r2(+e.atg);
    if (!(atgL >= 0) || (tank.capacity && atgL > tank.capacity * 1.02)) return s.status(400).json({ error: `${tank.name}: enter the ATG stock in litres (0 to the tank capacity).` });
    prep.push({ tank, litres, dip, dobs: hasDens ? dobs : null, tmp: hasDens ? tmp : null, d15: hasDens ? d15 : null, cid: cid || null, note: String(e.note || "").slice(0, 100), atg: atgL });
  }
  db.transaction(() => {
    for (const x of prep) db.prepare("insert into dips(tank_id,litres,dip,dens_obs,temp,d15,note,user_id,t,cid,purpose,bd) values(?,?,?,?,?,?,?,?,?,?,?,?)").run(String(x.tank.id), r2(x.litres), x.dip, x.dobs, x.tmp, x.d15, x.note, q.user.id, now(), x.cid, "morning", bd);
    for (const x of prep) db.prepare("insert or ignore into atg_readings(tank_id,bd,litres,t,user_id) values(?,?,?,?,?)").run(String(x.tank.id), bd, x.atg, now(), q.user.id);
  })();
  audit(q.user, "dip", `Morning reading for ${prep.length} tank(s), ${bd}`);
  s.json({ ok: true, saved: prep.length });
});
app.post("/api/density/morning", need(), (q, s) => {
  const b = q.body || {}, st = stateNow();
  const tank = (st.tanks || []).find((t) => String(t.id) === String(b.tank_id));
  if (!tank) return s.status(400).json({ error: "Choose a tank." });
  let bd = bizDate();
  if (/^\d{4}-\d{2}-\d{2}$/.test(b.date || "") && q.user.role !== "worker") bd = b.date;
  const dip = db.prepare("select * from dips where tank_id=? and bd=? and purpose='morning' order by id limit 1").get(String(tank.id), bd);
  if (!dip) return s.status(400).json({ error: `Take the 6 AM dip for ${tank.name} before recording its density.` });
  if (dip.dens_obs != null) return s.status(409).json({ error: `The morning density for ${tank.name} is already recorded for this day.` });
  const dobs = b.dens_obs === "" || b.dens_obs == null ? NaN : +b.dens_obs;
  if (!(dobs >= 500 && dobs <= 1200)) return s.status(400).json({ error: "Enter the measured density (kg/m3), such as 745.0." });
  const tmp = b.temp === "" || b.temp == null ? NaN : +b.temp;
  if (!(tmp >= -10 && tmp <= 90)) return s.status(400).json({ error: "Check the temperature." });
  let d15 = b.d15 === "" || b.d15 == null ? NaN : +b.d15;
  if (Number.isNaN(d15)) d15 = density15(dobs, tmp);
  else if (!(d15 >= 500 && d15 <= 1200)) return s.status(400).json({ error: "Check the density at 15 °C." });
  db.prepare("update dips set dens_obs=?, temp=?, d15=? where id=?").run(dobs, tmp, d15, dip.id);
  audit(q.user, "density", `Morning density ${tank.name}: ${dobs} kg/m3 at ${tmp} °C`);
  s.json({ ok: true, d15 });
});
app.post("/api/dips", need(), (q, s) => {
  const b = q.body || {}, cid = String(b.cid || "").slice(0, 40);
  if (cid) { const ex = db.prepare("select id,litres from dips where cid=? and user_id=?").get(cid, q.user.id); if (ex) return s.json({ id: ex.id, litres: ex.litres }); }
  const tank = (stateNow().tanks || []).find((t) => String(t.id) === String(b.tank_id));
  if (!tank) return s.status(400).json({ error: "Choose a tank." });
  let litres = num(b.litres);
  const dip = b.dip === "" || b.dip == null ? null : num(b.dip);
  if (Number.isNaN(litres)) {
    if (dip === null || Number.isNaN(dip)) return s.status(400).json({ error: "Enter the litres or the dip reading." });
    const r = fromChart(tank.chart, dip);
    if (r.err) return s.status(400).json({ error: r.err });
    litres = r.l;
  }
  if (tank.capacity && litres > tank.capacity * 1.02) return s.status(400).json({ error: `That is more than the tank capacity (${tank.capacity} L). Check the reading.` });
  const dobs = null, tmp = null, d15 = null; // density is recorded on the morning reading only
  if (d15 == null && dobs != null && tmp != null) d15 = density15(dobs, tmp);
  if (dip !== null && (Number.isNaN(dip) || dip < 0)) return s.status(400).json({ error: "A dip reading cannot be negative." });
  const purpose = "morning";
  let bd = new Date(now() * 1000 - 6 * 3600e3).toLocaleDateString("en-CA", { timeZone: TZ });
  if (/^\d{4}-\d{2}-\d{2}$/.test(b.date || "") && q.user.role !== "worker") bd = b.date;
  if (db.prepare("select 1 from dips where tank_id=? and bd=?").get(String(tank.id), bd)) return s.status(409).json({ error: "This tank's 6 AM dip is already taken for this day. Only one dip per tank per day." });
  const id = db.prepare("insert into dips(tank_id,litres,dip,dens_obs,temp,d15,note,user_id,t,cid,purpose,bd) values(?,?,?,?,?,?,?,?,?,?,?,?)").run(String(tank.id), r2(litres), dip, dobs, tmp, d15, String(b.note || "").slice(0, 200), q.user.id, now(), cid || null, purpose, bd).lastInsertRowid;
  s.json({ id, litres: r2(litres) });
});
// ---- Density checks (deliveries and dips) with flags
const DENS_DEF = { "Petrol (MS)": { min: 720, max: 775 }, "Diesel (HSD)": { min: 820, max: 860 }, "Power petrol": { min: 720, max: 775 }, "Power diesel": { min: 820, max: 860 } };
function densCfg(st, fuel) {
  const p = (st.fuelprods || []).find((x) => x.name === fuel), d = DENS_DEF[fuel] || {}, pick = (x, def) => (x === undefined || x === null || x === "" ? def : +x);
  return { min: pick(p && p.dmin, d.min), max: pick(p && p.dmax, d.max), tol: pick(p && p.dtol, 3), unit: (p && p.unit) || "L" };
}
function densFlags(cfg, r) {
  const v = r.d15 ?? r.obs, f = [];
  if (v == null || cfg.unit !== "L") return f;
  if ((cfg.min != null && v < cfg.min) || (cfg.max != null && v > cfg.max)) f.push(`Outside the allowed range (${cfg.min} to ${cfg.max})`);
  if (r.inv != null && Math.abs(v - r.inv) > cfg.tol + 1e-9) f.push(`Differs from the chalan density by ${(Math.abs(v - r.inv)).toFixed(1)} (limit ${cfg.tol})`);
  return f;
}
app.get("/api/density", need("owner", "manager"), (q, s) => {
  const st = stateNow(), tanks = {}, rows = [], nn = (x) => (x === "" || x == null || !Number.isFinite(+x) ? null : +x);
  (st.tanks || []).forEach((t) => (tanks[String(t.id)] = t));
  (st.deliv || []).forEach((d) => (d.lines || []).forEach((l) => {
    const dn = l.dens, t = tanks[String(l.tank_id)];
    if (!dn || !t) return;
    const cs = (dn.comps || []).map((c) => (c ? (c.d15 != null ? +c.d15 : c.obs != null && c.temp != null ? density15(c.obs, c.temp) : null) : null)).filter((x) => x != null);
    const mixv = dn.mix != null ? +dn.mix : dn.d15 != null ? +dn.d15 : cs.length ? Math.round((cs.reduce((x, y) => x + y, 0) / cs.length) * 10) / 10 : null;
    const o = { src: "Delivery", t: Math.floor((d.ts || 0) / 1000), d: d.d, tank: t.name, fuel: t.fuel, inv: nn(dn.inv), obs: nn(dn.obs), temp: nn(dn.temp), d15: nn(mixv), by: "" };
    if (o.inv == null && o.obs == null && o.d15 == null) return;
    o.flags = densFlags(densCfg(st, t.fuel), o); rows.push(o);
  }));
  db.prepare("select di.*, u.name by_name from dips di join users u on u.id=di.user_id where di.dens_obs is not null or di.d15 is not null order by di.t desc limit 200").all().forEach((x) => {
    const t = tanks[x.tank_id]; if (!t) return;
    const o = { src: "Dip", t: x.t, d: new Date(x.t * 1000).toLocaleDateString("en-CA", { timeZone: TZ }), tank: t.name, fuel: t.fuel, inv: null, obs: x.dens_obs, temp: x.temp, d15: x.d15, by: x.by_name };
    o.flags = densFlags(densCfg(st, t.fuel), o); rows.push(o);
  });
  rows.sort((a, b) => b.t - a.t);
  s.json(rows.slice(0, 80));
});
// ---- Stock and density registers (one per fuel, by month)
app.get("/api/registers", need("owner", "manager"), (q, s) => {
  const st = stateNow(), all = st.tanks || [], fuels = [...new Set([...all.map((t) => t.fuel), ...(st.nozzles || []).map((n) => n.fuel)].filter(Boolean))];
  const month = /^\d{4}-(0[1-9]|1[0-2])$/.test(q.query.month || "") ? q.query.month : bizDate().slice(0, 7);
  const fuel = fuels.includes(q.query.fuel) ? q.query.fuel : fuels[0] || "";
  if (!fuel) return s.json({ fuels, fuel: "", month, tanks: [], stock: null, density: null });
  const tanks = all.filter((t) => t.fuel === fuel), tids = tanks.map((t) => String(t.id)), days = daysOfMonth(month), nm = nozzleMap(st);
  const test = {}, receipts = {};
  const allNoz = (st.nozzles || []).filter((n) => n.fuel);
  const fuelOf = {}; allNoz.forEach((n) => (fuelOf[String(n.id)] = n.fuel));
  const allDuty = db.prepare("select d.d d, dl.nozzle_id n, dl.opening o, dl.closing c, dl.testing t from duty_lines dl join duties d on d.id=dl.duty_id where d.status='closed' and d.d in (select d from days where status in ('closed','approved')) and dl.closing is not null and dl.opening is not null order by d.id, dl.id").all()
    .map((r) => ({ d: r.d, nozzle_id: String(r.n), opening: r.o, closing: r.c, testing: r.t || 0 }));
  allDuty.forEach((x) => { if (x.d.slice(0, 7) === month && fuelOf[x.nozzle_id] === fuel) test[x.d] = (test[x.d] || 0) + x.testing; });
  const earliest = [...allNoz.map((n) => n.since).filter(Boolean), ...allDuty.map((x) => x.d)].sort()[0];
  const lastDay = days[days.length - 1];
  const span = earliest && earliest <= lastDay ? daysBetween(earliest, lastDay) : [];
  // One meter register for every tank and product.
  const reg = buildMeterRegister({ days: span, nozzles: allNoz, duties: allDuty });
  const mFuels = [...new Set(allNoz.map((n) => n.fuel))];
  const meter = {};
  days.forEach((d) => { if (reg.fuelDay[d] && reg.fuelDay[d][fuel]) meter[d] = reg.fuelDay[d][fuel].sales; });
  const meterView = {
    fuels: mFuels,
    nozzles: allNoz.map((n) => ({ id: n.id, name: n.name, fuel: n.fuel, since: reg.since[String(n.id)] || null })),
    rows: days.map((d) => {
      const fd = reg.fuelDay[d] || {};
      const byFuel = mFuels.reduce((o, f) => { o[f] = fd[f] ? { sales: fd[f].sales, check: fd[f].check } : { sales: 0, check: 0 }; return o; }, {});
      return {
        d,
        cells: allNoz.reduce((o, n) => { const c = reg.cells[String(n.id)] && reg.cells[String(n.id)][d]; o[String(n.id)] = c ? { reading: c.end, sales: c.sales, check: c.check } : null; return o; }, {}),
        byFuel,
        check: r2(mFuels.reduce((a, f) => a + byFuel[f].check, 0)),
      };
    }),
  };
  (st.deliv || []).forEach((d) => (d.lines || []).forEach((l) => { if (tids.includes(String(l.tank_id))) receipts[d.d] = (receipts[d.d] || 0) + (+l.litres || 0); }));
  const dips0 = db.prepare(`select * from dips where tank_id in (${tids.map(() => "?").join(",")}) order by t, id`).all(...tids);
  const prevDay = (x) => new Date(new Date(x + "T00:00:00Z").getTime() - 864e5).toISOString().slice(0, 10);
  const dips = [...dips0, ...dips0.filter((x) => x.purpose === "morning").map((x) => ({ ...x, purpose: "closing", bd: prevDay(x.bd) }))];
  const perDay = (purpose) => {
    const by = {}, out = {};
    dips.filter((x) => x.purpose === purpose).forEach((x) => { (by[x.bd] = by[x.bd] || {})[x.tank_id] = x.litres; });
    Object.keys(by).forEach((d) => { if (tids.every((t) => by[d][t] != null)) out[d] = tids.reduce((a, t) => a + by[d][t], 0); });
    return out;
  };
  const main = tanks.find((t) => t.main) || tanks[0], names = {};
  tanks.forEach((t) => (names[String(t.id)] = t.name));
  const cfg = densCfg(st, fuel);
  s.json({
    fuels, fuel, month, tanks: tanks.map((t) => ({ id: t.id, name: t.name, main: t.id === main.id })), cfg,
    meter: meterView,
    stock: buildStockRegister(days, { receipts, meter, test, closing: perDay("closing"), morning: perDay("morning") }),
    density: buildDensityRegister({ days, mainId: main ? main.id : null, tankIds: tids, tankNames: names, deliv: st.deliv || [], dips, cfg }),
  });
});
// ---- Cash flow register (owner and manager)
// Opening = starting cash for the first day, then the previous day's cash in hand.
// Cash in hand = opening + morning + evening + night cash (cash mode only, closed duties)
//                - bank deposits + credit recovery in cash - expenses paid from the Cash account.
const cfMonth = (m) => (/^\d{4}-(0[1-9]|1[0-2])$/.test(m || "") ? m : bizDate().slice(0, 7));
// Book keys: each payment mode has its own book; Bank is separate. Older names (Cash, UPI, Bank) map to the same books.
function bookKeyOf(name, st) {
  if (name == null || name === "") return "cash";
  const n = String(name).trim().toLowerCase();
  if (n === "cash") return "cash";
  if (n === "upi" || n === "upi / wallet" || n === "wallet") return "upi";
  if (["bank", "bank transfer", "cheque", "neft", "rtgs", "imps"].includes(n)) return "bank";
  const m = ((st && st.paymodes) || []).find((x) => String(x.name).toLowerCase() === n || x.key === n);
  if (m) return m.key;
  return n === "card" ? "card" : "other";
}
function bookLabel(k, st) {
  const m = ((st && st.paymodes) || []).find((x) => x.key === k);
  if (m) return m.name;
  return { cash: "Cash", upi: "UPI", bank: "Bank", card: "Card", other: "Other" }[k] || String(k);
}

// Cash flow, shared by the cash flow screen and the owner's dashboard. Rows run from the start date to `last`.
function cashFlowRows(st, last) {
  const cf = st.cf || {};
  const open0 = r2(+cf.open || 0);
  if (!cf.start || !/^\d{4}-\d{2}-\d{2}$/.test(cf.start)) return { start: null, open: 0, rows: [] };
  if (last < cf.start) return { start: cf.start, open: open0, rows: [] };
  const days = daysBetween(cf.start, last);
  const duties = db.prepare("select * from duties where status='closed' and d>=? and d<=?").all(cf.start, last).map(detail);
  const bk = st.bk || [], credit = {};
  (st.c || []).forEach((c) => (c.e || []).forEach((x) => { if (x.t === "pay" && bookKeyOf(x.n, st) === "cash") credit[x.d] = (credit[x.d] || 0) + (+x.a || 0); }));
  (st.shop || []).forEach((x) => { if (bookKeyOf(x.mode, st) === "cash") credit[x.d] = (credit[x.d] || 0) + (+x.total || 0); });
  const rows = [];
  let open = open0;
  days.forEach((d) => {
    const sh = { Morning: 0, Evening: 0, Night: 0 };
    duties.filter((x) => x.d === d).forEach((x) => { if (sh[x.shift] !== undefined) sh[x.shift] = r2(sh[x.shift] + (+x.pay.cash || 0)); });
    const dep = r2(bk.filter((b) => b.dep && b.d === d).reduce((a, b) => a + (+b.a || 0), 0));
    const exp = r2(bk.filter((b) => b.t === "out" && !b.dep && bookKeyOf(b.acct, st) === "cash" && b.d === d).reduce((a, b) => a + (+b.a || 0), 0));
    const rec = r2(credit[d] || 0);
    const close = r2(open + sh.Morning + sh.Evening + sh.Night - dep + rec - exp);
    rows.push({ d, open, morning: sh.Morning, evening: sh.Evening, night: sh.Night, deposit: dep, recovery: rec, expense: exp, close });
    open = close;
  });
  return { start: cf.start, open: open0, rows };
}
app.get("/api/cashflow", need("owner", "manager"), (q, s) => {
  const month = cfMonth(q.query.month), st = stateNow();
  const last = daysOfMonth(month).slice(-1)[0];
  const cr = cashFlowRows(st, last);
  s.json({ month, start: cr.start, open: cr.open, rows: cr.rows.filter((r) => r.d.slice(0, 7) === month) });
});
// ---- Dashboards, by role
app.get("/api/dashboard", need(), (q, s) => {
  const me = q.user, today = bizDate(), st = stateNow();
  if (me.role === "worker") {
    const mine = db.prepare("select * from duties where worker_id=? order by id desc limit 40").all(me.id).map(detail);
    const todays = mine.filter((x) => x.d === today);
    const cs = db.prepare("select status, a from credit_sales where worker_id=? and d=?").all(me.id, today);
    const ok = cs.filter((x) => x.status === "ok");
    const pay = payFor(me, cfMonth());
    return s.json({
      role: "worker", today, name: me.name,
      duty: todays.find((x) => x.status === "open") || todays[0] || null,
      credit: { count: ok.length, amount: r2(ok.reduce((a, x) => a + x.a, 0)), pending: cs.filter((x) => x.status === "pending").length },
      dips: db.prepare("select count(*) n from dips where user_id=? and bd=?").get(me.id, today).n,
      pay: { month: pay.month || cfMonth(), net: pay.net, balance: pay.balance, paid: pay.paid, duties: pay.duties },
      shortage: (() => {
        const sd = mine.filter((x) => x.status === "closed" && x.d.slice(0, 7) === cfMonth() && x.diff <= -1);
        return { count: sd.length, amount: r2(sd.reduce((a, x) => a - x.diff, 0)), waived: r2(pay.waived || 0), deducted: r2(Math.max(0, (pay.short || 0) - (pay.waived || 0))) };
      })(),
      recent: mine.filter((x) => x.status !== "open").slice(0, 5).map((x) => ({ id: x.id, d: x.d, shift: x.shift, status: x.status, sales: r2(x.sales + x.lube), diff: x.diff })),
    });
  }
  // owner and manager
  const todays = db.prepare("select * from duties where d=?").all(today).map(detail);
  const sold = todays.filter((x) => x.status !== "open");
  const sum = (arr, f) => r2(arr.reduce((a, x) => a + f(x), 0));
  const products = {};
  sold.forEach((x) => x.lines.forEach((l) => {
    const k = l.fuel || "Other", p = products[k] || (products[k] = { fuel: k, unit: l.unit || "L", qty: 0, amount: 0 });
    p.qty = r2(p.qty + l.litres); p.amount = r2(p.amount + l.amount);
  }));
  const sales = {
    fuel: sum(sold, (x) => x.sales), lube: sum(sold, (x) => x.lube), total: sum(sold, (x) => x.sales + x.lube),
    litres: sum(sold, (x) => x.litres), collected: sum(sold, (x) => x.collected),
    cash: sum(sold, (x) => +x.pay.cash || 0), upi: sum(sold, (x) => +x.pay.upi || 0),
    short: sum(sold.filter((x) => x.diff < 0), (x) => -x.diff), excess: sum(sold.filter((x) => x.diff > 0), (x) => x.diff),
  };
  const shopToday = (st.shop || []).filter((x) => x.d === today);
  const shopT = r2(shopToday.reduce((a, x) => a + (+x.total || 0), 0));
  const shopBy = (k) => r2(shopToday.filter((x) => bookKeyOf(x.mode, st) === k).reduce((a, x) => a + (+x.total || 0), 0));
  sales.lube = r2(sales.lube + shopT); sales.total = r2(sales.total + shopT); sales.collected = r2(sales.collected + shopT);
  sales.cash = r2(sales.cash + shopBy("cash")); sales.upi = r2(sales.upi + shopBy("upi"));
  const dutyCount = { open: todays.filter((x) => x.status === "open").length, waiting: todays.filter((x) => x.status === "submitted").length, closed: todays.filter((x) => x.status === "closed").length };
  // last seven business days (today and six before)
  const start7 = new Date(new Date(today + "T00:00:00Z").getTime() - 6 * 864e5).toISOString().slice(0, 10);
  const week = daysBetween(start7, today).map((d) => {
    const ds = db.prepare("select * from duties where d=? and status in ('submitted','closed')").all(d).map(detail);
    return { d, sales: sum(ds, (x) => x.sales + x.lube), collected: sum(ds, (x) => x.collected) };
  });
  // credit
  const sums = {};
  db.prepare("select cust_id, sum(a) t from credit_sales where status='ok' group by cust_id").all().forEach((x) => (sums[x.cust_id] = x.t));
  let outstanding = 0, owing = 0, over = 0;
  (st.c || []).forEach((c) => {
    if (c.active === false) return;
    const due = r2((c.e || []).reduce((a, x) => a + (x.t === "sale" ? x.a : -x.a), 0) + (sums[String(c.id)] || 0));
    if (due > 0) { outstanding += due; owing++; if (due > (+c.limit || 0)) over++; }
  });
  const pending = db.prepare("select count(*) n from credit_sales where status='pending'").get().n;
  const tanks = tankChecks().map((t) => {
    const lastDay = t.last ? new Date(t.last.t * 1000 - 6 * 3600e3).toLocaleDateString("en-CA", { timeZone: TZ }) : null;
    return { name: t.name, fuel: t.fuel, capacity: t.capacity, book: t.book, pct: t.capacity && t.book != null ? Math.max(0, Math.min(100, Math.round((t.book / t.capacity) * 100))) : null, dipToday: lastDay === today, lastDip: lastDay };
  });
  const monthShort = db.prepare("select * from duties where status='closed' and substr(d,1,7)=?").all(cfMonth()).map(detail).filter((x) => x.diff <= -1);
  // Pay shortage this month, worker by worker (same figures the worker sees on their own dashboard).
  const payShortage = db.prepare("select id,name,role from users where role='worker' and active=1 order by name").all().map((u) => {
    const pay = payFor(u, cfMonth());
    const sd = db.prepare("select * from duties where worker_id=? and status='closed' and substr(d,1,7)=?").all(u.id, cfMonth()).map(detail).filter((x) => x.diff <= -1);
    return { id: u.id, name: u.name, count: sd.length, short: r2(pay.short || 0), waived: r2(pay.waived || 0), deducted: r2(Math.max(0, (pay.short || 0) - (pay.waived || 0))) };
  }).filter((x) => x.count > 0 || x.short > 0 || x.waived > 0);
  payShortage.sort((a, b) => b.deducted - a.deducted || a.name.localeCompare(b.name));
  const out = {
    role: me.role, today, name: me.name, day: dayStatus(today), sales, duties: dutyCount, products: Object.values(products), week, payShortage,
    credit: { outstanding: r2(outstanding), owing, over, pending },
    lowStock: (st.items || []).filter((i) => +i.stock <= +i.low).map((i) => ({ name: i.name, stock: i.stock, unit: i.unit, low: i.low })),
    tanks,
    shortages: { count: monthShort.length, amount: sum(monthShort, (x) => -x.diff), month: cfMonth() },
    cash: null,
  };
  if (me.role === "owner" || me.role === "manager") out.licences = licSummary(licRows());
  if (me.role === "owner" || me.role === "manager") {
    const cr = cashFlowRows(st, today);
    out.cash = { start: cr.start, open: cr.open, closing: cr.rows.length ? cr.rows[cr.rows.length - 1].close : cr.open };
  }
  s.json(out);
});
// ---- Expenses register: workers' duty expenses and the manager's Book expenses, one list
app.get("/api/expenses", need("owner", "manager"), (q, s) => {
  const month = cfMonth(q.query.month), st = stateNow();
  const duty = db.prepare("select de.cat, de.note, de.amount, d.d, d.shift, d.status, u.name worker from duty_expenses de join duties d on d.id=de.duty_id join users u on u.id=d.worker_id where d.status<>'open' and substr(d.d,1,7)=? order by d.d, d.id, de.id").all(month)
    .map((x) => ({ d: x.d, source: "Duty", who: x.worker, detail: x.shift + " duty" + (x.note ? " \u00b7 " + x.note : ""), cat: x.cat || "Other", mode: "Till", amount: r2(x.amount), status: x.status === "closed" ? "Closed" : "Waiting for manager" }));
  const book = (st.bk || []).filter((b) => b.t === "out" && !b.dep && String(b.d || "").slice(0, 7) === month)
    .map((b) => ({ d: b.d, source: "Manager", who: "Manager (Book)", detail: b.n || "", cat: b.cat || "Other", mode: bookLabel(bookKeyOf(b.acct || "Cash", st), st), amount: r2(+b.a || 0), status: "Recorded" }));
  const rows = [...duty, ...book].sort((a, b) => (a.d < b.d ? -1 : a.d > b.d ? 1 : 0));
  const days = {}, cats = {};
  let dutyT = 0, mgrT = 0;
  rows.forEach((r) => {
    const dd = days[r.d] || (days[r.d] = { d: r.d, duty: 0, manager: 0, total: 0 });
    if (r.source === "Duty") { dd.duty = r2(dd.duty + r.amount); dutyT = r2(dutyT + r.amount); }
    else { dd.manager = r2(dd.manager + r.amount); mgrT = r2(mgrT + r.amount); }
    dd.total = r2(dd.total + r.amount);
    cats[r.cat] = r2((cats[r.cat] || 0) + r.amount);
  });
  s.json({
    month, total: r2(dutyT + mgrT), duty: dutyT, manager: mgrT, count: rows.length, rows,
    days: Object.values(days).sort((a, b) => (a.d < b.d ? -1 : 1)),
    cats: Object.keys(cats).map((k) => ({ cat: k, amount: cats[k] })).sort((a, b) => b.amount - a.amount),
    categories: Object.keys(cats).sort(),
  });
});
// ---- ATG stock (separate from the registers): book = yesterday's ATG + receipts - closed sales; variation = ATG - book.
function atgReport(st, from, to) {
  const nm = nozzleMap(st), readings = db.prepare("select * from atg_readings order by bd").all();
  const got = {}, firstDay = {};
  readings.forEach((r) => { got[r.tank_id + "|" + r.bd] = r.litres; if (!firstDay[r.tank_id] || r.bd < firstDay[r.tank_id]) firstDay[r.tank_id] = r.bd; });
  const sales = {};
  db.prepare("select d.d d, dl.nozzle_id n, dl.closing-dl.opening-dl.testing lt from duty_lines dl join duties d on d.id=dl.duty_id where d.status='closed' and dl.closing is not null and dl.opening is not null").all().forEach((x) => {
    const tid = String((nm[x.n] || {}).tank_id || ""); if (!tid) return;
    sales[tid + "|" + x.d] = (sales[tid + "|" + x.d] || 0) + (x.lt || 0);
  });
  const recv = {};
  (st.deliv || []).forEach((dv) => (dv.lines || []).forEach((l) => { const k = String(l.tank_id) + "|" + dv.d; recv[k] = (recv[k] || 0) + (+l.litres || 0); }));
  const starts = readings.map((r) => r.bd).sort();
  const start = starts.length && starts[0] < from ? starts[0] : from;
  const days = daysBetween(start, to);
  return (st.tanks || []).map((t) => {
    const tid = String(t.id);
    let prev = null, cum = 0, started = false; const rows = [];
    days.forEach((d) => {
      const atg = got[tid + "|" + d] != null ? got[tid + "|" + d] : null;
      const rc = r2(recv[tid + "|" + d] || 0), sl = r2(sales[tid + "|" + d] || 0);
      const open = prev;
      const book = open != null ? r2(open + rc - sl) : null;
      const dv = atg != null && book != null ? r2(atg - book) : null;
      if (dv != null) { cum = r2(cum + dv); started = true; }
      if (d >= from && d <= to) rows.push({ d, atg, opening: open, receipts: rc, sales: sl, book, daily: dv, cumulative: started ? cum : null });
      prev = atg;
    });
    return { id: t.id, name: t.name, fuel: t.fuel, rows };
  });
}
app.get("/api/atg", need("owner", "manager"), (q, s) => {
  const month = cfMonth(q.query.month), st = stateNow();
  const from = month + "-01", to = daysOfMonth(month).slice(-1)[0];
  const today = bizDate();
  const recorded = {};
  db.prepare("select tank_id from atg_readings where bd=?").all(today).forEach((r) => (recorded[r.tank_id] = true));
  s.json({ month, today, recorded, tanks: atgReport(st, from, to) });
});
app.post("/api/atg", need("owner", "manager"), (q, s) => {
  const b = q.body || {}, st = stateNow(), list = Array.isArray(b.tanks) ? b.tanks : [];
  let bd = bizDate();
  if (/^\d{4}-\d{2}-\d{2}$/.test(b.date || "")) bd = b.date;
  const allTanks = st.tanks || [];
  if (!allTanks.length) return s.status(400).json({ error: "No tanks are set up yet." });
  const taken = new Set(db.prepare("select tank_id from atg_readings where bd=?").all(bd).map((r) => String(r.tank_id)));
  const missing = allTanks.filter((t) => !taken.has(String(t.id)) && !list.some((e) => String(e.tank_id) === String(t.id) && e.litres !== "" && e.litres != null));
  if (missing.length) return s.status(400).json({ error: `Enter the ATG stock for: ${missing.map((t) => t.name).join(", ")}. Nothing was saved.` });
  const prep = [];
  for (const e of list) {
    const tank = allTanks.find((t) => String(t.id) === String(e.tank_id));
    if (!tank) return s.status(400).json({ error: "Choose a tank for every line." });
    if (taken.has(String(tank.id))) continue;
    const l = +e.litres;
    if (!(l >= 0) || (tank.capacity && l > tank.capacity * 1.02)) return s.status(400).json({ error: `${tank.name}: enter the ATG stock in litres (0 to the tank capacity).` });
    prep.push({ tank, litres: r2(l) });
  }
  db.transaction(() => { for (const x of prep) db.prepare("insert into atg_readings(tank_id,bd,litres,t,user_id) values(?,?,?,?,?)").run(String(x.tank.id), bd, x.litres, now(), q.user.id); })();
  audit(q.user, "atg", `ATG stock recorded for ${prep.length} tank(s), ${bd}`);
  s.json({ ok: true, saved: prep.length });
});
// ---- Licences: owner only. Days left and status are worked out from the business day.
db.exec(`create table if not exists licences(id integer primary key, name text not null, number text, issued text, expires text not null, doc_name text, doc_type text, doc_data text, created integer not null, updated integer not null);`);
const LIC_SUGGEST = ["Trade licence", "Pollution consent to operate", "Fire safety NOC", "Legal metrology (dispenser calibration)", "PESO explosives licence", "Petroleum retail licence", "GST registration", "Shop and establishment licence"];
const licStatus = (days) => (days < 0 ? "expired" : days <= 30 ? "soon30" : days <= 90 ? "soon90" : "ok");
function licRows() {
  const today = bizDate();
  return db.prepare("select id,name,number,issued,expires,doc_name,doc_type,created,updated from licences order by expires, id").all().map((r) => {
    const days = Math.round((new Date(r.expires + "T00:00:00Z") - new Date(today + "T00:00:00Z")) / 864e5);
    return { id: r.id, name: r.name, number: r.number || "", issued: r.issued || "", expires: r.expires, days, status: licStatus(days), hasDoc: !!r.doc_name, docName: r.doc_name || "" };
  });
}
function licSummary(rows) {
  return { tracked: rows.length, expired: rows.filter((x) => x.status === "expired").length, soon30: rows.filter((x) => x.status === "soon30").length, soon90: rows.filter((x) => x.status === "soon90").length, noCopy: rows.filter((x) => !x.hasDoc).length };
}
const isDay = (x) => /^\d{4}-\d{2}-\d{2}$/.test(x || "") && !Number.isNaN(Date.parse(x + "T00:00:00Z"));
app.get("/api/licences", need("owner", "manager"), (q, s) => {
  const rows = licRows();
  s.json({ licences: rows, summary: licSummary(rows), suggestions: LIC_SUGGEST });
});
app.post("/api/licences", need("owner", "manager"), (q, s) => {
  const b = q.body || {};
  const name = String(b.name || "").trim().slice(0, 80);
  if (!name) return s.status(400).json({ error: "Enter the licence name." });
  if (!isDay(b.expires)) return s.status(400).json({ error: "Enter the date this licence expires." });
  if (b.issued && !isDay(b.issued)) return s.status(400).json({ error: "Check the issue date." });
  let doc = { name: null, type: null, data: null };
  if (b.doc && b.doc.data) {
    const type = /^application\/pdf$/.test(b.doc.type) ? "pdf" : /^image\/png$/.test(b.doc.type) ? "png" : null;
    if (!type) return s.status(400).json({ error: "The scanned copy must be a PDF or PNG file." });
    if (String(b.doc.data).length > 7000000) return s.status(400).json({ error: "The scanned copy is larger than 5 MB." });
    doc = { name: String(b.doc.name || "licence." + type).slice(0, 80), type, data: String(b.doc.data) };
  }
  const id = db.prepare("insert into licences(name,number,issued,expires,doc_name,doc_type,doc_data,created,updated) values(?,?,?,?,?,?,?,?,?)").run(name, String(b.number || "").slice(0, 60), b.issued || null, b.expires, doc.name, doc.type, doc.data, now(), now()).lastInsertRowid;
  audit(q.user, "licence", `Licence added: ${name}`);
  s.json({ ok: true, id });
});
app.put("/api/licences/:id", need("owner", "manager"), (q, s) => {
  const r = db.prepare("select * from licences where id=?").get(+q.params.id);
  if (!r) return s.status(404).json({ error: "Licence not found." });
  const b = q.body || {};
  const name = b.name !== undefined ? String(b.name || "").trim().slice(0, 80) : r.name;
  if (!name) return s.status(400).json({ error: "Enter the licence name." });
  const expires = b.expires !== undefined ? b.expires : r.expires;
  if (!isDay(expires)) return s.status(400).json({ error: "Enter the date this licence expires." });
  const issued = b.issued !== undefined ? (b.issued || null) : r.issued;
  if (issued && !isDay(issued)) return s.status(400).json({ error: "Check the issue date." });
  let doc = { name: r.doc_name, type: r.doc_type, data: r.doc_data };
  if (b.doc && b.doc.data) {
    const type = /^application\/pdf$/.test(b.doc.type) ? "pdf" : /^image\/png$/.test(b.doc.type) ? "png" : null;
    if (!type) return s.status(400).json({ error: "The scanned copy must be a PDF or PNG file." });
    if (String(b.doc.data).length > 7000000) return s.status(400).json({ error: "The scanned copy is larger than 5 MB." });
    doc = { name: String(b.doc.name || "licence." + type).slice(0, 80), type, data: String(b.doc.data) };
  }
  db.prepare("update licences set name=?, number=?, issued=?, expires=?, doc_name=?, doc_type=?, doc_data=?, updated=? where id=?").run(name, b.number !== undefined ? String(b.number || "").slice(0, 60) : (r.number || ""), issued, expires, doc.name, doc.type, doc.data, now(), r.id);
  audit(q.user, "licence", `Licence updated: ${name}`);
  s.json({ ok: true });
});
app.delete("/api/licences/:id", need("owner", "manager"), (q, s) => {
  const r = db.prepare("select name from licences where id=?").get(+q.params.id);
  if (!r) return s.status(404).json({ error: "Licence not found." });
  db.prepare("delete from licences where id=?").run(+q.params.id);
  audit(q.user, "licence", `Licence removed: ${r.name}`);
  s.json({ ok: true });
});
app.get("/api/licences/:id/doc", need("owner", "manager"), (q, s) => {
  const r = db.prepare("select doc_name,doc_type,doc_data from licences where id=?").get(+q.params.id);
  if (!r || !r.doc_data) return s.status(404).json({ error: "No copy attached." });
  const buf = Buffer.from(r.doc_data, "base64");
  s.setHeader("Content-Type", r.doc_type === "pdf" ? "application/pdf" : "image/png");
  s.setHeader("Content-Disposition", `inline; filename="${String(r.doc_name).replace(/[^\w.-]/g, "_")}"`);
  s.send(buf);
});
// ---- Daily required: what must be done today, by role (a tick when it is done)
app.get("/api/daily-required", need(), (q, s) => {
  const me = q.user, today = bizDate(), st = stateNow(), items = [];
  const tanks = st.tanks || [];
  const tankRow = (t) => db.prepare("select * from dips where tank_id=? and bd=? and purpose='morning' order by id limit 1").get(String(t.id), today);
  const atgDone = (t) => !!db.prepare("select 1 from atg_readings where tank_id=? and bd=?").get(String(t.id), today);
  if (me.role === "worker") {
    const mine = db.prepare("select * from duties where worker_id=? and d=?").all(me.id, today);
    items.push({ label: "Duty started today", done: mine.length > 0, detail: mine.length ? `${mine.length} duty(ies) today` : "Your manager assigns your shift and nozzles." });
    items.push({ label: "Duty submitted", done: mine.some((x) => x.status !== "open" && x.status !== "returned"), detail: mine.some((x) => x.status === "returned") ? "Sent back by the manager: correct and submit again." : "Submit the duty when the shift ends." });
  } else {
    const miss = tanks.filter((t) => !tankRow(t));
    items.push({ label: "Morning reading (stock) for every tank", done: tanks.length > 0 && miss.length === 0, detail: miss.length ? "Missing: " + miss.map((t) => t.name).join(", ") : "All tanks read." });
    const densMiss = tanks.filter((t) => { const r = tankRow(t); return !r || r.dens_obs == null; });
    items.push({ label: "Density for every tank", done: tanks.length > 0 && densMiss.length === 0, detail: densMiss.length ? "Missing: " + densMiss.map((t) => t.name).join(", ") : "All tanks have density." });
    const atgMiss = tanks.filter((t) => !atgDone(t));
    items.push({ label: "ATG stock for every tank", done: tanks.length > 0 && atgMiss.length === 0, detail: atgMiss.length ? "Missing: " + atgMiss.map((t) => t.name).join(", ") : "All tanks recorded." });
    const todays = db.prepare("select status from duties where d=?").all(today);
    items.push({ label: "Duties assigned for today", done: todays.length > 0, detail: todays.length ? `${todays.length} duty(ies) today` : "No duty assigned yet." });
    const open = todays.filter((x) => x.status !== "closed").length;
    items.push({ label: "All duties closed", done: todays.length > 0 && open === 0, detail: open ? `${open} duty(ies) still open or waiting for the manager.` : "Nothing waiting." });
    const dayRow = db.prepare("select status from days where d=?").get(today) || { status: "open" };
    items.push({ label: "Day closed", done: dayRow.status === "closed" || dayRow.status === "approved", detail: dayRow.status === "open" ? "Close the day once all duties are closed." : "Closed." });
    const vs = dayVerifyState(today, st);
    items.push({ label: "Collections verified for every mode", done: vs.missing.length === 0 && (dayRow.status === "closed" || dayRow.status === "approved"), detail: vs.missing.length ? "Still to verify: " + vs.missing.map((x) => x.name).join(", ") : "Every mode ticked." });
    if (me.role === "owner") items.push({ label: "Day approved", done: dayRow.status === "approved", detail: dayRow.status === "approved" ? "Approved." : "Approve after the collections are verified." });
    const pend = db.prepare("select count(*) n from credit_sales where status='pending'").get().n;
    items.push({ label: "Credit sales waiting for approval", done: pend === 0, detail: pend ? `${pend} waiting` : "None waiting." });
    const lic = licRows().filter((x) => x.status === "expired" || x.status === "soon30");
    if (me.role === "owner" || me.role === "manager") items.push({ label: "Licences due within 30 days", done: lic.length === 0, detail: lic.length ? lic.map((x) => x.name).join(", ") : "None due." });
  }
  s.json({ today, role: me.role, items, done: items.filter((x) => x.done).length, total: items.length });
});
app.get("/api/stock-check", need("owner", "manager"), (q, s) => s.json(tankChecks()));
app.delete("/api/dips/:id", need("owner", "manager"), (q, s) => {
  db.prepare("delete from dips where id=?").run(+q.params.id);
  s.json({ ok: true });
});

// ---- Worker pay (owner manages; each worker can see their own)
db.exec(`
create table if not exists pay_rates(worker_id integer not null, shift text not null, rate real not null, primary key(worker_id, shift));
create table if not exists pay_items(
  id integer primary key, worker_id integer not null, month text not null,
  kind text not null check(kind in ('advance','bonus','waive','paid')),
  amount real not null, note text, d text not null, created integer not null);
`);
const SHIFTS = ["Morning", "Evening", "Night"];
const monthOf = (m) => (/^\d{4}-(0[1-9]|1[0-2])$/.test(m || "") ? m : today().slice(0, 7));
function payFor(u, month) {
  const rates = {};
  db.prepare("select shift,rate from pay_rates where worker_id=?").all(u.id).forEach((r) => (rates[r.shift] = r.rate));
  const ds = db.prepare("select * from duties where worker_id=? and status='closed' and substr(d,1,7)=?").all(u.id, month).map(detail);
  const pending = db.prepare("select count(*) n from duties where worker_id=? and status in ('open','submitted') and substr(d,1,7)=?").get(u.id, month).n;
  const count = { Morning: 0, Evening: 0, Night: 0 };
  const shiftsPaid = new Set(); // one shift on one day is paid once, however many duties were submitted in it
  let earn = 0, short = 0, excess = 0, missing = false;
  ds.forEach((d) => {
    const key = d.d + "|" + d.shift;
    if (!shiftsPaid.has(key)) {
      shiftsPaid.add(key);
      count[d.shift] = (count[d.shift] || 0) + 1;
      if (rates[d.shift] == null) missing = true;
      earn += rates[d.shift] || 0;
    }
    if (d.diff <= -1) short += -d.diff;
    else if (d.diff >= 1) excess += d.diff;
  });
  const items = db.prepare("select id,kind,amount,note,d from pay_items where worker_id=? and month=? order by id").all(u.id, month);
  const sum = (k) => r2(items.filter((x) => x.kind === k).reduce((a, x) => a + x.amount, 0));
  const advance = sum("advance"), bonus = sum("bonus"), waived = sum("waive"), paid = sum("paid");
  earn = r2(earn); short = r2(short); excess = r2(excess);
  const net = r2(earn + bonus + excess - advance - Math.max(0, short - waived));
  return { id: u.id, name: u.name, role: u.role, rates, count, duties: shiftsPaid.size, pending, missing_rate: missing, earn, short, excess, advance, bonus, waived, paid, net, balance: r2(net - paid), items };
}
app.get("/api/payroll", need("owner"), (q, s) => {
  const m = monthOf(q.query.month);
  const us = db.prepare("select id,name,role from users where role='worker' or id in (select worker_id from duties where substr(d,1,7)=?) order by name").all(m);
  s.json({ month: m, workers: us.map((u) => payFor(u, m)) });
});
app.put("/api/payroll/rates", need("owner"), (q, s) => {
  const { worker_id, rates } = q.body || {};
  if (!db.prepare("select 1 from users where id=?").get(+worker_id)) return s.status(404).json({ error: "Worker not found." });
  const vals = {};
  for (const sh of SHIFTS) {
    const x = rates && rates[sh];
    if (x === "" || x == null) continue;
    const n = num(x);
    if (Number.isNaN(n)) return s.status(400).json({ error: `Check the ${sh} rate.` });
    vals[sh] = n;
  }
  db.transaction(() => {
    db.prepare("delete from pay_rates where worker_id=?").run(+worker_id);
    Object.keys(vals).forEach((sh) => db.prepare("insert into pay_rates values(?,?,?)").run(+worker_id, sh, vals[sh]));
  })();
  s.json({ ok: true });
});
app.post("/api/payroll/items", need("owner"), (q, s) => {
  const { worker_id, month, kind, amount, note } = q.body || {};
  if (!db.prepare("select 1 from users where id=?").get(+worker_id)) return s.status(404).json({ error: "Worker not found." });
  if (!["advance", "bonus", "waive", "paid"].includes(kind)) return s.status(400).json({ error: "Invalid entry type." });
  const a = num(amount);
  if (Number.isNaN(a) || a <= 0 || a > 1e7) return s.status(400).json({ error: "Enter an amount above zero." });
  const pid = db.prepare("insert into pay_items(worker_id,month,kind,amount,note,d,created) values(?,?,?,?,?,?,?)").run(+worker_id, monthOf(month), kind, r2(a), String(note || "").slice(0, 100), today(), now()).lastInsertRowid;
  s.json({ ok: true, id: pid });
});
app.delete("/api/payroll/items/:id", need("owner"), (q, s) => {
  db.prepare("delete from pay_items where id=?").run(+q.params.id);
  s.json({ ok: true });
});
app.get("/api/my-pay", need(), (q, s) => {
  const m = monthOf(q.query.month);
  s.json({ month: m, worker: payFor(q.user, m) });
});

// ---- Daily summary text (for the owner's WhatsApp)
const R0 = (n) => "\u20b9" + Math.round(n).toLocaleString("en-IN");
const L1 = (n) => (Math.round(n * 10) / 10).toLocaleString("en-IN") + " L";
app.get("/api/daily-summary", need("owner", "manager"), (q, s) => {
  const d = /^\d{4}-\d{2}-\d{2}$/.test(q.query.d || "") ? q.query.d : bizDate();
  const st = stateNow(), biz = st.biz || {};
  const ds = db.prepare("select * from duties where d=? and status in ('submitted','closed') order by id").all(d).map(detail);
  const waiting = ds.filter((x) => x.status === "submitted").length;
  const fuel = {};
  let lit = 0, amt = 0, cash = 0, upi = 0, card = 0, diff = 0;
  ds.forEach((x) => {
    cash += x.cash; upi += x.upi; card += x.card; diff += x.diff;
    x.lines.forEach((l) => { const f = fuel[l.fuel || "Other"] || (fuel[l.fuel || "Other"] = { l: 0, a: 0, u: l.unit }); f.l += l.litres; f.a += l.amount; if (l.unit === "L") lit += l.litres; amt += l.amount; });
  });
  const when = new Date(d + "T00:00:00").toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" });
  const out = [`*Daily summary: ${when}*`];
  if (biz.name) out.push(biz.name);
  out.push("", "*Fuel sold*");
  if (!ds.length) out.push("No duties submitted for this date.");
  else {
    Object.keys(fuel).forEach((k) => out.push(`${k}: ${fuel[k].u === "L" ? L1(fuel[k].l) : (Math.round(fuel[k].l * 10) / 10).toLocaleString("en-IN") + " " + fuel[k].u} = ${R0(fuel[k].a)}`));
    out.push(`Total: ${lit ? L1(lit) + " of liquid fuel, " : ""}${R0(amt)} fuel sales`);
    const lb = ds.reduce((a, x) => a + x.lube, 0);
    if (lb > 0) out.push(`Lube and shop sales: ${R0(lb)}`);
    const pt = {}, mn = {};
    ds.forEach((x) => Object.keys(x.pay).forEach((k) => (pt[k] = (pt[k] || 0) + (+x.pay[k] || 0))));
    allModes(st).forEach((m) => (mn[m.key] = m.name));
    out.push("", "*Collections*", Object.keys(pt).map((k) => `${mn[k] || k} ${R0(pt[k])}`).join(" | "), `Total collected: ${R0(ds.reduce((a, x) => a + x.collected, 0))}`);
    const shorts = ds.filter((x) => x.diff <= -1).map((x) => `${x.worker} (${x.shift}): short ${R0(-x.diff)}`);
    const excess = ds.filter((x) => x.diff >= 1).map((x) => `${x.worker} (${x.shift}): excess ${R0(x.diff)}`);
    if (!shorts.length && !excess.length) out.push("All duties tally.");
    shorts.concat(excess).forEach((x) => out.push(x));
    out.push(`Net difference: ${Math.abs(diff) < 1 ? "none" : (diff < 0 ? "short " : "excess ") + R0(Math.abs(diff))}`);
    out.push(`${ds.length} dut${ds.length === 1 ? "y" : "ies"}${waiting ? `, ${waiting} not yet closed` : ""}`);
  }
  // credit
  const sums = {};
  db.prepare("select cust_id, sum(a) t from credit_sales where status='ok' group by cust_id").all().forEach((x) => (sums[x.cust_id] = x.t));
  let owed = 0, owing = 0;
  (st.c || []).forEach((c) => {
    const due = (c.e || []).reduce((a, x) => a + (x.t === "sale" ? x.a : -x.a), 0) + (sums[String(c.id)] || 0);
    if (due > 0) { owed += due; owing++; }
  });
  const cs = db.prepare("select count(*) n, coalesce(sum(a),0) t from credit_sales where d=? and status='ok'").get(d);
  const ledgerToday = (st.c || []).reduce((a, c) => a + (c.e || []).filter((x) => x.t === "sale" && x.d === d).reduce((b, x) => b + x.a, 0), 0);
  out.push("", "*Credit*", `Credit sales today: ${R0(cs.t + ledgerToday)}`, `Total outstanding: ${R0(owed)} from ${owing} customer${owing === 1 ? "" : "s"}`);
  const pend = db.prepare("select count(*) n from credit_sales where status='pending'").get().n;
  if (pend) out.push(`${pend} credit sale${pend === 1 ? "" : "s"} waiting for approval`);
  // stock
  const tanks = tankChecks();
  out.push("", "*Tank stock*");
  if (!tanks.length) out.push("No tanks set up.");
  tanks.forEach((t) => out.push(t.book == null ? `${t.name} - ${t.fuel}: no dip yet` : `${t.name} - ${t.fuel}: about ${L1(t.book)}${t.capacity ? ` (${Math.round((t.book / t.capacity) * 100)}% full)` : ""}`));
  const low = (st.items || []).filter((i) => +i.stock <= +i.low);
  if (low.length) { out.push("", "*Low stock*"); low.forEach((i) => out.push(`${i.name}: ${i.stock} ${i.unit} left`)); }
  const owner = db.prepare("select mobile from users where role='owner' order by id limit 1").get();
  s.json({ text: out.join("\n"), to: owner ? owner.mobile : "" });
});

// ---- Server backups (owner): a nightly copy of the whole database, plus restore
const fs = require("fs");
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(__dirname, "backups");
fs.mkdirSync(BACKUP_DIR, { recursive: true });
const BK_NAME = /^[A-Za-z0-9._-]+\.db$/;
async function makeBackup(name) {
  await db.backup(path.join(BACKUP_DIR, name));
  const files = fs.readdirSync(BACKUP_DIR).filter((f) => BK_NAME.test(f)).map((f) => ({ f, t: fs.statSync(path.join(BACKUP_DIR, f)).mtimeMs })).sort((a, b) => b.t - a.t);
  files.slice(30).forEach((x) => fs.unlinkSync(path.join(BACKUP_DIR, x.f)));
  return name;
}
const stamp = () => new Date().toLocaleString("sv-SE", { timeZone: TZ }).replace(/[: ]/g, "-").slice(0, 16);
function nightlyBackup() {
  const hour = +new Date().toLocaleString("en-GB", { timeZone: TZ, hour: "2-digit", hour12: false }), name = `data-${today()}.db`;
  if (hour < 2 || fs.existsSync(path.join(BACKUP_DIR, name))) return;
  makeBackup(name).then(() => audit(null, "backup", `Nightly backup ${name}`)).catch((e) => console.error("Nightly backup failed:", e.message));
}
setInterval(nightlyBackup, 10 * 60e3).unref();
setTimeout(nightlyBackup, 5000).unref();
app.get("/api/backups", need("owner"), (q, s) => {
  s.json(fs.readdirSync(BACKUP_DIR).filter((f) => BK_NAME.test(f)).map((f) => { const st = fs.statSync(path.join(BACKUP_DIR, f)); return { name: f, size: st.size, t: Math.floor(st.mtimeMs / 1000) }; }).sort((a, b) => b.t - a.t));
});
app.post("/api/backups/run", need("owner"), (q, s) => {
  const name = `data-manual-${stamp()}.db`;
  makeBackup(name).then(() => { audit(q.user, "backup", `Manual backup ${name}`); s.json({ name }); }).catch(() => s.status(500).json({ error: "Backup failed." }));
});
app.get("/api/backups/:name", need("owner"), (q, s) => {
  if (!BK_NAME.test(q.params.name) || !fs.existsSync(path.join(BACKUP_DIR, q.params.name))) return s.status(404).json({ error: "Backup not found." });
  s.download(path.join(BACKUP_DIR, q.params.name));
});
// Restore copies every table from the chosen backup over the live data. A safety copy is taken first.
const RESTORE_TABLES = ["users", "sections", "state", "audit", "credit_sales", "duties", "duty_lines", "duty_items", "duty_expenses", "days", "dips", "pay_rates", "pay_items"];
app.post("/api/backups/restore", need("owner"), async (q, s) => {
  const name = q.body && q.body.name;
  if (!BK_NAME.test(String(name)) || !fs.existsSync(path.join(BACKUP_DIR, name))) return s.status(404).json({ error: "Backup not found." });
  try {
    await makeBackup(`data-before-restore-${stamp()}.db`);
    db.prepare("attach database ? as bk").run(path.join(BACKUP_DIR, name));
    try {
      db.transaction(() => {
        for (const t of RESTORE_TABLES) {
          const there = db.prepare("select 1 from bk.sqlite_master where type='table' and name=?").get(t);
          db.exec(`delete from main.${t}`);
          if (!there) continue;
          const mainCols = db.prepare(`pragma main.table_info(${t})`).all().map((c) => c.name), bkCols = db.prepare(`pragma bk.table_info(${t})`).all().map((c) => c.name);
          const cols = mainCols.filter((c) => bkCols.includes(c)).join(",");
          db.exec(`insert into main.${t}(${cols}) select ${cols} from bk.${t}`);
        }
        db.exec("delete from main.sessions");
      })();
    } finally { db.exec("detach database bk"); }
    audit(q.user, "restore", `Restored data from ${name}`);
    s.json({ ok: true });
  } catch (e) { console.error("Restore failed:", e.message); s.status(500).json({ error: "Restore failed. Your data was not changed." }); }
});

// ---- Manager sends a submitted duty back for correction. Allowed only while its nozzles are not with anyone else.
app.post("/api/duties/:id/return", need("owner", "manager"), (q, s) => {
  const d = db.prepare("select * from duties where id=? and status='submitted'").get(+q.params.id);
  if (!d) return s.status(404).json({ error: "Only a submitted duty can be sent back." });
  db.prepare("update duties set status='returned' where id=?").run(d.id);
  audit(q.user, "duty", `Duty #${d.id} sent back for correction`);
  s.json({ ok: true });
});
// Manager cancels a hand-over that has not been submitted yet. The receiving duty is removed; the closing reading unlocks.
app.post("/api/duties/:id/cancel-handover", need("owner", "manager"), (q, s) => {
  const d = db.prepare("select * from duties where id=? and handover_from is not null and status in ('open','returned')").get(+q.params.id);
  if (!d) return s.status(404).json({ error: "Only a hand-over that is still in progress can be cancelled." });
  db.transaction(() => {
    db.prepare("delete from duty_lines where duty_id=?").run(d.id);
    db.prepare("delete from duty_items where duty_id=?").run(d.id);
    db.prepare("delete from duty_expenses where duty_id=?").run(d.id);
    db.prepare("delete from duties where id=?").run(d.id);
  })();
  audit(q.user, "duty", `Hand-over cancelled (duty #${d.id}, from duty #${d.handover_from})`);
  s.json({ ok: true });
});
// ---- Worker hands over a nozzle from one of today's submitted duties to another worker. No approval.
app.post("/api/duty/:id/handover", need(), (q, s) => {
  const src = db.prepare("select * from duties where id=? and worker_id=? and status in ('submitted','closed')").get(+q.params.id, q.user.id);
  if (!src) return s.status(404).json({ error: "Only your submitted duties can be handed over." });
  if (src.d !== bizDate()) return s.status(400).json({ error: "Only today's duties can be handed over." });
  const b = q.body || {};
  const target = db.prepare("select * from users where id=? and role='worker' and active=1").get(+b.worker_id);
  if (!target || target.id === q.user.id) return s.status(400).json({ error: "Choose another worker." });
  if (!SHIFTS.includes(b.shift)) return s.status(400).json({ error: "Choose a shift." });
  if (openDuty(target.id)) return s.status(409).json({ error: `${target.name} already has a duty in progress.` });
  const lines = db.prepare("select * from duty_lines where duty_id=?").all(src.id);
  if (!lines.length) return s.status(400).json({ error: "This duty has no nozzles." });
  const st = stateNow(), nm = nozzleMap(st), d = bizDate(), rows = [];
  for (const l of lines) {
    const n = nm[l.nozzle_id] || {};
    const busy = db.prepare("select u.name w from duty_lines dl join duties du on du.id=dl.duty_id join users u on u.id=du.worker_id where dl.nozzle_id=? and du.status in ('open','returned') limit 1").get(l.nozzle_id);
    if (busy) return s.status(409).json({ error: `${n.name || "A nozzle"} is with ${busy.w}.` });
    const rate = rateFor(st, n.fuel, d);
    if (rate == null) return s.status(400).json({ error: `Set the ${n.fuel} rate in Pump setup first.` });
    const lc = lastClose(l.nozzle_id);
    const opening = lc.c ?? (n.open ?? null);
    if (opening == null) return s.status(400).json({ error: `Set the opening reading for ${n.name} in Pump setup first.` });
    rows.push({ nid: l.nozzle_id, opening, rate, name: n.name });
  }
  const id = db.transaction(() => {
    const did = db.prepare("insert into duties(worker_id,d,shift,started,assigned_by,handover_from) values(?,?,?,?,?,?)").run(target.id, d, b.shift, now(), q.user.id, src.id).lastInsertRowid;
    rows.forEach((r) => db.prepare("insert into duty_lines(duty_id,nozzle_id,opening,rate) values(?,?,?,?)").run(did, r.nid, r.opening, r.rate));
    return did;
  })();
  audit(q.user, "duty", `Nozzles ${rows.map((r) => r.name).join(", ")} handed over from ${src.id ? "duty #" + src.id : "a duty"} to ${target.name}`);
  s.json({ id });
});
// ---- Worker records an expense from the till on their open duty (same list as the duty form)
app.post("/api/duty/expense", need(), (q, s) => {
  const d = openDuty(q.user.id);
  if (!d) return s.status(400).json({ error: "Start a duty first." });
  const b = q.body || {};
  const cat = String(b.cat || "Other").slice(0, 40), note = String(b.note || "").slice(0, 60), amt = r2(+b.amount);
  if (!(amt > 0) || amt > 1e7) return s.status(400).json({ error: "Enter an amount above zero." });
  db.prepare("insert into duty_expenses(duty_id,cat,note,amount) values(?,?,?,?)").run(d.id, cat, note, amt);
  audit(q.user, "expense", `Duty expense ${money(amt)} (${cat})`);
  s.json({ ok: true });
});
// ---- Shop sales (manager and worker): reduce stock and record the sale against a payment mode
app.post("/api/shop-sales", need(), (q, s) => {
  const b = q.body || {}, st = readSections().state, items = st.items || [];
  const valid = new Set(["cash", "upi", "card", ...((st.paymodes || []).map((m) => m.key))]);
  const mode = String(b.mode || "");
  if (!valid.has(mode)) return s.status(400).json({ error: "Choose a payment mode." });
  const rows = (Array.isArray(b.lines) ? b.lines : []).slice(0, 6);
  const need = {}, L = [];
  for (const r of rows) {
    if (!r || r.item_id === "" || r.item_id == null) continue;
    const it = items.find((x) => String(x.id) === String(r.item_id));
    if (!it) return s.status(400).json({ error: "Choose each item from the stock list." });
    const qty = +r.qty;
    if (!(qty > 0) || qty > 100000) return s.status(400).json({ error: `Enter the quantity for ${it.name}.` });
    need[it.id] = (need[it.id] || 0) + qty;
    const g = it.gst == null ? 18 : +it.gst;
    L.push({ item_id: String(it.id), name: it.name, qty, price: +it.sell, gst: g, amount: r2(qty * (+it.sell || 0) * (1 + g / 100)), cost: r2(qty * (+it.buy || 0)) });
  }
  if (!L.length) return s.status(400).json({ error: "Choose at least one item." });
  for (const k in need) {
    const it = items.find((x) => String(x.id) === k);
    if (need[k] > (+it.stock || 0)) return s.status(400).json({ error: `Only ${it.stock} ${it.unit} of ${it.name} in stock.` });
  }
  for (const k in need) { const it = items.find((x) => String(x.id) === k); it.stock = r2((+it.stock || 0) - need[k]); }
  writeSection("items", { items, itemcats: st.itemcats || [] });
  const total = r2(L.reduce((a, x) => a + x.amount, 0));
  const id = db.prepare("insert into shop_sales(d,mode,lines_json,total,note,worker_id,created) values(?,?,?,?,?,?,?)").run(bizDate(), mode, JSON.stringify(L), total, String(b.note || "").slice(0, 100), q.user.id, now()).lastInsertRowid;
  audit(q.user, "shop", `Shop sale ${money(total)} (${mode})`);
  s.json({ ok: true, id, total });
});
// ---- Payroll report, day by day, one section per worker. Owner and manager: every worker. A worker: only themselves.
const PAY_KIND = { advance: "Advance taken", bonus: "Bonus", waive: "Shortage waived", paid: "Salary paid" };
app.get("/api/payroll-report", need(), (q, s) => {
  const month = cfMonth(q.query.month), me = q.user;
  const list = me.role === "worker"
    ? [db.prepare("select id,name,role from users where id=?").get(me.id)]
    : db.prepare("select id,name,role from users where role='worker' order by name").all();
  const workers = list.map((u) => {
    const pay = payFor(u, month);
    const rates = {};
    db.prepare("select shift,rate from pay_rates where worker_id=?").all(u.id).forEach((r) => (rates[r.shift] = r.rate));
    const days = {};
    const day = (d) => days[d] || (days[d] = { d, duties: [], entries: [] });
    const paidShift = new Set();
    db.prepare("select * from duties where worker_id=? and status='closed' and substr(d,1,7)=? order by d,id").all(u.id, month).map(detail).forEach((x) => {
      const dd = day(x.d);
      const first = !paidShift.has(x.d + "|" + x.shift);
      paidShift.add(x.d + "|" + x.shift);
      dd.duties.push({ shift: x.shift, nozzles: x.lines.map((l) => l.nozzle).join(", "), litres: r2(x.litres), sales: r2(x.sales + x.lube), collected: r2(x.collected), diff: r2(x.diff), pay: first ? r2(rates[x.shift] || 0) : 0 });
      if (x.diff >= 1) dd.entries.push({ kind: "excess", label: "Excess credited to advance", amount: r2(x.diff), note: "" });
    });
    pay.items.forEach((it) => day(it.d).entries.push({ kind: it.kind, label: PAY_KIND[it.kind] || it.kind, amount: r2(it.amount), note: it.note || "" }));
    return {
      id: u.id, name: u.name,
      days: Object.values(days).sort((a, b) => (a.d < b.d ? -1 : a.d > b.d ? 1 : 0)),
      summary: { duties: pay.duties, earn: pay.earn, bonus: pay.bonus, excess: pay.excess, advance: pay.advance, short: pay.short, waived: pay.waived, deducted: r2(Math.max(0, (pay.short || 0) - (pay.waived || 0))), paid: pay.paid, net: pay.net, balance: pay.balance },
    };
  });
  s.json({ month, workers });
});
app.use(express.static(path.join(__dirname, "public")));
app.use("/api", (q, s) => s.status(404).json({ error: "Not found." }));
app.use((err, q, s, n) => s.status(err.status || 500).json({ error: err.status === 400 ? "Invalid request." : "Something went wrong." }));

setInterval(() => db.prepare("delete from sessions where exp<?").run(now()), 3600e3).unref();
app.listen(PORT, HOST, () => console.log(`Petrol pump server on http://${HOST}:${PORT}`));
