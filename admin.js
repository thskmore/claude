"use strict";
// Platform operator ("super admin") accounts.
// They manage stations (suspend, reactivate, see contact and status) and other admins.
// By design nothing here opens a station database, so an admin can never read a station's business data.
// Everything lives in the central registry (registry.db), apart from station logins.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const SESSION_SECS = 8 * 3600;
const now = () => Math.floor(Date.now() / 1000);
const hs = (t) => crypto.createHash("sha256").update(t).digest("hex");
const mob = (x) => String(x || "").replace(/\D/g, "").slice(-10);

function initSchema(REG) {
  REG.exec(`
    create table if not exists admins(id integer primary key autoincrement, name text not null, mobile text not null unique, hash text not null, created integer not null, last_login integer);
    create table if not exists admin_sessions(token text primary key, admin_id integer not null, exp integer not null);
    create table if not exists admin_fails(k text primary key, n integer not null, t integer not null);
    create table if not exists admin_audit(id integer primary key autoincrement, t integer not null, admin_id integer, admin_name text, action text not null, detail text);
    create table if not exists billing_settings(key text primary key, value text not null);
    create table if not exists payments(id integer primary key autoincrement, station_slug text not null, amount real not null, reference text not null, paid_date text not null, note text, recorded_by integer, recorded_at integer not null);
  `);
  const billingCols = [
    "alter table stations add column billing_status text not null default 'trial'",
    "alter table stations add column trial_ends integer",
    "alter table stations add column paid_until integer",
    "alter table stations add column grace_ends integer",
  ];
  for (const sql of billingCols) {
    try { REG.exec(sql); } catch (e) { /* already there */ }
  }
  // Seed default billing settings
  const defaults = { trial_days: '30', grace_days: '7', yearly_fee: '0', upi_id: '', bank_name: '', bank_account: '', bank_ifsc: '', bank_holder: '' };
  for (const [k, v] of Object.entries(defaults)) {
    REG.prepare("insert or ignore into billing_settings(key,value) values(?,?)").run(k, v);
  }
  try {
    REG.prepare("update stations set trial_ends = coalesce(created, strftime('%s','now')) + 30 * 86400 where trial_ends is null and paid_until is null and status != 'deleted'").run();
  } catch (e) { /* ignore */ }
}

// An admin account is stricter than a station login: 10+ characters with a letter and a digit.
function checkAdmin(name, m, pw) {
  if (!String(name || "").trim() || String(name).length > 60) return "Enter a name (up to 60 characters).";
  if (m.length !== 10) return "Enter a 10-digit mobile number.";
  if (typeof pw !== "string" || pw.length < 10 || pw.length > 100) return "Password must be at least 10 characters.";
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return "Password needs at least one letter and one digit.";
  return null;
}

function createAdmin(REG, bcrypt, { name, mobile, password }) {
  const m = mob(mobile), e = checkAdmin(name, m, password);
  if (e) return { error: e };
  if (REG.prepare("select 1 from admins where mobile=?").get(m)) return { error: "An admin with this mobile number already exists." };
  const id = REG.prepare("insert into admins(name,mobile,hash,created) values(?,?,?,?)").run(String(name).trim(), m, bcrypt.hashSync(password, 12), now()).lastInsertRowid;
  return { id: Number(id), name: String(name).trim(), mobile: m };
}

// ---- First-run setup code. The very first admin is created on a web screen, but only by someone who can read this code from the server
// (its log, or the file first-run-code.txt in the data folder). Without it, whoever opened the site first would become the admin.
const codeFile = (dataDir) => path.join(dataDir, "first-run-code.txt");
function firstRunCode(dataDir) {
  const fromEnv = String(process.env.ADMIN_SETUP_CODE || "").trim();
  if (fromEnv.length >= 10) return fromEnv;
  try { const c = fs.readFileSync(codeFile(dataDir), "utf8").trim(); if (c) return c; } catch (e) { /* none yet */ }
  const letters = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", b = crypto.randomBytes(10);
  let c = "";
  for (let i = 0; i < 10; i++) { c += letters[b[i] % letters.length]; if (i === 4) c += "-"; }
  fs.writeFileSync(codeFile(dataDir), c + "\n", { mode: 0o600 });
  return c;
}
function announceFirstRun(dataDir, REG) {
  initSchema(REG);
  if (REG.prepare("select count(*) n from admins").get().n > 0) return;
  if (process.env.ADMIN_SETUP_CODE && String(process.env.ADMIN_SETUP_CODE).trim().length < 10) console.warn("ADMIN_SETUP_CODE is shorter than 10 characters, so it is ignored.");
  const c = firstRunCode(dataDir);
  console.log("\n========================================================\n  FIRST-TIME SETUP\n  Open the site and create the platform admin account.\n  Setup code: " + c + "\n  (also saved in " + codeFile(dataDir) + ")\n========================================================\n");
}

function getBillingSettings(REG) {
  const rows = REG.prepare("select key, value from billing_settings").all();
  const s = {};
  for (const r of rows) s[r.key] = r.value;
  return {
    trial_days: Math.max(1, parseInt(s.trial_days) || 30),
    grace_days: Math.max(0, parseInt(s.grace_days) || 7),
    yearly_fee: parseFloat(s.yearly_fee) || 0,
    upi_id: s.upi_id || '',
    bank_name: s.bank_name || '',
    bank_account: s.bank_account || '',
    bank_ifsc: s.bank_ifsc || '',
    bank_holder: s.bank_holder || '',
  };
}

function computeBilling(station, settings) {
  const n = Math.floor(Date.now() / 1000);
  const DAY = 86400;
  let status = station.billing_status || 'trial';
  let expires_at = null;
  let days_left = null;

  if (status === 'trial') {
    expires_at = station.trial_ends;
    if (expires_at && n > expires_at) {
      status = 'grace';
      const grace_ends = expires_at + settings.grace_days * DAY;
      if (n > grace_ends) status = 'readonly';
      else { expires_at = grace_ends; days_left = Math.ceil((grace_ends - n) / DAY); }
    } else if (expires_at) {
      days_left = Math.ceil((expires_at - n) / DAY);
    }
  } else if (status === 'active') {
    expires_at = station.paid_until;
    if (expires_at && n > expires_at) {
      status = 'grace';
      const grace_ends = expires_at + settings.grace_days * DAY;
      if (n > grace_ends) status = 'readonly';
      else { expires_at = grace_ends; days_left = Math.ceil((grace_ends - n) / DAY); }
    } else if (expires_at) {
      days_left = Math.ceil((expires_at - n) / DAY);
    }
  } else if (status === 'grace') {
    expires_at = station.grace_ends;
    if (expires_at && n > expires_at) status = 'readonly';
    else if (expires_at) days_left = Math.ceil((expires_at - n) / DAY);
  }
  return { billing_status: status, expires_at, days_left };
}

function mount(app, { REG, bcrypt, stationsDir, publicDir, purgeStation, graceDays, DAY, dataDir }) {
  initSchema(REG);
  const DUMMY = bcrypt.hashSync("not-a-real-password-1", 12); // so a wrong mobile number takes as long as a wrong password
  const audit = (a, action, detail) => REG.prepare("insert into admin_audit(t,admin_id,admin_name,action,detail) values(?,?,?,?,?)").run(now(), a ? a.id : null, a ? a.name : null, action, String(detail || "").slice(0, 300));
  const token = (q) => { const m = String(q.headers.cookie || "").match(/(?:^|;\s*)adm=([a-f0-9]{64})/); return m ? m[1] : null; };
  const getAdmin = (q) => {
    const t = token(q);
    if (!t) return null;
    const r = REG.prepare("select a.id,a.name,a.mobile,s.exp from admin_sessions s join admins a on a.id=s.admin_id where s.token=?").get(hs(t));
    return r && r.exp >= now() ? r : null;
  };
  const need = (q, s, n) => {
    const a = getAdmin(q);
    if (!a) return s.status(401).json({ error: "Please log in." });
    q.admin = a;
    n();
  };
  const pub = (a) => ({ id: a.id, name: a.name, mobile: a.mobile });
  const passwordOk = (id, pw) => { const a = REG.prepare("select hash from admins where id=?").get(id); return !!a && bcrypt.compareSync(String(pw || ""), a.hash); };

  // Login throttle: 5 wrong tries per IP + mobile locks that pair for 15 minutes.
  const failRow = (k) => REG.prepare("select n,t from admin_fails where k=?").get(k);
  const blocked = (k) => { const f = failRow(k); return !!f && f.n >= 5 && Date.now() - f.t < 15 * 60e3; };
  const addFail = (k) => { const f = failRow(k); const n = f && Date.now() - f.t <= 15 * 60e3 ? f.n + 1 : 1; REG.prepare("insert into admin_fails(k,n,t) values(?,?,?) on conflict(k) do update set n=excluded.n, t=excluded.t").run(k, n, Date.now()); };
  const clearFail = (k) => REG.prepare("delete from admin_fails where k=?").run(k);

  app.get("/admin", (q, s) => s.sendFile(path.join(publicDir, "admin.html")));

  app.get("/api/admin/me", (q, s) => {
    const a = getAdmin(q);
    s.json({ admin: a ? pub(a) : null, none: REG.prepare("select count(*) n from admins").get().n === 0 });
  });
  app.post("/api/admin/login", (q, s) => {
    const m = mob(q.body && q.body.mobile), p = String((q.body && q.body.password) || ""), k = q.ip + "|" + m;
    if (blocked(k)) return s.status(429).json({ error: "Too many wrong tries. Try again in 15 minutes." });
    const a = REG.prepare("select * from admins where mobile=?").get(m);
    const good = bcrypt.compareSync(p, a ? a.hash : DUMMY);
    if (!a || !good) { addFail(k); return s.status(401).json({ error: "Wrong mobile number or password." }); }
    clearFail(k);
    REG.prepare("delete from admin_sessions where exp<?").run(now());
    const t = crypto.randomBytes(32).toString("hex");
    REG.prepare("insert into admin_sessions(token,admin_id,exp) values(?,?,?)").run(hs(t), a.id, now() + SESSION_SECS);
    REG.prepare("update admins set last_login=? where id=?").run(now(), a.id);
    // The cookie is only sent to /api/admin, never to station routes.
    s.setHeader("Set-Cookie", `adm=${t}; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age=${SESSION_SECS}${q.secure ? "; Secure" : ""}`);
    audit(a, "login", "");
    s.json({ admin: pub(a) });
  });
  // The first admin, created on the web. It needs the setup code, and only works while no admin exists.
  app.post("/api/admin/first-run", (q, s) => {
    if (REG.prepare("select count(*) n from admins").get().n > 0) return s.status(409).json({ error: "The platform admin already exists. Please log in." });
    const k = "first-run|" + q.ip, b = q.body || {};
    if (blocked(k)) return s.status(429).json({ error: "Too many wrong tries. Try again in 15 minutes." });
    const norm = (x) => Buffer.from(String(x || "").replace(/\s/g, "").toUpperCase());
    const given = norm(b.code), want = norm(firstRunCode(dataDir));
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
      addFail(k);
      return s.status(403).json({ error: "That setup code is not correct. It is in the server log, and in the file first-run-code.txt in the data folder." });
    }
    const r = createAdmin(REG, bcrypt, b);
    if (r.error) return s.status(400).json({ error: r.error });
    clearFail(k);
    try { fs.unlinkSync(codeFile(dataDir)); } catch (e) { /* already gone */ }
    const a = REG.prepare("select * from admins where id=?").get(r.id);
    const t = crypto.randomBytes(32).toString("hex");
    REG.prepare("insert into admin_sessions(token,admin_id,exp) values(?,?,?)").run(hs(t), a.id, now() + SESSION_SECS);
    REG.prepare("update admins set last_login=? where id=?").run(now(), a.id);
    s.setHeader("Set-Cookie", `adm=${t}; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age=${SESSION_SECS}${q.secure ? "; Secure" : ""}`);
    audit(a, "first_admin_created", "");
    s.json({ admin: pub(a) });
  });
  app.post("/api/admin/logout", (q, s) => {
    const t = token(q);
    if (t) REG.prepare("delete from admin_sessions where token=?").run(hs(t));
    s.setHeader("Set-Cookie", "adm=; HttpOnly; SameSite=Strict; Path=/api/admin; Max-Age=0");
    s.json({ ok: true });
  });

  // ---- Stations: contact and status only. No business data.
  app.get("/api/admin/stations", need, (q, s) => {
    const cfg = getBillingSettings(REG);
    const rows = REG.prepare("select slug,name,status,owner_mobile,created,consent_at,notice_version,deletion_requested,deleted_at,billing_status,trial_ends,paid_until,grace_ends from stations order by created desc").all();
    s.json(rows.map((r) => {
      let bytes = 0;
      try { bytes = fs.statSync(path.join(stationsDir, r.slug + ".db")).size; } catch (e) { /* the file may be gone */ }
      const billing = computeBilling(r, cfg);
      return { ...r, db_bytes: bytes, purge_at: r.status === "pending_deletion" ? r.deletion_requested + graceDays() * DAY : null, billing };
    }));
  });
  app.post("/api/admin/stations/:slug/status", need, (q, s) => {
    const to = q.body && q.body.status;
    if (!["active", "suspended"].includes(to)) return s.status(400).json({ error: "Choose active or suspended." });
    const r = REG.prepare("select * from stations where slug=?").get(q.params.slug);
    if (!r) return s.status(404).json({ error: "Station not found." });
    if (r.status === "deleted") return s.status(409).json({ error: "This station has been deleted." });
    if (r.status === "pending_deletion") return s.status(409).json({ error: "This station has asked to be deleted. Its status cannot be changed here. The owner can cancel the request." });
    if (r.status !== to) {
      REG.prepare("update stations set status=? where slug=?").run(to, r.slug);
      audit(q.admin, to === "suspended" ? "station_suspended" : "station_reactivated", `${r.slug}${q.body.reason ? ": " + String(q.body.reason).slice(0, 150) : ""}`);
    }
    s.json({ ok: true, status: to });
  });

  // Erase a station that asked to be deleted, before its grace period ends. Nothing else can be erased from here.
  app.post("/api/admin/stations/:slug/purge", need, (q, s) => {
    const b = q.body || {};
    if (!passwordOk(q.admin.id, b.confirm_password)) return s.status(403).json({ error: "Your password is not correct." });
    const r = REG.prepare("select * from stations where slug=?").get(q.params.slug);
    if (!r) return s.status(404).json({ error: "Station not found." });
    if (r.status !== "pending_deletion") return s.status(409).json({ error: "Only a station that asked to be deleted can be erased here." });
    if (String(b.confirm_slug || "") !== r.slug) return s.status(400).json({ error: "Type the station address exactly to confirm." });
    purgeStation(r.slug);
    audit(q.admin, "station_deleted", r.slug);
    s.json({ ok: true });
  });

  // ---- Admins
  app.get("/api/admin/admins", need, (q, s) => {
    s.json(REG.prepare("select id,name,mobile,created,last_login from admins order by id").all());
  });
  app.post("/api/admin/admins", need, (q, s) => {
    const b = q.body || {};
    if (!passwordOk(q.admin.id, b.confirm_password)) return s.status(403).json({ error: "Your password is not correct." });
    const r = createAdmin(REG, bcrypt, b);
    if (r.error) return s.status(400).json({ error: r.error });
    audit(q.admin, "admin_created", `${r.name} (${r.mobile})`);
    s.json({ ok: true, admin: r });
  });
  app.post("/api/admin/admins/:id/remove", need, (q, s) => {
    const id = +q.params.id;
    if (!passwordOk(q.admin.id, q.body && q.body.confirm_password)) return s.status(403).json({ error: "Your password is not correct." });
    if (id === q.admin.id) return s.status(400).json({ error: "You cannot remove your own account." });
    const a = REG.prepare("select * from admins where id=?").get(id);
    if (!a) return s.status(404).json({ error: "Admin not found." });
    REG.transaction(() => {
      REG.prepare("delete from admin_sessions where admin_id=?").run(id);
      REG.prepare("delete from admins where id=?").run(id);
    })();
    audit(q.admin, "admin_removed", `${a.name} (${a.mobile})`);
    s.json({ ok: true });
  });
  app.post("/api/admin/password", need, (q, s) => {
    const b = q.body || {};
    if (!passwordOk(q.admin.id, b.current)) return s.status(403).json({ error: "Your current password is not correct." });
    const e = checkAdmin(q.admin.name, mob(q.admin.mobile), b.next);
    if (e) return s.status(400).json({ error: e });
    REG.prepare("update admins set hash=? where id=?").run(bcrypt.hashSync(b.next, 12), q.admin.id);
    REG.prepare("delete from admin_sessions where admin_id=? and token<>?").run(q.admin.id, hs(token(q))); // other devices are logged out
    audit(q.admin, "password_changed", "");
    s.json({ ok: true });
  });

  app.get("/api/admin/audit", need, (q, s) => {
    s.json(REG.prepare("select t,admin_name,action,detail from admin_audit order by id desc limit 100").all());
  });

  // ---- Billing: public info (no auth) - UPI/bank details for renew screen
  app.get("/api/billing-info", (q, s) => {
    const cfg = getBillingSettings(REG);
    s.json({ upi_id: cfg.upi_id, bank_name: cfg.bank_name, bank_account: cfg.bank_account, bank_ifsc: cfg.bank_ifsc, bank_holder: cfg.bank_holder, yearly_fee: cfg.yearly_fee });
  });

  // ---- Billing: admin endpoints
  app.get("/api/admin/billing-settings", need, (q, s) => {
    s.json(getBillingSettings(REG));
  });
  app.post("/api/admin/billing-settings", need, (q, s) => {
    const b = q.body || {};
    const allowed = ["trial_days", "grace_days", "yearly_fee", "upi_id", "bank_name", "bank_account", "bank_ifsc", "bank_holder"];
    for (const k of allowed) {
      if (b[k] !== undefined) REG.prepare("insert or replace into billing_settings(key,value) values(?,?)").run(k, String(b[k]));
    }
    audit(q.admin, "billing_settings_updated", "");
    s.json({ ok: true });
  });
  app.post("/api/admin/stations/:slug/mark-paid", need, (q, s) => {
    const b = q.body || {};
    const r = REG.prepare("select * from stations where slug=?").get(q.params.slug);
    if (!r) return s.status(404).json({ error: "Station not found." });
    if (r.status === "deleted") return s.status(409).json({ error: "This station has been deleted." });
    const amount = parseFloat(b.amount);
    if (!amount || amount <= 0) return s.status(400).json({ error: "Enter a valid amount." });
    if (!String(b.reference || "").trim()) return s.status(400).json({ error: "Enter the UPI or bank reference." });
    if (!String(b.paid_date || "").trim()) return s.status(400).json({ error: "Enter the payment date." });
    const n = Math.floor(Date.now() / 1000);
    const paid_until = n + 365 * 86400;
    REG.transaction(() => {
      REG.prepare("update stations set billing_status='active', paid_until=?, grace_ends=null where slug=?").run(paid_until, r.slug);
      REG.prepare("insert into payments(station_slug,amount,reference,paid_date,note,recorded_by,recorded_at) values(?,?,?,?,?,?,?)").run(
        r.slug, amount, String(b.reference).trim(), String(b.paid_date).trim(), String(b.note || "").slice(0, 300), q.admin.id, n
      );
    })();
    audit(q.admin, "station_marked_paid", `${r.slug}: ₹${amount} ref=${b.reference}`);
    s.json({ ok: true, paid_until });
  });
  app.post("/api/admin/stations/:slug/extend-trial", need, (q, s) => {
    const b = q.body || {};
    const days = Math.max(1, parseInt(b.days) || 30);
    const r = REG.prepare("select * from stations where slug=?").get(q.params.slug);
    if (!r) return s.status(404).json({ error: "Station not found." });
    if (r.status === "deleted") return s.status(409).json({ error: "This station has been deleted." });
    const n = Math.floor(Date.now() / 1000);
    const current = r.trial_ends && r.trial_ends > n ? r.trial_ends : n;
    const new_end = current + days * 86400;
    REG.prepare("update stations set billing_status='trial', trial_ends=?, grace_ends=null where slug=?").run(new_end, r.slug);
    audit(q.admin, "trial_extended", `${r.slug}: +${days} days`);
    s.json({ ok: true, trial_ends: new_end });
  });
  app.get("/api/admin/stations/:slug/payments", need, (q, s) => {
    const rows = REG.prepare("select p.*, a.name as admin_name from payments p left join admins a on a.id=p.recorded_by where p.station_slug=? order by p.id desc").all(q.params.slug);
    s.json(rows);
  });
  app.get("/api/admin/expiring-soon", need, (q, s) => {
    const n = Math.floor(Date.now() / 1000);
    const cfg = getBillingSettings(REG);
    const in7 = n + 7 * 86400;
    // Stations in trial or active that expire within 7 days, plus those already in grace
    const rows = REG.prepare("select slug,name,billing_status,trial_ends,paid_until,grace_ends,owner_mobile from stations where status not in ('deleted') and (billing_status='grace' or (billing_status='trial' and trial_ends between ? and ?) or (billing_status='active' and paid_until between ? and ?)) order by coalesce(trial_ends,paid_until,grace_ends) asc").all(n, in7, n, in7);
    s.json(rows.map(r => ({ ...r, ...computeBilling(r, cfg) })));
  });
}

module.exports = { mount, initSchema, createAdmin, checkAdmin, mob, announceFirstRun, firstRunCode, getBillingSettings, computeBilling };
