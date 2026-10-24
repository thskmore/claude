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
  `);
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

function mount(app, { REG, bcrypt, stationsDir, publicDir }) {
  initSchema(REG);
  const DUMMY = bcrypt.hashSync("not-a-real-password-1", 12); // so a wrong mobile number takes as long as a wrong password
  const audit = (a, action, detail) => REG.prepare("insert into admin_audit(t,admin_id,admin_name,action,detail) values(?,?,?,?,?)").run(now(), a ? a.id : null, a ? a.name : null, action, String(detail || "").slice(0, 300));
  const token = (q) => {
    const auth = q.headers.authorization;
    if (auth && auth.startsWith("Bearer ")) return auth.slice(7).trim();
    const xToken = q.headers["x-admin-token"] || q.headers["x-token"];
    if (xToken) return String(xToken).trim();
    const m = String(q.headers.cookie || "").match(/(?:^|;\s*)adm=([a-f0-9]{64})/);
    return m ? m[1] : null;
  };
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
    const isSecure = q.secure || q.headers["x-forwarded-proto"] === "https";
    const cookieOpts = isSecure ? "SameSite=None; Secure; Partitioned" : "SameSite=Lax";
    s.setHeader("Set-Cookie", `adm=${t}; HttpOnly; ${cookieOpts}; Path=/api/admin; Max-Age=${SESSION_SECS}`);
    audit(a, "login", "");
    s.json({ admin: pub(a), token: t });
  });
  app.post("/api/admin/logout", (q, s) => {
    const t = token(q);
    if (t) REG.prepare("delete from admin_sessions where token=?").run(hs(t));
    const isSecure = q.secure || q.headers["x-forwarded-proto"] === "https";
    const cookieOpts = isSecure ? "SameSite=None; Secure; Partitioned" : "SameSite=Lax";
    s.setHeader("Set-Cookie", `adm=; HttpOnly; ${cookieOpts}; Path=/api/admin; Max-Age=0`);
    s.json({ ok: true });
  });

  // ---- Stations: contact and status only. No business data.
  app.get("/api/admin/stations", need, (q, s) => {
    const rows = REG.prepare("select slug,name,status,owner_mobile,created,consent_at,notice_version,deletion_requested from stations order by created desc").all();
    s.json(rows.map((r) => {
      let bytes = 0;
      try { bytes = fs.statSync(path.join(stationsDir, r.slug + ".db")).size; } catch (e) { /* the file may be gone */ }
      return { ...r, db_bytes: bytes };
    }));
  });
  app.post("/api/admin/stations/:slug/status", need, (q, s) => {
    const to = q.body && q.body.status;
    if (!["active", "suspended"].includes(to)) return s.status(400).json({ error: "Choose active or suspended." });
    const r = REG.prepare("select * from stations where slug=?").get(q.params.slug);
    if (!r) return s.status(404).json({ error: "Station not found." });
    if (r.status === "pending_deletion") return s.status(409).json({ error: "This station has asked to be deleted. Its status cannot be changed here." });
    if (r.status !== to) {
      REG.prepare("update stations set status=? where slug=?").run(to, r.slug);
      audit(q.admin, to === "suspended" ? "station_suspended" : "station_reactivated", `${r.slug}${q.body.reason ? ": " + String(q.body.reason).slice(0, 150) : ""}`);
    }
    s.json({ ok: true, status: to });
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
}

module.exports = { mount, initSchema, createAdmin, checkAdmin, mob };
