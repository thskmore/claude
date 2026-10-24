#!/usr/bin/env node
"use strict";
// Creates a super admin (platform operator) account. Run it on the server:
//   node create-admin.js
// It asks for a name, a mobile number and a password (typed password is hidden).
// Use the same DATA_DIR as the server if you have set one.
// For scripts, set ADMIN_NAME, ADMIN_MOBILE and ADMIN_PASSWORD instead (a password in the environment can be seen by other users on the machine).
const path = require("path");
const readline = require("readline");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const admin = require("./admin");

const DATA_DIR = process.env.DATA_DIR || __dirname;
const REG = new Database(path.join(DATA_DIR, "registry.db"));
admin.initSchema(REG);

// One reader for the whole run, so answers that arrive together (pasted or piped) are not lost.
const tty = !!process.stdin.isTTY;
const rl = readline.createInterface({ input: process.stdin, output: tty ? process.stdout : undefined, terminal: tty });
const lines = rl[Symbol.asyncIterator]();
let muted = false;
if (tty) { const echo = rl._writeToOutput.bind(rl); rl._writeToOutput = (s) => { if (!muted) echo(s); }; } // a typed password is not shown at all
async function ask(question, hidden) {
  process.stdout.write(question);
  muted = !!hidden;
  const r = await lines.next();
  muted = false;
  if (tty || hidden) process.stdout.write("\n");
  return r.done ? "" : r.value;
}

(async () => {
  let name = process.env.ADMIN_NAME, mobile = process.env.ADMIN_MOBILE, password = process.env.ADMIN_PASSWORD;
  if (!name || !mobile || !password) {
    name = await ask("Name: ", false);
    mobile = await ask("Mobile number (10 digits): ", false);
    password = await ask("Password (10+ characters, with a letter and a digit): ", true);
    const again = await ask("Type the password again: ", true);
    if (again !== password) { console.error("The passwords do not match. Nothing was created."); process.exit(1); }
  }
  const r = admin.createAdmin(REG, bcrypt, { name, mobile, password });
  if (r.error) { console.error(r.error + " Nothing was created."); process.exit(1); }
  console.log(`Super admin created: ${r.name} (${r.mobile}). Log in at /admin on your server.`);
  process.exit(0);
})();
