"use strict";
// Calculations for the stock register and the density register. Pure functions, no database access.

const r1 = (x) => Math.round(x * 10) / 10;

// Density at 15 C from the observed density (kg/m3) and temperature (C).
// Uses the generalised-products correction of API MPMS 11.1 / ASTM D1250 (Table 53B style):
// find rho15 such that rho_t = rho15 * exp(-a * dt * (1 + 0.8 * a * dt)).
function density15(obs, t) {
  obs = +obs; t = +t;
  if (!isFinite(obs) || !isFinite(t) || obs <= 0) return null;
  const dt = t - 15;
  let r = obs;
  for (let i = 0; i < 100; i++) {
    let a;
    if (r < 770.352) a = (346.4228 + 0.4388 * r) / (r * r);          // gasolines
    else if (r < 787.52) a = -0.0018684 + 1489.067 / (r * r);          // transition zone
    else if (r < 838.3127) a = 594.5418 / (r * r);                      // jet fuels, kerosene
    else a = (186.9696 + 0.4862 * r) / (r * r);                         // diesel, fuel oils
    const next = obs / Math.exp(-a * dt * (1 + 0.8 * a * dt));
    if (Math.abs(next - r) < 1e-9) { r = next; break; }
    r = next;
  }
  return r1(r);
}

function daysOfMonth(month) {
  const [y, m] = month.split("-").map(Number), n = new Date(Date.UTC(y, m, 0)).getUTCDate(), out = [];
  for (let d = 1; d <= n; d++) out.push(`${month}-${String(d).padStart(2, "0")}`);
  return out;
}
const prevDay = (d) => new Date(new Date(d + "T00:00:00Z").getTime() - 864e5).toISOString().slice(0, 10);

// o.receipts, o.meter, o.test, o.closing, o.morning: maps from date to litres (closing and morning only when every tank has a reading).
// Opening stock is the previous day's closing dip stock. If that day has no closing, the opening is carried from the last
// known closing and that row is marked "carried": its sales by dip and variation are left blank because they would span several days.
function buildStockRegister(days, o) {
  const first = days[0];
  let last = null;
  Object.keys(o.closing).sort().forEach((d) => { if (d < first) last = { d, v: o.closing[d] }; });
  const sumRec = (from, to) => Object.keys(o.receipts).filter((x) => x > from && x < to).reduce((a, x) => a + o.receipts[x], 0);
  const rows = []; let cum = 0, cumVar = 0;
  const T = { receipts: 0, meter: 0, test: 0, net: 0, dip: 0, variation: 0, missingClosing: 0, carried: 0 };
  for (const d of days) {
    const rec = o.receipts[d] || 0, meter = o.meter[d] || 0, test = o.test[d] || 0, net = meter - test;
    let opening = null, carried = false;
    if (last) {
      if (last.d === prevDay(d)) opening = last.v;
      else { opening = last.v + sumRec(last.d, d); carried = true; }
    } else if (o.morning && o.morning[d] != null) { opening = o.morning[d]; carried = true; }
    const total = opening == null ? null : opening + rec;
    const closing = o.closing[d] != null ? o.closing[d] : null;
    let dip = null, variation = null;
    if (total != null && closing != null && !carried) { dip = total - closing; variation = meter - dip; }
    cum += net;
    if (variation != null) cumVar += variation;
    const hasData = rec || meter || test || closing != null || opening != null;
    rows.push({ d, opening, receipts: rec, total, meter, test, net, cum, dip, variation, cumVar, closing, carried, hasData: !!hasData });
    T.receipts += rec; T.meter += meter; T.test += test; T.net += net;
    if (dip != null) { T.dip += dip; T.variation += variation; }
    if (closing == null && (meter || rec)) T.missingClosing++;
    if (carried) T.carried++;
    if (closing != null) last = { d, v: closing };
  }
  return { rows, totals: T };
}

// Density register. Morning density comes from the main tank. Each tanker receipt is one row.
function buildDensityRegister({ days, mainId, tankIds, tankNames, deliv, dips, cfg }) {
  const inRange = (v) => v != null && ((cfg.min != null && v < cfg.min) || (cfg.max != null && v > cfg.max));
  const d15of = (x) => (x.d15 != null ? +x.d15 : x.dens_obs != null && x.temp != null ? density15(x.dens_obs, x.temp) : null);
  const morning = {};
  dips.filter((x) => x.purpose === "morning" && String(x.tank_id) === String(mainId)).forEach((x) => { if (!morning[x.bd]) morning[x.bd] = x; });
  const before = {}, after = {};
  dips.forEach((x) => {
    const k = x.bd + "|" + x.tank_id;
    if (x.purpose === "before") (before[k] = before[k] || []).push(x);
    if (x.purpose === "after") (after[k] = after[k] || []).push(x);
  });
  const recs = {}, used = {};
  (deliv || []).forEach((dv) => (dv.lines || []).forEach((l) => {
    if (!tankIds.includes(String(l.tank_id))) return;
    const k = dv.d + "|" + l.tank_id, i = used[k] || 0; used[k] = i + 1;
    const dn = l.dens || {};
    const comps = [0, 1, 2, 3].map((j) => {
      const c = (dn.comps || [])[j];
      if (!c) return null;
      const v = c.d15 != null ? +c.d15 : c.obs != null && c.temp != null ? density15(c.obs, c.temp) : null;
      return v == null || isNaN(v) ? null : v;
    });
    const have = comps.filter((x) => x != null);
    const mix = dn.mix != null ? +dn.mix : have.length ? r1(have.reduce((a, b) => a + b, 0) / have.length) : null;
    const chalan = dn.inv != null ? +dn.inv : null;
    const diff = mix != null && chalan != null ? r1(Math.abs(mix - chalan)) : null;
    const b = (before[k] || [])[i], aL = l.after || null, ad = aL ? (aL.d15 != null ? +aL.d15 : aL.obs != null && aL.temp != null ? density15(aL.obs, aL.temp) : null) : null;
    (recs[dv.d] = recs[dv.d] || []).push({
      comps, mix, chalan, diff, diffBad: diff != null && diff > cfg.tol + 1e-9,
      before: b ? { dip: b.dip, litres: b.litres } : null,
      after: aL ? { obs: aL.obs, temp: aL.temp, d15: ad, bad: inRange(ad) } : null,
      kl: (+l.litres || 0) / 1000, chalanNo: dv.billno || "", tank: tankNames[String(l.tank_id)] || "",
    });
  }));
  const rows = [];
  for (const d of days) {
    const m = morning[d], mrow = m ? { obs: m.dens_obs, temp: m.temp, d15: d15of(m), bad: inRange(d15of(m)) } : null, list = recs[d] || [];
    if (!list.length) rows.push({ d, morning: mrow, comps: [null, null, null, null], mix: null, chalan: null, diff: null, diffBad: false, before: null, after: null, kl: null, chalanNo: "", tank: "" });
    else list.forEach((r, i) => rows.push({ d, morning: i === 0 ? mrow : null, ...r }));
  }
  return { rows };
}

const r2 = (x) => Math.round(x * 100) / 100;
function daysBetween(a, b) {
  const out = [], end = new Date(b + "T00:00:00Z");
  for (let t = new Date(a + "T00:00:00Z"); t <= end; t = new Date(t.getTime() + 864e5)) out.push(t.toISOString().slice(0, 10));
  return out;
}
// Pump meter register, one line per nozzle.
// Reading = the last closing reading of the day (unchanged on a day with no duty).
// Sale = today's reading minus the previous reading. A nozzle starts from the opening meter set when it was added.
// Check = sale minus the duty figures (closing minus opening, summed). 0 means the duties and the meter agree.
function buildMeterRegister({ days, nozzles, duties }) {
  const byN = {};
  duties.forEach((x) => { const k = String(x.nozzle_id); (byN[k] = byN[k] || []).push(x); });
  const cells = {}, since = {}, fuelDay = {};
  nozzles.forEach((n) => {
    const k = String(n.id), list = byN[k] || [];
    const s0 = n.since || (list.length ? list[0].d : null);
    if (!s0) return;
    since[k] = s0; cells[k] = {};
    let start = null;
    days.forEach((d) => {
      if (d < s0) return;
      const ds = list.filter((x) => x.d === d);
      if (start == null) {
        if (n.open != null && n.open !== "" && isFinite(+n.open)) start = +n.open;
        else if (ds.length) start = +ds[0].opening;
        else return;
      }
      const end = ds.length ? +ds[ds.length - 1].closing : start;
      const dutyMeter = r2(ds.reduce((a, x) => a + (+x.closing - +x.opening), 0));
      const sales = r2(end - start);
      const check = r2(sales - dutyMeter);
      cells[k][d] = { start, end, sales, dutyMeter, check, duties: ds.length };
      const f = n.fuel || "";
      const fd = fuelDay[d] || (fuelDay[d] = {});
      const o = fd[f] || (fd[f] = { sales: 0, check: 0 });
      o.sales = r2(o.sales + sales); o.check = r2(o.check + check);
      start = end;
    });
  });
  return { cells, since, fuelDay };
}
module.exports = { density15, daysOfMonth, buildStockRegister, buildDensityRegister, buildMeterRegister, daysBetween };

