// Unit tests for the pure calculation functions in registers.js (run with: npm test)
const test = require("node:test");
const assert = require("node:assert/strict");
const R = require("../registers.js");

test("density15 converts a reading at 30 C to the 15 C density", () => {
  const d = R.density15(745, 30);
  assert.ok(d > 750 && d < 765, "745 kg/m3 at 30 C should be about 758.5 at 15 C, got " + d);
});

test("density15 leaves a reading taken at 15 C unchanged", () => {
  assert.ok(Math.abs(R.density15(750, 15) - 750) < 0.2);
});

test("daysBetween includes both ends", () => {
  assert.deepEqual(R.daysBetween("2026-10-01", "2026-10-03"), ["2026-10-01", "2026-10-02", "2026-10-03"]);
});

test("daysOfMonth gives every day of the month", () => {
  assert.equal(R.daysOfMonth("2026-02").length, 28);
  assert.equal(R.daysOfMonth("2026-10").length, 31);
  assert.equal(R.daysOfMonth("2026-10")[0], "2026-10-01");
});
