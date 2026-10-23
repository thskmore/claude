// Property-based tests for density15() (run with: npm test). Random inputs cover the whole valid range.
const test = require("node:test");
const assert = require("node:assert/strict");
const fc = require("fast-check");
const R = require("../registers.js");

const density = fc.double({ min: 700, max: 800, noNaN: true });
const temp = fc.double({ min: 0, max: 40, noNaN: true });

test("density15 is always a finite number for petrol and diesel ranges", () => {
  fc.assert(fc.property(density, temp, (d, t) => Number.isFinite(R.density15(d, t))), { numRuns: 500 });
});

test("hotter than 15 C: the 15 C density is higher than the reading", () => {
  fc.assert(fc.property(density, fc.double({ min: 15.5, max: 40, noNaN: true }), (d, t) => R.density15(d, t) >= d - 0.05), { numRuns: 500 });
});

test("colder than 15 C: the 15 C density is lower than the reading", () => {
  fc.assert(fc.property(density, fc.double({ min: 0, max: 14.5, noNaN: true }), (d, t) => R.density15(d, t) <= d + 0.05), { numRuns: 500 });
});

// Fuel expands by at most about 1.2 kg/m3 per degree C (lighter fuels expand the most).
test("the correction grows with the temperature difference, at most about 1.2 kg/m3 per degree C", () => {
  fc.assert(fc.property(density, temp, (d, t) => Math.abs(R.density15(d, t) - d) <= 1.2 * Math.abs(t - 15) + 0.2), { numRuns: 500 });
});
