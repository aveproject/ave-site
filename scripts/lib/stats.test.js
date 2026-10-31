"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { recordStats } = require("./stats");

test("recordStats: counts layers, statuses and severities", () => {
  const s = recordStats([
    { detection_layer: "runtime", status: "active", severity: "HIGH" },
    { detection_layer: "runtime", status: "active", severity: "LOW" },
    { detection_layer: "transport", status: "deprecated", severity: "HIGH" },
  ]);
  assert.equal(s.total, 3);
  assert.deepEqual(s.layers, { runtime: 2, transport: 1 });
  assert.deepEqual(s.status, { active: 2, deprecated: 1 });
  assert.deepEqual(s.severity, { HIGH: 2, LOW: 1 });
});

test("recordStats: a record with no detection_layer is a content record, as the registry shows it", () => {
  assert.deepEqual(recordStats([{ status: "active", severity: "LOW" }, { detection_layer: "content", status: "active", severity: "LOW" }]).layers, { content: 2 });
});

test("recordStats: a record with no status or severity is counted, not dropped", () => {
  const s = recordStats([{ detection_layer: "content" }]);
  assert.equal(s.total, 1);
  assert.deepEqual(s.status, { unknown: 1 });
  assert.deepEqual(s.severity, { unknown: 1 });
});

test("recordStats: no records is an empty count", () => {
  assert.deepEqual(recordStats([]), { total: 0, layers: {}, status: {}, severity: {} });
});
