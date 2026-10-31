"use strict";

// Run with: npm test
// The synthetic documents below are small copies of the shapes aveproject/ave's
// README.md and CONTRIBUTING.md use; the last group of tests reads the real ones
// when an ave checkout sits next to this repository and records.js has been built.

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("fs");
const path = require("path");
const S = require("./scoring");

const FENCE = "```";

const CONTRIBUTING = `# Contributing

### AIVSS v0.8 calculation

${FENCE}
AIVSS = ((CVSS_Base + AARS) / 2) x ThM x Mitigation_Factor
${FENCE}

Score each AARF factor 0.0 (not applicable) to 1.0 (fully applicable):

| Factor | Score when... |
|---|---|
| autonomy | agent acts without human confirmation |
| tool_use | component grants access to external tools or APIs |

ThM values:
- \`0.75\` -- theoretical, no known PoC
- \`0.90\` -- PoC exists
- \`1.0\` -- exploited in the wild or weaponised

### Step 3 -- Validate locally

${FENCE}bash
# a comment inside a fence is not a heading
python scripts/validate_records.py
${FENCE}
`;

const README = `# Project

## AIVSS Scoring

${FENCE}
AIVSS = ((CVSS_Base + AARS) / 2) x ThM x Mitigation_Factor
${FENCE}

| # | Factor | Why it matters |
|---|---|---|
| 1 | **Autonomy** | Agent acts without human approval |
| 2 | **Tool Use** | Agent has access to external tools or APIs |

| Band | AIVSS | Meaning |
|---|---|---|
| CRITICAL | >= 9.0 | Immediate exploitation |
| HIGH | 7.0-8.9 | Significant data loss |
| MEDIUM | 4.0-6.9 | Meaningful risk |
| LOW | < 4.0 | Limited impact |

**ThM (Threat Maturity) valid values:** \`0.75\` (theoretical) · \`0.90\` (PoC exists) · \`1.0\` (in-the-wild)

## Record index
`;

const SCHEMA = {
  properties: { aivss: { properties: {
    cvss_base: { minimum: 0, maximum: 10, description: "CVSS base score (0-10)." },
    aarf: { properties: { autonomy: {}, tool_use: {} } },
    aars: { minimum: 0, maximum: 10, description: "Agentic Amplification and Reachability Score (0-10)." },
    thm: { minimum: 0.5, maximum: 1.5, description: "Threat and Heuristic Multiplier (0.5-1.5)." },
    mitigation_factor: { minimum: 0, maximum: 1, description: "Mitigation factor (0-1). 1.0 = no known effective mitigation." },
    spec_version: { const: "0.8" },
  } } },
};

const bandOf = (s) => (s >= 9 ? "CRITICAL" : s >= 7 ? "HIGH" : s >= 4 ? "MEDIUM" : "LOW");

// a record whose numbers agree with the formula unless an override says otherwise
function rec(id, o = {}) {
  const aarf = o.aarf || { autonomy: 1, tool_use: 0.5 };
  const sum = Object.values(aarf).reduce((a, b) => a + b, 0);
  const cvss = o.cvss === undefined ? 8 : o.cvss;
  const thm = o.thm === undefined ? 1 : o.thm;
  const mf = o.mf === undefined ? 1 : o.mf;
  const score = o.score === undefined ? Math.round(((cvss + sum) / 2) * thm * mf * 10) / 10 : o.score;
  const aivss = { cvss_base: cvss, aarf, aars: o.aars === undefined ? sum : o.aars, thm, mitigation_factor: mf, aivss_score: score, spec_version: "0.8" };
  if (o.notes) aivss.notes = o.notes;
  return { ave_id: id, title: o.title || `Title of ${id}`, severity: o.severity || bandOf(score), aivss };
}

const sources = (over = {}) => ({ contributing: CONTRIBUTING, readme: README, schema: SCHEMA, records: [rec("AVE-2026-00001")], sha: "abcdef0123456789", ...over });
const change = (text, from, to) => {
  assert.ok(text.includes(from), `fixture does not contain ${from}`);
  return text.replace(from, to);
};
const build = (over) => S.buildScoring(sources(over));

// ── reading the documents ─────────────────────────────────────────────────────

test("section: stops at the next heading of the same or a higher level, and ignores # inside a fence", () => {
  const md = `## A\none\n${FENCE}\n# not a heading\n${FENCE}\ntwo\n### sub\nthree\n## B\nfour\n`;
  const a = S.section(md, "## A", "x");
  assert.match(a, /one/);
  assert.match(a, /not a heading/);
  assert.match(a, /two/);
  assert.match(a, /three/, "a lower-level heading stays inside the section");
  assert.doesNotMatch(a, /four/);
});

test("section: a fence that holds a # line does not end CONTRIBUTING's section early", () => {
  const s = S.section(CONTRIBUTING, "### AIVSS v0.8 calculation", "CONTRIBUTING.md");
  assert.match(s, /1\.0` -- exploited/);
  assert.doesNotMatch(s, /Validate locally/);
});

test("section: a missing heading names the file and the heading", () => {
  assert.throws(() => S.section("# x\n", "## AIVSS Scoring", "README.md"), /README\.md has no "## AIVSS Scoring" section/);
});

test("tables: separator rows are skipped and two tables stay apart", () => {
  const t = S.tables("| A | B |\n|---|:-:|\n| 1 | 2 |\n\ntext\n\n| C |\n|---|\n| 3 |\n");
  assert.equal(t.length, 2);
  assert.deepEqual(t[0].header, ["A", "B"]);
  assert.deepEqual(t[0].rows, [["1", "2"]]);
  assert.deepEqual(t[1].rows, [["3"]]);
});

test("parseContributing: formula, factors in order, ThM values", () => {
  const c = S.parseContributing(CONTRIBUTING);
  assert.equal(c.formula, S.EQUATIONS.ave1.text);
  assert.deepEqual(c.factors.map((f) => f.name), ["autonomy", "tool_use"]);
  assert.equal(c.factors[0].when, "agent acts without human confirmation");
  assert.deepEqual(c.thm.map((t) => t.value), [0.75, 0.9, 1]);
  assert.equal(c.thm[1].shown, "0.90");
});

test("parseContributing: says what is missing", () => {
  assert.throws(() => S.parseContributing(change(CONTRIBUTING, "| Factor | Score when... |", "| Name | Text |")), /no Factor table/);
  assert.throws(() => S.parseContributing(change(CONTRIBUTING, "- `0.75` -- theoretical, no known PoC\n- `0.90` -- PoC exists\n- `1.0` -- exploited in the wild or weaponised", "see the schema")), /lists no ThM values/);
  assert.throws(() => S.parseContributing(change(CONTRIBUTING, FENCE + "\nAIVSS", "\nAIVSS").replace(FENCE + "\n\nScore", "\nScore")), /no code block/);
});

test("parseReadme: factor names become the schema's snake_case, bands and ThM are read", () => {
  const r = S.parseReadme(README);
  assert.deepEqual(r.factors, ["autonomy", "tool_use"]);
  assert.deepEqual(r.thm.map((t) => t.value), [0.75, 0.9, 1]);
  assert.equal(r.bands.CRITICAL.min, 9);
  assert.equal(r.bands.HIGH.min, 7);
  assert.equal(r.bands.MEDIUM.min, 4);
  assert.equal(r.bands.LOW.below, 4);
  assert.equal(r.bands.HIGH.meaning, "Significant data loss");
});

test("parseReadme: Multi-Agent and Natural Language Input map to the schema's names", () => {
  const md = change(README, "| 2 | **Tool Use** |", "| 2 | **Multi-Agent** |");
  assert.deepEqual(S.parseReadme(md).factors, ["autonomy", "multi_agent"]);
  assert.deepEqual(S.parseReadme(change(README, "**Autonomy**", "**Natural Language Input**")).factors, ["natural_language_input", "tool_use"]);
});

test("parseReadme: says what is missing", () => {
  assert.throws(() => S.parseReadme(change(README, "| # | Factor |", "| # | Name |")), /no factor table/);
  assert.throws(() => S.parseReadme(change(README, "| Band | AIVSS | Meaning |", "| Level | Range | Text |")), /no severity band table/);
  assert.throws(() => S.parseReadme(change(README, "**ThM (Threat Maturity) valid values:**", "ThM values:")), /no "ThM/);
  assert.throws(() => S.parseReadme(change(README, "`0.75` (theoretical) · `0.90` (PoC exists) · `1.0` (in-the-wild)", "0.75, 0.9, 1.0")), /could not read the ThM values/);
});

test("parseBands: a range it cannot read, a missing band, a gap and an overlap all throw", () => {
  const rows = [["CRITICAL", ">= 9.0", "a"], ["HIGH", "7.0-8.9", "b"], ["MEDIUM", "4.0-6.9", "c"], ["LOW", "< 4.0", "d"]];
  assert.equal(S.parseBands(rows).HIGH.max, 8.9);
  const swap = (i, range) => rows.map((r, j) => (i === j ? [r[0], range, r[2]] : r));
  assert.throws(() => S.parseBands(swap(0, "9 or more")), /cannot read "9 or more" for CRITICAL/);
  assert.throws(() => S.parseBands(rows.slice(1)), /missing CRITICAL/);
  assert.throws(() => S.parseBands(swap(1, "7.0-8.5")), /gap or overlap/);
  assert.throws(() => S.parseBands(swap(1, "7.0-9.0")), /gap or overlap/);
  assert.throws(() => S.parseBands(swap(3, "< 3.0")), /gap or overlap/);
});

test("crossCheck: the documents agree, or each disagreement is named", () => {
  const c = S.parseContributing(CONTRIBUTING);
  const r = S.parseReadme(README);
  assert.deepEqual(S.crossCheck(c, r, SCHEMA), []);

  const other = S.parseContributing(change(CONTRIBUTING, "((CVSS_Base + AARS) / 2) x ThM", "(CVSS_Base + AARS) x ThM"));
  assert.match(S.crossCheck(other, r, SCHEMA).join("\n"), /CONTRIBUTING\.md states the equation/);
  const other2 = S.parseReadme(change(README, "((CVSS_Base + AARS) / 2) x ThM", "(CVSS_Base + AARS) x ThM"));
  assert.match(S.crossCheck(c, other2, SCHEMA).join("\n"), /README\.md states the equation/);

  // the same factors in another order are not a disagreement: the README lists OWASP's order, the schema its own
  const reordered = S.parseContributing(change(change(change(CONTRIBUTING, "| autonomy |", "| @@ |"), "| tool_use |", "| autonomy |"), "| @@ |", "| tool_use |"));
  assert.deepEqual(S.crossCheck(reordered, r, SCHEMA), []);
  // a factor listed twice, or one the schema lacks, is
  const twice = S.parseContributing(change(CONTRIBUTING, "| tool_use |", "| autonomy |"));
  assert.match(S.crossCheck(twice, r, SCHEMA).join("\n"), /factors differ: CONTRIBUTING\.md/);
  const listedTwice = S.parseContributing(change(CONTRIBUTING, "| autonomy | agent acts without human confirmation |", "| autonomy | agent acts without human confirmation |\n| autonomy | said again |"));
  assert.match(S.crossCheck(listedTwice, r, SCHEMA).join("\n"), /factors differ: CONTRIBUTING\.md/);
  const renamed = S.parseContributing(change(CONTRIBUTING, "| tool_use |", "| tools |"));
  assert.match(S.crossCheck(renamed, r, SCHEMA).join("\n"), /factors differ: CONTRIBUTING\.md/);
  const missingInReadme = S.parseReadme(change(README, "| 2 | **Tool Use** | Agent has access to external tools or APIs |\n", ""));
  assert.match(S.crossCheck(c, missingInReadme, SCHEMA).join("\n"), /factors differ: README\.md/);

  const otherThm = S.parseReadme(change(README, "`0.90` (PoC exists)", "`0.95` (PoC exists)"));
  assert.match(S.crossCheck(c, otherThm, SCHEMA).join("\n"), /ThM values differ/);

  const noSpec = { properties: { aivss: { properties: { ...SCHEMA.properties.aivss.properties, spec_version: {} } } } };
  assert.match(S.crossCheck(c, r, noSpec).join("\n"), /spec_version/);
});

// ── the records ───────────────────────────────────────────────────────────────

test("checkRecords: a record that agrees with the documents has no problem, including ties that round down", () => {
  const bands = S.bandFor(S.parseReadme(README).bands);
  const good = [
    rec("AVE-2026-00001"),
    // 9.25 is stored as 9.2 and 7.35 as 7.3, as Python's round() does on the float
    rec("AVE-2026-00002", { cvss: 10, aarf: { autonomy: 1, tool_use: 1, a: 1, b: 1, c: 1, d: 1, e: 1, f: 1, g: 0.5 }, score: 9.2 }),
    rec("AVE-2026-00003", { cvss: 8.2, aarf: { autonomy: 1, tool_use: 1, a: 1, b: 1, c: 1, d: 1, e: 0.5 }, score: 7.3 }),
  ];
  assert.deepEqual(S.checkRecords(good, bands, [0.75, 0.9, 1], "ave1"), []);
});

test("checkRecords: each way a record can disagree is a separate, named problem", () => {
  const bands = S.bandFor(S.parseReadme(README).bands);
  const run = (r) => S.checkRecords([r], bands, [0.75, 0.9, 1], "ave1");
  assert.match(run(rec("AVE-2026-00009", { aars: 2 }))[0], /^AVE-2026-00009: aars is 2 but its inputs give 1\.5/);
  assert.match(run(rec("AVE-2026-00009", { score: 7.5 }))[0], /stored score 7\.5, the equation gives 4\.75/);
  assert.match(run(rec("AVE-2026-00009", { severity: "HIGH" }))[0], /severity HIGH but score 4\.8 is in MEDIUM/);
  assert.match(run(rec("AVE-2026-00009", { thm: 0.5 }))[0], /ThM 0\.5 is not one of the documented values/);
});

test("checkRecords: a score 0.05 away from the formula is rounding, 0.1 away is not", () => {
  const bands = S.bandFor(S.parseReadme(README).bands);
  const base = { cvss: 5, aarf: { autonomy: 1, tool_use: 0 }, thm: 1, mf: 1 }; // formula gives exactly 3.0
  assert.deepEqual(S.checkRecords([rec("A", { ...base, score: 3.05, severity: "LOW" })], bands, [1], "ave1"), []);
  assert.equal(S.checkRecords([rec("A", { ...base, score: 3.1, severity: "LOW" })], bands, [1], "ave1").length, 1);
});

test("summarize: bands, whole-number bins, the highest and the lowest, ties by id", () => {
  const factors = ["autonomy", "tool_use"];
  const records = [
    rec("AVE-2026-00005", { cvss: 10, aarf: { autonomy: 1, tool_use: 1 }, score: 10 }),
    rec("AVE-2026-00002", { cvss: 10, aarf: { autonomy: 1, tool_use: 1 }, score: 10 }),
    rec("AVE-2026-00004", { cvss: 2, aarf: { autonomy: 0, tool_use: 0 }, score: 1 }),
    rec("AVE-2026-00003", { cvss: 2, aarf: { autonomy: 0, tool_use: 0 }, score: 1 }),
    rec("AVE-2026-00006", { cvss: 9, aarf: { autonomy: 0.5, tool_use: 0 }, score: 5 }),
  ];
  const s = S.summarize(records, factors, bandOf);
  assert.equal(s.total, 5);
  assert.equal(s.highest.ave_id, "AVE-2026-00002");
  assert.equal(s.lowest.ave_id, "AVE-2026-00003");
  assert.equal(s.bands.CRITICAL, 2);
  assert.equal(s.bands.LOW, 2);
  assert.equal(s.bins[9], 2, "a score of 10 is counted in the top bin");
  assert.equal(s.bins[1], 2);
  assert.equal(s.factor.autonomy.above, 3);
  assert.equal(s.factor.autonomy.full, 2);
  assert.equal(s.factor.autonomy.mean, 2.5 / 5);
  assert.equal(s.severeBase.total, 3, "a cvss_base of exactly 9.0 counts");
  assert.equal(s.severeBase.bands.CRITICAL, 2);
  assert.equal(s.severeBase.bands.MEDIUM, 1);
});

test("bandFor: a band starts at its minimum, not above it", () => {
  const bands = S.bandFor(S.parseReadme(README).bands);
  assert.deepEqual([10, 9, 8.9, 7, 6.9, 4, 3.9, 0].map(bands), ["CRITICAL", "CRITICAL", "HIGH", "HIGH", "MEDIUM", "MEDIUM", "LOW", "LOW"]);
});

test("summarize: records without an aivss object are not counted", () => {
  const s = S.summarize([rec("AVE-2026-00001"), { ave_id: "AVE-2026-00002", title: "draft" }], ["autonomy", "tool_use"], bandOf);
  assert.equal(s.total, 1);
});

// ── the page ──────────────────────────────────────────────────────────────────

test("buildScoring: a page with every placeholder filled and the sums it states", () => {
  const records = [rec("AVE-2026-00001"), rec("AVE-2026-00002", { cvss: 3, aarf: { autonomy: 0, tool_use: 0 }, thm: 0.75, mf: 0.83 })];
  const page = build({ records });
  assert.deepEqual(page.warnings, []);
  assert.equal(page.values["{{RECORD_COUNT}}"], "2");
  assert.equal(page.values["{{AIVSS_SPEC}}"], "0.8");
  const all = Object.values(page.values).join("\n");
  assert.doesNotMatch(all, /\{\{|<!-- ave:/);
  assert.match(page.values["<!-- ave:scoring-checked -->"], /2 of 2 records/);
  assert.match(page.values["<!-- ave:scoring-checked -->"], /aveproject\/ave@abcdef0/);
  assert.match(page.values["<!-- ave:scoring-thm -->"], /0\.75<\/td><td>theoretical, no known PoC<\/td><td class="num">1 of 2/);
  assert.match(page.values["<!-- ave:scoring-thm -->"], /0\.83<\/td><td class="num">1 of 2/);
  assert.match(page.values["<!-- ave:scoring-bands -->"], /<span class="sev CRITICAL">CRITICAL<\/span><\/td><td class="mono">&gt;= 9\.0/);
});

test("buildScoring: the worked examples are the two ends of the records, and follow them", () => {
  const lo = rec("AVE-2026-00007", { cvss: 2, aarf: { autonomy: 0, tool_use: 0 }, thm: 0.75, mf: 0.83 });
  const hi = rec("AVE-2026-00008", { cvss: 10, aarf: { autonomy: 1, tool_use: 1 } });
  const html = build({ records: [rec("AVE-2026-00001"), lo, hi] }).values["<!-- ave:scoring-examples -->"];
  assert.match(html, /highest score \(6\) and the lowest \(0\.6\)/);
  assert.ok(html.indexOf("AVE-2026-00008") < html.indexOf("AVE-2026-00007"), "highest first");
  assert.match(html, /\(\(10\.0 \+ 2\.0\) \/ 2\) &times; 1\.0 &times; 1\.0 = 6/);
  const rescored = rec("AVE-2026-00008", { cvss: 4, aarf: { autonomy: 0, tool_use: 0 } });
  const html2 = build({ records: [rec("AVE-2026-00001"), lo, rescored] }).values["<!-- ave:scoring-examples -->"];
  assert.doesNotMatch(html2, /AVE-2026-00008/, "a re-scored record leaves the examples");
});

test("buildScoring: one record is shown once", () => {
  const html = build().values["<!-- ave:scoring-examples -->"];
  assert.match(html, /The only scored record/);
  assert.equal(html.match(/class="calc"/g).length, 1);
});

test("buildScoring: the computed value is shown next to the stored one when rounding changed it", () => {
  const r = rec("AVE-2026-00002", { cvss: 10, aarf: { autonomy: 1, tool_use: 1, a: 1, b: 1, c: 1, d: 1, e: 1, f: 1, g: 0.5 }, score: 9.2 });
  const html = build({ records: [r] }).values["<!-- ave:scoring-examples -->"];
  assert.match(html, /= 9\.25 &rarr; stored as <strong>9\.2<\/strong>/);
});

test("buildScoring: float noise is not shown in the arithmetic", () => {
  const r = rec("AVE-2026-00003", { cvss: 8.2, aarf: { autonomy: 1, tool_use: 1, a: 1, b: 1, c: 1, d: 1, e: 0.5 }, score: 7.3 });
  const html = build({ records: [r] }).values["<!-- ave:scoring-examples -->"];
  assert.match(html, /= 7\.35 &rarr; stored as <strong>7\.3<\/strong>/);
});

test("buildScoring: float noise in a product is not shown either", () => {
  // in JavaScript ((7.5 + 2.5) / 2) * 1 * 0.83 is 4.1499999999999995; the shown value is 4.15
  const r = rec("AVE-2026-00061", { cvss: 7.5, aarf: { autonomy: 0.5, tool_use: 0.5, a: 1, b: 0.5 }, mf: 0.83, score: 4.1 });
  const html = build({ records: [r] }).values["<!-- ave:scoring-examples -->"];
  assert.match(html, /= 4\.15 &rarr; stored as <strong>4\.1<\/strong>/);
});

test("buildScoring: a record with no aivss object (a draft) is left out, not a crash", () => {
  const page = build({ records: [rec("AVE-2026-00001"), { ave_id: "AVE-2026-00002", title: "draft", status: "draft" }] });
  assert.equal(page.values["{{RECORD_COUNT}}"], "1");
  assert.deepEqual(page.warnings, []);
});

test("buildScoring: record text is escaped", () => {
  const r = rec("AVE-2026-00001", { title: "<img src=x onerror=alert(1)>", notes: "a <b>note</b> & more" });
  const html = build({ records: [r] }).values["<!-- ave:scoring-examples -->"];
  assert.doesNotMatch(html, /<img|<b>note/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(html, /a &lt;b&gt;note&lt;\/b&gt; &amp; more/);
});

test("buildScoring: a record that disagrees is a warning and is counted, not a failure", () => {
  const bad = rec("AVE-2026-00002", { score: 9.9, severity: "HIGH" });
  const page = build({ records: [rec("AVE-2026-00001"), bad] });
  assert.equal(page.warnings.length, 2);
  assert.ok(page.warnings.every((w) => w.startsWith("AVE-2026-00002:")));
  assert.match(page.values["<!-- ave:scoring-checked -->"], /1 of 2 records/);
});

test("buildScoring: a ThM outside the documented values is listed as such", () => {
  const page = build({ records: [rec("AVE-2026-00001", { thm: 0.5 })] });
  assert.match(page.values["<!-- ave:scoring-thm -->"], /0\.5<\/td><td>not a documented value<\/td><td class="num">1 of 1/);
});

test("buildScoring: disagreeing documents stop the build and every disagreement is in the message", () => {
  const readme = change(change(README, "`0.90` (PoC exists)", "`0.95` (PoC exists)"), "((CVSS_Base + AARS) / 2) x ThM", "(CVSS_Base + AARS) x ThM");
  assert.throws(() => build({ readme }), (e) => /cannot be built/.test(e.message) && /ThM values differ/.test(e.message) && /README\.md states the equation/.test(e.message));
});

test("buildScoring: a schema whose factors changed stops the build", () => {
  const schema = { properties: { aivss: { properties: { ...SCHEMA.properties.aivss.properties, aarf: { properties: { autonomy: {}, tool_use: {}, extra: {} } } } } } };
  assert.throws(() => build({ schema }), /factors differ: CONTRIBUTING\.md lists autonomy, tool_use; the schema has autonomy, tool_use, extra/);
});

test("buildScoring: the formula is the one the arithmetic is coded for", () => {
  const html = build().values["<!-- ave:scoring-formula -->"];
  assert.match(html, /\(\(<span class="g">CVSS_Base<\/span> \+ <span class="g">AARS<\/span>\) \/ 2\) &times; <span class="g">ThM<\/span> &times; <span class="g">Mitigation_Factor<\/span>/);
  assert.match(html, /9\.25 is stored as 9\.2/);
  assert.match(html, /scripts\/validate_records\.py/);
});

// ── the v0.8 equation (schema 2.x) ────────────────────────────────────────────
// The page understands the 1.x equation and OWASP AIVSS v0.8 until 2.0.0 has shipped; the 1.x support goes with it.

const CONTRIBUTING_V08 = `# Contributing

### AIVSS v0.8 calculation

${FENCE}
AARS  = (10 - CVSS_Base) x (Factor_Sum / 10) x ThM
AIVSS = (CVSS_Base + AARS) x Mitigation_Factor
${FENCE}

| Factor | Score when... |
|---|---|
| autonomy | agent acts without human verification |
| tool_use | component grants access to broad or privileged external tools or APIs |

ThM values:
- \`0.5\` -- theoretical, no known PoC (Unreported)
- \`0.97\` -- PoC exists (Proof-of-Concept)
- \`1.0\` -- exploited in the wild or weaponised (Attacked)

### Step 3 -- Validate locally
`;

const README_V08 = `# Project

## AIVSS Scoring

${FENCE}
AARS  = (10 - CVSS_Base) x (Factor_Sum / 10) x ThM
AIVSS = (CVSS_Base + AARS) x Mitigation_Factor
${FENCE}

| # | Factor | AVE key | What it measures |
|---|---|---|---|
| 1 | **Autonomy** | \`autonomy\` | Executes actions without human verification |
| 2 | **Tools** | \`tool_use\` | Breadth and privilege of the external tools |

| Band | AIVSS | Meaning |
|---|---|---|
| CRITICAL | >= 9.0 | Immediate exploitation |
| HIGH | 7.0-8.9 | Significant data loss |
| MEDIUM | 4.0-6.9 | Meaningful risk |
| LOW | < 4.0 | Limited impact |

**ThM (Threat Multiplier) valid values:** \`0.5\` (Unreported, theoretical) · \`0.97\` (Proof-of-Concept) · \`1.0\` (Attacked, in the wild)

## Record index
`;

const SCHEMA_V08 = {
  properties: { aivss: { properties: {
    cvss_base: { minimum: 0, maximum: 10, description: "CVSS v4.0 base score (0-10)." },
    aarf: { description: "The ten AIVSS v0.8 factors.", properties: { autonomy: {}, tool_use: {} } },
    aars: { minimum: 0, maximum: 10, description: "Agentic AI Risk Score (AARS): the agentic uplift." },
    thm: { enum: [0.5, 0.97, 1], description: "Threat Multiplier (ThM) from exploit maturity." },
    mitigation_factor: { enum: [0.67, 0.83, 1], description: "Mitigation Factor." },
    spec_version: { const: "0.8" },
  } } },
};

// a record whose numbers follow the v0.8 equation, aars stored to four decimals
function rec08(id, o = {}) {
  const aarf = o.aarf || { autonomy: 1, tool_use: 0.5 };
  const sum = Object.values(aarf).reduce((a, b) => a + b, 0);
  const cvss = o.cvss === undefined ? 6 : o.cvss;
  const thm = o.thm === undefined ? 0.97 : o.thm;
  const mf = o.mf === undefined ? 1 : o.mf;
  const aars = (10 - cvss) * (sum / 10) * thm;
  const raw = (cvss + aars) * mf;
  const score = o.score === undefined ? Math.round(raw * 10) / 10 : o.score;
  const aivss = { cvss_base: cvss, aarf, aars: o.aars === undefined ? Number(aars.toFixed(4)) : o.aars, thm, mitigation_factor: mf, aivss_score: score, spec_version: "0.8" };
  if (o.notes) aivss.notes = o.notes;
  return { ave_id: id, title: o.title || `Title of ${id}`, severity: o.severity || bandOf(score), aivss };
}
const build08 = (over) => S.buildScoring({ ...sources({ contributing: CONTRIBUTING_V08, readme: README_V08, schema: SCHEMA_V08, records: [rec08("AVE-2026-00001")] }), ...over });

test("equationOf: each known equation is recognised from the way the documents write it, and nothing else is", () => {
  assert.equal(S.equationOf(S.parseContributing(CONTRIBUTING).formula), "ave1");
  assert.equal(S.equationOf(S.parseContributing(CONTRIBUTING_V08).formula), "v08");
  assert.equal(S.equationOf(S.parseReadme(README_V08).formula), "v08");
  assert.equal(S.equationOf("AIVSS = CVSS_Base x ThM"), null);
});

test("parseReadme: the AVE key column names the factors when OWASP's names differ from the schema's keys", () => {
  assert.deepEqual(S.parseReadme(README_V08).factors, ["autonomy", "tool_use"]);
  assert.deepEqual(S.parseReadme(README_V08).thm.map((x) => x.value), [0.5, 0.97, 1]);
});

test("crossCheck: v0.8 documents agree", () => {
  assert.deepEqual(S.crossCheck(S.parseContributing(CONTRIBUTING_V08), S.parseReadme(README_V08), SCHEMA_V08), []);
});

test("crossCheck: one document on each equation is a disagreement, named", () => {
  const found = S.crossCheck(S.parseContributing(CONTRIBUTING_V08), S.parseReadme(README), SCHEMA).join("\n");
  assert.match(found, /the equations differ: CONTRIBUTING\.md states "AARS = /);
});

test("crossCheck: an equation this page does not know stops the build and names the ones it does", () => {
  const unknown = S.parseContributing(change(CONTRIBUTING, "((CVSS_Base + AARS) / 2) x ThM x Mitigation_Factor", "CVSS_Base x ThM"));
  const found = S.crossCheck(unknown, S.parseReadme(README), SCHEMA).join("\n");
  assert.match(found, /CONTRIBUTING\.md states the equation as "AIVSS = CVSS_Base × ThM"; this page is built for/);
  assert.ok(found.includes(S.EQUATIONS.ave1.text) && found.includes(S.EQUATIONS.v08.text), "both known equations are listed");
});

test("buildScoring: documents in neither format fail loudly, with every disagreement in the message", () => {
  const bad = (d) => change(d, "((CVSS_Base + AARS) / 2) x ThM x Mitigation_Factor", "CVSS_Base x ThM");
  assert.throws(() => build({ contributing: bad(CONTRIBUTING), readme: bad(README) }),
    (e) => /cannot be built/.test(e.message) && /CONTRIBUTING\.md states the equation as/.test(e.message) && /README\.md states the equation as/.test(e.message) && /this page is built for/.test(e.message));
  // and a document that has lost its scoring section altogether fails just as loudly
  assert.throws(() => build({ contributing: change(CONTRIBUTING, "### AIVSS v0.8 calculation", "### Something else") }), /has no "### AIVSS v0.8 calculation" section/);
});

test("derive: v0.8 reproduces OWASP's first worked example (CVSS 9.4, factor sum 9.0, ThM 0.97)", () => {
  const a = { cvss_base: 9.4, thm: 0.97, mitigation_factor: 1, aarf: { a: 1, b: 1, c: 1, d: 1, e: 1, f: 1, g: 1, h: 1, i: 1 } };
  const d = S.derive("v08", a);
  assert.equal(Number(d.aars.toFixed(4)), 0.5238);
  assert.equal(Number(d.raw.toFixed(4)), 9.9238);
});

test("derive: the 1.x equation is unchanged, and a record with no aarf falls back to its stored aars", () => {
  assert.deepEqual(S.derive("ave1", { cvss_base: 8, thm: 1, mitigation_factor: 1, aarf: { a: 1, b: 0.5 } }), { aars: 1.5, raw: 4.75 + 0 });
  assert.equal(S.derive("v08", { cvss_base: 8, thm: 1, mitigation_factor: 1, aars: 0.4 }).raw, 8.4);
  assert.equal(S.derive("ave1", { cvss_base: 8, thm: 1, mitigation_factor: 1, aars: 2 }).raw, 5);
});

test("checkRecords: a v0.8 record passes, a stored aars is allowed its four-decimal rounding, and a 1.x score is a mismatch", () => {
  const bands = S.bandFor(S.parseReadme(README_V08).bands);
  assert.deepEqual(S.checkRecords([rec08("AVE-2026-00001"), rec08("AVE-2026-00002", { cvss: 9.4, aarf: { autonomy: 1, tool_use: 1 } })], bands, [0.5, 0.97, 1], "v08"), []);
  const wrongAars = S.checkRecords([rec08("AVE-2026-00003", { aars: 3 })], bands, [0.5, 0.97, 1], "v08");
  assert.match(wrongAars[0], /^AVE-2026-00003: aars is 3 but its inputs give/);
  // a record scored under the 1.x equation: aars is the factor sum and the score is averaged
  const oneX = rec("AVE-2026-00004", { cvss: 6, aarf: { autonomy: 1, tool_use: 0.5 }, thm: 1 });
  const found = S.checkRecords([oneX], bands, [0.5, 0.97, 1, 0.75], "v08").join("\n");
  assert.match(found, /AVE-2026-00004: aars is 1\.5 but its inputs give/);
  assert.match(found, /stored score 3\.8, the equation gives/);
});

test("buildScoring: a v0.8 page shows Factor_Sum, the uplift step and the floor callout, and not the 1.x text", () => {
  const page = build08({ records: [rec08("AVE-2026-00001", { cvss: 9.4, aarf: { autonomy: 1, tool_use: 1 } }), rec08("AVE-2026-00002")] });
  assert.equal(page.equation, "v08");
  assert.deepEqual(page.warnings, []);
  const all = Object.values(page.values).join("\n");
  assert.doesNotMatch(all, /\{\{|<!-- ave:/);
  assert.match(page.values["<!-- ave:scoring-formula -->"], /Factor_Sum<\/span> \/ 10\) &times; <span class="g">ThM<\/span>\n<span class="g">AIVSS<\/span> = \(<span class="g">CVSS_Base/);
  assert.match(page.values["<!-- ave:scoring-formula -->"], /<tr><td class="mono">Factor_Sum<\/td><td class="mono">0 to 2<\/td>/);
  assert.match(page.values["<!-- ave:scoring-formula -->"], /one of 0\.5, 0\.97, 1/);
  assert.match(page.values["<!-- ave:scoring-formula -->"], /rounded half up to one decimal/);
  assert.match(page.values["<!-- ave:scoring-examples -->"], /<strong>Uplift<\/strong>.*AARS = \(10 - 9\.4\) &times; \(2\.0 \/ 10\) &times; 0\.97 = 0\.1164/);
  assert.match(page.values["<!-- ave:scoring-examples -->"], /AIVSS = \(9\.4 \+ 0\.1164\) &times; 1\.0 = 9\.5164 &rarr; stored as <strong>9\.5<\/strong>/);
  assert.match(page.values["<!-- ave:scoring-bands -->"], /The CVSS base is the floor/);
  assert.doesNotMatch(page.values["<!-- ave:scoring-bands -->"], /A severe flaw is not a severe score/);
  assert.match(page.values["<!-- ave:scoring-checked -->"], /the uplift their inputs give/);
});

test("derive: v0.8 applies the mitigation factor to the whole of cvss_base plus the uplift", () => {
  const a = { cvss_base: 7.5, thm: 1, mitigation_factor: 0.83, aarf: { a: 0.5, b: 0.5 } };
  assert.equal(Number(S.derive("v08", a).raw.toFixed(4)), 6.4325);
  assert.equal(S.derive("v08", { ...a, mitigation_factor: 1 }).raw, 7.75);
});

test("checkRecords: a stored aars is accepted to its fourth decimal and refused beyond it", () => {
  const bands = S.bandFor(S.parseReadme(README_V08).bands);
  // (10 - 7.3) x (1.5 / 10) x 0.97 = 0.39285, which a record stores as 0.3929 (the four decimals the schema example uses)
  const r = rec08("AVE-2026-00005", { cvss: 7.3, aarf: { autonomy: 1, tool_use: 0.5 } });
  assert.equal(r.aivss.aars, 0.3929);
  assert.deepEqual(S.checkRecords([r], bands, [0.5, 0.97, 1], "v08"), []);
  const off = rec08("AVE-2026-00006", { cvss: 7.3, aarf: { autonomy: 1, tool_use: 0.5 }, aars: 0.393 });
  assert.match(S.checkRecords([off], bands, [0.5, 0.97, 1], "v08")[0], /^AVE-2026-00006: aars is 0\.393 but its inputs give 0\.39285/);
});

test("buildScoring: a v0.8 page's numbers come from the records, not from fixed text", () => {
  const records = [
    rec08("AVE-2026-00001", { cvss: 9.4, aarf: { autonomy: 1, tool_use: 1 } }),              // aars 0.1164, score 9.5
    rec08("AVE-2026-00005", { cvss: 7.3, aarf: { autonomy: 1, tool_use: 0.5 } }),            // aars 0.3929, score 7.7
    rec08("AVE-2026-00002", { cvss: 5, aarf: { autonomy: 1, tool_use: 1 }, thm: 1 }),        // aars 1, score 6
  ];
  const page = build08({ records });
  const bands = page.values["<!-- ave:scoring-bands -->"];
  assert.match(bands, /runs from 0\.1164 to 1 and averages 0\.50, against an average score of 7\.7:/);
  // the worked example shows the exact uplift the inputs give, not the four decimals a record stores
  const worked = build08({ records: [records[1], records[0]] }).values["<!-- ave:scoring-examples -->"];
  assert.match(worked, /AARS = \(10 - 7\.3\) &times; \(1\.5 \/ 10\) &times; 0\.97 = 0\.39285/);
  assert.match(worked, /AIVSS = \(7\.3 \+ 0\.39285\) &times; 1\.0 = 7\.69285/);
  const factors = page.values["<!-- ave:scoring-factors -->"];
  assert.match(factors, /Factor_Sum is the sum of ten factors, each scored 0 \(none\), 0\.5 \(partial\) or 1 \(full\)/);
  assert.doesNotMatch(factors, /AARS is the sum of ten factors/);
  assert.match(build({ records: [rec("AVE-2026-00001")] }).values["<!-- ave:scoring-factors -->"], /AARS is the sum of ten factors/);
});

test("buildScoring: a 1.x page keeps the 1.x text and says which equation it built for", () => {
  const page = build({ records: [rec("AVE-2026-00001", { cvss: 9.4, aarf: { autonomy: 1, tool_use: 1 }, thm: 1 })] });
  assert.equal(page.equation, "ave1");
  assert.match(page.values["<!-- ave:scoring-formula -->"], /Python's <code>round\(\)<\/code>/);
  assert.doesNotMatch(page.values["<!-- ave:scoring-examples -->"], /<strong>Uplift<\/strong>/);
  assert.doesNotMatch(page.values["<!-- ave:scoring-bands -->"], /The CVSS base is the floor/);
});

test("buildScoring: the v0.8 page counts a v0.8 record that disagrees with its own inputs", () => {
  const page = build08({ records: [rec08("AVE-2026-00001"), rec08("AVE-2026-00002", { score: 9.9 })] });
  assert.equal(page.warnings.length, 1);
  assert.match(page.values["<!-- ave:scoring-checked -->"], /1 of 2 records/);
});

// ── the real documents, when they are here ────────────────────────────────────

const AVE = path.join(__dirname, "../../../ave");
const RECORDS = path.join(__dirname, "../../records.js");
const real = fs.existsSync(path.join(AVE, "CONTRIBUTING.md")) && fs.existsSync(RECORDS);

test("the real AVE documents and records build a page with no warnings", { skip: !real && "needs ../ave and records.js" }, () => {
  const records = require(RECORDS);
  const page = S.buildScoring({ ...S.loadSources(AVE), records, sha: "0123456789abcdef" });
  assert.deepEqual(page.warnings, []);
  assert.equal(page.summary.total, records.filter((r) => r.aivss).length);
  assert.equal(Object.keys(page.summary.factor).length, 10);
  const scores = records.map((r) => r.aivss.aivss_score);
  assert.equal(page.summary.highest.aivss.aivss_score, Math.max(...scores));
  assert.equal(page.summary.lowest.aivss.aivss_score, Math.min(...scores));
  assert.equal(Object.values(page.summary.bands).reduce((a, b) => a + b, 0), page.summary.total);
});
