"use strict";

/**
 * scoring.js
 *
 * Everything the Scoring page states about AVE scoring, read from aveproject/ave
 * so the page cannot drift from it:
 *
 *   the formula, the factor wording, the ThM values   CONTRIBUTING.md, "AIVSS v0.8 calculation"
 *   the same, plus the severity bands                 README.md, "AIVSS Scoring"
 *   factor names, ranges, field descriptions          schema/ave-record.schema.json
 *   every number, example and distribution            the records the registry shows
 *
 * The documents are read, never trusted. When they disagree with each other, or
 * state an equation this module does not know (EQUATIONS), buildScoring() throws and the deploy stops
 * instead of publishing a page that is wrong. A record that disagrees with the
 * documents does not stop the deploy (aveproject/ave's own CI owns that); it comes
 * back as a warning and the page counts it.
 *
 * Nothing here touches the disk except loadSources(), so the rest is tested with
 * synthetic documents (scoring.test.js).
 */

const fs = require("fs");
const path = require("path");

const BANDS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
// The equations this page can explain and recompute. The ave repo's documents must state one of them exactly;
// any other stops the build, because the arithmetic below would be wrong for it.
// Both are here so this page keeps building across the move to schema 2.0.0 (aveproject/ave#399): it must be deployed
// before the ave repo's documents change. Once 2.0.0 has shipped and the page is built from it, delete ave1 and the
// `eq === "v08"` branches.
const EQUATIONS = {
  // schema 1.x: the AIVSS v0.5 equation with the v0.8 Mitigation_Factor added (aveproject/ave#395)
  ave1: { text: "AIVSS = ((CVSS_Base + AARS) / 2) × ThM × Mitigation_Factor" },
  // schema 2.x: OWASP AIVSS v0.8, sections 3.3 to 3.5
  v08: { text: "AARS = (10 - CVSS_Base) × (Factor_Sum / 10) × ThM AIVSS = (CVSS_Base + AARS) × Mitigation_Factor" },
};
const equationOf = (formula) => Object.keys(EQUATIONS).find((k) => EQUATIONS[k].text === formula) || null;
const REPO = "https://github.com/aveproject/ave";

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// 1 -> "1.0", 0.75 -> "0.75": the way the records and the documents write a score
const fmt = (n) => (Number.isInteger(n) ? n.toFixed(1) : String(n));
// 7.3499999999999996 -> 7.35: float noise is not part of the arithmetic shown
const trim = (n) => String(Number(n.toPrecision(10)));
const pct = (n, total) => (total ? Math.round((100 * n) / total) : 0);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// ── reading the documents ─────────────────────────────────────────────────────

// What: the text under one heading, up to the next heading of the same or a higher level
// Why:  README and CONTRIBUTING mention AIVSS in several places; one section in each states the rules
// How:  a line starting with # inside a fenced block is not a heading
function section(md, heading, source) {
  const lines = md.split("\n");
  const level = /^#+/.exec(heading)[0].length;
  let start = -1;
  let end = lines.length;
  let fenced = false;
  for (let i = 0; i < lines.length; i++) {
    if (/^\s*```/.test(lines[i])) { fenced = !fenced; continue; }
    if (fenced) continue;
    if (start === -1) {
      if (lines[i].trim() === heading) start = i;
    } else {
      const m = /^(#+)\s/.exec(lines[i]);
      if (m && m[1].length <= level) { end = i; break; }
    }
  }
  if (start === -1) throw new Error(`${source} has no "${heading}" section`);
  return lines.slice(start + 1, end).join("\n");
}

function firstFence(md, where) {
  const m = /```[a-z]*\n([\s\S]*?)```/.exec(md);
  if (!m) throw new Error(`${where} has no code block holding the formula`);
  return m[1].trim();
}

// What: the pipe tables in a block of markdown, as { header, rows } of trimmed cells
function tables(md) {
  const out = [];
  let current = null;
  for (const line of md.split("\n")) {
    if (!/^\s*\|/.test(line)) { current = null; continue; }
    const cells = line.trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
    if (cells.every((c) => /^:?-+:?$/.test(c))) continue;
    if (!current) { current = { header: cells, rows: [] }; out.push(current); } else current.rows.push(cells);
  }
  return out;
}

const plain = (cell) => cell.replace(/[`*]/g, "").trim();
const snake = (cell) => plain(cell).toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
const normFormula = (f) => f.replace(/\s+x\s+/g, " × ").replace(/\s+/g, " ").trim();

// What: CONTRIBUTING.md's statement of the rules a researcher scores a record by
function parseContributing(md) {
  const where = 'CONTRIBUTING.md "AIVSS v0.8 calculation"';
  const s = section(md, "### AIVSS v0.8 calculation", "CONTRIBUTING.md");
  const table = tables(s).find((t) => /^factor$/i.test(plain(t.header[0])));
  if (!table || !table.rows.length) throw new Error(`${where} has no Factor table`);
  const thm = [...s.matchAll(/^- `([0-9.]+)` -- (.+)$/gm)].map((m) => ({ shown: m[1], value: Number(m[1]), meaning: m[2].trim() }));
  if (!thm.length) throw new Error(`${where} lists no ThM values (expected lines like "- \`0.75\` -- theoretical")`);
  return {
    formula: normFormula(firstFence(s, where)),
    factors: table.rows.map((r) => ({ name: plain(r[0]), when: plain(r[1]) })),
    thm,
  };
}

// What: README.md's own statement of the same rules, plus the severity bands
function parseReadme(md) {
  const where = 'README.md "AIVSS Scoring"';
  const s = section(md, "## AIVSS Scoring", "README.md");
  const factorTable = tables(s).find((t) => plain(t.header[1] || "").toLowerCase() === "factor");
  const bandTable = tables(s).find((t) => plain(t.header[0]).toLowerCase() === "band");
  if (!factorTable) throw new Error(`${where} has no factor table`);
  if (!bandTable) throw new Error(`${where} has no severity band table`);
  const line = /\*\*ThM[^*]*\*\*(.*)$/m.exec(s);
  if (!line) throw new Error(`${where} has no "ThM ... valid values" line`);
  const thm = [...line[1].matchAll(/`([0-9.]+)` \(([^)]*)\)/g)].map((m) => ({ shown: m[1], value: Number(m[1]), meaning: m[2].trim() }));
  if (!thm.length) throw new Error(`${where}: could not read the ThM values from "${line[1].trim()}"`);
  const keyColumn = factorTable.header.findIndex((h) => /^ave key$/i.test(plain(h)));
  return {
    formula: normFormula(firstFence(s, where)),
    factors: factorTable.rows.map((r) => (keyColumn === -1 ? snake(r[1]) : plain(r[keyColumn]))),
    thm,
    bands: parseBands(bandTable.rows),
  };
}

// What: the README's band table as { BAND: { range, meaning, min } }, min being the lowest score in the band
// How:  ">= 9.0", "7.0-8.9" and "< 4.0" are the only shapes; bands must meet with no gap and no overlap
function parseBands(rows) {
  const out = {};
  for (const [name, range, meaning] of rows) {
    const band = plain(name);
    const r = plain(range);
    let m;
    if ((m = /^>=\s*([0-9.]+)$/.exec(r))) out[band] = { min: Number(m[1]) };
    else if ((m = /^([0-9.]+)\s*-\s*([0-9.]+)$/.exec(r))) out[band] = { min: Number(m[1]), max: Number(m[2]) };
    else if ((m = /^<\s*([0-9.]+)$/.exec(r))) out[band] = { min: 0, below: Number(m[1]) };
    else throw new Error(`README.md severity bands: cannot read "${r}" for ${band}`);
    out[band].range = r;
    out[band].meaning = plain(meaning || "");
  }
  const missing = BANDS.filter((b) => !out[b]);
  if (missing.length) throw new Error(`README.md severity bands are missing ${missing.join(", ")}`);
  const joined = (upper, lower) => Math.abs(upper.max - (lower.min - 0.1)) < 1e-9;
  if (!joined(out.HIGH, out.CRITICAL) || !joined(out.MEDIUM, out.HIGH) || out.LOW.below !== out.MEDIUM.min) {
    throw new Error("README.md severity bands leave a gap or overlap between bands");
  }
  return out;
}

// What: the disagreements between the documents, and between them and the arithmetic coded here
function crossCheck(contributing, readme, schema) {
  const problems = [];
  const known = Object.values(EQUATIONS).map((e) => `"${e.text}"`).join(" or ");
  const eqC = equationOf(contributing.formula);
  const eqR = equationOf(readme.formula);
  if (!eqC) problems.push(`CONTRIBUTING.md states the equation as "${contributing.formula}"; this page is built for ${known}`);
  if (!eqR) problems.push(`README.md states the equation as "${readme.formula}"; this page is built for ${known}`);
  if (eqC && eqR && eqC !== eqR) problems.push(`the equations differ: CONTRIBUTING.md states "${contributing.formula}"; README.md states "${readme.formula}"`);

  const schemaFactors = Object.keys(schema.properties.aivss.properties.aarf.properties);
  const contribFactors = contributing.factors.map((f) => f.name);
  // the same factors, once each; the order is presentation (the README lists OWASP's order, the schema its own)
  const same = (a, b) => [...a].sort().join() === [...b].sort().join();
  if (!same(contribFactors, schemaFactors)) problems.push(`factors differ: CONTRIBUTING.md lists ${contribFactors.join(", ")}; the schema has ${schemaFactors.join(", ")}`);
  if (!same(readme.factors, schemaFactors)) problems.push(`factors differ: README.md lists ${readme.factors.join(", ")}; the schema has ${schemaFactors.join(", ")}`);

  const values = (list) => list.map((t) => t.value).sort((a, b) => a - b).join(", ");
  if (values(contributing.thm) !== values(readme.thm)) problems.push(`ThM values differ: CONTRIBUTING.md lists ${values(contributing.thm)}; README.md lists ${values(readme.thm)}`);

  const spec = schema.properties.aivss.properties.spec_version;
  if (!spec || !spec.const) problems.push("the schema's aivss.spec_version has no const to name the AIVSS version");
  return problems;
}

// ── reading the records ───────────────────────────────────────────────────────

function bandFor(bands) {
  return (score) => (score >= bands.CRITICAL.min ? "CRITICAL" : score >= bands.HIGH.min ? "HIGH" : score >= bands.MEDIUM.min ? "MEDIUM" : "LOW");
}

const factorSum = (a) => Object.values(a.aarf || {}).reduce((x, y) => x + y, 0);

// What: the aars and the unrounded score a record's own inputs give under one equation
// How:  v0.8: aars is the uplift (10 - CVSS_Base) x (Factor_Sum / 10) x ThM and the score adds it to the base;
//       ave1: aars is the plain sum of the factors and the score averages it with the base
function derive(eq, a) {
  if (!a.aarf) {
    return { aars: a.aars, raw: eq === "v08" ? (a.cvss_base + a.aars) * a.mitigation_factor : ((a.cvss_base + a.aars) / 2) * a.thm * a.mitigation_factor };
  }
  const sum = factorSum(a);
  if (eq === "v08") {
    const aars = (10 - a.cvss_base) * (sum / 10) * a.thm;
    return { aars, raw: (a.cvss_base + aars) * a.mitigation_factor };
  }
  return { aars: sum, raw: ((a.cvss_base + sum) / 2) * a.thm * a.mitigation_factor };
}

// What: each way a record's own numbers disagree with the documents, as sentences
// Why:  the page says "recomputed from each record's own inputs"; it should be true, and say so when not
// How:  a stored score is the formula rounded to one decimal, so it sits within 0.05 of it
function checkRecords(records, bandOf, thmValues, eq) {
  const problems = [];
  for (const r of records) {
    const a = r.aivss;
    const id = r.ave_id;
    const { aars, raw } = derive(eq, a);
    // v0.8 records store aars to four decimals; the 1.x sum is exact
    if (a.aarf && Math.abs(aars - a.aars) > 6e-5) problems.push(`${id}: aars is ${a.aars} but its inputs give ${trim(aars)}`);
    if (Math.abs(raw - a.aivss_score) > 0.0501) problems.push(`${id}: stored score ${a.aivss_score}, the equation gives ${trim(raw)}`);
    if (r.severity !== bandOf(a.aivss_score)) problems.push(`${id}: severity ${r.severity} but score ${a.aivss_score} is in ${bandOf(a.aivss_score)}`);
    if (!thmValues.includes(a.thm)) problems.push(`${id}: ThM ${a.thm} is not one of the documented values ${thmValues.join(", ")}`);
  }
  return problems;
}

// What: the counts the page shows, from the records that carry an aivss object
function summarize(records, factors, bandOf) {
  const scored = records.filter((r) => r.aivss);
  const byId = (a, b) => a.ave_id.localeCompare(b.ave_id);
  const bySc = (a, b) => b.aivss.aivss_score - a.aivss.aivss_score || byId(a, b);
  const ranked = scored.slice().sort(bySc);
  const count = (key) => {
    const m = new Map();
    for (const r of scored) m.set(r.aivss[key], (m.get(r.aivss[key]) || 0) + 1);
    return m;
  };
  const bands = Object.fromEntries(BANDS.map((b) => [b, 0]));
  const bins = Array.from({ length: 10 }, () => 0);
  for (const r of scored) {
    bands[bandOf(r.aivss.aivss_score)] += 1;
    bins[Math.min(9, Math.floor(r.aivss.aivss_score))] += 1;
  }
  const factor = Object.fromEntries(factors.map((f) => {
    const values = scored.map((r) => (r.aivss.aarf || {})[f] || 0);
    return [f, { above: values.filter((v) => v > 0).length, full: values.filter((v) => v === 1).length, mean: values.reduce((x, y) => x + y, 0) / (values.length || 1) }];
  }));
  const severeBase = scored.filter((r) => r.aivss.cvss_base >= 9);
  const uplift = scored.map((r) => r.aivss.aars);
  const mean = (list) => list.reduce((x, y) => x + y, 0) / (list.length || 1);
  return {
    total: scored.length,
    uplift: { min: Math.min(...uplift), max: Math.max(...uplift), mean: mean(uplift) },
    meanScore: mean(scored.map((r) => r.aivss.aivss_score)),
    bands, bins, factor,
    thm: count("thm"),
    mitigation: count("mitigation_factor"),
    highest: ranked[0] || null,
    // the lowest score; among equals the lowest id, as the highest does
    lowest: scored.slice().sort((a, b) => a.aivss.aivss_score - b.aivss.aivss_score || byId(a, b))[0] || null,
    severeBase: { total: severeBase.length, bands: Object.fromEntries(BANDS.map((b) => [b, severeBase.filter((r) => bandOf(r.aivss.aivss_score) === b).length])) },
  };
}

// ── the page ──────────────────────────────────────────────────────────────────

// A schema range: min to max, or the exact values when the schema lists them
const allowed = (p) => (p.enum ? `one of ${p.enum.map(fmt).join(", ")}` : `${p.minimum} to ${p.maximum}`);

function renderFormula(schema, eq) {
  const a = schema.properties.aivss.properties;
  const factorMax = Object.keys(a.aarf.properties).length;
  const code = eq === "v08"
    ? `<div class="codeblock"><span class="g">AARS</span>  = (10 - <span class="g">CVSS_Base</span>) &times; (<span class="g">Factor_Sum</span> / 10) &times; <span class="g">ThM</span>\n<span class="g">AIVSS</span> = (<span class="g">CVSS_Base</span> + <span class="g">AARS</span>) &times; <span class="g">Mitigation_Factor</span></div>`
    : `<div class="codeblock"><span class="g">AIVSS</span> = ((<span class="g">CVSS_Base</span> + <span class="g">AARS</span>) / 2) &times; <span class="g">ThM</span> &times; <span class="g">Mitigation_Factor</span></div>`;
  const terms = [["CVSS_Base", "cvss_base", allowed(a.cvss_base), a.cvss_base.description]];
  if (eq === "v08") terms.push(["Factor_Sum", "aarf", `0 to ${factorMax}`, a.aarf.description]);
  terms.push(["AARS", "aars", allowed(a.aars), a.aars.description], ["ThM", "thm", allowed(a.thm), a.thm.description],
    ["Mitigation_Factor", "mitigation_factor", allowed(a.mitigation_factor), a.mitigation_factor.description]);
  const rounding = eq === "v08"
    ? `    <p>The score a record carries is the result rounded half up to one decimal, as the OWASP document specifies: 9.85 is 9.9. <a href="${REPO}/blob/main/scripts/validate_records.py"><code>scripts/validate_records.py</code></a> works in exact decimal arithmetic and computes the score from the exact uplift, while <code>aivss.aars</code> is stored to four decimals.</p>`
    : `    <p>The score a record carries is the result rounded to one decimal, the way <a href="${REPO}/blob/main/scripts/validate_records.py"><code>scripts/validate_records.py</code></a> computes it with Python's <code>round()</code> on the floating-point result. A value that looks like a tie can therefore round either way: 9.25 is stored as 9.2.</p>`;
  return `${code}\n` +
    `    <p>${terms.length === 5 ? "Five terms" : "Four inputs"}. The ranges and descriptions are the schema's.</p>\n` +
    `    <div class="tbl-wrap"><table class="ref"><thead><tr><th>Term</th><th>Range</th><th>What it is</th></tr></thead><tbody>\n` +
    terms.map(([term, field, range, description]) => `      <tr><td class="mono">${term}</td><td class="mono">${esc(range)}</td><td>${esc(description)} Stored as <code>aivss.${field}</code>.</td></tr>`).join("\n") +
    `\n    </tbody></table></div>\n` + rounding;
}

function renderFactors(contributing, summary, eq) {
  const rows = contributing.factors.map((f) => {
    const s = summary.factor[f.name];
    return `      <tr><td class="mono">${esc(f.name)}</td><td>${esc(f.when)}</td>` +
      `<td class="num">${s.above} of ${summary.total}</td>` +
      `<td class="num"><span class="bar" role="img" aria-label="mean ${s.mean.toFixed(2)} of 1"><i style="width:${Math.round(s.mean * 100)}%"></i></span> ${s.mean.toFixed(2)}</td></tr>`;
  });
  const intro = eq === "v08"
    ? `<p>Factor_Sum is the sum of ten factors, each scored 0 (none), 0.5 (partial) or 1 (full). They are stored in <code>aivss.aarf</code> and feed AARS, the agentic uplift. The wording is CONTRIBUTING's; the last two columns are measured on the records.</p>`
    : `<p>AARS is the sum of ten factors, each scored 0.0 (not applicable) to 1.0 (fully applicable). They are stored in <code>aivss.aarf</code>, and <code>aivss.aars</code> is their sum. The wording is CONTRIBUTING's; the last two columns are measured on the records.</p>`;
  return intro + `\n` +
    `    <div class="tbl-wrap"><table class="ref stack-sm"><thead><tr><th>Factor</th><th>Score 1.0 when&hellip;</th><th class="num">Scored above 0</th><th class="num">Mean score</th></tr></thead><tbody>\n` +
    rows.join("\n") + `\n    </tbody></table></div>`;
}

function renderThm(contributing, schema, summary) {
  const a = schema.properties.aivss.properties;
  const used = (map, v) => map.get(v) || 0;
  const known = contributing.thm.map((t) => t.value);
  const stray = [...summary.thm.entries()].filter(([v]) => !known.includes(v));
  const thmRows = contributing.thm.map((t) => `      <tr><td class="mono">${esc(t.shown)}</td><td>${esc(t.meaning)}</td><td class="num">${used(summary.thm, t.value)} of ${summary.total}</td></tr>`)
    .concat(stray.map(([v, n]) => `      <tr><td class="mono">${esc(fmt(v))}</td><td>not a documented value</td><td class="num">${n} of ${summary.total}</td></tr>`));
  const mf = [...summary.mitigation.entries()].sort((x, y) => y[0] - x[0]);
  const mfRows = mf.map(([v, n]) => `      <tr><td class="mono">${esc(fmt(v))}</td><td class="num">${n} of ${summary.total}</td></tr>`);
  return `<p><strong>ThM</strong>: ${esc(a.thm.description)} The schema allows ${allowed(a.thm)}; the AVE documents list ${plural(contributing.thm.length, "value", "values")}. How often each is used:</p>\n` +
    `    <div class="tbl-wrap"><table class="ref"><thead><tr><th>ThM</th><th>When to use it</th><th class="num">Records</th></tr></thead><tbody>\n` +
    thmRows.join("\n") + `\n    </tbody></table></div>\n` +
    `    <p><strong>Mitigation_Factor</strong>: ${esc(a.mitigation_factor.description)} The values in use, and how often:</p>\n` +
    `    <div class="tbl-wrap"><table class="ref"><thead><tr><th>Mitigation_Factor</th><th class="num">Records</th></tr></thead><tbody>\n` +
    mfRows.join("\n") + `\n    </tbody></table></div>\n` +
    `    <p>Guidance on choosing between them is in the repository's <a href="${REPO}/blob/main/references/aivss-scoring.md">scoring reference</a>.</p>`;
}

function renderBands(readme, summary, eq) {
  const rows = BANDS.map((b) => {
    const n = summary.bands[b];
    return `      <tr><td><span class="sev ${b}">${b}</span></td><td class="mono">${esc(readme.bands[b].range)}</td><td>${esc(readme.bands[b].meaning)}</td>` +
      `<td class="num"><span class="bar ${b}" role="img" aria-label="${pct(n, summary.total)} percent"><i style="width:${pct(n, summary.total)}%"></i></span> ${n} (${pct(n, summary.total)}%)</td></tr>`;
  });
  const bandOf = bandFor(readme.bands);
  const peak = Math.max(1, ...summary.bins);
  const hist = summary.bins.map((n, i) => `<div class="col"><b>${n}</b><i class="b-${bandOf(i)}" style="height:${Math.round((100 * n) / peak)}%"></i><span>${i}</span></div>`).join("");
  const alt = summary.bins.map((n, i) => `${i} to ${i}.9: ${n}`).join(", ");
  const sb = summary.severeBase;
  const floor = eq === "v08" && summary.total ?
    `    <div class="callout">\n      <span class="k">The CVSS base is the floor</span>\n` +
    `      <p>The equation adds the agentic uplift to the CVSS base score, so a record never scores below its <code>cvss_base</code> times its <code>mitigation_factor</code>. In the published records the uplift (<code>aars</code>) runs from ${trim(summary.uplift.min)} to ${trim(summary.uplift.max)} and averages ${summary.uplift.mean.toFixed(2)}, against an average score of ${summary.meanScore.toFixed(1)}: the base decides most of the score, so an honest CVSS v4.0 assessment matters most.</p>\n    </div>\n` : "";
  const callout = eq === "v08" ? floor : sb.total ?
    `    <div class="callout">\n      <span class="k">A severe flaw is not a severe score</span>\n` +
    `      <p>The repository's scoring reference says AARF rewards breadth of amplification, not just raw impact, so a narrow, single-mechanism class with a near-maximum <code>cvss_base</code> still averages down. Here, ${plural(sb.total, "record has", "records have")} a <code>cvss_base</code> of 9.0 or more: ` +
    BANDS.filter((b) => sb.bands[b]).map((b) => `${sb.bands[b]} ${b}`).join(", ") + `. The honest computed result is reported, with the reason in <code>aivss.notes</code>.</p>\n    </div>\n` : "";
  return `<p>The final score maps to <code>severity</code>, and the two must agree. How the ${summary.total} published records fall:</p>\n` +
    `    <div class="tbl-wrap"><table class="ref stack-sm"><thead><tr><th>Band</th><th>AIVSS</th><th>Meaning</th><th class="num">Records</th></tr></thead><tbody>\n` +
    rows.join("\n") + `\n    </tbody></table></div>\n` +
    `    <figure class="histfig"><div class="hist" role="img" aria-label="Records by whole-number score. ${alt}.">${hist}</div>\n` +
    `    <figcaption>Records by whole-number score (2.0 to 2.9 is column 2)</figcaption></figure>\n` + callout;
}

function renderCalc(record, bandOf, factors, eq) {
  const a = record.aivss;
  const { aars, raw } = derive(eq, a);
  const stored = a.aivss_score;
  const band = bandOf(stored);
  const id = esc(record.ave_id);
  const list = factors.map((f) => {
    const v = (a.aarf || {})[f] || 0;
    return `<li><span class="mono">${esc(f)}</span><span class="bar" role="img" aria-label="${fmt(v)} of 1"><i style="width:${Math.round(v * 100)}%"></i></span><b>${fmt(v)}</b></li>`;
  }).join("");
  const rounded = trim(raw) === String(stored) ? "" : ` &rarr; stored as <strong>${stored}</strong>`;
  const sum = factorSum(a);
  const steps = eq === "v08"
    ? `        <li><div><strong>AARF factors</strong>, summing to Factor_Sum = ${fmt(sum)}<ul class="factors">${list}</ul></div></li>\n` +
      `        <li><div><strong>Uplift</strong><div class="eq">AARS = (10 - ${fmt(a.cvss_base)}) &times; (${fmt(sum)} / 10) &times; ${fmt(a.thm)} = ${trim(aars)}</div></div></li>\n` +
      `        <li><div><strong>Compose</strong><div class="eq">AIVSS = (${fmt(a.cvss_base)} + ${trim(aars)}) &times; ${fmt(a.mitigation_factor)} = ${trim(raw)}${rounded}</div></div></li>\n`
    : `        <li><div><strong>AARF factors</strong>, summing to AARS = ${fmt(a.aars)}<ul class="factors">${list}</ul></div></li>\n` +
      `        <li><div><strong>Compose</strong><div class="eq">((${fmt(a.cvss_base)} + ${fmt(a.aars)}) / 2) &times; ${fmt(a.thm)} &times; ${fmt(a.mitigation_factor)} = ${trim(raw)}${rounded}</div></div></li>\n`;
  return `    <article class="calc" aria-labelledby="calc-${id}">\n` +
    `      <header><a class="aveid" href="registry.html#${id}">${id}</a><span class="sev ${band}">${band}</span><h3 id="calc-${id}">${esc(record.title)}</h3></header>\n` +
    `      <ol>\n` +
    `        <li><div><strong>Inputs</strong><dl class="inputs"><div><dt>CVSS_Base</dt><dd>${fmt(a.cvss_base)}</dd></div><div><dt>ThM</dt><dd>${fmt(a.thm)}</dd></div><div><dt>Mitigation_Factor</dt><dd>${fmt(a.mitigation_factor)}</dd></div></dl></div></li>\n` +
    steps +
    `      </ol>\n` +
    (a.notes ? `      <p class="why"><strong>The record's note on its scoring:</strong> ${esc(a.notes)}</p>\n` : "") +
    `    </article>`;
}

function renderExamples(summary, bandOf, factors, eq) {
  const { highest, lowest } = summary;
  if (!highest) return "<p>No scored records.</p>";
  const same = highest.ave_id === lowest.ave_id;
  const intro = same ? "<p>The only scored record.</p>"
    : `<p>The two ends of the published set: the highest score (${highest.aivss.aivss_score}) and the lowest (${lowest.aivss.aivss_score}). Each is built from the record's own <code>aivss</code> object, so the page follows the records if they are re-scored.</p>`;
  return intro + "\n" + renderCalc(highest, bandOf, factors, eq) + (same ? "" : "\n" + renderCalc(lowest, bandOf, factors, eq));
}

function renderChecked(summary, records, problems, sha, eq) {
  const bad = new Set(problems.map((p) => p.split(":")[0]));
  const ok = records.length - [...bad].filter((id) => records.some((r) => r.ave_id === id)).length;
  return `<p class="checked">Recomputed when this page was built, from <a href="${REPO}/tree/${esc(sha)}">aveproject/ave@${esc(sha.slice(0, 7))}</a>: ` +
    `${ok} of ${records.length} records have an aars equal to ${eq === "v08" ? "the uplift their inputs give" : "the sum of their factors"}, a stored score within rounding of the equation, a severity that matches its band, and a documented ThM.</p>`;
}

// What: the filled-in pieces of scoring.html, and the warnings found on the way
// How:  throws when the documents cannot be read or disagree; returns record-level disagreements as warnings
function buildScoring({ contributing, readme, schema, records, sha }) {
  const c = parseContributing(contributing);
  const r = parseReadme(readme);
  const problems = crossCheck(c, r, schema);
  if (problems.length) throw new Error(`the AVE documents disagree, so the scoring page cannot be built:\n  - ${problems.join("\n  - ")}`);

  const eq = equationOf(c.formula);
  const factors = c.factors.map((f) => f.name);
  const bandOf = bandFor(r.bands);
  const scored = records.filter((x) => x.aivss);
  const warnings = checkRecords(scored, bandOf, c.thm.map((t) => t.value), eq);
  const summary = summarize(scored, factors, bandOf);
  const spec = schema.properties.aivss.properties.spec_version.const;
  return {
    warnings,
    summary,
    equation: eq,
    values: {
      "{{AIVSS_SPEC}}": esc(spec),
      "{{RECORD_COUNT}}": String(summary.total),
      "<!-- ave:scoring-formula -->": renderFormula(schema, eq),
      "<!-- ave:scoring-factors -->": renderFactors(c, summary, eq),
      "<!-- ave:scoring-thm -->": renderThm(c, schema, summary),
      "<!-- ave:scoring-bands -->": renderBands(r, summary, eq),
      "<!-- ave:scoring-examples -->": renderExamples(summary, bandOf, factors, eq),
      "<!-- ave:scoring-checked -->": renderChecked(summary, scored, warnings, sha, eq),
    },
  };
}

function loadSources(aveDir) {
  const read = (p) => fs.readFileSync(path.join(aveDir, p), "utf8");
  return {
    contributing: read("CONTRIBUTING.md"),
    readme: read("README.md"),
    schema: JSON.parse(read("schema/ave-record.schema.json")),
  };
}

module.exports = { buildScoring, loadSources, parseContributing, parseReadme, parseBands, crossCheck, checkRecords, summarize, bandFor, section, tables, derive, equationOf, EQUATIONS };
