#!/usr/bin/env node
/**
 * build-pages.js
 *
 * Generates the three reference pages from aveproject/ave, so they can never
 * drift from it:
 *   schema.html             from schema/ave-record.schema.json (the alias, newest version)
 *   implementer-guide.html  from docs/specs/ave-implementer-guide.md
 *   scoring.html            from CONTRIBUTING.md, README.md, the schema and the records
 *                           (scripts/lib/scoring.js says which part comes from where)
 *
 * Each page is a template under templates/ (layout, styles, scripts) with
 * placeholders this script fills. The outputs are build artifacts: listed in
 * .gitignore, written by deploy.yml, never committed.
 *
 * Usage:
 *   node scripts/build-pages.js
 *   node scripts/build-pages.js --ave-dir ../ave --out-dir .
 *
 * scoring.html reads records.js, the records the registry shows, so build the
 * records first (npm run build:local).
 *
 * Exit codes: 0 success, 1 a source is missing, a placeholder is left unfilled,
 * the schema has a property this script cannot place, or the AVE documents
 * disagree about scoring (outputs NOT written).
 */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const { Marked } = require("marked");
const scoring = require("./lib/scoring");

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(name);
  return i !== -1 ? args[i + 1] : fallback;
};

const AVE_DIR = path.resolve(flag("--ave-dir", path.join(__dirname, "../../ave")));
const OUT_DIR = path.resolve(flag("--out-dir", path.join(__dirname, "..")));
const TEMPLATES = path.join(__dirname, "../templates");
const REPO_URL = "https://github.com/aveproject/ave";

const log = (...a) => console.log("[build-pages]", ...a);
const fail = (...a) => { console.error("[build-pages] ERROR", ...a); process.exit(1); };

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const code = (s) => `<code>${esc(s)}</code>`;

// ── schema.html ───────────────────────────────────────────────────────────────

// The page's sections, in order. Every schema property must be placed exactly
// once; a property added to the schema later and not listed here still appears,
// under "Other fields", and the build says so.
const SECTIONS = [
  {
    id: "identity", nav: "Identity", title: "Identity &amp; description",
    fields: ["ave_id", "schema_version", "status", "merged_into", "rejection_reason", "published", "last_updated",
      "title", "attack_class", "component_type", "description", "behavioral_fingerprint", "behavioral_vector",
      "example_patterns", "severity", "aivss_score", "cvss_base_vector", "mutation_count"],
    intro: (r) => `<p>${r.core.length} fields are required on every record, whatever its status, including ${code(r.reducedStatus)}: the core a submission needs. A ${code(r.reducedStatus)} record is not yet peer-reviewed; everything else is enrichment added before promotion to ${code("active")}. ${r.full.length} more are required for every status except ${code(r.reducedStatus)} (marked below), so a record keeps its full content when it leaves ${code("active")}.${r.byStatusSentence}</p>`,
  },
  {
    id: "frameworks", nav: "Frameworks", title: "Framework mappings",
    fields: ["owasp_mcp", "owasp_asi", "mitre_atlas", "nist_ai_rmf", "framework_sources", "affected_platforms", "affected_registries"],
    intro: (r) => `<p><strong>owasp_mcp</strong> ${r.phrase("owasp_mcp")}: at least one anchor, the core OWASP grounding every published record must have. The other framework fields are optional but strongly recommended when they apply: <strong>owasp_asi</strong> for the OWASP Agentic Security Initiative Top 10, <strong>mitre_atlas</strong> when an ATLAS technique applies, <strong>nist_ai_rmf</strong> when relevant, and <strong>framework_sources</strong> to say which edition of each framework the mappings were made against.</p>`,
  },
  {
    id: "provenance-vector", nav: "Provenance vector", title: "Provenance vector &amp; trifecta profile",
    fields: ["provenance_vector", "trifecta_profile"],
    intro: () => `<p>Two optional classification objects. Absent or ${code("null")} means not yet classified, not &ldquo;does not apply.&rdquo; Neither affects severity or aivss_score; they are descriptive, not scoring inputs.</p>`,
  },
  {
    id: "mitigation", nav: "Mitigation", title: "Mitigation strategy",
    fields: ["mitigation"],
    intro: () => `<p><strong>mitigation</strong> is an optional, vendor-neutral companion to the prose ${code("remediation")} field: it names the class of defense, not a runnable control, so any enforcement tool can build a concrete implementation from these values.</p>`,
  },
  {
    id: "detection", nav: "Detection", title: "Detection &amp; remediation",
    fields: ["indicators_of_compromise", "detection_methodology", "remediation", "kill_switch_active"],
    intro: (r) => `<p><strong>indicators_of_compromise</strong> ${r.phrase("indicators_of_compromise")}, with at least one entry, and <strong>remediation</strong> ${r.phrase("remediation")}. A published record with no indicators gives defenders nothing to act on.</p>`,
  },
  {
    id: "provenance", nav: "Provenance", title: "Provenance",
    fields: ["references", "researcher", "researcher_url"],
    intro: (r) => `<p><strong>references</strong> ${r.phrase("references")}: even an unreviewed record needs at least one citable source, the provenance signal a skeptic checks first. <strong>researcher</strong> ${r.phrase("researcher")}: records must be attributable.</p>`,
  },
  {
    id: "aivss", nav: "AIVSS", title: "The <code>aivss</code> object: OWASP AIVSS v0.8",
    fields: ["aivss"],
    intro: (r) => `<p><strong>aivss</strong> ${r.phrase("aivss")}. Its ${code("aarf")} block records the agentic amplification factors that distinguish AIVSS from plain CVSS; the sub-fields marked required are required whenever ${code("aivss")} is present.</p>`,
  },
  {
    id: "evidence", nav: "Evidence", title: "Scanner evidence declarations (optional)",
    fields: ["evidence_kind_default", "detection_stage", "detection_layer", "confidence_baseline", "evidence_basis_engines",
      "derivable_into", "evidence_vantage", "evidence_method", "verification_basis"],
    intro: () => `<p>Scanner-facing defaults. The record declares baselines; the scanner assigns per-finding actuals. Never carry per-detection values like confidence in a record. See <a href="architecture.html">architecture</a> for the declares-vs-assigns contract.</p>`,
  },
  {
    id: "rationale", nav: "Rationale", title: "Vulnerability rationale (optional)",
    fields: ["security_boundary", "missing_control", "vulnerability_rationale"],
    intro: () => `<p>Why the class is a vulnerability and not only a capability: the trust boundary it crosses, the control whose absence makes exploitation possible, and the three-line rationale that ties capability, condition and result together.</p>`,
  },
  {
    id: "history", nav: "Revisions", title: "Revision history (optional)",
    fields: ["revisions"],
    intro: () => `<p>An append-only history of edits that changed a value a consumer may gate on. Its absence makes no claim either way; it does not mean the record was never revised.</p>`,
  },
];

// What: how a field's presence is required, from the schema's own structure
// How:  top-level "required" is every record; an if/then/else on one status
//       value ("draft") gives the set every other status requires; allOf
//       if/then entries on a status give a status's own requirements
function requirementRules(schema) {
  const core = schema.required || [];
  const reducedStatus = schema.if && schema.if.properties && schema.if.properties.status && schema.if.properties.status.const;
  const full = (reducedStatus && schema.else && schema.else.required) || [];
  const byStatus = {};
  for (const rule of schema.allOf || []) {
    const s = rule.if && rule.if.properties && rule.if.properties.status && rule.if.properties.status.const;
    if (s && rule.then && rule.then.required) byStatus[s] = rule.then.required;
  }
  const label = (field) => {
    if (core.includes(field)) return { cls: "y", text: "required" };
    if (full.includes(field)) return { cls: "y", text: `required unless ${reducedStatus}` };
    const statuses = Object.keys(byStatus).filter((s) => byStatus[s].includes(field));
    if (statuses.length) return { cls: "c", text: `required when ${statuses.join(" or ")}` };
    return { cls: "n", text: "optional" };
  };
  const phrase = (field) => {
    if (core.includes(field)) return `is required on every record, including ${code(reducedStatus || "draft")}`;
    if (full.includes(field)) return `is required for every status except ${code(reducedStatus)}`;
    return "is optional";
  };
  const parts = Object.entries(byStatus).map(([s, f]) => `${code(s)} also requires ${f.map(code).join(", ")}`);
  const byStatusSentence = parts.length ? " " + parts.join("; ").replace(/^./, (c) => c.toUpperCase()) + "." : "";
  return { core, full, reducedStatus, byStatus, label, phrase, byStatusSentence };
}

function typeOf(p) {
  if (!p || typeof p !== "object") return "any";
  if (p.const !== undefined) return "const";
  if (p.enum) return "enum";
  const t = p.type;
  if (Array.isArray(t)) return t.join(" | ");
  if (t === "string" && p.format) return p.format;
  if (t === "array") {
    const it = p.items || {};
    const inner = it.enum ? "enum" : it.type === "string" && it.format ? it.format : it.type || "object";
    return `${Array.isArray(inner) ? inner.join(" | ") : inner}[]`;
  }
  if (!t) return p.not ? "any but null" : "any";
  return t;
}

function valuesOf(p) {
  if (!p) return "";
  const list = p.enum || (p.items && p.items.enum);
  if (list) return `<span class="vals">${list.map((v) => `<code>${esc(v)}</code>`).join(" ")}</span>`;
  if (p.const !== undefined) return `<span class="vals">value <code>${esc(p.const)}</code></span>`;
  return "";
}

const anchorId = (name) => "field-" + name.replace(/\[\]/g, "").replace(/[^A-Za-z0-9_-]/g, "-");

function row(name, p, req, child) {
  const id = anchorId(name);
  const desc = p.description ? esc(p.description) : "";
  return `<tr id="${id}"${child ? ' class="sub"' : ""} data-field="${esc(name)}"><td class="mono"><a class="fanchor" href="#${id}" aria-label="Link to ${esc(name)}">${esc(name)}</a></td>` +
    `<td class="mono inl">${esc(typeOf(p))}</td><td class="inl"><span class="req ${req.cls}">${esc(req.text)}</span></td>` +
    `<td>${desc}${desc && valuesOf(p) ? " " : ""}${valuesOf(p)}</td></tr>`;
}

// A field's row, then one row per sub-field of an object, or of each item of an array of objects.
function rows(name, p, req) {
  const out = [row(name, p, req, false)];
  const obj = p.type === "object" && p.properties ? p : p.type === "array" && p.items && p.items.properties ? p.items : null;
  if (obj) {
    const prefix = obj === p ? `${name}.` : `${name}[].`;
    for (const [child, cp] of Object.entries(obj.properties)) {
      const required = (obj.required || []).includes(child);
      out.push(row(prefix + child, cp, required ? { cls: "y", text: "required" } : { cls: "n", text: "optional" }, true));
    }
  }
  return out;
}

function buildSchemaPage(commit) {
  const schemaPath = path.join(AVE_DIR, "schema/ave-record.schema.json");
  const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
  const m = /ave-record-([0-9]+\.[0-9]+\.[0-9]+)\.schema\.json$/.exec(schema.$id || "");
  if (!m) fail(`${schemaPath}: $id ${schema.$id} does not name a version`);
  const version = m[1];
  const example = schema.properties.schema_version && (schema.properties.schema_version.examples || [])[0];
  if (example && example !== version) fail(`${schemaPath}: $id says ${version}, the schema_version example says ${example}`);

  const r = requirementRules(schema);
  const props = schema.properties;
  const placed = new Set();
  const sections = SECTIONS.map((s) => ({ ...s, fields: s.fields.filter((f) => {
    if (!props[f]) { log(`note: ${f} is not in schema ${version}; left out of "${s.title}"`); return false; }
    if (placed.has(f)) fail(`${f} is listed in two sections`);
    placed.add(f);
    return true;
  }) })).filter((s) => s.fields.length);
  const other = Object.keys(props).filter((f) => !placed.has(f));
  if (other.length) {
    console.log(`::warning::schema ${version} has fields no section lists: ${other.join(", ")}; shown under "Other fields"`);
    sections.push({ id: "other", title: "Other fields", fields: other, intro: () => "" });
  }

  let fieldCount = 0;
  const body = sections.map((s) => {
    const trs = s.fields.flatMap((f) => rows(f, props[f], r.label(f)));
    fieldCount += trs.length;
    return `  <section class="fieldsec">\n  <h2 id="sec-${s.id}">${s.title}</h2>\n  ${s.intro(r)}\n` +
      `  <div class="tbl-wrap"><table class="ref stack-sm"><thead><tr><th>Field</th><th>Type</th><th>Presence</th><th>Description</th></tr></thead><tbody>\n` +
      trs.join("\n") + `\n  </tbody></table></div>\n  </section>\n`;
  }).join("\n");

  const onpage = `  <nav class="onpage" aria-label="On this page"><span class="h">On this page</span>` +
    sections.map((s) => `<a href="#sec-${s.id}">${s.nav || "Other"}</a>`).join("") +
    `<a href="#sec-relationships">Field relationships</a><a href="#sec-required">Required fields</a><a href="#sec-example">Example record</a></nav>\n` +
    `  <div class="filterbar"><input type="search" id="field-filter" placeholder="Filter ${fieldCount} fields by name or description" aria-label="Filter fields" autocomplete="off"><span id="field-filter-count" class="count" aria-live="polite"></span></div>\n` +
    `  <p id="field-filter-none" class="emptynote" hidden>No field matches that filter.</p>\n\n`;

  const line = (list) => {
    const out = [];
    for (let i = 0; i < list.length; i += 4) out.push(list.slice(i, i + 4).map(esc).join(" &middot; "));
    return out.join("\n");
  };
  const required = `  <p>${r.core.length} fields are required on every record, including ${code(r.reducedStatus)}:</p>\n` +
    `  <div class="codeblock"><span class="g">${line(r.core)}</span></div>\n` +
    `  <p style="margin-top:16px;">${r.full.length} more are required for every status except ${code(r.reducedStatus)}:</p>\n` +
    `  <div class="codeblock"><span class="g">${line(r.full)}</span></div>\n` +
    (r.byStatusSentence ? `  <p style="margin-top:16px;">${r.byStatusSentence.trim()}</p>\n` : "");

  log(`schema ${version}: ${Object.keys(props).length} top-level properties, ${fieldCount} rows in ${sections.length} sections`);
  return fill("schema.html", {
    "{{SCHEMA_VERSION}}": version,
    "<!-- ave:schema-sections -->": onpage + body,
    "<!-- ave:required-fields -->": required,
    "{{AVE_COMMIT}}": commit,
    "{{AVE_COMMIT_SHORT}}": commit.slice(0, 7),
  });
}

// ── implementer-guide.html ────────────────────────────────────────────────────

// GitHub's heading anchors, so links into the guide work the same on the site
function slugger() {
  const seen = {};
  return (text) => {
    let s = text.toLowerCase().trim().replace(/<[^>]+>/g, "").replace(/[^\p{L}\p{N}\s_-]/gu, "").replace(/\s/g, "-");
    if (seen[s] !== undefined) { seen[s] += 1; s = `${s}-${seen[s]}`; } else seen[s] = 0;
    return s;
  };
}

// The guide's relative links point into aveproject/ave; on the site they open on GitHub.
function resolveLink(href) {
  if (!href || /^(#|[a-z][a-z0-9+.-]*:)/i.test(href)) return href;
  const [p, frag] = href.split("#");
  if (p === "ave-implementer-guide.md") return frag ? `#${frag}` : "#";
  const target = path.posix.normalize(path.posix.join("docs/specs", p));
  if (target.startsWith("..")) fail(`guide link ${href} leaves the repository`);
  const kind = p.endsWith("/") ? "tree" : "blob";
  return `${REPO_URL}/${kind}/main/${target.replace(/\/$/, "")}${frag ? `#${frag}` : ""}`;
}

const COPY_BUTTON = `<button class="copy-btn" type="button" aria-label="Copy code" title="Copy">
    <svg class="i-copy" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    <svg class="i-check" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
  </button>`;

function buildGuidePage(commit) {
  const mdPath = path.join(AVE_DIR, "docs/specs/ave-implementer-guide.md");
  const src = fs.readFileSync(mdPath, "utf8");
  const slug = slugger();
  const toc = [];
  const marked = new Marked({ gfm: true });
  marked.use({
    renderer: {
      heading({ tokens, depth }) {
        const html = this.parser.parseInline(tokens);
        const id = slug(html);
        if (depth === 2) toc.push({ id, html });
        return `<h${depth} id="${id}">${html}<a class="hanchor" href="#${id}" aria-label="Link to this section">#</a></h${depth}>\n`;
      },
      code({ text, lang }) {
        const label = lang ? `<span class="lang">${esc(lang)}</span>` : "";
        return `<div class="codeblock-wrap">${label}${COPY_BUTTON}<div class="codeblock">${esc(text)}</div></div>\n`;
      },
      link({ href, title, tokens }) {
        const url = resolveLink(href);
        const external = /^https?:/i.test(url);
        return `<a href="${esc(url)}"${title ? ` title="${esc(title)}"` : ""}${external ? ' target="_blank" rel="noopener"' : ""}>${this.parser.parseInline(tokens)}</a>`;
      },
      hr() { return ""; },
    },
  });

  const tokens = marked.lexer(src);
  const first = tokens.findIndex((t) => t.type !== "space");
  if (tokens[first].type !== "heading" || tokens[first].depth !== 1) fail(`${mdPath} does not start with a level-1 heading`);
  const title = tokens[first].text;
  let i = first + 1;
  const intro = [];
  for (; i < tokens.length && tokens[i].type !== "hr" && tokens[i].type !== "heading"; i++) {
    if (tokens[i].type === "paragraph") intro.push(tokens[i]);
  }
  if (!intro.length) fail(`${mdPath} has no introduction before its first section`);
  const rest = tokens.slice(i);
  rest.links = tokens.links;
  const body = marked.parser(rest)
    .replace(/<table>/g, '<div class="tbl-wrap"><table class="ref">').replace(/<\/table>/g, "</table></div>");
  const introHtml = intro.map((t) => `    <p>${marked.parseInline(t.text)}</p>`).join("\n");
  const description = intro[intro.length - 1].text.replace(/[`*_]/g, "").replace(/\[([^\]]+)\]\([^)]*\)/g, "$1");
  const tocHtml = `  <nav class="toc" aria-label="Contents"><span class="h">Contents</span><ol>` +
    toc.map((t) => `<li><a href="#${t.id}">${t.html}</a></li>`).join("") + `</ol></nav>\n`;

  log(`guide: "${title}", ${toc.length} sections`);
  return fill("implementer-guide.html", {
    "{{GUIDE_TITLE}}": esc(title),
    "{{GUIDE_INTRO}}": introHtml,
    "{{GUIDE_DESCRIPTION}}": esc(description),
    "<!-- ave:guide-body -->": tocHtml + body,
    "{{AVE_COMMIT}}": commit,
    "{{AVE_COMMIT_SHORT}}": commit.slice(0, 7),
  });
}

// ── scoring.html ──────────────────────────────────────────────────────────────

// The records are the ones the registry shows (records.js), so the two pages count the same set.
function buildScoringPage(commit) {
  const recordsPath = path.join(OUT_DIR, "records.js");
  if (!fs.existsSync(recordsPath)) fail(`${recordsPath} not found; scoring.html is built from the records the registry shows, so run the records build first (npm run build:local)`);
  let page;
  try {
    page = scoring.buildScoring({ ...scoring.loadSources(AVE_DIR), records: require(recordsPath), sha: commit });
  } catch (e) {
    fail(e.message);
  }
  for (const w of page.warnings) console.log(`::warning::scoring: ${w}`);
  log(`scoring: ${page.summary.total} records, ${page.warnings.length} disagreeing with the documents`);
  return fill("scoring.html", {
    ...page.values,
    "{{AVE_COMMIT_SHORT}}": commit.slice(0, 7),
  });
}

// ── shared ────────────────────────────────────────────────────────────────────

function fill(name, values) {
  let html = fs.readFileSync(path.join(TEMPLATES, name), "utf8");
  for (const [key, value] of Object.entries(values)) {
    if (!html.includes(key)) fail(`templates/${name} has no ${key}`);
    html = html.split(key).join(value);
  }
  const left = html.match(/\{\{[A-Z_]+\}\}|<!-- ave:[a-z-]+ -->/g);
  if (left) fail(`templates/${name}: unfilled ${[...new Set(left)].join(", ")}`);
  return { name, html };
}

const commit = execFileSync("git", ["-C", AVE_DIR, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
const pages = [buildSchemaPage(commit), buildGuidePage(commit), buildScoringPage(commit)];
for (const { name, html } of pages) {
  fs.writeFileSync(path.join(OUT_DIR, name), html, "utf8");
  log(`Written: ${path.join(OUT_DIR, name)}`);
}
