#!/usr/bin/env node
/**
 * build-records.js
 *
 * Reads every AVE record from aveproject/ave/records/*.json and writes
 * records.js — the static JS module the site loads at runtime.
 *
 * Usage:
 *   node scripts/build-records.js
 *   node scripts/build-records.js --records-dir ../ave/records
 *   node scripts/build-records.js --records-dir ../ave/records --out records.js
 *
 * The script validates each record against the schema before including it.
 * Records with status "draft" are excluded from the production build unless
 * the --include-drafts flag is passed.
 *
 * Exit codes:
 *   0  success
 *   1  validation errors found (records.js is NOT written)
 */

const fs   = require("fs");
const path = require("path");

// ── argument parsing ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(name);
  return i !== -1 ? args[i + 1] : fallback;
};
const has = (name) => args.includes(name);

const RECORDS_DIR    = flag("--records-dir", path.join(__dirname, "../../ave/records"));
const SCHEMA_PATH    = flag("--schema",      path.join(__dirname, "../../ave/schema/ave-record.schema.json"));
const OUT_PATH       = flag("--out",         path.join(__dirname, "../records.js"));
const INCLUDE_DRAFTS    = has("--include-drafts");
const DRY_RUN          = has("--dry-run");
const SKIP_VALIDATION  = has("--skip-validation");

// ── helpers ───────────────────────────────────────────────────────────────────

const log  = (...a) => console.log("[build-records]", ...a);
const warn = (...a) => console.warn("[build-records] WARN", ...a);
const fail = (...a) => { console.error("[build-records] ERROR", ...a); process.exit(1); };

// ── resolve records directory ─────────────────────────────────────────────────

const recordsDir = path.resolve(RECORDS_DIR);
if (!fs.existsSync(recordsDir)) {
  fail(
    `Records directory not found: ${recordsDir}\n` +
    `  Make sure aveproject/ave is checked out alongside aveproject/ave-site, or pass\n` +
    `  --records-dir <path> pointing to the records/ folder.`
  );
}

// ── optional schema validation ────────────────────────────────────────────────

let validate = null;
const schemaPath = path.resolve(SCHEMA_PATH);
if (fs.existsSync(schemaPath)) {
  try {
    const Ajv = require("ajv/dist/2020");
    const addFormats = require("ajv-formats");
    const ajv = new Ajv({ strict: false });
    addFormats(ajv);
    const schema = JSON.parse(fs.readFileSync(schemaPath, "utf8"));
    validate = ajv.compile(schema);
    log(`Schema loaded: ${schemaPath}`);
  } catch (e) {
    warn(`Could not load schema validator (${e.message}). Skipping validation.`);
    warn(`Run: npm install ajv ajv-formats  to enable validation.`);
  }
} else {
  warn(`Schema not found at ${schemaPath}. Skipping validation.`);
  warn(`Pass --schema <path> to enable validation.`);
}
if (SKIP_VALIDATION) {
  log(`Schema validation SKIPPED (--skip-validation flag set). Records will not be validated.`);
}

// ── read and parse records ────────────────────────────────────────────────────

const files = fs
  .readdirSync(recordsDir)
  .filter((f) => f.match(/^AVE-\d{4}-\d{5}\.json$/))
  .sort();

if (files.length === 0) {
  fail(`No AVE record files found in: ${recordsDir}`);
}

log(`Found ${files.length} record files.`);

const records  = [];
const errors   = [];
let   skipped  = 0;

for (const file of files) {
  const filePath = path.join(recordsDir, file);
  let record;

  // parse
  try {
    record = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (e) {
    errors.push(`${file}: JSON parse error — ${e.message}`);
    continue;
  }

  // skip drafts unless flag is set
  if (record.status === "draft" && !INCLUDE_DRAFTS) {
    log(`  skip  ${file}  (draft)`);
    skipped++;
    continue;
  }

  // validate against schema
  if (validate && !SKIP_VALIDATION) {
    const valid = validate(record);
    if (!valid) {
      const messages = validate.errors
        .map((e) => `    ${e.instancePath || "/"} ${e.message}`)
        .join("\n");
      errors.push(`${file}: schema validation failed\n${messages}`);
      continue;
    }
  }

  records.push(record);
  log(`  ok    ${file}  (${record.severity})`);
}

// ── report errors ─────────────────────────────────────────────────────────────

if (errors.length > 0) {
  console.error("\n[build-records] Validation errors:\n");
  errors.forEach((e) => console.error("  ✗", e));
  console.error(`\n${errors.length} error(s). records.js was NOT written.`);
  process.exit(1);
}

// ── sort: CRITICAL first, then HIGH, MEDIUM, LOW; then by ave_id ─────────────

const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
records.sort((a, b) => {
  const sd = (SEV_ORDER[a.severity] ?? 4) - (SEV_ORDER[b.severity] ?? 4);
  return sd !== 0 ? sd : a.ave_id.localeCompare(b.ave_id);
});

// ── generate output ───────────────────────────────────────────────────────────

const now     = new Date().toISOString();
const banner  = [
  `// records.js — generated by scripts/build-records.js`,
  `// built: ${now}`,
  `// records: ${records.length} (${skipped} drafts excluded)`,
  `// source:  https://github.com/aveproject/ave/tree/main/records`,
  `// DO NOT edit by hand — re-run: node scripts/build-records.js`,
].join("\n");

const output = [
  banner,
  "(function () {",
  "  var RECORDS = " + JSON.stringify(records, null, 2).replace(/^/gm, "  ").trimStart() + ";",
  "  if (typeof window !== 'undefined') window.RECORDS = RECORDS;",
  "  if (typeof module !== 'undefined') module.exports = RECORDS;",
  "})();",
].join("\n");

// ── write ─────────────────────────────────────────────────────────────────────

if (DRY_RUN) {
  log(`Dry run — would write ${records.length} records to ${OUT_PATH}`);
  log(`Output size: ${(output.length / 1024).toFixed(1)} KB`);
} else {
  const outDir = path.dirname(OUT_PATH);
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(OUT_PATH, output, "utf8");
  log(`Written: ${OUT_PATH}`);
  log(`Records: ${records.length}  |  Skipped drafts: ${skipped}  |  Size: ${(output.length / 1024).toFixed(1)} KB`);
}