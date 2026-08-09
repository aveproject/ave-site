#!/usr/bin/env node
/**
 * publish-schemas.js
 *
 * Syncs every *.schema.json file from aveproject/ave's schema/ directory
 * into this repo's schema/ output directory, so each file's own "$id"
 * (e.g. https://aveproject.org/schema/crosswalk-1.0.0.schema.json) actually
 * resolves once the site deploys. Before this script existed, ave-site had
 * no mechanism at all to publish schema/ — schemas were declared as if
 * self-hosted but never copied anywhere, so every one of them 404'd
 * (crosswalk-1.0.0.schema.json included; see aveproject/ave#94, #121).
 *
 * This does a full sync (copy + prune), not an append, so a future schema
 * file just needs to exist in aveproject/ave/schema/ — nothing here needs
 * to be told about it by name.
 *
 * Usage:
 *   node scripts/publish-schemas.js
 *   node scripts/publish-schemas.js --schema-dir ../ave/schema --out-dir schema
 *
 * Exit codes:
 *   0  success
 *   1  source schema directory not found
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

const SCHEMA_DIR = flag("--schema-dir", path.join(__dirname, "../../ave/schema"));
const OUT_DIR     = flag("--out-dir",    path.join(__dirname, "../schema"));
const DRY_RUN     = has("--dry-run");

// ── helpers ───────────────────────────────────────────────────────────────────

const log  = (...a) => console.log("[publish-schemas]", ...a);
const warn = (...a) => console.warn("[publish-schemas] WARN", ...a);
const fail = (...a) => { console.error("[publish-schemas] ERROR", ...a); process.exit(1); };

// ── resolve source directory ──────────────────────────────────────────────────

const schemaDir = path.resolve(SCHEMA_DIR);
if (!fs.existsSync(schemaDir)) {
  fail(
    `Schema directory not found: ${schemaDir}\n` +
    `  Make sure aveproject/ave is checked out alongside aveproject/ave-site, or\n` +
    `  pass --schema-dir <path> pointing to its schema/ folder.`
  );
}

const outDir = path.resolve(OUT_DIR);

// ── find source files ─────────────────────────────────────────────────────────

const sourceFiles = fs
  .readdirSync(schemaDir)
  .filter((f) => f.endsWith(".schema.json"))
  .sort();

if (sourceFiles.length === 0) {
  fail(`No *.schema.json files found in: ${schemaDir}`);
}

log(`Found ${sourceFiles.length} schema file(s) in ${schemaDir}`);

// ── prune stale files already published that no longer exist upstream ────────

const existing = fs.existsSync(outDir)
  ? fs.readdirSync(outDir).filter((f) => f.endsWith(".schema.json"))
  : [];

const stale = existing.filter((f) => !sourceFiles.includes(f));

for (const f of stale) {
  if (DRY_RUN) {
    log(`  prune ${f}  (dry run, not removed)`);
  } else {
    fs.unlinkSync(path.join(outDir, f));
    log(`  prune ${f}`);
  }
}

// ── copy current files ────────────────────────────────────────────────────────

if (!DRY_RUN && !fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

let copied = 0;
for (const f of sourceFiles) {
  const src  = path.join(schemaDir, f);
  const dest = path.join(outDir, f);

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(src, "utf8"));
  } catch (e) {
    fail(`${f}: JSON parse error — ${e.message}`);
  }

  const expectedId = `https://aveproject.org/schema/${f}`;
  if (parsed["$id"] && parsed["$id"] !== expectedId) {
    warn(`${f}: $id is "${parsed["$id"]}", expected "${expectedId}" — publishing anyway, but this file's $id won't match where it's served.`);
  }

  if (DRY_RUN) {
    log(`  copy  ${f}  (dry run, not written)`);
  } else {
    fs.copyFileSync(src, dest);
    log(`  copy  ${f}`);
  }
  copied++;
}

log(`Done. ${copied} file(s) published${stale.length ? `, ${stale.length} pruned` : ""}${DRY_RUN ? " (dry run)" : ""}.`);
