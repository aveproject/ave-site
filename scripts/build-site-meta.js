#!/usr/bin/env node
/**
 * build-site-meta.js
 *
 * Writes site-meta.js: which catalog release and which records the site shows.
 * Every page's version strip and versions.html read it at runtime.
 *
 * Sources, all from the aveproject/ave checkout or its releases:
 *   - dist/ave-records-latest.json: the counts the home and architecture pages show
 *     (records per detection layer, status and severity)
 *   - the newest v* tag of the checkout (deploy.yml fetches tags)
 *   - dist/ave-records-latest.manifest.json: schema_version, record_count,
 *     sha256 and generated_at of the records this build publishes
 *   - the GitHub Releases API, and each release's ave-records.manifest.json
 *     asset, for the versions page (skipped with --offline)
 *
 * Usage:
 *   node scripts/build-site-meta.js
 *   node scripts/build-site-meta.js --ave-dir ../ave --out site-meta.js
 *   node scripts/build-site-meta.js --offline     # no network: releases from tags only
 *
 * GITHUB_TOKEN, when set, authenticates the API call (deploy.yml passes the
 * workflow token, which avoids the unauthenticated rate limit).
 *
 * Exit codes: 0 success, 1 any source missing or inconsistent (site-meta.js is NOT written).
 */

const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const { recordStats } = require("./lib/stats");

const args = process.argv.slice(2);
const flag = (name, fallback) => {
  const i = args.indexOf(name);
  return i !== -1 ? args[i + 1] : fallback;
};
const has = (name) => args.includes(name);

const AVE_DIR = path.resolve(flag("--ave-dir", path.join(__dirname, "../../ave")));
const OUT_PATH = path.resolve(flag("--out", path.join(__dirname, "../site-meta.js")));
const OFFLINE = has("--offline");
const REPO = "aveproject/ave";
const API = `https://api.github.com/repos/${REPO}/releases?per_page=100`;
const TAG = /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;

const log = (...a) => console.log("[build-site-meta]", ...a);
const fail = (...a) => { console.error("[build-site-meta] ERROR", ...a); process.exit(1); };

function git(...cmd) {
  return execFileSync("git", ["-C", AVE_DIR, ...cmd], { encoding: "utf8" }).trim();
}

// What: the catalog release tags in the checkout, newest first, with their dates
// Why:  the strip names the newest release; a shallow checkout without tags would
//       silently name none, so no tags at all is an error
// How:  git tag --list v*, keep strict vX.Y.Z, sort numerically
function releaseTags() {
  const tags = git("tag", "--list", "v*").split("\n").filter((t) => TAG.test(t));
  if (!tags.length) fail(`no vX.Y.Z tags in ${AVE_DIR}; check it out with fetch-depth: 0 and tags`);
  const key = (t) => t.slice(1).split(".").map(Number);
  tags.sort((a, b) => {
    const [x, y] = [key(a), key(b)];
    return y[0] - x[0] || y[1] - x[1] || y[2] - x[2];
  });
  return tags.map((tag) => ({ tag, date: git("log", "-1", "--format=%cs", `${tag}^{commit}`) }));
}

async function getJSON(url, auth) {
  const headers = { "Accept": "application/vnd.github+json", "User-Agent": "aveproject-ave-site-build" };
  if (auth && process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(url, { headers, signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.json();
}

// What: every published release, with its manifest when it has one
// Why:  versions.html lists them; a release without the three catalog files
//       (v1.0.0, v1.1.0) is shown as not pinnable instead of being dropped
// How:  the Releases API, then each ave-records.manifest.json asset (public,
//       fetched without the token so it is never sent to the download host);
//       a manifest whose release is not its tag fails the build
async function releases() {
  const list = (await getJSON(API, true)).filter((r) => !r.draft && TAG.test(r.tag_name));
  const out = [];
  for (const r of list) {
    const assets = r.assets.map((a) => ({ name: a.name, url: a.browser_download_url, size: a.size }));
    const names = new Set(assets.map((a) => a.name));
    const pinnable = ["ave-records.json", "ave-records.manifest.json", "SHA256SUMS"].every((n) => names.has(n));
    let manifest = null;
    if (pinnable) {
      const m = await getJSON(assets.find((a) => a.name === "ave-records.manifest.json").url, false);
      if (m.release !== r.tag_name) fail(`${r.tag_name}: its manifest says release ${m.release}`);
      manifest = {
        schema_version: m.schema_version, record_count: m.record_count, sha256: m.sha256,
        source_commit: m.source_commit || null, generated_at: m.generated_at,
      };
    }
    out.push({
      tag: r.tag_name, name: r.name, published_at: r.published_at, url: r.html_url,
      prerelease: r.prerelease, pinnable, manifest, assets,
    });
  }
  return out;
}

// What: every published schema version, and the frozen record set named after it
// Why:  versions.html lists them beside the catalog releases, since the two numbers
//       differ and dist/ave-records-vX.Y.Z.json is named after a schema version
// How:  schema/ave-record-X.Y.Z.schema.json files, newest first, with the matching
//       dist/ave-records-vX.Y.Z.manifest.json when one exists
function schemaVersions() {
  const out = [];
  for (const f of fs.readdirSync(path.join(AVE_DIR, "schema"))) {
    const m = /^ave-record-([0-9]+\.[0-9]+\.[0-9]+)\.schema\.json$/.exec(f);
    if (!m) continue;
    const snapPath = path.join(AVE_DIR, `dist/ave-records-v${m[1]}.manifest.json`);
    let snapshot = null;
    if (fs.existsSync(snapPath)) {
      const sm = JSON.parse(fs.readFileSync(snapPath, "utf8"));
      snapshot = { file: `dist/ave-records-v${m[1]}.json`, record_count: sm.record_count, sha256: sm.sha256 || null };
    }
    out.push({ version: m[1], file: `schema/${f}`, snapshot });
  }
  const key = (v) => v.split(".").map(Number);
  return out.sort((a, b) => {
    const [x, y] = [key(a.version), key(b.version)];
    return y[0] - x[0] || y[1] - x[1] || y[2] - x[2];
  });
}

async function main() {
  const manifestPath = path.join(AVE_DIR, "dist/ave-records-latest.manifest.json");
  if (!fs.existsSync(manifestPath)) fail(`not found: ${manifestPath}`);
  const latest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  for (const k of ["schema_version", "record_count", "sha256", "generated_at"]) {
    if (latest[k] === undefined) fail(`${manifestPath} has no ${k}`);
  }

  // The manifest describes dist/; the site's records.js is built from records/.
  // Say so loudly if they disagree, since the strip quotes the manifest's count.
  const recordFiles = fs.readdirSync(path.join(AVE_DIR, "records")).filter((f) => /^AVE-.*\.json$/.test(f));
  const published = recordFiles.filter((f) =>
    JSON.parse(fs.readFileSync(path.join(AVE_DIR, "records", f), "utf8")).status !== "draft").length;
  if (published !== latest.record_count) {
    console.log(`::warning::dist/ave-records-latest.manifest.json says ${latest.record_count} records, records/ holds ${published} non-draft records`);
  }

  const recordsPath = path.join(AVE_DIR, "dist/ave-records-latest.json");
  if (!fs.existsSync(recordsPath)) fail(`not found: ${recordsPath}`);
  const stats = recordStats(JSON.parse(fs.readFileSync(recordsPath, "utf8")));
  if (stats.total !== latest.record_count) {
    console.log(`::warning::dist/ave-records-latest.json holds ${stats.total} records, its manifest says ${latest.record_count}`);
  }

  const tags = releaseTags();
  let list = null;
  if (OFFLINE) {
    log("offline: releases listed from tags only, without manifests");
  } else {
    try {
      list = await releases();
    } catch (e) {
      fail(`could not read releases: ${e.message} (use --offline for a local build without network)`);
    }
  }

  const newest = tags[0];
  const newestRelease = list && list.find((r) => r.tag === newest.tag);
  const meta = {
    generated_at: new Date().toISOString(),
    ave_commit: git("rev-parse", "HEAD"),
    catalog: {
      tag: newest.tag,
      date: newestRelease ? newestRelease.published_at.slice(0, 10) : newest.date,
      manifest: newestRelease ? newestRelease.manifest : null,
    },
    latest: {
      schema_version: latest.schema_version,
      record_count: latest.record_count,
      sha256: latest.sha256,
      generated_at: latest.generated_at,
    },
    // true when the site's records are exactly the newest release's records
    latest_is_release: Boolean(newestRelease && newestRelease.manifest && newestRelease.manifest.sha256 === latest.sha256),
    releases: list || tags.map((t) => ({ tag: t.tag, published_at: t.date, url: `https://github.com/${REPO}/releases/tag/${t.tag}`, pinnable: null, manifest: null, assets: [] })),
    releases_offline: OFFLINE,
    schemas: schemaVersions(),
    stats,
  };

  const output = [
    "// site-meta.js, generated by scripts/build-site-meta.js; never edit or commit it",
    "(function () {",
    "  var META = " + JSON.stringify(meta, null, 2).replace(/\n/g, "\n  ") + ";",
    "  if (typeof window !== 'undefined') window.AVE_SITE_META = META;",
    "  if (typeof module !== 'undefined') module.exports = META;",
    "})();",
    "",
  ].join("\n");
  fs.writeFileSync(OUT_PATH, output, "utf8");
  log(`Written: ${OUT_PATH}`);
  log(`catalog ${meta.catalog.tag} | records schema ${latest.schema_version}, ${latest.record_count} records` +
      ` | ${meta.latest_is_release ? "same as the release" : "newer than the release"} | releases: ${meta.releases.length}`);
}

main();
