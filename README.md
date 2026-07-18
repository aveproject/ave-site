<div align="center">

<img src="https://aveproject.org/ave-logo-full.svg" alt="AVE — Agentic Vulnerability Enumeration" width="320" />

<br/>
<br/>

**Website for the [AVE](https://github.com/bawbel/ave) open standard — the behavioral classification standard for agentic AI components.**

[![Live site](https://img.shields.io/badge/live-aveproject.org-0a3024?style=flat-square&logo=googlechrome&logoColor=d4a017)](https://aveproject.org)
[![Deploy](https://img.shields.io/github/actions/workflow/status/bawbel/ave-site/deploy.yml?style=flat-square&label=deploy&color=0f6e56)](https://github.com/bawbel/ave-site/actions/workflows/deploy.yml)
[![AVE standard](https://img.shields.io/badge/standard-bawbel%2Fave-0a3024?style=flat-square)](https://github.com/bawbel/ave)
[![Records](https://img.shields.io/badge/records-59-0f6e56?style=flat-square)](https://aveproject.org/registry.html)
[![Schema](https://img.shields.io/badge/schema-v1.0.0-d4a017?style=flat-square)](https://aveproject.org/schema.html)
[![License](https://img.shields.io/badge/license-Apache%202.0-green?style=flat-square)](LICENSE)

</div>

---

## What this repo is

This repo contains the website only — HTML, CSS, JS, and assets for `aveproject.org`. It is a **consumer** of the AVE standard, not part of the standard itself.

The records, schema, detection rules, and fixtures live in **[bawbel/ave](https://github.com/bawbel/ave)**. Pushing new AVE records to that repo automatically triggers a rebuild and deployment of this site via GitHub Actions `repository_dispatch`.

AVE is the behavioral classification standard for agentic AI components. It plays a similar role to CWE in the traditional software world — a classification layer that Top-10-style frameworks (OWASP AST10, OWASP MCP Top 10) are built on top of. See [Crosswalks](#crosswalks) below for how this maps across frameworks on the site.

---

## Pages

| Page | URL | What it does |
|---|---|---|
| Landing | `/` | Overview, stats, links to all sections |
| Registry | `/registry.html` | Searchable, filterable table of all AVE records with full detail drawer |
| Crosswalks | `/crosswalks.html` | How SkillSpector, ClawScan, OWASP AST10, OWASP MCP, and MITRE ATLAS map to AVE ids |
| Architecture | `/architecture.html` | How an AVE record works — for tool implementers |
| Scoring | `/scoring.html` | The AIVSS v0.8 formula, AARF factors, and worked examples |
| Schema | `/schema.html` | Every field, type, required/optional, meaning — schema v1.0.0 reference |

---

## Crosswalks

The crosswalks page has two genuinely different data sources, and they do **not** scale the same way when records are added. Read this before editing anything in `crosswalks/`.

### Fully dynamic — the AVE to OWASP and MITRE ATLAS table

This table is inline in `crosswalks.html` and reads `window.RECORDS` from `records.js` directly. It loops over every record and renders one row per record, using the `owasp_mcp`, `owasp_mapping`, and `mitre_atlas_mapping` fields already present on each record. **When you rebuild `records.js` with more records, this table grows automatically. No content changes needed, ever.**

### Dynamic rendering, static content — the SkillSpector / ClawScan / AST10 tables

These three tables live in `crosswalks/*.json`, loaded via `crosswalks/manifest.json`. The **rendering** is dynamic — drop a new crosswalk JSON file into the folder, add one line to `manifest.json`, and it appears on the page with no HTML changes. But the **mapping content inside each file is hand-authored**, not derived from `records.js`. There is no code that infers "AVE-2026-00049 belongs in the `header-tamper` ClawScan category" — that judgment call has to be made once by a person and written into the JSON.

**Practical implication:** when new AVE records are added to `bawbel/ave`, the bottom OWASP/MITRE table picks them up automatically on the next site rebuild. The three external crosswalks will not mention them until someone manually adds entries to the relevant `crosswalks/*.json` files. This is a one-time task per new record, not a recurring burden — existing records already have their crosswalk entries.

```
crosswalks/
├── manifest.json              lists which JSON files to load, in order
├── skillspector-to-ave.json   NVIDIA SkillSpector, 16 categories
├── clawscan-to-ave.json       ClawScan, 7 modules / 21 rules
└── ave-to-ast10.json          OWASP AST10, 10 risk categories with severity
```

Add a new crosswalk: drop the JSON file here, add one line to `manifest.json`'s `files` array. The page auto-detects the shape (`category`+`ave_ids` vs `ast_id`+`ast_title`+`ast_severity`+`ave_ids`) and renders the right template — no HTML edits required.

---

## Local development

**Prerequisites:** Node.js 18+, and `bawbel/ave` checked out as a sibling directory.

```
parent/
├── ave/          <- github.com/bawbel/ave
└── ave-site/     <- github.com/bawbel/ave-site  (this repo)
```

```bash
git clone https://github.com/bawbel/ave
git clone https://github.com/bawbel/ave-site
cd ave-site

npm install
npm run build:local   # reads ../ave/records -> writes records.js

# serve locally — fetch() requires real HTTP, file:// will not work
# for crosswalks.html or any page that loads records.js via fetch
npx serve .
# or
python3 -m http.server 8080
```

Open [http://localhost:8080](http://localhost:8080).

### Build commands

| Command | What it does |
|---|---|
| `npm run build:local` | Build from `../ave/records` (local dev, validates against schema) |
| `npm run build` | Build from default path (CI) |
| `npm run build:drafts` | Include `status: "draft"` records |
| `npm run build:dry` | Validate records without writing `records.js` |

Note: `--skip-validation` was required before the v1.1.0 migration. All 51 records are
now at schema v1.0.0. Use `npm run build:local` without any flag.

### Custom path

```bash
node scripts/build-records.js \
  --records-dir ../ave/records \
  --schema      ../ave/schema/ave-record-1.0.0.schema.json \
  --out         records.js
```

---

## How the build works

`scripts/build-records.js` reads every `AVE-YYYY-NNNNN.json` from the records
directory, validates against the schema, excludes drafts, sorts CRITICAL to HIGH to MEDIUM to LOW then by id, and writes
`records.js` — the static JS module the site loads at runtime.

`records.js` is **gitignored**. It is generated fresh on every CI build from
the canonical source in `bawbel/ave`. Never edit it by hand.

This script only touches `records.js`. It does not touch `crosswalks/*.json` —
see [Crosswalks](#crosswalks) above for why that is a separate, manual step.

---

## Deployment

Deploys to [GitHub Pages](https://docs.github.com/en/pages) via `.github/workflows/deploy.yml`.

**Triggers:**
- Push to `main` in this repo
- `repository_dispatch` (`ave-records-updated`) from `bawbel/ave` when records, schema, or rules change
- Manual trigger from the Actions tab

**To wire up the cross-repo trigger:**

1. Create a fine-grained PAT — repository `bawbel/ave-site`, permissions: Contents (read) + Actions (write)
2. Add it as `AVE_SITE_DEPLOY_TOKEN` in `bawbel/ave` under Settings then Secrets
3. Copy `notify-ave-site.yml` into `bawbel/ave/.github/workflows/`

After that, pushing a new AVE record to `bawbel/ave` automatically rebuilds and
deploys the site within a few minutes. Remember: this updates `records.js` (and
therefore the bottom OWASP/MITRE table) automatically — it does **not** update
the three external crosswalks. See [Crosswalks](#crosswalks).

**Custom domain:** Set `aveproject.org` as the custom domain in GitHub Pages settings.
Add a CNAME record in Namecheap pointing `ave` to `bawbel.github.io`.

---

## Repository structure

```
ave-site/
├── index.html              Landing page
├── registry.html           Searchable AVE registry
├── crosswalks.html         Scanner and framework crosswalks (dynamic loader)
├── architecture.html       Implementer guide with SVG diagrams
├── scoring.html            AIVSS scoring formula and worked examples
├── schema.html             Schema v1.0.0 field reference
├── styles.css              Shared stylesheet (all pages)
├── records.js              GENERATED — gitignored, never edit by hand
├── crosswalks/
│   ├── manifest.json          lists crosswalk files to load
│   ├── skillspector-to-ave.json
│   ├── clawscan-to-ave.json
│   └── ave-to-ast10.json
├── CNAME                   Custom domain: aveproject.org
├── manifest.json           PWA manifest (root level — distinct from crosswalks/manifest.json)
├── robots.txt
├── sitemap.xml
├── favicon.ico             Multi-size (16/32/48px) — transparent stingray
├── ave-favicon.svg         SVG favicon — transparent background
├── apple-touch-icon.png    180px — iOS home screen (dark background)
├── ave-favicon-192.png     Android home screen
├── ave-favicon-512.png     PWA / OG image
├── scripts/
│   └── build-records.js    Generates records.js from bawbel/ave records
└── .github/
    └── workflows/
        └── deploy.yml      Build + deploy to GitHub Pages
```

---

## SEO and performance

- Unique `<title>` and `<meta description>` per page
- Open Graph + Twitter card on all pages
- JSON-LD structured data (WebSite schema with SearchAction)
- `sitemap.xml` and `robots.txt`
- PWA manifest with theme colour `#0a3024`
- Responsive to 375px (iPhone SE)
- Static files only — no backend, no runtime JS dependencies, no CDN for functionality
- Google Fonts loaded via preconnect for IBM Plex Sans / Mono + Playfair Display

---

## Contributing

This repo is for the website. To propose a new AVE record or a schema change, open an issue in **[bawbel/ave](https://github.com/bawbel/ave)**.

To fix a bug or improve the site (UI, crosswalk tables, content), open a PR here. Keep the site a consumer of the standard — no AVE record data lives here except what `build-records.js` generates and what is hand-authored in `crosswalks/*.json`.

Adding a new external-tool crosswalk (for example a fourth scanner): create the JSON file in `crosswalks/` following the shape of the existing files, add one line to `crosswalks/manifest.json`, open a PR. No HTML changes needed.

---

## Related

| | |
|---|---|
| [bawbel/ave](https://github.com/bawbel/ave) | The AVE standard — records, schema, rules |
| [bawbel/scanner](https://github.com/bawbel/scanner) | Reference implementation of AVE |
| [OWASP AST10](https://github.com/OWASP/www-project-agentic-skills-top-10) | Agentic Skills Top 10 — see `crosswalks/ave-to-ast10.json` |
| [api.piranha.bawbel.io](https://api.piranha.bawbel.io) | Threat intel API |
| [bawbel.io](https://bawbel.io) | Bawbel |

---

## License

Apache 2.0 — the same license as the AVE standard itself.