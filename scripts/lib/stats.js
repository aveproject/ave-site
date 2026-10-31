"use strict";

/**
 * stats.js
 *
 * The counts the home and architecture pages show, from the published records file
 * (dist/ave-records-latest.json). They used to load records.js, about 750 KB of record
 * text, to count five things; scripts/build-site-meta.js now writes these into
 * site-meta.js and the pages read them from there.
 */

// What: how many records sit in each detection layer, status and severity
// Why:  the architecture page's layer table and the home page's counts
// How:  a record that omits detection_layer counts as "content", as the registry does
function recordStats(records) {
  const count = (key, fallback) => {
    const out = {};
    for (const r of records) {
      const value = r[key] || fallback;
      out[value] = (out[value] || 0) + 1;
    }
    return out;
  };
  return {
    total: records.length,
    layers: count("detection_layer", "content"),
    status: count("status", "unknown"),
    severity: count("severity", "unknown"),
  };
}

module.exports = { recordStats };
