// version-strip.js: fills every [data-ave-version] element with the catalog
// release and the records this site shows, from site-meta.js (generated at
// build by scripts/build-site-meta.js). The attribute's value is the link to
// the versions page. Without site-meta.js (a local preview that skipped the
// build) the element stays empty.
(function () {
  function text(parent, s) { parent.appendChild(document.createTextNode(s)); }

  function render() {
    var meta = window.AVE_SITE_META;
    var els = document.querySelectorAll("[data-ave-version]");
    if (!meta || !els.length) return;
    var updated = String(meta.latest.generated_at || "").slice(0, 10);
    var newer = !meta.latest_is_release;
    Array.prototype.forEach.call(els, function (el) {
      el.textContent = "";
      var link = document.createElement("a");
      link.href = el.getAttribute("data-ave-version") || "versions.html";
      link.textContent = "AVE catalog " + meta.catalog.tag;
      el.appendChild(link);
      if (newer) text(el, " + unreleased changes");
      text(el, " · schema " + meta.latest.schema_version +
               " · " + meta.latest.record_count + " records" +
               (updated ? " · updated " + updated : ""));
      el.title = newer
        ? "The records on this site are newer than catalog release " + meta.catalog.tag +
          ". Pin a release for results you can reproduce."
        : "The records on this site are exactly catalog release " + meta.catalog.tag + ".";
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", render);
  else render();
})();
