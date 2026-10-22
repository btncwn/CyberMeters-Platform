// Deliberately small, reviewed snapshot. No runtime lookup or comprehensive
// coverage claim. Ranges concern declared library labels, not verified bytes.
export const JAVASCRIPT_ADVISORY_DATA = Object.freeze({
  version: "2026.10.22.1", reviewed_at: "2026-10-22",
  advisories: Object.freeze([
    Object.freeze({ package: "jquery", id: "CVE-2020-11022", introduced: "1.2.0", fixed: "3.5.0",
      source: "https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2" }),
    Object.freeze({ package: "lodash", id: "CVE-2020-8203", introduced: "3.7.0", fixed: "4.17.19",
      source: "https://github.com/advisories/GHSA-p6mc-m468-83gw" }),
  ]),
});
