#!/usr/bin/env node
// Canonical ASM alert event → customer email label parity.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const moduleUrl = process.env.ASSET_ALERT_LABELS_MODULE_URL ||
  pathToFileURL(path.join(
    root,
    "workers/scan-api/src/engines/asset-alerts.js",
  )).href;
const {
  ASSET_ALERT_EMAIL_LABELS,
  ASSET_ALERT_EVENTS,
  buildAssetAlertEmail,
} = await import(moduleUrl);

const EXPECTED_ASSERTIONS = 32;
let assertionsPassed = 0;
let assertionFailures = 0;

function assert(name, condition, detail = "") {
  if (condition) assertionsPassed += 1;
  else {
    assertionFailures += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

function equal(name, actual, expected) {
  assert(
    name,
    actual === expected,
    `got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`,
  );
}

function emailFor(counts, severity = "medium") {
  return buildAssetAlertEmail(
    "example.com",
    "workspace-label-fixture",
    "scan-label-fixture",
    counts,
    ["admin.example.com"],
    severity,
    "https://app.cybermeters.com/assets",
    "complete",
  );
}

function textLabelRows(email) {
  const labels = new Set(Object.values(ASSET_ALERT_EMAIL_LABELS));
  return email.text.split("\n").filter((line) => {
    const separator = line.lastIndexOf(": ");
    return separator > 0 && labels.has(line.slice(0, separator));
  });
}

function htmlLabelRowCount(email) {
  return (email.html.match(/<li style="margin-bottom:6px">/g) || []).length;
}

const canonicalEvents = [...ASSET_ALERT_EVENTS];
const labelEvents = Object.keys(ASSET_ALERT_EMAIL_LABELS);
const missingLabels = canonicalEvents.filter(
  (eventType) => !ASSET_ALERT_EMAIL_LABELS[eventType],
);
const extraLabels = labelEvents.filter(
  (eventType) => !ASSET_ALERT_EVENTS.has(eventType),
);

equal("every canonical event has an email label", missingLabels.length, 0);
equal("label map contains no non-canonical event vocabulary", extraLabels.length, 0);
assert("canonical email label map is frozen", Object.isFrozen(ASSET_ALERT_EMAIL_LABELS));
equal(
  "asset_no_longer_seen label is exact",
  ASSET_ALERT_EMAIL_LABELS.asset_no_longer_seen,
  "No longer seen",
);
equal(
  "asset_reappeared label is exact",
  ASSET_ALERT_EMAIL_LABELS.asset_reappeared,
  "Seen again",
);
assert(
  "asset_no_longer_seen never claims removal, resolution or a fix",
  !/\b(?:removed|resolved|fixed)\b/i.test(
    ASSET_ALERT_EMAIL_LABELS.asset_no_longer_seen,
  ),
);
assert(
  "every canonical label remains evidence-first",
  canonicalEvents.every((eventType) =>
    /\b(?:observed|seen)\b/i.test(ASSET_ALERT_EMAIL_LABELS[eventType])),
);

const adminOnly = emailFor({ admin_surface_detected: 2 }, "high");
assert(
  "admin-only email contains a text event-count row",
  adminOnly.text.includes("Admin surfaces observed: 2"),
);
assert(
  "admin-only email contains an HTML event-count row",
  adminOnly.html.includes("Admin surfaces observed: 2"),
);
equal("admin-only email contains exactly one label row", textLabelRows(adminOnly).length, 1);

const certificateOnly = emailFor({
  certificate_new_detected: 1,
  certificate_new_san_detected: 2,
  certificate_new_issuer_detected: 3,
});
assert(
  "certificate-only email labels newly observed certificates",
  certificateOnly.text.includes("New certificates observed: 1"),
);
assert(
  "certificate-only email labels newly observed certificate names",
  certificateOnly.text.includes("New certificate names observed: 2"),
);
assert(
  "certificate-only email labels newly observed certificate issuers",
  certificateOnly.text.includes("New certificate issuers observed: 3"),
);
assert(
  "certificate-only HTML contains all three event-count rows",
  certificateOnly.html.includes("New certificates observed: 1") &&
  certificateOnly.html.includes("New certificate names observed: 2") &&
  certificateOnly.html.includes("New certificate issuers observed: 3"),
);
equal(
  "certificate-only email contains exactly three label rows",
  textLabelRows(certificateOnly).length,
  3,
);

const mixed = emailFor({
  asset_no_longer_seen: 1,
  asset_reappeared: 2,
  admin_surface_detected: 3,
  certificate_new_detected: 4,
}, "high");
assert("mixed email says No longer seen", mixed.text.includes("No longer seen: 1"));
assert("mixed email says Seen again", mixed.text.includes("Seen again: 2"));
assert(
  "mixed email retains admin observation wording",
  mixed.text.includes("Admin surfaces observed: 3"),
);
assert(
  "mixed email retains certificate observation wording",
  mixed.text.includes("New certificates observed: 4"),
);
equal("mixed email contains exactly four label rows", textLabelRows(mixed).length, 4);
assert(
  "mixed event-count rows never say removed, resolved or fixed",
  textLabelRows(mixed).every(
    (line) => !/\b(?:removed|resolved|fixed)\b/i.test(line),
  ),
);

const everyCanonicalCount = Object.fromEntries(
  canonicalEvents.map((eventType, index) => [eventType, index + 1]),
);
const everyCanonical = emailFor(everyCanonicalCount, "critical");
for (const [index, eventType] of canonicalEvents.entries()) {
  assert(
    `${eventType}: generated email contains its canonical count row`,
    everyCanonical.text.includes(
      `${ASSET_ALERT_EMAIL_LABELS[eventType]}: ${index + 1}`,
    ),
  );
}
equal(
  "all-canonical email HTML contains one row per canonical event",
  htmlLabelRowCount(everyCanonical),
  canonicalEvents.length,
);

console.log(
  `Asset alert email labels: ${assertionsPassed}/${EXPECTED_ASSERTIONS} assertions passed`,
);
if (
  assertionsPassed !== EXPECTED_ASSERTIONS ||
  assertionFailures > 0
) process.exit(1);
