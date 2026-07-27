#!/usr/bin/env node
// Item 10 P5 corrective — domain projection is independent from list paging.
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const routeUrl = process.env.ITEM10_P5_CORRECTIVE_ROUTE_MODULE_URL ||
  pathToFileURL(path.join(
    root,
    "workers/scan-api/src/routes/attack-surface.js",
  )).href;
const { attackSurfaceRoutes } = await import(routeUrl);

const EXPECTED_ASSERTIONS = 33;
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

function makeD1(db, counters) {
  const statement = (sql, args = []) => ({
    bind: (...bound) => statement(sql, bound),
    first: async () => {
      counters.reads += 1;
      return db.prepare(sql).get(...args) ?? null;
    },
    all: async () => {
      counters.reads += 1;
      return { results: db.prepare(sql).all(...args) };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) => Promise.all(
      statements.map((row) => row.all()),
    ),
  };
}

const db = new DatabaseSync(":memory:");
db.exec(`
  CREATE TABLE workspaces (
    id TEXT PRIMARY KEY
  );
  CREATE TABLE workspace_assets (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain_id TEXT,
    hostname TEXT,
    asset_type TEXT,
    source TEXT,
    first_seen TEXT,
    last_seen TEXT,
    status TEXT,
    wildcard_dns INTEGER,
    ip_addresses TEXT,
    cname TEXT,
    redirect_to TEXT,
    cloud_provider TEXT,
    risk_level TEXT,
    metadata_json TEXT,
    created_at TEXT,
    updated_at TEXT,
    lifecycle_state TEXT,
    last_observation_state TEXT,
    lifecycle_policy_version TEXT,
    confirmed_removed_at TEXT,
    last_observation_scan_id TEXT
  );
  CREATE TABLE attack_surface_signal_observations (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    signal_key TEXT NOT NULL,
    state TEXT NOT NULL,
    reason TEXT,
    evidence_count INTEGER,
    sources_json TEXT,
    limitations_json TEXT,
    model_version TEXT,
    observed_at TEXT
  );
  CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain_id TEXT
  );
  CREATE TABLE asset_alert_records (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    event_counts TEXT,
    sent_at TEXT
  );
  CREATE TABLE asset_events (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL,
    domain_id TEXT,
    asset_id TEXT,
    scan_id TEXT,
    event_type TEXT,
    hostname TEXT,
    severity TEXT,
    description TEXT,
    created_at TEXT
  );
  INSERT INTO workspaces VALUES ('ws-238');
  INSERT INTO workspaces VALUES ('ws-501');
  INSERT INTO workspaces VALUES ('ws-foreign');
`);

const insertAsset = db.prepare(`
  INSERT INTO workspace_assets (
    id, workspace_id, domain_id, hostname, asset_type, source,
    first_seen, last_seen, status, wildcard_dns, ip_addresses,
    cname, redirect_to, cloud_provider, risk_level, metadata_json,
    created_at, updated_at, lifecycle_state, last_observation_state,
    lifecycle_policy_version, confirmed_removed_at,
    last_observation_scan_id
  ) VALUES (?, ?, ?, ?, 'subdomain', 'fixture', ?, ?, ?, 0, '[]',
            NULL, NULL, NULL, 'low', '{}', ?, ?, ?, ?,
            'asset-removal-confirmation-v1', ?, ?)
`);

const insertAssets = (workspaceId, count, domainFor) => {
  db.exec("BEGIN");
  for (let index = 0; index < count; index += 1) {
    const id = `${workspaceId}-asset-${String(index).padStart(4, "0")}`;
    const removed = workspaceId === "ws-238" && index === count - 1;
    const observedAt = "2026-07-27T12:00:00.000Z";
    insertAsset.run(
      id,
      workspaceId,
      domainFor(index),
      `${String(index).padStart(4, "0")}.${workspaceId}.example`,
      "2026-07-01T00:00:00.000Z",
      observedAt,
      removed ? "inactive" : "active",
      "2026-07-01T00:00:00.000Z",
      observedAt,
      removed ? "confirmed_removed" : "observed",
      removed ? "not_observed" : "observed",
      removed ? "2026-07-27T11:59:00.000Z" : null,
      `scan-${workspaceId}`,
    );
  }
  db.exec("COMMIT");
};
insertAssets("ws-238", 238, (index) => index % 2 ? "dom-b" : "dom-a");
insertAssets("ws-501", 501, () => "dom-truncated");
insertAssets("ws-foreign", 1, () => "dom-foreign");

const signalKeys = [
  "subdomain_discovery",
  "dns_resolution",
  "http_https_service",
  "technology",
  "exposure_admin_surface",
  "takeover_candidate",
  "cve",
  "kev",
  "cloud_storage",
];
const insertSignal = db.prepare(`
  INSERT INTO attack_surface_signal_observations (
    id, workspace_id, domain_id, scan_id, signal_key, state, reason,
    evidence_count, sources_json, limitations_json, model_version, observed_at
  ) VALUES (?, ?, ?, ?, ?, 'observed', 'fixture_observed', 1,
            '["fixture"]', '[]',
            'attack-surface-signal-completeness-v1', ?)
`);
const insertSignals = (workspaceId, domains) => {
  db.exec("BEGIN");
  for (const domainId of domains) {
    for (const signalKey of signalKeys) {
      insertSignal.run(
        `${workspaceId}-${domainId}-${signalKey}`,
        workspaceId,
        domainId,
        `scan-${workspaceId}`,
        signalKey,
        "2026-07-27T12:00:00.000Z",
      );
    }
  }
  db.exec("COMMIT");
};
insertSignals("ws-238", ["dom-a", "dom-b"]);
insertSignals("ws-501", ["dom-truncated"]);

db.exec(`
  INSERT INTO asset_events VALUES (
    'evt-a', 'ws-238', 'dom-a', 'ws-238-asset-0000',
    'scan-ws-238', 'new_asset_discovered', '0000.ws-238.example',
    'info', 'New asset observed.', '2026-07-27T12:00:00.000Z'
  );
  INSERT INTO asset_events VALUES (
    'evt-b', 'ws-238', 'dom-b', 'ws-238-asset-0237',
    'scan-ws-238', 'asset_no_longer_seen', '0237.ws-238.example',
    'low', 'Historical lifecycle event.', '2026-07-27T11:59:00.000Z'
  );
`);

const counters = { reads: 0 };
const env = { cybermeters_db: makeD1(db, counters) };
const routeContext = (target) => ({
  request: new Request(target),
  env,
  url: new URL(target),
  json: (body, status = 200) => ({ body, status }),
  requireAuth: async () => ({ id: "fixture-user" }),
  requireWorkspaceRole: async () => ({ role: "owner" }),
});
const call = async (pathName) => attackSurfaceRoutes(routeContext(
  `https://api.example${pathName}`,
));

const readsBeforeLimit = counters.reads;
const limitOne = await call("/api/workspaces/ws-238/assets?limit=1");
const limitOneReads = counters.reads - readsBeforeLimit;
const defaults = await call("/api/workspaces/ws-238/assets");
const activeOnly = await call(
  "/api/workspaces/ws-238/assets?status=active&limit=37",
);
const feed = await call("/api/workspaces/ws-238/exposure/feed?limit=1");
const full = await call("/api/workspaces/ws-238/assets?limit=238");

equal("limit=1 route succeeds", limitOne.status, 200);
equal("default route succeeds", defaults.status, 200);
equal("status-filtered route succeeds", activeOnly.status, 200);
equal("exposure feed succeeds", feed.status, 200);
equal("238-row route succeeds", full.status, 200);
equal("limit=1 returns one list row", limitOne.body.assets.length, 1);
equal("default returns the 200-row page", defaults.body.assets.length, 200);
equal("status-filter applies only to list rows", activeOnly.body.assets.length, 37);

const canonicalProjection = JSON.stringify(
  limitOne.body.attack_surface_assurance,
);
equal(
  "default projection is independent from list pagination",
  JSON.stringify(defaults.body.attack_surface_assurance),
  canonicalProjection,
);
equal(
  "status-filtered projection is independent from list filtering",
  JSON.stringify(activeOnly.body.attack_surface_assurance),
  canonicalProjection,
);
equal(
  "exposure feed and Assets API use the same independent projection",
  JSON.stringify(feed.body.attack_surface_assurance),
  canonicalProjection,
);

const removalRecord = limitOne.body.attack_surface_assurance
  .flatMap((projection) => projection.lifecycle.records || [])
  .find((record) => record.asset_id === "ws-238-asset-0237");
equal(
  "confirmed removal excluded from active list remains in domain projection",
  removalRecord?.lifecycle_state,
  "confirmed_removed",
);
equal(
  "confirmed removal timestamp remains visible",
  removalRecord?.confirmed_removed_at,
  "2026-07-27T11:59:00.000Z",
);
equal(
  "238-asset workspace lifecycle read is complete at bound 500",
  limitOne.body.attack_surface_assurance_coverage?.status,
  "complete",
);
equal(
  "238-asset workspace coverage total is independent from list limit",
  limitOne.body.attack_surface_assurance_coverage?.total,
  238,
);
equal(
  "independent lifecycle read declares its bound",
  limitOne.body.attack_surface_assurance_coverage?.bound,
  500,
);
assert(
  "limit=1 route query count is bounded and not N+1",
  limitOneReads <= 5,
  `read count ${limitOneReads}`,
);

assert(
  "list rows do not duplicate attack_surface_assurance",
  full.body.assets.every(
    (asset) => !Object.hasOwn(asset, "attack_surface_assurance"),
  ),
);
equal(
  "list response carries the domain projection exactly once",
  (JSON.stringify(full.body).match(
    /"attack_surface_assurance":/g,
  ) || []).length,
  1,
);

const singleProjectionBytes = Buffer.byteLength(JSON.stringify(
  full.body.attack_surface_assurance,
));
const afterBytes = Buffer.byteLength(JSON.stringify(full.body));
const simulatedBefore = {
  ...full.body,
  assets: full.body.assets.map((asset) => {
    const domainProjection = full.body.attack_surface_assurance.find(
      (projection) => projection.domain_id === asset.domain_id,
    );
    const lifecycleRecord = domainProjection?.lifecycle?.records?.find(
      (record) => record.asset_id === asset.id,
    );
    return {
      ...asset,
      attack_surface_assurance: {
        ...domainProjection,
        lifecycle: {
          ...domainProjection.lifecycle,
          records: lifecycleRecord ? [lifecycleRecord] : [],
        },
      },
    };
  }),
};
const beforeBytes = Buffer.byteLength(JSON.stringify(simulatedBefore));
assert(
  "238-asset list stays below three single-projection payloads",
  afterBytes < singleProjectionBytes * 3,
  `after=${afterBytes}, projection=${singleProjectionBytes}`,
);
assert(
  "238-asset de-duplicated response is at least four times smaller",
  afterBytes * 4 < beforeBytes,
  `before=${beforeBytes}, after=${afterBytes}`,
);

const truncated = await call("/api/workspaces/ws-501/assets?limit=1");
equal("bound-exceeded route succeeds", truncated.status, 200);
equal(
  "bound-exceeded coverage reports returned rows",
  truncated.body.attack_surface_assurance_coverage?.returned,
  500,
);
equal(
  "bound-exceeded coverage reports total rows",
  truncated.body.attack_surface_assurance_coverage?.total,
  501,
);
equal(
  "bound-exceeded projection contains exactly the declared returned rows",
  truncated.body.attack_surface_assurance?.[0]?.lifecycle?.records?.length,
  500,
);
equal(
  "bound-exceeded coverage is explicitly truncated",
  truncated.body.attack_surface_assurance_coverage?.truncated,
  true,
);
equal(
  "bound-exceeded coverage status is truncated",
  truncated.body.attack_surface_assurance_coverage?.status,
  "truncated",
);
assert(
  "bound-exceeded wording states partial evidence",
  /500 of 501[\s\S]*partial[\s\S]*not presented as complete/i.test(
    truncated.body.attack_surface_assurance_coverage?.customer_message || "",
  ),
);

const detail = await call(
  "/api/workspaces/ws-238/assets/ws-238-asset-0237",
);
equal("asset detail route succeeds", detail.status, 200);
equal(
  "asset detail keeps one asset-scoped lifecycle record",
  detail.body.attack_surface_assurance?.lifecycle?.records?.length,
  1,
);
equal(
  "asset detail keeps confirmed_removed state",
  detail.body.attack_surface_assurance?.lifecycle?.records?.[0]
    ?.lifecycle_state,
  "confirmed_removed",
);
equal(
  "asset detail legacy nested alias matches top-level projection",
  JSON.stringify(detail.body.asset?.attack_surface_assurance),
  JSON.stringify(detail.body.attack_surface_assurance),
);
assert(
  "workspace responses remain tenant isolated",
  !JSON.stringify({
    limitOne: limitOne.body,
    feed: feed.body,
    detail: detail.body,
  }).includes("ws-foreign"),
);

console.log(
  `Item 10 P5 pagination corrective: ${assertionsPassed}/${EXPECTED_ASSERTIONS} assertions passed`,
);
console.log(
  `Item 10 P5 238-asset response bytes: before=${beforeBytes}; after=${afterBytes}; single_projection=${singleProjectionBytes}`,
);
if (
  assertionsPassed !== EXPECTED_ASSERTIONS ||
  assertionFailures > 0
) process.exit(1);

db.close();
