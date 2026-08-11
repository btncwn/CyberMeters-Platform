#!/usr/bin/env node
// Identity U1 + B4 semantic gate. Every fixture is named by the accepted V3
// contract and runs against production SQL/functions or an explicit source
// invariant. The unchanged parent is expected to fail semantically, while the
// green controls prove the harness itself is live.

import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { upsertIdentityAssets } from "../workers/scan-api/src/engines/asset-persistence.js";
import * as contract from "../workers/scan-api/src/engines/identity-evidence-contract.js";
import {
  listRelatedChanges, getRelatedChange, correlateRelatedChanges, computeClusterKey,
} from "../workers/scan-api/src/engines/related-changes.js";
import { collectChangeEvents } from "../workers/scan-api/src/engines/related-changes-adapter.js";
import { clusterToApi } from "../workers/scan-api/src/routes/related-changes.js";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const NOW = "2026-08-11T10:00:00.000Z";
const LATER = "2026-08-11T11:00:00.000Z";

function makeD1(db, metrics = { prepares: 0, runs: [] }, onPrepare = null) {
  const wrapped = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      metrics.runs.push({ sql, args, changes: Number(result.changes) });
      return { success: true, meta: { changes: Number(result.changes) } };
    },
  });
  return {
    metrics,
    prepare(sql) {
      metrics.prepares += 1;
      onPrepare?.(sql, db);
      const statement = wrapped(sql, []);
      statement.bind = (...args) => wrapped(sql, args);
      return statement;
    },
    batch: async (items) => Promise.all(items.map((item) => item.all())),
  };
}

function fixtureDb(onPrepare = null) {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, name TEXT, deleted_at TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT NOT NULL, domain_id TEXT NOT NULL);
    CREATE TABLE identity_assets (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, domain_id TEXT NOT NULL,
      scan_id TEXT, hostname TEXT, asset_type TEXT, identity_type TEXT,
      provider TEXT, internet_exposed INTEGER, source TEXT, risk_score INTEGER,
      evidence TEXT, first_seen TEXT, last_seen TEXT, status TEXT,
      created_at TEXT, updated_at TEXT
    );
    CREATE INDEX idx_identity_assets_workspace ON identity_assets(workspace_id,status);
    CREATE INDEX idx_identity_assets_provider ON identity_assets(workspace_id,provider);
    CREATE INDEX idx_identity_assets_hostname ON identity_assets(workspace_id,hostname,identity_type);
    CREATE TABLE workspace_vendors (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, vendor_name TEXT NOT NULL,
      category TEXT NOT NULL, source TEXT, evidence TEXT, confidence,
      risk_level TEXT, first_seen TEXT, last_seen TEXT, status TEXT,
      source_module TEXT, created_at TEXT, updated_at TEXT,
      UNIQUE(workspace_id,vendor_name,category)
    );
    CREATE TABLE related_changes (
      id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, cluster_key TEXT,
      registrable_domain TEXT,
      rule_id TEXT, direction TEXT, signal_family_count INTEGER,
      independent_producer_count INTEGER, confidence TEXT, completeness TEXT,
      customer_state TEXT, first_seen TEXT, last_seen TEXT,
      recurrence_count INTEGER, last_scan_id TEXT, linked_case_id TEXT,
      created_at TEXT, updated_at TEXT,
      UNIQUE(workspace_id,cluster_key)
    );
    CREATE TABLE related_change_evidence (
      id TEXT PRIMARY KEY, related_change_id TEXT, workspace_id TEXT,
      producer_family TEXT, source_table TEXT, source_record_id TEXT,
      source_event_type TEXT, entity_key TEXT, observed_at TEXT,
      evidence_ref TEXT, scan_id TEXT, created_at TEXT,
      UNIQUE(related_change_id,source_table,source_record_id,source_event_type,entity_key)
    );
    CREATE TABLE scans (
      id TEXT PRIMARY KEY, workspace_id TEXT, domain_id TEXT, status TEXT,
      scan_quality TEXT, created_at TEXT
    );
    CREATE TABLE asset_events (
      id TEXT PRIMARY KEY, workspace_id TEXT, event_type TEXT, hostname TEXT, created_at TEXT
    );
    CREATE TABLE audit_events (id TEXT PRIMARY KEY, workspace_id TEXT, created_at TEXT);
    CREATE TABLE notification_events (id TEXT PRIMARY KEY, workspace_id TEXT, created_at TEXT);
    INSERT INTO workspaces(id,name,deleted_at) VALUES
      ('ws-a','A',NULL),('ws-b','B',NULL),('ws-deleted','Deleted','2026-08-11T09:00:00Z');
    INSERT INTO workspace_domains(workspace_id,domain_id) VALUES
      ('ws-a','d-a'),('ws-a','d-b'),('ws-b','d-a'),
      ('ws-deleted','d-a'),('ws-deleted','d-deleted');
  `);
  const metrics = { prepares: 0, runs: [] };
  return { db, metrics, env: { cybermeters_db: makeD1(db, metrics, onPrepare) } };
}

function identityModule({ hostname = null, provider = null, type = "login_portal", risk = 10, evidence = "new" } = {}) {
  const row = {
    asset_type: provider && !hostname ? "provider" : "portal",
    identity_type: type, provider, hostname, internet_exposed: true,
    source: provider ? "identity_discovery" : "hostname_pattern", risk_score: risk,
    confidence: 80, evidence: [{ source: "legacy", detail: evidence }],
  };
  return { detected: true, providers: provider && !hostname ? [row] : [], portals: provider && !hostname ? [] : [row] };
}

function seedIdentity(db, {
  id, ws = "ws-a", domain = "d-a", hostname = null, provider = null,
  type = "login_portal", first = NOW, last = NOW, risk = 10,
  evidence = `["${id}"]`, scan = "scan-old", created = first, updated = last,
  internet = 1,
} = {}) {
  db.prepare(`INSERT INTO identity_assets
    (id,workspace_id,domain_id,scan_id,hostname,asset_type,identity_type,provider,
     internet_exposed,source,risk_score,evidence,first_seen,last_seen,status,created_at,updated_at)
    VALUES (?,?,?,?,?,'portal',?,?,?,'identity_discovery',?,?,?,?,'active',?,?)`)
    .run(id, ws, domain, scan, hostname, type, provider, internet, risk, evidence, first, last, created, updated);
}

function bytes(db, id) {
  return JSON.stringify(db.prepare("SELECT * FROM identity_assets WHERE id=?").get(id));
}

async function repeatedWrite(domain, mod, count = 5, setup = null) {
  const fx = fixtureDb();
  if (setup) setup(fx);
  for (let i = 0; i < count; i += 1) await upsertIdentityAssets(domain, `scan-${i}`, mod, fx.env);
  return fx;
}

function canonicalRows(db, query, binds) {
  if (typeof query !== "string") return null;
  return db.prepare(query).all(...binds);
}

async function seedExistingIdentityCorrelation(fx) {
  const observedAt = "2026-08-11T11:00:00.000Z";
  const previousAt = "2026-08-11T10:00:00.000Z";
  const clusterKey = await computeClusterKey("example.com", "identity_with_cert");
  seedIdentity(fx.db, {
    id: "identity-existing", hostname: "login.example.com",
    first: observedAt, last: observedAt, created: observedAt, updated: observedAt,
  });
  fx.db.prepare("INSERT INTO scans(id,workspace_id,domain_id,status,scan_quality,created_at) VALUES(?,?,?,?,?,?)")
    .run("scan-1", "ws-a", "d-a", "completed", "complete", previousAt);
  fx.db.prepare("INSERT INTO asset_events(id,workspace_id,event_type,hostname,created_at) VALUES(?,?,?,?,?)")
    .run("cert-existing", "ws-a", "certificate_new_detected", "login.example.com", observedAt);
  fx.db.prepare(`INSERT INTO related_changes
    (id,workspace_id,cluster_key,registrable_domain,rule_id,direction,
     signal_family_count,independent_producer_count,confidence,completeness,
     customer_state,first_seen,last_seen,recurrence_count,last_scan_id,created_at,updated_at)
    VALUES(?,?,?,?,?,'appeared',2,2,'correlated','complete','new',?,?,1,?,?,?)`)
    .run("rc-existing", "ws-a", clusterKey, "example.com", "identity_with_cert",
      previousAt, previousAt, "scan-1", previousAt, previousAt);
  fx.db.prepare(`INSERT INTO related_change_evidence
    (id,related_change_id,workspace_id,producer_family,source_table,source_record_id,
     source_event_type,entity_key,observed_at,evidence_ref,scan_id,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run("rce-identity-existing", "rc-existing", "ws-a", "identity", "identity_assets",
      "identity-existing", "identity_surface_observed", "host:login.example.com",
      observedAt, "identity-existing", "scan-1", observedAt);
  fx.db.prepare(`INSERT INTO related_change_evidence
    (id,related_change_id,workspace_id,producer_family,source_table,source_record_id,
     source_event_type,entity_key,observed_at,evidence_ref,scan_id,created_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run("rce-cert-existing", "rc-existing", "ws-a", "cert", "asset_events",
      "cert-existing", "certificate_new_detected", "host:login.example.com",
      observedAt, "cert-existing", "scan-1", observedAt);
}

async function correlateFixtureScan(fx, scanId, assessedAt) {
  const result = await correlateRelatedChanges(fx.env, {
    workspaceId: "ws-a", domainId: "d-a", scanId,
    scanQuality: "complete", assessedAt,
  });
  fx.db.prepare("INSERT INTO scans(id,workspace_id,domain_id,status,scan_quality,created_at) VALUES(?,?,?,?,?,?)")
    .run(scanId, "ws-a", "d-a", "completed", "complete", assessedAt);
  return result;
}

function recurrenceState(db) {
  const cluster = db.prepare("SELECT * FROM related_changes WHERE id='rc-existing'").get();
  const evidence = db.prepare("SELECT * FROM related_change_evidence WHERE related_change_id='rc-existing' ORDER BY id").all();
  return { cluster, evidence };
}

function rawIdentityConsumerFiles() {
  const root = path.join(ROOT, "workers", "scan-api", "src");
  const found = [];
  const visit = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (entry.isFile() && entry.name.endsWith(".js") &&
        /(?:FROM|JOIN|UPDATE|INTO)\s+identity_assets/i.test(fs.readFileSync(absolute, "utf8"))) {
        found.push(path.relative(ROOT, absolute).replaceAll(path.sep, "/"));
      }
    }
  };
  visit(root);
  return found.sort();
}

const source = (relative) => fs.readFileSync(path.join(ROOT, relative), "utf8");
const writerSource = () => source("workers/scan-api/src/engines/asset-persistence.js");

const FIXTURES = [
  { id: "U1-W01", run: async () => { const fx = await repeatedWrite("d-a", identityModule({ provider: "Okta" })); const rows = fx.db.prepare("SELECT * FROM identity_assets WHERE workspace_id='ws-a' AND domain_id='d-a'").all(); return rows.length === 1 && rows[0].first_seen === rows[0].created_at && rows[0].scan_id === "scan-4"; } },
  { id: "U1-W02", run: async () => { const fx = await repeatedWrite("d-a", identityModule({ hostname: "login.example" })); return fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-a' AND domain_id='d-a'").get().n === 1; } },
  { id: "U1-W03", run: async () => { const fx = fixtureDb(); await Promise.all(Array.from({ length: 8 }, (_, i) => upsertIdentityAssets("d-a", `race-${i}`, identityModule({ provider: "Auth0" }), fx.env))); return fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-a' AND domain_id='d-a'").get().n === 1; } },
  { id: "U1-W04", run: async () => { const insertFx=fixtureDb(); seedIdentity(insertFx.db,{id:"domain-a-existing",domain:"d-a",provider:"Entra",type:"login_portal",first:"2026-01-01T00:00:00Z",created:"2026-01-01T00:00:00Z"}); await upsertIdentityAssets("d-b","domain-b-insert",identityModule({provider:"Entra",risk:20}),insertFx.env); const insertRows=canonicalRows(insertFx.db,contract.IDENTITY_CANONICAL_LIST_QUERY,["ws-a",200]); const insertArm=insertFx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-a'").get().n===2 && insertRows?.length===2; const updateFx=fixtureDb(); seedIdentity(updateFx.db,{id:"domain-a-old",domain:"d-a",provider:"Entra",type:"login_portal",first:"2026-01-01T00:00:00Z",created:"2026-01-01T00:00:00Z",scan:"scan-a",risk:10}); seedIdentity(updateFx.db,{id:"domain-b-newer",domain:"d-b",provider:"Entra",type:"login_portal",first:"2026-02-01T00:00:00Z",created:"2026-02-01T00:00:00Z",scan:"scan-b",risk:20}); const aBefore=bytes(updateFx.db,"domain-a-old"); await upsertIdentityAssets("d-b","domain-b-refresh",identityModule({provider:"Entra",risk:30}),updateFx.env); const b=updateFx.db.prepare("SELECT * FROM identity_assets WHERE id='domain-b-newer'").get(); return insertArm && bytes(updateFx.db,"domain-a-old")===aBefore && b?.scan_id==="domain-b-refresh" && b?.risk_score===30; } },
  { id: "U1-W05", run: async () => { const fx = await repeatedWrite("d-a", identityModule({ provider: "Okta", hostname: null })); const r = fx.db.prepare("SELECT * FROM identity_assets WHERE workspace_id='ws-a'").all(); return r.length === 1 && r[0].hostname === null; } },
  { id: "U1-W06", run: async () => { const fx = await repeatedWrite("d-a", identityModule({ hostname: "vpn.example", provider: null })); const r = fx.db.prepare("SELECT * FROM identity_assets WHERE workspace_id='ws-a'").all(); return r.length === 1 && r[0].provider === null; } },
  { id: "U1-W07", run: async () => { const fx = await repeatedWrite("d-a", identityModule({ hostname: null, provider: null })); return fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-a'").get().n === 1; } },
  { id: "U1-W08", run: async () => { const fx = fixtureDb(); for (const id of ["z-legacy","y-legacy","x-legacy","w-legacy","v-legacy","b-legacy","a-legacy"]) seedIdentity(fx.db,{id,first:NOW,created:NOW}); const nonrep = bytes(fx.db,"z-legacy"); await upsertIdentityAssets("d-a","new-scan",identityModule({}),fx.env); const rows=fx.db.prepare("SELECT * FROM identity_assets WHERE workspace_id='ws-a'").all(); return rows.length===7 && fx.db.prepare("SELECT scan_id FROM identity_assets WHERE id='a-legacy'").get()?.scan_id==="new-scan" && bytes(fx.db,"z-legacy")===nonrep; } },
  // Accepted unchanged-parent green control: reading historical bytes is inert.
  { id: "U1-W09", control: true, run: async () => { const fx=fixtureDb(); seedIdentity(fx.db,{id:"z-history",evidence:'{\"legacy\":true}',first:NOW,created:NOW}); seedIdentity(fx.db,{id:"a-history",evidence:'{\"canonical\":true}',first:NOW,created:NOW}); const before=bytes(fx.db,"z-history"); await upsertIdentityAssets("d-a","history-refresh",identityModule({}),fx.env); const rows=canonicalRows(fx.db,contract.IDENTITY_CANONICAL_LIST_QUERY,["ws-a",200]); return rows?.[0]?.id==="a-history" && fx.db.prepare("SELECT scan_id FROM identity_assets WHERE id='a-history'").get()?.scan_id==="history-refresh" && bytes(fx.db,"z-history")===before; } },
  { id: "U1-SD01", run: async () => { const fx=fixtureDb(); fx.db.prepare("INSERT INTO workspace_domains(workspace_id,domain_id) VALUES('ws-a','d-deleted')").run(); await upsertIdentityAssets("d-deleted","s",identityModule({provider:"Okta"}),fx.env); const assetRuns=fx.metrics.runs.filter((r)=>/INSERT INTO identity_assets/.test(r.sql)); const vendorRuns=fx.metrics.runs.filter((r)=>/INSERT OR IGNORE INTO workspace_vendors/.test(r.sql)); return fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-deleted'").get().n===0 && fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-a'").get().n===1 && fx.db.prepare("SELECT COUNT(*) n FROM workspace_vendors WHERE workspace_id='ws-deleted'").get().n===0 && fx.db.prepare("SELECT COUNT(*) n FROM workspace_vendors WHERE workspace_id='ws-a'").get().n===1 && assetRuns.length===1 && assetRuns[0].changes===1 && vendorRuns.length===1 && vendorRuns[0].changes===1; } },
  { id: "U1-SD02", run: async () => { let fired=false; const fx=fixtureDb((sql,db)=>{ if(!fired && /INSERT INTO identity_assets/.test(sql)){ fired=true; db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws-a'").run(NOW); } }); await upsertIdentityAssets("d-a","s",identityModule({provider:"Okta"}),fx.env); const insertChanges=fx.metrics.runs.filter((r)=>/INSERT INTO identity_assets/.test(r.sql)).map((r)=>r.changes).sort(); const insertArm=fired && fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-a'").get().n===0 && fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-b'").get().n===1 && JSON.stringify(insertChanges)===JSON.stringify([0,1]); let updateFired=false; const updateFx=fixtureDb((sql,db)=>{ if(!updateFired && /INSERT INTO identity_assets/.test(sql)){ updateFired=true; db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws-a'").run(NOW); } }); seedIdentity(updateFx.db,{id:"existing-update",provider:"Okta",type:"login_portal",evidence:"old-evidence",scan:"old-scan"}); const before=bytes(updateFx.db,"existing-update"); await upsertIdentityAssets("d-a","new-scan",identityModule({provider:"Okta"}),updateFx.env); const updateChanges=updateFx.metrics.runs.filter((r)=>/UPDATE identity_assets/.test(r.sql)).map((r)=>r.changes).sort(); const updateArm=updateFired && bytes(updateFx.db,"existing-update")===before && updateFx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-b'").get().n===1 && JSON.stringify(updateChanges)===JSON.stringify([0,1]); return insertArm && updateArm; } },
  { id: "U1-SD03", run: async () => { let fired=false; const fx=fixtureDb((sql,db)=>{ if(!fired && /INSERT OR IGNORE INTO workspace_vendors/.test(sql)){ fired=true; db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws-a'").run(NOW); } }); await upsertIdentityAssets("d-a","s",identityModule({provider:"Okta"}),fx.env); const vendorInsertChanges=fx.metrics.runs.filter((r)=>/INSERT OR IGNORE INTO workspace_vendors/.test(r.sql)).map((r)=>r.changes).sort(); const insertArm=fired && fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-a'").get().n===1 && fx.db.prepare("SELECT COUNT(*) n FROM workspace_vendors WHERE workspace_id='ws-a'").get().n===0 && fx.db.prepare("SELECT COUNT(*) n FROM workspace_vendors WHERE workspace_id='ws-b'").get().n===1 && JSON.stringify(vendorInsertChanges)===JSON.stringify([0,1]); let updateFired=false; const updateFx=fixtureDb((sql,db)=>{ if(!updateFired && /INSERT OR IGNORE INTO workspace_vendors/.test(sql)){ updateFired=true; db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws-a'").run(NOW); } }); updateFx.db.prepare(`INSERT INTO workspace_vendors(id,workspace_id,vendor_name,category,evidence,confidence,risk_level,first_seen,last_seen,status,source_module,created_at,updated_at) VALUES('vendor-old','ws-a','Okta','identity_provider','old',10,'low',?,?, 'active','identity_discovery',?,?)`).run(NOW,NOW,NOW,NOW); const before=JSON.stringify(updateFx.db.prepare("SELECT * FROM workspace_vendors WHERE id='vendor-old'").get()); await upsertIdentityAssets("d-a","s",identityModule({provider:"Okta"}),updateFx.env); const vendorUpdateChanges=updateFx.metrics.runs.filter((r)=>/UPDATE workspace_vendors/.test(r.sql)).map((r)=>r.changes).sort(); const updateArm=updateFired && JSON.stringify(updateFx.db.prepare("SELECT * FROM workspace_vendors WHERE id='vendor-old'").get())===before && updateFx.db.prepare("SELECT COUNT(*) n FROM workspace_vendors WHERE workspace_id='ws-b'").get().n===1 && JSON.stringify(vendorUpdateChanges)===JSON.stringify([0,1]); return insertArm && updateArm; } },
  { id: "U1-SD04", run: async () => { const fx=fixtureDb(); await upsertIdentityAssets("d-a","s",identityModule({hostname:"login.same"}),fx.env); const assetRuns=fx.metrics.runs.filter((r)=>/INSERT INTO identity_assets/.test(r.sql)); return fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-deleted'").get().n===0 && fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-a'").get().n===1 && fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-b'").get().n===1 && assetRuns.length===2 && assetRuns.every((r)=>r.changes===1); } },
  { id: "U1-SD05", control: true, run: async () => { const fx=fixtureDb(); await upsertIdentityAssets("d-a","s",identityModule({provider:"Okta"}),fx.env); return fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-a'").get().n===1 && fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-b'").get().n===1; } },
  { id: "U1-C01", run: () => { const fx=fixtureDb(); seedIdentity(fx.db,{id:"c1",hostname:"ab",provider:"c"}); seedIdentity(fx.db,{id:"c2",hostname:"a",provider:"bc"}); const rows=canonicalRows(fx.db,contract.IDENTITY_CANONICAL_LIST_QUERY,["ws-a",200]); const total=canonicalRows(fx.db,contract.IDENTITY_CANONICAL_SUMMARY_TOTAL_QUERY,["ws-a"]); return rows?.length===2 && total?.[0]?.n===2; } },
  { id: "U1-C02", run: async () => { const fx=fixtureDb(); seedIdentity(fx.db,{id:"z",first:NOW,created:NOW}); seedIdentity(fx.db,{id:"a",first:NOW,created:NOW}); const zBefore=bytes(fx.db,"z"); await upsertIdentityAssets("d-a","tie-refresh",identityModule({evidence:"refresh"}),fx.env); const rows=canonicalRows(fx.db,contract.IDENTITY_CANONICAL_LIST_QUERY,["ws-a",200]); return rows?.length===1 && rows[0].id==="a" && fx.db.prepare("SELECT scan_id FROM identity_assets WHERE id='a'").get()?.scan_id==="tie-refresh" && bytes(fx.db,"z")===zBefore; } },
  { id: "U1-C03", run: () => { const fx=fixtureDb(); seedIdentity(fx.db,{id:"a",updated:NOW,last:NOW,scan:"s1"}); seedIdentity(fx.db,{id:"z",updated:NOW,last:NOW,scan:"s1"}); const rows=canonicalRows(fx.db,contract.IDENTITY_CANONICAL_LIST_QUERY,["ws-a",200]); return rows?.length===1 && rows[0].scan_id==="s1" && rows[0].evidence==='[\"z\"]'; } },
  { id: "U1-C04", run: () => { if(typeof contract.IDENTITY_CANONICAL_LIST_QUERY!=="string") return false; const fx=fixtureDb(); seedIdentity(fx.db,{id:"a",internet:0}); seedIdentity(fx.db,{id:"m"}); seedIdentity(fx.db,{id:"z"}); seedIdentity(fx.db,{id:"empty-a",hostname:null,provider:"Empty"}); seedIdentity(fx.db,{id:"empty-b",hostname:"",provider:"Empty"}); const before=canonicalRows(fx.db,contract.IDENTITY_CANONICAL_LIST_QUERY,["ws-a",200]); fx.db.exec("DROP INDEX idx_identity_assets_workspace; DROP INDEX idx_identity_assets_provider; DROP INDEX idx_identity_assets_hostname;"); const after=canonicalRows(fx.db,contract.IDENTITY_CANONICAL_LIST_QUERY,["ws-a",200]); const primary=before?.find((row)=>row.provider===null); const normalized=before?.find((row)=>row.provider==="Empty"); return before?.length===2 && primary?.id==="a" && primary.evidence==='[\"z\"]' && primary.internet_exposed===0 && primary.historical_row_count===3 && normalized?.hostname===null && normalized.historical_row_count===2 && JSON.stringify(before)===JSON.stringify(after); } },
  { id: "U1-C05", run: () => { if(typeof contract.IDENTITY_CANONICAL_LIST_QUERY!=="string") return false; const fx=fixtureDb(); const ids=Array.from({length:20},(_,i)=>String.fromCharCode(97+i)); for(const id of ids) seedIdentity(fx.db,{id}); const values=Array.from({length:20},()=>JSON.stringify(canonicalRows(fx.db,contract.IDENTITY_CANONICAL_LIST_QUERY,["ws-a",200]))); const row=JSON.parse(values[0])?.[0]; return row?.id==="a" && row?.evidence==='[\"t\"]' && new Set(values).size===1; } },
  ...[
    ["U1-CONS01","IDENTITY_CANONICAL_SUMMARY_TOTAL_QUERY",1],
    ["U1-CONS02","IDENTITY_CANONICAL_SUMMARY_TYPE_QUERY",1],
    ["U1-CONS03","IDENTITY_CANONICAL_SUMMARY_PROVIDER_QUERY",1],
    ["U1-CONS04","IDENTITY_CANONICAL_SUMMARY_HIGH_RISK_QUERY",1],
    ["U1-CONS05","IDENTITY_CANONICAL_LIST_QUERY",1],
    ["U1-CONS06","IDENTITY_CANONICAL_EXPOSURE_QUERY",1],
    ["U1-CONS07","IDENTITY_CANONICAL_SHADOW_QUERY",1],
    ["U1-CONS08","IDENTITY_CANONICAL_LIFECYCLE_QUERY",1],
    ["U1-CONS09","IDENTITY_CANONICAL_RELATED_CHANGES_QUERY",1],
  ].map(([id,key]) => ({ id, run: () => { const fx=fixtureDb(); const duplicateCount=id==="U1-CONS06"?125:7; for(let i=0;i<duplicateCount;i++) seedIdentity(fx.db,{id:`${id}-${String(i).padStart(3,"0")}`,provider:"Okta",hostname:"login.example",risk:i===duplicateCount-1?40:20,first:"2026-08-02T00:00:00Z",last:"2026-08-02T01:00:00Z"}); seedIdentity(fx.db,{id:`${id}-domain-b`,domain:"d-b",provider:"Okta",hostname:"login.example",risk:30,first:"2026-08-02T00:00:00Z",last:"2026-08-02T01:00:00Z"}); const q=contract[key]; if(typeof q!=="string") return false; const bindCount=(q.match(/\?/g)||[]).length; const args=Array.from({length:bindCount},(_,i)=>i===0?"ws-a":key.includes("RELATED")?(i===1?"2026-08-01T00:00:00Z":"2026-08-31T00:00:00Z"):200); const rows=fx.db.prepare(q).all(...args); if(key.includes("TOTAL")||key.includes("HIGH_RISK")) return rows[0]?.n===2; if(key.includes("TYPE")||key.includes("PROVIDER")) return rows[0]?.n===2; if(key.includes("RELATED")) return rows.length===2 && new Set(rows.map((row)=>row.id)).size===2; return rows.length===2 && Math.max(...rows.map((row)=>row.risk_score??0))===40; } })),
  { id: "U1-B4-01", run: async () => { const fx=fixtureDb(); await seedExistingIdentityCorrelation(fx); const evidenceBefore=JSON.stringify(recurrenceState(fx.db).evidence); for(const [scanId,assessedAt] of [["scan-2","2026-08-11T11:00:00.000Z"],["scan-3","2026-08-11T12:00:00.000Z"],["scan-4","2026-08-11T13:00:00.000Z"],["scan-5","2026-08-11T14:00:00.000Z"],["scan-6","2026-08-11T15:00:00.000Z"]]) { await upsertIdentityAssets("d-a",scanId,identityModule({hostname:"login.example.com"}),fx.env); await correlateFixtureScan(fx,scanId,assessedAt); } const state=recurrenceState(fx.db); const physical=fx.db.prepare("SELECT * FROM identity_assets WHERE workspace_id='ws-a' AND domain_id='d-a' AND hostname='login.example.com'").all(); const legacy=fixtureDb(); for(let i=0;i<5;i++) seedIdentity(legacy.db,{id:`legacy-b4-${i}`,hostname:"legacy.b4.example",first:NOW,created:NOW}); const events=await collectChangeEvents(legacy.env,{workspaceId:"ws-a",windowStart:"2026-01-01T00:00:00Z",windowEnd:"2030-01-01T00:00:00Z"}); const identityIds=events.filter((e)=>e.producer_family==="identity").map((e)=>e.source_record_id); return physical.length===1 && physical[0].id==="identity-existing" && physical[0].first_seen==="2026-08-11T11:00:00.000Z" && state.cluster?.recurrence_count===1 && state.cluster?.last_scan_id==="scan-1" && state.evidence.length===2 && JSON.stringify(state.evidence)===evidenceBefore && identityIds.length===1 && identityIds[0]==="legacy-b4-0"; } },
  { id: "U1-B4-02", run: async () => { const fx=fixtureDb(); await seedExistingIdentityCorrelation(fx); seedIdentity(fx.db,{id:"identity-new",hostname:"admin.example.com",first:"2026-08-11T11:00:00.000Z",last:"2026-08-11T11:00:00.000Z"}); await correlateFixtureScan(fx,"scan-2","2026-08-11T11:00:00.000Z"); const state=recurrenceState(fx.db); const identityPointers=state.evidence.filter((row)=>row.source_table==="identity_assets"); return state.cluster?.recurrence_count===2 && state.cluster?.last_scan_id==="scan-2" && state.evidence.length===3 && identityPointers.length===2 && identityPointers.some((row)=>row.source_record_id==="identity-new"); } },
  { id: "U1-B4-03", run: async () => { const fx=fixtureDb(); seedIdentity(fx.db,{id:"polluted-a",hostname:"polluted.example"}); seedIdentity(fx.db,{id:"polluted-b",hostname:"polluted.example"}); fx.db.prepare("INSERT INTO related_changes(id,workspace_id,recurrence_count,last_seen) VALUES('rc-polluted','ws-a',7,?)").run(NOW); for(const id of ["polluted-a","polluted-b"]) fx.db.prepare("INSERT INTO related_change_evidence(id,related_change_id,workspace_id,source_table,source_record_id,source_event_type,entity_key) VALUES(?,?,?,?,?,?,?)").run(`ep-${id}`,"rc-polluted","ws-a","identity_assets",id,"identity_surface_observed","host:polluted.example"); const row=(await listRelatedChanges(fx.env,"ws-a"))[0]; const p=contract.projectRelatedChangeRecurrence?.(row); const api=clusterToApi(row); return p?.status==="not_comparable" && p.count===null && p.reason==="legacy_identity_multiplicity" && api.recurrence?.status==="not_comparable" && api.recurrence_count===7; } },
  { id: "U1-B4-04", run: async () => { const fx=fixtureDb(); seedIdentity(fx.db,{id:"pointed",hostname:"single-pointer.example"}); seedIdentity(fx.db,{id:"unpointed-legacy",hostname:"single-pointer.example"}); fx.db.prepare("INSERT INTO related_changes(id,workspace_id,recurrence_count,last_seen) VALUES('rc-comparable','ws-a',3,?)").run(NOW); fx.db.prepare("INSERT INTO related_change_evidence(id,related_change_id,workspace_id,source_table,source_record_id,source_event_type,entity_key) VALUES('ep','rc-comparable','ws-a','identity_assets','pointed','identity_surface_observed','host:single-pointer.example')").run(); const row=(await listRelatedChanges(fx.env,"ws-a"))[0]; const p=contract.projectRelatedChangeRecurrence?.(row); const api=clusterToApi(row); return p?.status==="comparable" && p.count===3 && p.reason===null && api.recurrence?.status==="comparable" && api.recurrence.count===3; } },
  { id: "U1-B4-05", run: async () => { const fx=fixtureDb(); fx.db.prepare("INSERT INTO related_changes(id,workspace_id,recurrence_count,last_seen) VALUES('rc-unresolved','ws-a',9,?)").run(NOW); fx.db.prepare("INSERT INTO related_change_evidence(id,related_change_id,workspace_id,source_table,source_record_id,source_event_type,entity_key) VALUES('ep','rc-unresolved','ws-a','identity_assets','missing','identity_surface_observed','host:missing.example')").run(); const row=(await listRelatedChanges(fx.env,"ws-a"))[0]; const p=contract.projectRelatedChangeRecurrence?.(row); const api=clusterToApi(row); return p?.status==="unknown" && p.count===null && p.reason==="identity_evidence_unavailable" && api.recurrence?.status==="unknown" && api.recurrence_count===9; } },
  { id: "U1-B4-06", control: true, run: async () => { const fx=fixtureDb(); await seedExistingIdentityCorrelation(fx); const before=recurrenceState(fx.db); fx.metrics.runs.length=0; await correlateFixtureScan(fx,"scan-2","2026-08-11T11:00:00.000Z"); const after=recurrenceState(fx.db); const evidenceWrites=fx.metrics.runs.filter((row)=>/INSERT OR IGNORE INTO related_change_evidence/.test(row.sql)); return evidenceWrites.length===2 && evidenceWrites.every((row)=>row.changes===0) && after.cluster?.recurrence_count===before.cluster?.recurrence_count && after.cluster?.last_seen===before.cluster?.last_seen && after.cluster?.last_scan_id===before.cluster?.last_scan_id && JSON.stringify(after.evidence)===JSON.stringify(before.evidence) && fx.db.prepare("SELECT COUNT(*) n FROM audit_events").get().n===0 && fx.db.prepare("SELECT COUNT(*) n FROM notification_events").get().n===0; } },
  { id: "U1-B4-07", run: () => { const list=source("frontend/src/components/RelatedChangesList.jsx"); const detail=source("frontend/src/pages/ws/WorkspaceRelatedChangeDetailPage.jsx"); const route=source("workers/scan-api/src/routes/related-changes.js"); return /recurrenceCopy\(rc\.recurrence\)/.test(list) && /recurrenceCopy\(rc\.recurrence\)/.test(detail) && !/recurrenceCopy\(rc\.recurrence_count\)/.test(list+detail) && /recurrence:\s*projectRelatedChangeRecurrence\(row\)/.test(route) && /legacy_identity_multiplicity/.test(list+detail); } },
  { id: "U1-B4-08", run: () => { const list=source("frontend/src/components/RelatedChangesList.jsx"); const detail=source("frontend/src/pages/ws/WorkspaceRelatedChangeDetailPage.jsx"); return /recurrenceCopy\(rc\.recurrence\)/.test(list) && /recurrenceCopy\(rc\.recurrence\)/.test(detail) && /Recurrence unavailable/.test(list) && /Recurrence unavailable/.test(detail); } },
  { id: "U1-HIST01", control: true, run: async () => { const fx=fixtureDb(); seedIdentity(fx.db,{id:"a-representative",evidence:"representative-before",first:NOW,created:NOW}); seedIdentity(fx.db,{id:"z-history",evidence:"historical-byte-string",first:NOW,created:NOW}); fx.db.prepare(`INSERT INTO related_changes(id,workspace_id,recurrence_count) VALUES('rc','ws-a',9)`).run(); fx.db.prepare(`INSERT INTO related_change_evidence(id,related_change_id,workspace_id,source_table,source_record_id,source_event_type,entity_key) VALUES('e','rc','ws-a','identity_assets','z-history','identity_surface_observed','host:history.example')`).run(); const nonRepresentativeBefore=bytes(fx.db,"z-history"), evidenceBefore=JSON.stringify(fx.db.prepare("SELECT * FROM related_change_evidence").all()), clusterBefore=JSON.stringify(fx.db.prepare("SELECT * FROM related_changes").all()); await upsertIdentityAssets("d-a","history-refresh",identityModule({evidence:"refreshed"}),fx.env); return bytes(fx.db,"z-history")===nonRepresentativeBefore && evidenceBefore===JSON.stringify(fx.db.prepare("SELECT * FROM related_change_evidence").all()) && clusterBefore===JSON.stringify(fx.db.prepare("SELECT * FROM related_changes").all()) && fx.db.prepare("SELECT first_seen FROM identity_assets WHERE id='a-representative'").get()?.first_seen===NOW; } },
  { id: "U1-IC1", control: true, run: async () => { const fx=fixtureDb(); await seedExistingIdentityCorrelation(fx); await correlateFixtureScan(fx,"scan-2","2026-08-11T11:00:00.000Z"); const state=recurrenceState(fx.db); const identityPointers=state.evidence.filter((row)=>row.source_table==="identity_assets"); return identityPointers.length===1 && identityPointers[0].source_event_type==="identity_surface_observed" && state.evidence.length===2 && state.cluster?.recurrence_count===1; } },
  { id: "U1-IC7", run: () => JSON.stringify(rawIdentityConsumerFiles())===JSON.stringify(["workers/scan-api/src/engines/asset-persistence.js","workers/scan-api/src/engines/identity-evidence-contract.js","workers/scan-api/src/engines/related-changes.js"]) && /raw-access allow-list[\s\S]*append-only[\s\S]*audit pointer resolution/i.test(source("workers/scan-api/src/engines/identity-evidence-contract.js")) },
  { id: "U1-IC8", run: async () => { const fx=fixtureDb(); for(let i=0;i<400;i++) seedIdentity(fx.db,{id:`perf-${i}`,hostname:"perf.example",provider:"Okta"}); fx.db.prepare("INSERT INTO related_changes(id,workspace_id,recurrence_count,last_seen) VALUES('rc','ws-a',5,?)").run(NOW); for(let i=0;i<100;i++) fx.db.prepare("INSERT INTO related_change_evidence(id,related_change_id,workspace_id,source_table,source_record_id,source_event_type) VALUES(?,?,?,?,?,?)").run(`e${i}`,"rc","ws-a","identity_assets",`perf-${i}`,"identity_surface_observed"); fx.metrics.prepares=0; const start=performance.now(); const list=await listRelatedChanges(fx.env,"ws-a"); const listQueries=fx.metrics.prepares; fx.metrics.prepares=0; const detail=await getRelatedChange(fx.env,"ws-a","rc"); const detailQueries=fx.metrics.prepares; const elapsed=performance.now()-start; return list.length===1 && list[0].recurrence?.status==="not_comparable" && detail?.cluster?.recurrence?.status==="not_comparable" && listQueries===1 && detailQueries===2 && elapsed<2000; } },
  { id: "U1-CONTRACT", run: () => JSON.stringify(contract.CANONICAL_IDENTITY_TUPLE_COLUMNS)===JSON.stringify(["workspace_id","domain_id","identity_type","IFNULL(hostname,'')","IFNULL(provider,'')"]) && /INSERT INTO identity_assets[\s\S]+SELECT[\s\S]+WHERE EXISTS[\s\S]+NOT EXISTS/.test(writerSource()) },
  { id: "U1-POS-DISTINCT-WRITE", control: true, run: async () => { const fx=fixtureDb(); await upsertIdentityAssets("d-a","positive",identityModule({provider:"Distinct IdP"}),fx.env); return fx.db.prepare("SELECT COUNT(*) n FROM identity_assets WHERE workspace_id='ws-a' AND domain_id='d-a'").get().n===1; } },
  { id: "U1-POS-UNIQUE", control: true, run: () => { const fx=fixtureDb(); seedIdentity(fx.db,{id:"unique",hostname:"unique.example",provider:"Okta",risk:20}); return contract.IDENTITY_CANONICAL_SUMMARY_TOTAL_QUERY && fx.db.prepare(contract.IDENTITY_CANONICAL_SUMMARY_TOTAL_QUERY).get("ws-a").n===1 && fx.db.prepare(contract.IDENTITY_CANONICAL_LIST_QUERY).all("ws-a",200).length===1 && fx.db.prepare(contract.IDENTITY_CANONICAL_EXPOSURE_QUERY).all("ws-a").length===1 && fx.db.prepare(contract.IDENTITY_CANONICAL_SHADOW_QUERY).all("ws-a").length===1 && fx.db.prepare(contract.IDENTITY_CANONICAL_LIFECYCLE_QUERY).all("ws-a").length===1 && fx.db.prepare(contract.IDENTITY_CANONICAL_RELATED_CHANGES_QUERY).all("ws-a","2026-01-01T00:00:00Z","2030-01-01T00:00:00Z").length===1; } },
  { id: "U1-POS-FORWARD-EVENT", control: true, run: async () => { const fx=fixtureDb(); seedIdentity(fx.db,{id:"forward",hostname:"forward.example"}); const rows=await collectChangeEvents(fx.env,{workspaceId:"ws-a",windowStart:"2026-01-01T00:00:00Z",windowEnd:"2030-01-01T00:00:00Z"}); return rows.filter((row)=>row.producer_family==="identity").length===1; } },
  { id: "U1-B4-POS", control: true, run: () => { const list=source("frontend/src/components/RelatedChangesList.jsx"); const detail=source("frontend/src/pages/ws/WorkspaceRelatedChangeDetailPage.jsx"); return /Seen \$\{recurrence\.count\} times/.test(list) && /Seen \$\{recurrence\.count\} times/.test(detail); } },
];

const fixtureArg = process.argv.find((arg) => arg.startsWith("--fixtures="));
const selectedIds = fixtureArg ? new Set(fixtureArg.slice("--fixtures=".length).split(",").filter(Boolean)) : null;
const SELECTED = selectedIds ? FIXTURES.filter((fixture) => selectedIds.has(fixture.id)) : FIXTURES;
if (selectedIds && SELECTED.length !== selectedIds.size) {
  console.error("HARNESS unknown fixture selection");
  process.exit(2);
}
let passed=0, failed=0;
for (const fixture of SELECTED) {
  let result=false;
  try { result=Boolean(await fixture.run()); } catch (error) { result=false; }
  if (result) { passed+=1; console.log(`PASS ${fixture.id}${fixture.control?" [control]":""}`); }
  else { failed+=1; console.error(`FAIL ${fixture.id}${fixture.control?" [control]":""}`); }
}
console.log(`identity U1+B4: ${passed}/${SELECTED.length} passed; ${failed} failed`);
if (failed) process.exit(1);
