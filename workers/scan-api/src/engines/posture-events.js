// ── Posture diff event engine ──
// Cross-scan Exposure Timeline events for email-auth posture and internet-exposed
// services. Reads the previous completed scan report from R2, compares it with
// the current in-memory modules, and writes asset_events. All failures are
// non-fatal so scan completion never depends on timeline event generation.
import { createId } from "../lib/util.js";
import { loadTimelineComparisonContext } from "./timeline-trust.js";
import { diffResolvedAuthorizations } from "./spf-resolver.js";

function normalizeValue(value) {
  return String(value ?? "").trim();
}

function boolState(value) {
  return typeof value === "boolean" ? value : null;
}

function policyValue(emailMod) {
  const policy = normalizeValue(emailMod?.dmarc?.policy).toLowerCase();
  if (policy) return policy;
  const present = boolState(emailMod?.dmarc?.present);
  if (present === false) return "absent";
  return "";
}

function dmarcSeverity(oldPolicy, newPolicy) {
  const strong = new Set(["reject", "quarantine"]);
  if ((strong.has(oldPolicy) && newPolicy === "none") || newPolicy === "absent") return "high";
  if (oldPolicy === "none" && strong.has(newPolicy)) return "low";
  return "medium";
}

function serviceKey(service) {
  const hostname = normalizeValue(service?.hostname).toLowerCase();
  const product = normalizeValue(service?.product).toLowerCase();
  if (!hostname || !product) return "";
  return `${hostname}::${product}`;
}

function serviceMap(adminModule) {
  const map = new Map();
  for (const service of adminModule?.services || []) {
    const key = serviceKey(service);
    if (key && !map.has(key)) map.set(key, service);
  }
  return map;
}

function pushEvent(events, { event_type, hostname, severity, description, evidence = undefined }) {
  const event = { event_type, hostname, severity, description };
  if (evidence !== undefined) event.evidence = evidence;
  events.push(event);
}

function spfEvidenceComplete(spf) {
  return spf?.resolution_status === "complete" && Array.isArray(spf?.resolved_pass_authorisations);
}

export function buildSpfDiffEvents(domain, prevModules, currentModules) {
  const events = [];
  const previousEmail = prevModules?.email_security || {};
  const currentEmail = currentModules?.email_security || {};
  const previousSpf = previousEmail?.spf;
  const currentSpf = currentEmail?.spf;

  if (!spfEvidenceComplete(previousSpf) || !spfEvidenceComplete(currentSpf)) {
    return events;
  }

  const prevSpfPresent = boolState(previousSpf?.present);
  const currSpfPresent = boolState(currentSpf?.present);
  const prevSpfRecord = normalizeValue(previousSpf?.record);
  const currSpfRecord = normalizeValue(currentSpf?.record);
  if (prevSpfPresent !== null && currSpfPresent !== null && prevSpfPresent !== currSpfPresent) {
    pushEvent(events, {
      event_type: "email_spf_changed",
      hostname: domain,
      severity: prevSpfPresent && !currSpfPresent ? "high" : "low",
      description: `SPF record changed for ${domain}`,
    });
  } else if (prevSpfRecord && currSpfRecord && prevSpfRecord !== currSpfRecord) {
    pushEvent(events, {
      event_type: "email_spf_changed",
      hostname: domain,
      severity: "medium",
      description: `SPF record changed for ${domain}`,
    });
  }

  // Resolved PASS-authorisation-set change (PR-A). Independent of the root-string
  // diff above: a provider adding IPs inside their own include:spf.provider.com
  // leaves the root record UNCHANGED, so email_spf_changed does not fire, but the
  // resolved set does. diffResolvedAuthorizations returns null (comparison NOT
  // performed) unless BOTH snapshots resolved to status "complete" — so a
  // temperror, partial resolution, permerror, or a legacy report without the
  // resolved fields can NEVER produce a false authorisation-change event.
  const spfDelta = diffResolvedAuthorizations(previousSpf, currentSpf);
  if (spfDelta && spfDelta.changed) {
    // Persist the CANONICAL added/removed CIDRs in the description (bounded so a
    // pathological record can never write an unbounded row) — asset_events has no
    // structured-evidence column, and the counts alone would lose the actual ranges.
    const cap = 12;
    const listOf = (arr) => arr.slice(0, cap).join(", ") + (arr.length > cap ? ` (+${arr.length - cap} more)` : "");
    const parts = [];
    if (spfDelta.added.length) parts.push(`added ${spfDelta.added.length} [${listOf(spfDelta.added)}]`);
    if (spfDelta.removed.length) parts.push(`removed ${spfDelta.removed.length} [${listOf(spfDelta.removed)}]`);
    pushEvent(events, {
      event_type: "email_spf_authorization_changed",
      hostname: domain,
      severity: spfDelta.added.length > 0 ? "medium" : "low",
      description: `SPF authorised sending sources changed for ${domain}: ${parts.join("; ")}`,
      evidence: { added: spfDelta.added, removed: spfDelta.removed },
    });
  }

  return events;
}

export function buildPostureDiffEvents(domain, prevModules, currentModules, opts = {}) {
  const events = [];
  if (opts.includeSpf !== false) {
    events.push(...buildSpfDiffEvents(domain, prevModules, currentModules));
  }
  if (opts.includeNonSpf === false) {
    return events;
  }

  const previousEmail = prevModules?.email_security || {};
  const currentEmail = currentModules?.email_security || {};

  // The coarse RFC-7489-era event remains readable for legacy reports, but a
  // scan carrying canonical DMARCbis evidence is owned by P4's immutable
  // snapshot comparison. Running both would duplicate one DNS observation in
  // Related Changes and, worse, the legacy projection cannot distinguish
  // absence from unavailable or exact policy from inheritance.
  const hasCanonicalDmarcbis =
    prevModules?.dmarc_core != null ||
    currentModules?.dmarc_core != null;
  if (!hasCanonicalDmarcbis) {
    const prevPolicy = policyValue(previousEmail);
    const currPolicy = policyValue(currentEmail);
    if (prevPolicy && currPolicy && prevPolicy !== currPolicy) {
      pushEvent(events, {
        event_type: "email_dmarc_policy_changed",
        hostname: domain,
        severity: dmarcSeverity(prevPolicy, currPolicy),
        description: `DMARC policy changed: ${prevPolicy} → ${currPolicy}`,
      });
    }
  }

  const prevDkimPresent = boolState(previousEmail?.dkim?.present);
  const currDkimPresent = boolState(currentEmail?.dkim?.present);
  if (prevDkimPresent !== null && currDkimPresent !== null && prevDkimPresent !== currDkimPresent) {
    pushEvent(events, {
      event_type: "email_dkim_changed",
      hostname: domain,
      severity: prevDkimPresent && !currDkimPresent ? "medium" : "low",
      description: `DKIM status changed for ${domain}`,
    });
  }

  const previousServices = serviceMap(prevModules?.admin_surface_detection);
  const currentServices = serviceMap(currentModules?.admin_surface_detection);
  for (const [key, service] of currentServices) {
    if (previousServices.has(key)) continue;
    pushEvent(events, {
      event_type: "exposed_service_detected",
      hostname: normalizeValue(service.hostname),
      severity: service.severity ?? service.risk_level ?? "high",
      description: `New internet-exposed service detected: ${service.product} on ${service.hostname}`,
    });
  }
  // A service's absence from the current scan only proves RESOLUTION when the current
  // admin-surface assessment actually COMPLETED with zero verified surfaces
  // (evidence_status === "assessed_healthy", the A3 canonical complete-success state).
  // unavailable / not_assessed / missing module / legacy report / failed-or-incomplete
  // probe must NEVER emit a false "resolved" — fail neutral, preserve uncertainty. A
  // current verified issue (issue_detected) also does not clear a prior exposure here.
  const currentAdminAssessedHealthy =
    currentModules?.admin_surface_detection?.evidence_status === "assessed_healthy";
  if (currentAdminAssessedHealthy) {
    for (const [key, service] of previousServices) {
      if (currentServices.has(key)) continue;
      pushEvent(events, {
        event_type: "exposed_service_resolved",
        hostname: normalizeValue(service.hostname),
        severity: "low",
        description: `Exposed service no longer detected: ${service.product} on ${service.hostname}`,
      });
    }
  }

  return events;
}

export async function recordPostureEvents(scanId, domainId, domain, modules, env, opts = {}) {
  try {
    const comparison = await loadTimelineComparisonContext(env, {
      scanId,
      domainId,
      currentReport: opts.currentReport,
    });
    if (!comparison.previousReport?.modules) return;

    const events = [
      ...buildSpfDiffEvents(domain, comparison.previousReport.modules, modules),
      ...(comparison.comparable
        ? buildPostureDiffEvents(domain, comparison.previousReport.modules, modules, { includeSpf: false })
        : []),
    ];
    if (events.length === 0) return;

    const r = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    const wsRows = r.results || [];
    if (wsRows.length === 0) return;

    const now = new Date().toISOString();
    for (const { workspace_id } of wsRows) {
      const recent = await env.cybermeters_db
        .prepare(
          `SELECT event_type, hostname FROM asset_events
           WHERE workspace_id = ? AND domain_id = ?
             AND created_at >= datetime('now', '-24 hours')`
        )
        .bind(workspace_id, domainId)
        .all();
      const recentEvtSet = new Set(
        (recent.results || []).map((row) => `${row.event_type}:${row.hostname}`)
      );

      for (const event of events) {
        const dedupeKey = `${event.event_type}:${event.hostname}`;
        if (recentEvtSet.has(dedupeKey)) continue;
        recentEvtSet.add(dedupeKey);

        let assetId = null;
        if (event.event_type.startsWith("exposed_service_")) {
          try {
            const assetRow = await env.cybermeters_db
              .prepare("SELECT id FROM workspace_assets WHERE workspace_id = ? AND hostname = ?")
              .bind(workspace_id, event.hostname)
              .first();
            assetId = assetRow?.id ?? null;
          } catch { /* asset link is best-effort */ }
        }

        await env.cybermeters_db
          .prepare(
            `INSERT INTO asset_events
               (id, workspace_id, domain_id, asset_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            createId("evt"),
            workspace_id,
            domainId,
            assetId,
            scanId,
            event.event_type,
            event.hostname,
            event.severity,
            event.description,
            now
          )
          .run();
      }
    }
  } catch { /* non-fatal — posture events catch up on a later scan */ }
}
