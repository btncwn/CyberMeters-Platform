// ── Vendor risk engine (v1 scoring) ──
// Per-vendor + per-workspace vendor-risk scoring: category multipliers, signal/concentration
// weights, source/confidence scoring, category normalisation, and D1 recompute helpers.
// Extracted verbatim from index.js (monolith decomposition, Phase 1c).
import { createId } from "../lib/util.js";

// ── Vendor Risk Engine v1 Scoring ────────────────────────────────────────────

const VENDOR_CATEGORY_MULTIPLIERS = {
  identity_provider: 3.0,
  payment_processor: 2.5,
  dns_provider: 2.0,
  cdn: 2.0,
  email_provider: 1.5,
  analytics: 1.2,
  marketing: 1.2,
  hosting: 1.0,
  monitoring: 1.0,
  security_tooling: 1.0,
  other: 1.0,
};

const VENDOR_CONCENTRATION_WEIGHTS = {
  identity_provider: 5,
  payment_processor: 5,
  dns_provider: 4,
  cdn: 4,
  email_provider: 3,
  analytics: 1,
  marketing: 1,
  hosting: 1,
  monitoring: 1,
  security_tooling: 1,
  other: 1,
};

const VENDOR_SIGNAL_WEIGHTS = {
  "csp:script-src": 1.0,
  "csp:connect-src": 0.95,
  script: 0.85,
  cname: 0.9,
  headers: 0.6,
  header: 0.6,
  server: 0.6,
  tech: 0.6,
};

export function confidenceToScore(confidence) {
  if (typeof confidence === "number") return Math.max(0, Math.min(1, confidence));
  const c = String(confidence || "").toLowerCase();
  if (c === "high") return 1.0;
  if (c === "medium") return 0.6;
  if (c === "low") return 0.25;
  return 0.1;
}

export function normalizeVendorKey(vendorName) {
  const raw = String(vendorName || "").toLowerCase().trim();
  if (!raw) return "unknown";
  const normalized = raw
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/[^\w.\s-]/g, " ")
    .replace(/\s+/g, " ")
    .trim();

  if (/stripe|js\.stripe\.com|assets\.stripe\.com/.test(normalized)) return "stripe";
  if (/cloudflare|cdnjs/.test(normalized)) return "cloudflare";
  if (/google|gtm|googletagmanager|google analytics|gts|recaptcha/.test(normalized)) return "google";
  if (/intercom|intercomcdn/.test(normalized)) return "intercom";
  if (/hotjar/.test(normalized)) return "hotjar";
  if (/segment/.test(normalized)) return "segment";
  if (/amplitude/.test(normalized)) return "amplitude";
  if (/paypal|paypalobjects/.test(normalized)) return "paypal";
  if (/microsoft|entra|office|outlook|azure/.test(normalized)) return "microsoft";
  if (/amazon|aws|cloudfront/.test(normalized)) return "aws";
  if (/zendesk|zdassets/.test(normalized)) return "zendesk";
  if (/hubspot|hubapi|hs-scripts|hsforms/.test(normalized)) return "hubspot";
  if (/salesforce|force\.com/.test(normalized)) return "salesforce";
  if (/okta/.test(normalized)) return "okta";
  if (/auth0/.test(normalized)) return "auth0";
  if (/datadog/.test(normalized)) return "datadog";

  return normalized
    .replace(/\.(com|net|org|io|co|app|dev|cloud|me)$/g, "")
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "") || "unknown";
}

function getVendorSources(row) {
  const sources = new Set();
  if (row?.source) sources.add(String(row.source));
  for (const s of (Array.isArray(row?._sources) ? row._sources : [])) sources.add(String(s));
  try {
    const parsed = typeof row?.evidence === "string" ? JSON.parse(row.evidence || "[]") : row?.evidence;
    for (const item of (Array.isArray(parsed) ? parsed : [])) {
      if (typeof item === "string") sources.add(item);
      else if (item?.source) sources.add(String(item.source));
    }
  } catch { /* ignore malformed evidence */ }
  return [...sources].filter(Boolean);
}

function signalWeightForSource(source) {
  const s = String(source || "").toLowerCase();
  if (VENDOR_SIGNAL_WEIGHTS[s] !== undefined) return VENDOR_SIGNAL_WEIGHTS[s];
  if (s.startsWith("csp:script-src")) return 1.0;
  if (s.startsWith("csp:connect-src")) return 0.95;
  if (s.startsWith("csp:")) return 0.9;
  if (["ns", "mx", "spf", "dkim"].includes(s)) return 0.9;
  if (["server", "tech", "x-powered-by", "via", "x-cache"].includes(s)) return 0.6;
  return 0.75;
}

export function signalWeightForVendor(row) {
  const sources = getVendorSources(row);
  if (sources.length === 0) return 0.75;
  return Math.max(...sources.map(signalWeightForSource));
}

export function normalizeVendorRiskCategory(category, vendorName = "", source = "") {
  const c = String(category || "").toLowerCase();
  const name = String(vendorName || "").toLowerCase();
  const src = String(source || "").toLowerCase();

  if (c === "identity_provider" || c === "identity") return "identity_provider";
  if (c === "payment_processor" || c === "payments") return "payment_processor";
  if (c === "dns_provider") return "dns_provider";
  if (c === "email_provider" || c === "email_identity") return "email_provider";
  if (c === "analytics") return "analytics";
  if (c === "marketing") return "marketing";
  if (c === "monitoring") return "monitoring";
  if (c === "security_tooling" || c === "security" || c === "certificate_authority") return "security_tooling";
  if (c === "cdn") return "cdn";
  if (c === "hosting" || c === "cloud") return "hosting";

  if (c === "infrastructure") {
    if (/cloudflare|akamai|fastly/.test(name)) return src === "ns" ? "dns_provider" : "cdn";
    return "cdn";
  }

  if (c === "saas") {
    if (/stripe|paypal|braintree|square|adyen|klarna|paddle/.test(name)) return "payment_processor";
    if (/sendgrid|mailchimp|mailgun|brevo|klaviyo|marketo|hubspot/.test(name)) return "marketing";
    return "other";
  }

  if (c === "support" || c === "collaboration" || c === "crm" || c === "ecommerce") return "other";
  return "other";
}

function riskLevelBaseScore(riskLevel) {
  const r = String(riskLevel || "").toLowerCase();
  if (r === "high" || r === "critical") return 80;
  if (r === "medium") return 60;
  if (r === "low") return 40;
  return 30;
}

export function identityVendorRiskEvidenceStatus(row = {}) {
  const modules = new Set([
    row.source_module,
    ...(Array.isArray(row._source_modules) ? row._source_modules : []),
  ].map((value) => String(value || "").toLowerCase()).filter(Boolean));
  const sources = getVendorSources(row).map((value) => String(value).toLowerCase());
  const independentSource = sources.some((value) =>
    value !== "identity_discovery" &&
    !["cname", "spf", "mx", "csp", "server", "certificate_transparency", "dns_bruteforce", "dns_mx", "unknown"].includes(value));
  const identityOnly = modules.size > 0 && [...modules].every((value) => value === "identity_discovery") && !independentSource;
  return identityOnly ? "relationship_only" : "independent_risk_evidence";
}

function scoreVendorRisk(row, categoryCounts, totalVendors) {
  const normalizedCategory = normalizeVendorRiskCategory(row.category, row.vendor_name, row.source);
  const multiplier = VENDOR_CATEGORY_MULTIPLIERS[normalizedCategory] ?? 1.0;
  const signalWeight = signalWeightForVendor(row);
  const confidenceScore = Number((confidenceToScore(row.confidence) * signalWeight).toFixed(3));
  const base = Math.round(riskLevelBaseScore(row.risk_level) * confidenceScore);
  const categoryCount = categoryCounts[normalizedCategory] || 0;
  const concentrationRatio = totalVendors > 0 ? categoryCount / totalVendors : 0;
  const concentrationPenalty = concentrationRatio >= 0.5 && categoryCount >= 3
    ? 15
    : concentrationRatio >= 0.35 && categoryCount >= 2
      ? 8
      : 0;
  const riskEvidenceStatus = identityVendorRiskEvidenceStatus(row);
  if (riskEvidenceStatus === "relationship_only") {
    return {
      normalized_category: normalizedCategory,
      score: 0,
      category_multiplier: multiplier,
      concentration_penalty: 0,
      confidence_score: confidenceScore,
      signal_weight: signalWeight,
      risk_evidence_status: riskEvidenceStatus,
    };
  }
  const score = Math.max(0, Math.min(100, Math.round(base * multiplier - concentrationPenalty)));
  return {
    normalized_category: normalizedCategory,
    score,
    category_multiplier: multiplier,
    concentration_penalty: concentrationPenalty,
    confidence_score: confidenceScore,
    signal_weight: signalWeight,
    risk_evidence_status: riskEvidenceStatus,
  };
}

function classifyWorkspaceVendorConcentration(vendors) {
  if (vendors.length === 0) {
    return { level: "low", dominant_category: null, dominant_count: 0, dominant_ratio: 0, weighted_dominance: 0, total_weight: 0 };
  }
  const weights = {};
  let totalWeight = 0;
  for (const v of vendors) {
    const cat = v.normalized_category || normalizeVendorRiskCategory(v.category, v.vendor_name, v.source);
    const weight = VENDOR_CONCENTRATION_WEIGHTS[cat] ?? 1;
    weights[cat] = (weights[cat] || 0) + weight;
    totalWeight += weight;
  }
  const [dominant_category, weighted_dominance] = Object.entries(weights)
    .sort((a, b) => b[1] - a[1])[0];
  const dominant_ratio = totalWeight > 0 ? weighted_dominance / totalWeight : 0;
  const level =
    dominant_ratio >= 0.65 ? "high" :
    dominant_ratio >= 0.45 ? "medium" : "low";
  return {
    level,
    dominant_category,
    dominant_count: vendors.filter((v) => (v.normalized_category || normalizeVendorRiskCategory(v.category, v.vendor_name, v.source)) === dominant_category).length,
    dominant_ratio: Number(dominant_ratio.toFixed(2)),
    weighted_dominance,
    total_weight: totalWeight,
  };
}

export function computeWorkspaceVendorRisk(vendors) {
  const active = vendors.filter((v) => (v.status || "active") === "active");
  if (active.length === 0) {
    return {
      workspace_vendor_risk_score: 0,
      concentration_risk: classifyWorkspaceVendorConcentration([]),
      top_vendors: [],
      scored_vendors: [],
    };
  }

  const canonical = new Map();
  for (const row of active) {
    const vendor_key = normalizeVendorKey(row.vendor_name || row.name);
    const normalized_category = normalizeVendorRiskCategory(row.category, row.vendor_name || row.name, row.source);
    const existing = canonical.get(vendor_key);
    const candidate = {
      ...row,
      vendor_key,
      normalized_category,
      _sources: getVendorSources(row),
      _source_modules: [row.source_module].filter(Boolean),
    };
    if (!existing) {
      canonical.set(vendor_key, candidate);
      continue;
    }

    const existingSignal = signalWeightForVendor(existing);
    const candidateSignal = signalWeightForVendor(candidate);
    const existingRank = riskLevelBaseScore(existing.risk_level) * confidenceToScore(existing.confidence) * existingSignal;
    const candidateRank = riskLevelBaseScore(candidate.risk_level) * confidenceToScore(candidate.confidence) * candidateSignal;
    const kept = candidateRank > existingRank ? candidate : existing;
    kept._sources = [...new Set([...(existing._sources || []), ...(candidate._sources || [])])];
    kept._source_modules = [...new Set([...(existing._source_modules || []), ...(candidate._source_modules || [])])];
    canonical.set(vendor_key, kept);
  }

  const deduped = [...canonical.values()];
  const categoryCounts = {};
  for (const row of deduped) {
    const cat = row.normalized_category || normalizeVendorRiskCategory(row.category, row.vendor_name, row.source);
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
  }

  const scored = deduped.map((row) => ({
    ...row,
    ...scoreVendorRisk(row, categoryCounts, deduped.length),
  }));
  const concentration = classifyWorkspaceVendorConcentration(scored);
  const topVendors = scored.slice().sort((a, b) => b.score - a.score).slice(0, 10);
  const riskEvaluatedTop = topVendors.filter((vendor) => vendor.risk_evidence_status !== "relationship_only");
  const topAvg = riskEvaluatedTop.length
    ? riskEvaluatedTop.reduce((sum, v) => sum + v.score, 0) / riskEvaluatedTop.length
    : 0;
  const concentrationBump = concentration.level === "high" ? 10 : concentration.level === "medium" ? 5 : 0;

  return {
    workspace_vendor_risk_score: Math.max(0, Math.min(100, Math.round(topAvg + concentrationBump))),
    concentration_risk: concentration,
    top_vendors: topVendors,
    scored_vendors: scored,
  };
}

async function recomputeWorkspaceVendorRiskScores(workspaceId, env) {
  if (!workspaceId) return null;
  const now = new Date().toISOString();
  const rows = await env.cybermeters_db
    .prepare(
      `SELECT id, workspace_id, vendor_name, category, source, evidence,
              confidence, risk_level, status, first_seen, last_seen,
              metadata_json, source_module
       FROM workspace_vendors
       WHERE workspace_id = ? AND status = 'active'`
    )
    .bind(workspaceId)
    .all();

  const vendors = rows.results || [];
  const aggregate = computeWorkspaceVendorRisk(vendors);
  const scoredIds = aggregate.scored_vendors.map((v) => v.id).filter(Boolean);

  try {
    if (scoredIds.length > 0) {
      const placeholders = scoredIds.map(() => "?").join(", ");
      await env.cybermeters_db
        .prepare(
          `DELETE FROM vendor_risk_scores
           WHERE workspace_id = ? AND vendor_id NOT IN (${placeholders})`
        )
        .bind(workspaceId, ...scoredIds)
        .run();
    } else {
      await env.cybermeters_db
        .prepare("DELETE FROM vendor_risk_scores WHERE workspace_id = ?")
        .bind(workspaceId)
        .run();
    }
  } catch { /* score cleanup is non-fatal */ }

  for (const v of aggregate.scored_vendors) {
    try {
      await env.cybermeters_db
        .prepare(
          `INSERT OR REPLACE INTO vendor_risk_scores
             (vendor_id, workspace_id, score, category_multiplier,
              concentration_penalty, updated_at)
           VALUES (?, ?, ?, ?, ?, ?)`
        )
        .bind(
          v.id, workspaceId, v.score, v.category_multiplier,
          v.concentration_penalty, now
        )
        .run();
      await env.cybermeters_db
        .prepare(
          `INSERT INTO vendor_risk_scores_history
             (id, vendor_id, workspace_id, score, snapshot_time)
           VALUES (?, ?, ?, ?, ?)`
        )
        .bind(createId("vscorehist"), v.id, workspaceId, v.score, now)
        .run();
    } catch { /* score persistence is non-fatal per vendor */ }
  }

  return aggregate;
}

export async function recomputeVendorRiskScoresForDomain(domainId, env) {
  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch { return; }

  for (const { workspace_id } of wsRows) {
    try {
      await recomputeWorkspaceVendorRiskScores(workspace_id, env);
    } catch { /* migration may not be applied yet; scans must not fail */ }
  }
}
