// ── Supply chain / resilience / third-party risk engine ──
// Parent-company + vendor-tier classification, dependency-graph + cascading-risk, operational
// resilience, compliance readiness, ASM maturity, and the supply-chain intelligence roll-up +
// D1 persistence. Extracted verbatim from index.js (monolith decomposition, Phase 1c).
import { normalizeVendorRiskCategory } from "./vendor-risk.js";
import { readWorkspaceBrsAssessment } from "./business-risk.js";

// ── Supply Chain, Resilience & Third-Party Risk Engine ───────────────────────
//
// Intelligence-layer only. No new scanning. Uses existing data from:
//   - workspace_vendors  (all source_modules)
//   - workspace_assets
//   - workspace_brs_scores
//   - R2 scan report JSON (modules.subdomains, modules.third_party_assets)
//
// Compliance readiness: low/medium/high confidence only. No legal assertions.
// Does not rewrite Vendor Risk Engine or BRS Engine.

// ── Parent company consolidation map ─────────────────────────────────────────
// Maps known subsidiary / product names → ultimate parent company.
// Used to detect concentration risk when multiple "different" vendors
// are actually the same corporate entity.
const PARENT_COMPANY_MAP = {
  // Google / Alphabet
  'google':        'Alphabet',
  'youtube':       'Alphabet',
  'googleapis':    'Alphabet',
  'googletagmanager': 'Alphabet',
  'googleanalytics': 'Alphabet',
  'doubleclick':   'Alphabet',
  'gstatic':       'Alphabet',
  'recaptcha':     'Alphabet',
  'firebase':      'Alphabet',
  // Meta
  'facebook':      'Meta',
  'instagram':     'Meta',
  'whatsapp':      'Meta',
  'meta':          'Meta',
  // Microsoft
  'microsoft':     'Microsoft',
  'azure':         'Microsoft',
  'office365':     'Microsoft',
  'linkedin':      'Microsoft',
  'github':        'Microsoft',
  'outlook':       'Microsoft',
  'live':          'Microsoft',
  'hotmail':       'Microsoft',
  // Amazon / AWS
  'amazon':        'Amazon',
  'aws':           'Amazon',
  'cloudfront':    'Amazon',
  's3':            'Amazon',
  'amazonaws':     'Amazon',
  // Cloudflare
  'cloudflare':    'Cloudflare',
  // Akamai
  'akamai':        'Akamai',
  'linode':        'Akamai',
  // Salesforce
  'salesforce':    'Salesforce',
  'heroku':        'Salesforce',
  'tableau':       'Salesforce',
  'slack':         'Salesforce',
  'mulesoft':      'Salesforce',
  // Okta / Auth0
  'okta':          'Okta',
  'auth0':         'Okta',
  // Twilio / SendGrid
  'twilio':        'Twilio',
  'sendgrid':      'Twilio',
  // Adobe
  'adobe':         'Adobe',
  'marketo':       'Adobe',
  'magento':       'Adobe',
  // Shopify
  'shopify':       'Shopify',
  // Stripe
  'stripe':        'Stripe',
  // HubSpot
  'hubspot':       'HubSpot',
  // Zendesk
  'zendesk':       'Zendesk',
  // Let's Encrypt / ISRG
  'letsencrypt':   'ISRG',
  'isrg':          'ISRG',
  // DigiCert
  'digicert':      'DigiCert',
  'geotrust':      'DigiCert',
  'rapidssl':      'DigiCert',
  // Sectigo / Comodo
  'sectigo':       'Sectigo',
  'comodo':        'Sectigo',
  // Fastly
  'fastly':        'Fastly',
};

// ── Vendor tier classification rules ────────────────────────────────────────
// Tier 1 = critical direct dependency (authentication, payments, core infra)
// Tier 2 = significant but not immediately critical (analytics, CRM, CDN)
// Tier 3 = low criticality (marketing, social, misc SaaS)
const VENDOR_TIER_RULES = {
  tier1_categories: ['identity_provider', 'payments', 'infrastructure', 'certificate_authority'],
  tier2_categories: ['cloud', 'hosting', 'cdn', 'security', 'email_identity', 'collaboration'],
  tier3_categories: ['analytics', 'crm', 'saas', 'support', 'ecommerce', 'social', 'identity'],
  tier1_risk_levels: ['high'],
  tier2_risk_levels: ['medium'],
};

/**
 * enrichVendors(vendors)
 *
 * Adds parent_company and tier fields to each vendor object.
 * Pure function — no I/O.
 */
function enrichVendors(vendors) {
  return vendors.map(v => {
    const nameKey = (v.vendor_name || '').toLowerCase().replace(/[\s.-]/g, '');
    let parent = null;
    for (const [key, corp] of Object.entries(PARENT_COMPANY_MAP)) {
      if (nameKey.includes(key)) { parent = corp; break; }
    }

    let tier;
    const cat = v.category || '';
    const risk = v.risk_level || '';
    if (VENDOR_TIER_RULES.tier1_categories.includes(cat) ||
        (VENDOR_TIER_RULES.tier1_risk_levels.includes(risk) && cat !== 'certificate_authority')) {
      tier = 1;
    } else if (VENDOR_TIER_RULES.tier2_categories.includes(cat)) {
      tier = 2;
    } else {
      tier = 3;
    }

    return { ...v, parent_company: parent, tier };
  });
}

/**
 * buildDependencyGraph(enrichedVendors)
 *
 * Returns a simplified dependency graph keyed by parent company (or vendor name).
 * Each node carries: tier, categories[], vendor_count, risk_levels[]
 */
function buildDependencyGraph(enrichedVendors) {
  const graph = {};
  for (const v of enrichedVendors) {
    const key = v.parent_company || v.vendor_name || 'Unknown';
    if (!graph[key]) {
      graph[key] = { tier: v.tier, categories: [], vendor_count: 0, risk_levels: [], vendors: [] };
    }
    const node = graph[key];
    node.vendor_count += 1;
    node.vendors.push(v.vendor_name);
    if (!node.categories.includes(v.category)) node.categories.push(v.category);
    if (!node.risk_levels.includes(v.risk_level)) node.risk_levels.push(v.risk_level);
    // Promote tier to highest (lowest number) seen
    if (v.tier < node.tier) node.tier = v.tier;
  }
  return graph;
}

/**
 * computeConcentration(graph, activeVendors)
 *
 * Detects concentration risk based on parent-company consolidation.
 * Returns { level, spofs, top_parents, concentration_score }
 */
export function computeConcentration(graph, activeVendors) {
  const total = activeVendors.length;
  if (total === 0) return { level: 'low', spofs: [], top_parents: [], concentration_score: 100 };

  const entries = Object.entries(graph).sort((a, b) => b[1].vendor_count - a[1].vendor_count);
  const top3Share = entries.slice(0, 3).reduce((s, [, n]) => s + n.vendor_count, 0) / total;

  const tier1Parents = entries.filter(([, n]) => n.tier === 1);
  const spofs = tier1Parents
    .filter(([, n]) => n.vendor_count === 1 || n.categories.some(c => ['identity_provider','payments'].includes(c)))
    .map(([name]) => name);

  // A "top-3 share" only means something with enough vendors to compare against.
  // With a tiny sample (1–2 identified) the share is trivially ~100% and must
  // not read as critical concentration — that's alarmist, not informative. So
  // share-based escalation requires >= 3 vendors; genuine single points of
  // failure (sole provider, identity/payments) still surface on their own.
  const shareMeaningful = total >= 3;
  let level;
  if ((shareMeaningful && top3Share > 0.7) || spofs.length >= 3) level = 'critical';
  else if ((shareMeaningful && top3Share > 0.5) || spofs.length >= 2) level = 'high';
  else if ((shareMeaningful && top3Share > 0.3) || spofs.length >= 1) level = 'medium';
  else level = 'low';

  const concentration_score = Math.max(0, 100 - Math.round(top3Share * 60) - spofs.length * 10);

  return {
    level,
    spofs,
    top_parents: entries.slice(0, 5).map(([name, n]) => ({ name, tier: n.tier, vendor_count: n.vendor_count, categories: n.categories })),
    concentration_score,
  };
}

/**
 * computeCascadingRisks(enrichedVendors, graph)
 *
 * Identifies potential cascade failure scenarios.
 * Returns array of risk objects: { scenario, affected_categories, severity, likelihood }
 */
function computeCascadingRisks(enrichedVendors, graph) {
  const risks = [];

  // Identity provider failure → auth collapse
  const idpVendors = enrichedVendors.filter(v => v.category === 'identity_provider' && v.status === 'active');
  if (idpVendors.length === 1) {
    risks.push({
      scenario: 'Single identity provider — authentication single point of failure',
      affected_categories: ['identity_provider'],
      severity: 'critical',
      likelihood: 'medium',
      vendors: idpVendors.map(v => v.vendor_name),
    });
  }

  // Payment processor failure
  const paymentVendors = enrichedVendors.filter(v => v.category === 'payments' && v.status === 'active');
  if (paymentVendors.length === 1) {
    risks.push({
      scenario: 'Single payment processor — revenue collection risk',
      affected_categories: ['payments'],
      severity: 'high',
      likelihood: 'low',
      vendors: paymentVendors.map(v => v.vendor_name),
    });
  }

  // Certificate authority concentration
  const caVendors = enrichedVendors.filter(v => v.category === 'certificate_authority' && v.status === 'active');
  const caParents = [...new Set(caVendors.map(v => v.parent_company || v.vendor_name))];
  if (caParents.length === 1 && caVendors.length >= 2) {
    risks.push({
      scenario: 'All SSL certificates from a single certificate authority',
      affected_categories: ['certificate_authority'],
      severity: 'medium',
      likelihood: 'low',
      vendors: caVendors.map(v => v.vendor_name),
    });
  }

  // Cloud / hosting concentration
  const infraVendors = enrichedVendors.filter(v => ['cloud','hosting','infrastructure'].includes(v.category) && v.status === 'active');
  const infraParents = [...new Set(infraVendors.map(v => v.parent_company || v.vendor_name))];
  if (infraVendors.length >= 2 && infraParents.length === 1) {
    risks.push({
      scenario: 'Cloud and hosting concentrated on a single provider',
      affected_categories: ['cloud', 'hosting', 'infrastructure'],
      severity: 'high',
      likelihood: 'low',
      vendors: infraVendors.map(v => v.vendor_name),
    });
  }

  // High-risk vendor count
  const highRiskActive = enrichedVendors.filter(v => v.risk_level === 'high' && v.status === 'active' && v.source_module === 'vendor_risk');
  if (highRiskActive.length >= 5) {
    risks.push({
      scenario: `${highRiskActive.length} high-risk vendors detected — elevated aggregate risk`,
      affected_categories: [...new Set(highRiskActive.map(v => v.category))],
      severity: 'high',
      likelihood: 'medium',
      vendors: highRiskActive.slice(0, 5).map(v => v.vendor_name),
    });
  }

  return risks;
}

/**
 * computeOperationalResilience(enrichedVendors, cascadingRisks, concentration)
 *
 * Produces a 0-100 resilience score.
 * Higher = more resilient.
 */
function computeOperationalResilience(enrichedVendors, cascadingRisks, concentration) {
  let score = 100;

  // Penalise for single points of failure
  score -= concentration.spofs.length * 12;

  // Penalise for cascading risk severity
  for (const r of cascadingRisks) {
    if (r.severity === 'critical') score -= 20;
    else if (r.severity === 'high') score -= 12;
    else if (r.severity === 'medium') score -= 6;
  }

  // Penalise for concentration level
  if (concentration.level === 'critical') score -= 20;
  else if (concentration.level === 'high') score -= 12;
  else if (concentration.level === 'medium') score -= 6;

  // Penalise for high-risk tier-1 vendors
  const highRiskTier1 = enrichedVendors.filter(v => v.tier === 1 && v.risk_level === 'high' && v.status === 'active');
  score -= highRiskTier1.length * 8;

  return Math.max(0, Math.min(100, score));
}

/**
 * computeComplianceReadiness(enrichedVendors, brsScore)
 *
 * Returns confidence signals for common compliance frameworks.
 * Outputs: low | medium | high — no legal assertions.
 */
function computeComplianceReadiness(enrichedVendors, brsScore) {
  const active = enrichedVendors.filter(v => v.status === 'active');

  // GDPR readiness signals
  const hasIdp = active.some(v => v.category === 'identity_provider');
  const highRiskCount = active.filter(v => v.risk_level === 'high').length;
  const euSignals = active.filter(v => {
    const n = (v.vendor_name || '').toLowerCase();
    return n.includes('eu') || n.includes('europe') || n.includes('gdpr');
  }).length;
  let gdpr = 'low';
  if (hasIdp && highRiskCount === 0 && brsScore >= 70) gdpr = 'high';
  else if (highRiskCount <= 2 && brsScore >= 50) gdpr = 'medium';

  // ISO 27001 / security governance signals
  const hasSecurityVendors = active.some(v => v.category === 'security');
  const hasCaVendors = active.some(v => v.category === 'certificate_authority');
  let security_governance = 'low';
  if (hasSecurityVendors && hasCaVendors && brsScore >= 75) security_governance = 'high';
  else if (hasCaVendors && brsScore >= 55) security_governance = 'medium';

  // PCI-DSS readiness signals
  const hasPayments = active.some(v => v.category === 'payments');
  const paymentHighRisk = active.filter(v => v.category === 'payments' && v.risk_level === 'high').length;
  let pci_dss = 'low';
  if (hasPayments && paymentHighRisk === 0 && brsScore >= 70) pci_dss = 'medium';
  else if (!hasPayments) pci_dss = 'medium'; // no payment processors detected = less exposure

  return {
    gdpr,
    security_governance,
    pci_dss,
    note: 'Confidence signals only. CyberMeters does not certify compliance. Engage a qualified assessor for formal certification.',
  };
}

/**
 * computeAsmMaturity(workspaceData)
 *
 * Estimates ASM programme maturity from available workspace signals.
 * Returns { level: 'initial'|'developing'|'defined'|'managed'|'optimising', score: 0-100 }
 */
function computeAsmMaturity(workspaceData) {
  let score = 0;
  const { total_scans = 0, total_vendors = 0, total_assets = 0, brs_score = 0 } = workspaceData;

  // Scan cadence
  if (total_scans >= 20) score += 25;
  else if (total_scans >= 10) score += 15;
  else if (total_scans >= 3) score += 8;
  else if (total_scans >= 1) score += 3;

  // Vendor visibility
  if (total_vendors >= 20) score += 20;
  else if (total_vendors >= 10) score += 12;
  else if (total_vendors >= 3) score += 6;

  // Asset visibility
  if (total_assets >= 50) score += 20;
  else if (total_assets >= 20) score += 12;
  else if (total_assets >= 5) score += 6;

  // Security posture
  if (brs_score >= 80) score += 35;
  else if (brs_score >= 65) score += 25;
  else if (brs_score >= 50) score += 15;
  else if (brs_score >= 30) score += 8;

  const level =
    score >= 80 ? 'optimising' :
    score >= 60 ? 'managed' :
    score >= 40 ? 'defined' :
    score >= 20 ? 'developing' :
    'initial';

  return { level, score: Math.min(100, score) };
}

function computeDnsResilienceSignalsFromVendors(activeVendors) {
  const dnsVendors = activeVendors.filter((v) => {
    const cat = normalizeVendorRiskCategory(v.category, v.vendor_name, v.source);
    const name = String(v.vendor_name || "").toLowerCase();
    return cat === "dns_provider" || /cloudflare|route ?53|awsdns|azure dns|google cloud dns|akamai|fastly/.test(name);
  });
  const caVendors = activeVendors.filter((v) => {
    const cat = String(v.category || "").toLowerCase();
    return cat === "certificate_authority" || cat === "security_tooling";
  });

  const dnsProviders = [...new Set(dnsVendors.map((v) => v.vendor_name).filter(Boolean))];
  const caProviders = [...new Set(caVendors.map((v) => v.vendor_name).filter(Boolean))];

  return {
    dns_provider_concentration: {
      provider_count: dnsProviders.length,
      providers: dnsProviders,
      dependency:
        dnsProviders.length === 0 ? "unknown" :
        dnsProviders.length === 1 ? "single-provider dependency" : "multi-provider dependency",
      label:
        dnsProviders.length === 1 ? `${dnsProviders[0]}-only` :
        dnsProviders.length > 1 ? "Multi-provider" : "Unknown",
    },
    certificate_authority_concentration: {
      provider_count: caProviders.length,
      providers: caProviders,
      dependency:
        caProviders.length === 0 ? "unknown" :
        caProviders.length === 1 ? "single_ca_dependency" : "multiple_ca_usage",
    },
    source: "workspace_vendors",
  };
}

/**
 * computeSupplyChainIntelligence(wsId, env)
 *
 * Orchestrates all supply chain intelligence computations.
 * Reads from D1 only (no R2 needed for this sprint).
 * Returns full intelligence payload or null on error.
 */
export async function computeSupplyChainIntelligence(wsId, env) {
  try {
    // ── Load vendors and workspace context from D1 ──────────────────────────
    const [vendorRows, wsRow, brsAssessment, assetRow, scanRow] = await Promise.all([
      env.cybermeters_db.prepare(
        `SELECT vendor_name, category, risk_level, status, source_module, confidence, first_seen, last_seen
         FROM workspace_vendors
         WHERE workspace_id = ?`
      ).bind(wsId).all().then(r => r.results || []),

      env.cybermeters_db.prepare(`SELECT id, name FROM workspaces WHERE id = ?`).bind(wsId).first(),

      readWorkspaceBrsAssessment(env, wsId),

      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS cnt FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`
      ).bind(wsId).first(),

      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS cnt FROM scans WHERE workspace_id = ?`
      ).bind(wsId).first(),
    ]);

    // M5.e: absent BRS is NOT a zero score — null fails every >= maturity
    // threshold (conservative) without fabricating a numeric assessment.
    const brsScore = brsAssessment?.state === "assessed"
      ? (brsAssessment.score ?? null)
      : null;
    const activeVendors = vendorRows.filter(v => v.status === 'active');
    const enriched = enrichVendors(activeVendors);

    const workspaceData = {
      total_scans:   scanRow?.cnt ?? 0,
      total_vendors: activeVendors.length,
      total_assets:  assetRow?.cnt ?? 0,
      brs_score:     brsScore,
    };

    // ── Core computations ───────────────────────────────────────────────────
    const graph           = buildDependencyGraph(enriched);
    const concentration   = computeConcentration(graph, activeVendors);
    const cascadingRisks  = computeCascadingRisks(enriched, graph);
    const resilienceScore = computeOperationalResilience(enriched, cascadingRisks, concentration);
    const dnsResilienceSignals = computeDnsResilienceSignalsFromVendors(activeVendors);
    const compliance      = computeComplianceReadiness(enriched, brsScore);
    const asmMaturity     = computeAsmMaturity(workspaceData);

    // ── Supply chain score (composite) ─────────────────────────────────────
    const concentrationScore = concentration.concentration_score;
    const vendorRiskPenalty  = Math.min(40, enriched.filter(v => v.risk_level === 'high' && v.source_module === 'vendor_risk').length * 5);
    const supplyChainScore   = Math.max(0, Math.round(
      concentrationScore * 0.4 +
      resilienceScore    * 0.35 +
      asmMaturity.score  * 0.25 -
      vendorRiskPenalty
    ));

    // ── Tier counts ─────────────────────────────────────────────────────────
    const tier1Count = enriched.filter(v => v.tier === 1).length;
    const tier2Count = enriched.filter(v => v.tier === 2).length;
    const tier3Count = enriched.filter(v => v.tier === 3).length;

    // ── Critical vendors list ───────────────────────────────────────────────
    const criticalVendors = enriched
      .filter(v => v.tier === 1 || v.risk_level === 'high')
      .map(v => ({
        name:           v.vendor_name,
        category:       v.category,
        tier:           v.tier,
        risk_level:     v.risk_level,
        parent_company: v.parent_company,
        source_module:  v.source_module,
      }));

    const payload = {
      supply_chain_score:          supplyChainScore,
      operational_resilience_score: resilienceScore,
      concentration_level:         concentration.level,
      critical_vendor_count:       criticalVendors.length,
      tier1_count:                 tier1Count,
      tier2_count:                 tier2Count,
      tier3_count:                 tier3Count,
      spof_count:                  concentration.spofs.length,
      critical_vendors:            criticalVendors,
      dependency_graph:            graph,
      cascading_risks:             cascadingRisks,
      concentration:               concentration,
      dns_resilience_signals:       dnsResilienceSignals,
      compliance_readiness:        compliance,
      asm_maturity:                asmMaturity,
      vendor_summary: {
        total:   vendorRows.length,
        active:  activeVendors.length,
        high:    enriched.filter(v => v.risk_level === 'high').length,
        medium:  enriched.filter(v => v.risk_level === 'medium').length,
        low:     enriched.filter(v => v.risk_level === 'low').length,
      },
      workspace: { id: wsId, name: wsRow?.name ?? '' },
      brs_score: brsScore,
      brs_state: brsAssessment?.state ?? "not_assessed",
      brs_state_reason: brsAssessment?.state_reason ?? null,
      last_complete_brs_assessment: brsAssessment?.last_complete_assessment ?? null,
      calculated_at: new Date().toISOString(),
    };

    return payload;
  } catch (err) {
    console.error('[supply-chain] computeSupplyChainIntelligence error:', err);
    return null;
  }
}

/**
 * upsertSupplyChainScore(wsId, payload, env)
 *
 * Persists latest supply chain intelligence to D1 and appends history row.
 * Called from Phase 8i in scan completion pipeline.
 */
export async function upsertSupplyChainScore(wsId, payload, env) {
  if (!payload) return;
  const now = new Date().toISOString();
  const id  = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);
  const hid = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).slice(2);

  await env.cybermeters_db.batch([
    env.cybermeters_db.prepare(`
      INSERT INTO workspace_supply_chain_scores
        (id, workspace_id, supply_chain_score, resilience_score, concentration_level,
         critical_vendor_count, tier1_count, tier2_count, tier3_count, spof_count,
         payload_json, calculated_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(workspace_id) DO UPDATE SET
        supply_chain_score    = excluded.supply_chain_score,
        resilience_score      = excluded.resilience_score,
        concentration_level   = excluded.concentration_level,
        critical_vendor_count = excluded.critical_vendor_count,
        tier1_count           = excluded.tier1_count,
        tier2_count           = excluded.tier2_count,
        tier3_count           = excluded.tier3_count,
        spof_count            = excluded.spof_count,
        payload_json          = excluded.payload_json,
        calculated_at         = excluded.calculated_at,
        updated_at            = excluded.updated_at
    `).bind(
      id, wsId,
      payload.supply_chain_score,
      payload.operational_resilience_score,
      payload.concentration_level,
      payload.critical_vendor_count,
      payload.tier1_count,
      payload.tier2_count,
      payload.tier3_count,
      payload.spof_count,
      JSON.stringify(payload),
      payload.calculated_at,
      now, now
    ),

    env.cybermeters_db.prepare(`
      INSERT INTO workspace_supply_chain_history
        (id, workspace_id, supply_chain_score, resilience_score, concentration_level,
         critical_vendor_count, spof_count, calculated_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      hid, wsId,
      payload.supply_chain_score,
      payload.operational_resilience_score,
      payload.concentration_level,
      payload.critical_vendor_count,
      payload.spof_count,
      payload.calculated_at,
      now
    ),
  ]);
}
