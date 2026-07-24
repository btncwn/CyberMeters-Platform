// ── Executive report builder (snapshot-native, M5.d) ──
// The online executive report renders the canonical immutable reporting
// snapshot verbatim. The five-pillar intelligence-engine registry that used to
// be this file's truth source is RETIRED (M5.d): the eight canonical domains
// are the only customer-facing grouping, and this builder performs no score,
// band, BRI, CE, domain-state, taxonomy, remediation or trend derivation.
//
// It is a PURE view over a verified snapshot read ({ snapshot, row, integrity }
// from readScanReportSnapshot): same snapshot in, same report out. The only
// live inputs a route may add around it are presentation metadata under the
// documented frozen-vs-live policy (branding, workspace display name).

export function buildExecutiveReportV2({ scan, workspace = null, read }) {
  const snap = read.snapshot;
  const s = snap.snapshot || {};
  const overall = snap.overall || {};
  const assessment = overall.assessment || {};
  const bri = overall.business_risk_indicator || {};

  const observed = Array.isArray(snap.observed_findings) ? snap.observed_findings : [];
  const observations = Array.isArray(snap.observations) ? snap.observations : [];
  const actions = Array.isArray(snap.remediation_actions) ? snap.remediation_actions : [];

  return {
    version: "3.0",
    report_type: "executive_scan_report",
    workspace: workspace ? { id: workspace.id, name: workspace.name } : null,
    domain: {
      id: scan?.domain_id ?? s.domain_id ?? null,
      name: s.domain ?? scan?.domain ?? null,
      scan_id: s.scan_id ?? scan?.id ?? null,
      scanned_at: s.scan_started_at ?? null,
      completed_at: s.scan_completed_at ?? null,
    },
    // Deterministic: the snapshot's own build time, never the request clock.
    generated_at: s.built_at ?? null,
    assessed_at: s.as_of ?? null,
    provenance: s.provenance ?? null,
    methodology: snap.methodology ?? null,

    // One-score rule: the only numeric presented as a score.
    cyber_metrics_score: {
      value: overall.cyber_metrics_score ?? null,
      rating: overall.score_band ?? null,
      provisional: assessment.provisional ?? null,
      comparable: assessment.comparable ?? null,
      quality: assessment.quality ?? null,
      message: assessment.message ?? null,
      evidence_grade: overall.assessment_evidence_grade ?? null,
    },
    // An indicator — band + explanation — never a second score.
    business_risk_indicator: {
      band: bri.band ?? null,
      explanation: bri.explanation ?? null,
      methodology_disclosure: bri.methodology_disclosure ?? null,
      evidence_grade: bri.evidence_grade ?? null,
    },

    executive_summary: {
      summary: overall.summary ?? null,
      evidence_grade: overall.evidence_grade ?? null,
      observed_findings_count: observed.length,
      observations_count: observations.length,
      not_fully_assessed: overall.not_fully_assessed ?? [],
      // Top actions verbatim from the canonical remediation actions.
      priority_actions: actions.slice(0, 5).map((a) => ({
        priority: a.priority ?? null,
        title: a.title ?? null,
        action: a.action ?? null,
        verification_ceiling: a.verification_ceiling ?? null,
      })),
    },

    cyber_mot_domains: snap.domains ?? [],
    monitoring_states: snap.monitoring_states ?? null,
    observed_findings: observed,
    observations,
    remediation_actions: actions,
    unmapped_finding_types: snap.unmapped_finding_types ?? [],
    evidence_completeness: overall.evidence_completeness ?? null,
    limitations: snap.limitations ?? [],
    snapshot_id: s.snapshot_id ?? read.row?.id ?? null,
    integrity: read.integrity ?? null,
  };
}
