import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, RefreshCw, Globe, Hash, AlertCircle, ScanLine,
  ChevronRight, Shield, FileText, CheckCircle, XCircle, Mail,
  Lock, Server, Clock, History, ChevronDown, Terminal,
  TrendingDown, TrendingUp, Minus,
} from 'lucide-react'
import { api } from '../api'
import StatusBadge from '../components/StatusBadge'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'

const ACTIVE  = new Set(['queued', 'running', 'processing'])
const POLL_MS = 4000

// ── Helpers ─────────────────────────────────────────────────────────────────

function formatDate(str) {
  if (!str) return '—'
  const d = new Date(str.includes('T') ? str : str.replace(' ', 'T') + 'Z')
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function durationSeconds(start, end) {
  if (!start || !end) return null
  const s = Math.round((new Date(end) - new Date(start)) / 1000)
  return `${s}s`
}

// ── Risk level config ────────────────────────────────────────────────────────

const RISK_CFG = {
  excellent: { color: '#00876A', cls: 'text-brand-600', pill: 'bg-brand-50 text-brand-700 border-brand-100', label: 'Excellent' },
  good:      { color: '#00876A', cls: 'text-brand-600', pill: 'bg-brand-50 text-brand-700 border-brand-100', label: 'Good'      },
  moderate:  { color: '#F59E0B', cls: 'text-amber-500', pill: 'bg-amber-50 text-amber-700 border-amber-100', label: 'Moderate'  },
  high:      { color: '#F97316', cls: 'text-orange-500',pill: 'bg-orange-50 text-orange-700 border-orange-100',label: 'High Risk'},
  critical:  { color: '#EF4444', cls: 'text-red-500',   pill: 'bg-red-50 text-red-700 border-red-100',       label: 'Critical'  },
  unknown:   { color: '#D1D5DB', cls: 'text-gray-400',  pill: 'bg-gray-100 text-gray-500 border-gray-200',   label: 'Unknown'   },
}

// ── Severity config ──────────────────────────────────────────────────────────

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const SEV_STYLE = {
  critical: 'bg-red-500 text-white',
  high:     'bg-orange-500 text-white',
  medium:   'bg-amber-400 text-white',
  low:      'bg-blue-400 text-white',
  info:     'bg-gray-300 text-gray-700',
}
const SEV_BADGE = {
  critical: 'badge-critical',
  high:     'badge-high',
  medium:   'badge-medium',
  low:      'badge-low',
  info:     'text-xs font-semibold px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 border border-gray-200',
}

// ── Components ───────────────────────────────────────────────────────────────

function SectionHeader({ icon: Icon, title, aside }) {
  return (
    <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 bg-gray-50">
      <div className="flex items-center gap-2.5">
        <div className="w-6 h-6 rounded-md bg-brand-100 flex items-center justify-center">
          <Icon className="w-3.5 h-3.5 text-brand-700" />
        </div>
        <h2 className="text-sm font-bold text-gray-900">{title}</h2>
      </div>
      {aside && <div>{aside}</div>}
    </div>
  )
}

function KV({ label, value }) {
  return (
    <div className="flex items-start justify-between gap-4 px-6 py-3 border-b border-gray-50 last:border-0">
      <span className="text-xs font-semibold text-gray-400 uppercase tracking-wide min-w-[130px] pt-0.5">{label}</span>
      <span className="text-sm text-gray-900 text-right flex-1 font-medium">{value ?? '—'}</span>
    </div>
  )
}

// ── Score Ring (compact) ─────────────────────────────────────────────────────

function ScoreRing({ score, riskLevel }) {
  const r    = 54
  const circ = 2 * Math.PI * r
  const fill = score != null ? circ * (score / 100) : 0
  const cfg  = RISK_CFG[riskLevel] || RISK_CFG.unknown

  return (
    <div className="flex flex-col items-center select-none">
      <div className="relative w-32 h-32">
        <svg viewBox="0 0 128 128" className="w-full h-full -rotate-90">
          <circle cx="64" cy="64" r={r} fill="none" stroke="#F3F4F6" strokeWidth="10" />
          {score != null && (
            <circle
              cx="64" cy="64" r={r} fill="none"
              stroke={cfg.color} strokeWidth="10" strokeLinecap="round"
              strokeDasharray={`${fill} ${circ - fill}`}
            />
          )}
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          {score != null
            ? <><span className={`text-3xl font-bold ${cfg.cls}`}>{score}</span><span className="text-[10px] text-gray-300 font-semibold">/100</span></>
            : <span className="text-gray-300 text-xs">—</span>
          }
        </div>
      </div>
      {riskLevel && riskLevel !== 'unknown' && (
        <span className={`text-xs font-bold px-3 py-1 rounded-full border mt-1 ${cfg.pill}`}>
          {cfg.label}
        </span>
      )}
    </div>
  )
}

// ── Findings Panel ───────────────────────────────────────────────────────────

// Sprint 9E.1 + 9E.2: numeric confidence → CSS class for badge rendering.
// ≥90 verified (green), ≥80 strong (emerald), ≥70 probable (amber), <70 weak (gray)
function confidenceStyle(n) {
  if (n == null) return 'bg-gray-100 text-gray-500 border-gray-200'
  if (n >= 90)   return 'bg-green-50 text-green-700 border-green-100'
  if (n >= 80)   return 'bg-emerald-50 text-emerald-700 border-emerald-100'
  if (n >= 70)   return 'bg-amber-50 text-amber-700 border-amber-100'
  return 'bg-gray-100 text-gray-500 border-gray-200'
}

// Sprint 9E.2: CSS class map for validation_quality and evidence_quality fields.
// excellent → green, good → emerald, partial → amber, weak/missing → gray
const QUALITY_STYLE = {
  excellent: 'bg-green-50 text-green-700 border-green-100',
  good:      'bg-emerald-50 text-emerald-700 border-emerald-100',
  partial:   'bg-amber-50 text-amber-700 border-amber-100',
  weak:      'bg-gray-100 text-gray-500 border-gray-200',
  missing:   'bg-gray-100 text-gray-400 border-gray-200',
}

function qualityLabel(q) {
  if (!q) return null
  return q.charAt(0).toUpperCase() + q.slice(1)
}

// Sprint 9E.1 (array support) + 9E.2 (Phase 4–5: table rows + verification command).
// Accepts evidence as Sprint 9C array [{type,label,value,source,...}] or legacy object.
// Confidence and quality badges moved to FindingRow — not repeated here.
function EvidencePanel({ evidence }) {
  if (!evidence) return null

  // Normalize: Sprint 9C produces arrays; pre-9C scans may have legacy objects
  const items = Array.isArray(evidence) ? evidence : [evidence]

  return (
    <div className="mt-2 rounded-xl border border-gray-100 bg-gray-50 overflow-hidden">
      <div className="px-3 py-2 bg-gray-100 border-b border-gray-200 flex items-center gap-1.5">
        <Terminal className="w-3 h-3 text-gray-400" />
        <span className="text-[10px] font-semibold text-gray-500 uppercase tracking-wide">Evidence</span>
      </div>
      {items.map((item, idx) => {
        // Support Sprint 9C array-item format (type/label/value) and legacy object format
        // (evidence_type/probe_target/observed_value). Other fields share names in both formats.
        const type   = item.type  ?? item.evidence_type  ?? null
        const lbl    = item.label ?? item.probe_target   ?? null
        const valRaw = item.value !== undefined ? item.value : item.observed_value
        const hasVal = valRaw !== undefined
        const src    = item.source ?? null
        const exp    = item.expected_value ?? null
        const chk    = item.checked_at ?? null
        const stat   = item.status_code  ?? null
        const mhdr   = item.missing_header ?? null
        const mvc    = item.manual_verification_command ?? null

        const rows = [
          type  && ['Type',           String(type)],
          lbl   && ['Target',         String(lbl)],
          hasVal && ['Observed',      String(valRaw ?? 'null (no record found)')],
          exp   && ['Expected',       String(exp)],
          src   && ['Source',         String(src)],
          chk   && ['Checked at',     new Date(chk).toLocaleString()],
          stat  && ['HTTP status',    String(stat)],
          mhdr  && ['Missing header', String(mhdr)],
        ].filter(Boolean)

        return (
          <div key={idx}>
            {items.length > 1 && idx > 0 && <div className="border-t border-gray-200" />}
            <div className="divide-y divide-gray-100">
              {rows.map(([label, value]) => (
                <div key={label} className="flex gap-3 px-3 py-1.5 text-xs">
                  <span className="text-gray-400 flex-shrink-0 w-24">{label}</span>
                  <span className="text-gray-700 font-mono break-all">{value}</span>
                </div>
              ))}
            </div>
            {/* Phase 5 — Verification Command */}
            {mvc && (
              <div className="border-t border-gray-200 px-3 py-2">
                <p className="text-[10px] font-semibold text-gray-400 uppercase tracking-wide mb-1">
                  Verification Command
                </p>
                <pre className="text-[10px] font-mono text-gray-700 bg-white border border-gray-200 rounded px-2 py-1.5 overflow-x-auto whitespace-pre-wrap break-all select-all">
                  {mvc}
                </pre>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

// Sprint 9E.2 — FindingRow with full trust layer display.
// Phases 1–3: confidence badge, validation_quality badge, evidence_quality badge.
// Phase 6: low-confidence warning always visible (not gated on evidence panel open).
// Phase 7: evidence panel collapsed by default; badges compact; no excessive height.
function FindingRow({ f, index }) {
  const [open, setOpen] = useState(false)

  // Normalize evidence: Sprint 9C always array; legacy scans may have object
  const hasEvidence = Array.isArray(f.evidence) ? f.evidence.length > 0 : !!f.evidence

  // evidence_quality set by applyEvidenceQuality() in Worker; fallback to legacy location
  const evidenceQuality = f.evidence_quality
    ?? (Array.isArray(f.evidence) ? null : f.evidence?.evidence_quality)
    ?? null

  // Phase 6: low-confidence finding — always visible, not inside collapsible panel
  const isLowConf = typeof f.confidence === 'number' && f.confidence < 70

  return (
    <li className="px-6 py-4">
      <div className="flex items-start gap-4">
        {/* Severity-colored index number */}
        <div className={`w-6 h-6 rounded-lg flex items-center justify-center text-[10px] font-bold flex-shrink-0 mt-0.5 ${SEV_STYLE[f.severity] || SEV_STYLE.info}`}>
          {index + 1}
        </div>

        <div className="flex-1 min-w-0">
          {/* Title + severity badge on same row */}
          <div className="flex items-start justify-between gap-2">
            <p className="text-sm font-semibold text-gray-900 leading-snug">{f.title}</p>
            <span className={`flex-shrink-0 text-xs ${SEV_BADGE[f.severity] || SEV_BADGE.info}`}>
              {f.severity}
            </span>
          </div>

          {/* Description */}
          <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{f.description}</p>

          {/* Trust badges row — Phase 1, 2, 3 + score impact + evidence toggle */}
          <div className="flex items-center gap-1.5 mt-2 flex-wrap">
            {/* Phase 1 — Confidence badge */}
            {f.confidence != null && (
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${confidenceStyle(f.confidence)}`}>
                {f.confidence} Confidence
              </span>
            )}

            {/* Phase 2 — Validation quality badge */}
            {f.validation_quality && (
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${QUALITY_STYLE[f.validation_quality] || QUALITY_STYLE.weak}`}>
                Validation: {qualityLabel(f.validation_quality)}
              </span>
            )}

            {/* Phase 3 — Evidence quality badge (skip "missing" — conveys nothing useful inline) */}
            {evidenceQuality && evidenceQuality !== 'missing' && (
              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${QUALITY_STYLE[evidenceQuality] || QUALITY_STYLE.weak}`}>
                Evidence: {qualityLabel(evidenceQuality)}
              </span>
            )}

            {/* Score impact */}
            {f.score_impact != null && f.score_impact !== 0 && (
              <span className="text-[10px] font-semibold text-red-400">
                {f.score_impact} pts
              </span>
            )}

            {/* Evidence toggle — pushed to the right */}
            {hasEvidence && (
              <button
                onClick={() => setOpen(o => !o)}
                className="flex items-center gap-1 text-[10px] text-brand-600 font-semibold hover:text-brand-800 transition-colors ml-auto"
              >
                <ChevronDown className={`w-3 h-3 transition-transform ${open ? 'rotate-180' : ''}`} />
                {open ? 'Hide evidence' : 'Show evidence'}
              </button>
            )}
          </div>

          {/* Phase 6 — Low confidence warning: always visible, not inside panel */}
          {isLowConf && (
            <div className="mt-2 flex items-start gap-2 rounded-lg bg-amber-50 border border-amber-100 px-3 py-2">
              <AlertCircle className="w-3 h-3 text-amber-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-[10px] font-bold text-amber-700">Needs Verification</p>
                <p className="text-[10px] text-amber-600 leading-relaxed mt-0.5">
                  This finding is based on a weak signal and should be manually verified before remediation decisions are made.
                </p>
              </div>
            </div>
          )}

          {/* Phase 4 — Evidence panel: collapsed by default */}
          {open && hasEvidence && (
            <EvidencePanel evidence={f.evidence} />
          )}
        </div>
      </div>
    </li>
  )
}

function FindingsPanel({ findings }) {
  const sorted = [...(findings || [])].sort(
    (a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
  )

  if (sorted.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 py-10 text-center">
        <div className="w-10 h-10 rounded-2xl bg-brand-50 flex items-center justify-center">
          <CheckCircle className="w-5 h-5 text-brand-600" />
        </div>
        <p className="text-sm font-semibold text-gray-700">No findings detected</p>
        <p className="text-xs text-gray-400">This domain passed all checks.</p>
      </div>
    )
  }

  return (
    <ul className="divide-y divide-gray-50">
      {sorted.map((f, i) => (
        <FindingRow key={f.id || i} f={f} index={i} />
      ))}
    </ul>
  )
}

// ── Recommendations Panel ────────────────────────────────────────────────────

function RecommendationsPanel({ recommendations }) {
  if (!recommendations?.length) {
    return (
      <div className="px-6 py-6 text-sm text-gray-400">No recommendations.</div>
    )
  }
  return (
    <ul className="divide-y divide-gray-50">
      {recommendations.map((r, i) => (
        <li key={i} className="flex items-start gap-4 px-6 py-4">
          <div className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold text-white flex-shrink-0 mt-0.5 bg-brand-600">
            {r.priority || i + 1}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-semibold text-gray-900">{r.title}</p>
            <p className="text-xs text-gray-400 mt-0.5 leading-relaxed">{r.description}</p>
          </div>
        </li>
      ))}
    </ul>
  )
}

// ── Boolean Check Row ────────────────────────────────────────────────────────

function CheckRow({ label, value, trueLabel = 'Yes', falseLabel = 'No' }) {
  return (
    <div className="flex items-center justify-between px-6 py-3 border-b border-gray-50 last:border-0">
      <span className="text-sm text-gray-600">{label}</span>
      {value == null
        ? <span className="text-xs text-gray-300">—</span>
        : value
          ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full">
              <CheckCircle className="w-3 h-3" /> {trueLabel}
            </span>
          : <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-50 border border-red-100 px-2 py-0.5 rounded-full">
              <XCircle className="w-3 h-3" /> {falseLabel}
            </span>
      }
    </div>
  )
}

// ── DNS Module Panel ─────────────────────────────────────────────────────────

function DnsPanel({ dns }) {
  if (!dns || dns.error) {
    return <div className="px-6 py-4 text-sm text-gray-400">{dns?.error || 'No DNS data'}</div>
  }
  return (
    <div className="divide-y divide-gray-50">
      <CheckRow label="Domain resolves (A/AAAA)"  value={dns.resolves} trueLabel="Resolves" falseLabel="Does not resolve" />
      <CheckRow label="IPv6 support (AAAA record)" value={dns.has_ipv6}  trueLabel="Enabled"  falseLabel="Not enabled" />
      <CheckRow label="MX records present"          value={dns.has_mx}   trueLabel="Present"  falseLabel="Not found" />
      {dns.nameservers?.length > 0 && (
        <div className="px-6 py-3 border-b border-gray-50">
          <p className="text-sm text-gray-600 mb-1">Nameservers</p>
          <p className="text-xs text-gray-400 mono">{dns.nameservers.join(', ')}</p>
        </div>
      )}
      {dns.a_records?.length > 0 && (
        <div className="px-6 py-3 border-b border-gray-50">
          <p className="text-sm text-gray-600 mb-1">A records</p>
          <p className="text-xs text-gray-400 mono">{dns.a_records.map(r => r.value).join(', ')}</p>
        </div>
      )}
      {dns.aaaa_records?.length > 0 && (
        <div className="px-6 py-3">
          <p className="text-sm text-gray-600 mb-1">AAAA records</p>
          <p className="text-xs text-gray-400 mono">{dns.aaaa_records.map(r => r.value).join(', ')}</p>
        </div>
      )}
    </div>
  )
}

// ── SSL Module Panel ─────────────────────────────────────────────────────────

function SslPanel({ ssl }) {
  if (!ssl || ssl.error) {
    return <div className="px-6 py-4 text-sm text-gray-400">{ssl?.error || 'No SSL data'}</div>
  }
  return (
    <div className="divide-y divide-gray-50">
      <CheckRow label="HTTPS available"              value={ssl.https_available}       trueLabel="Available"    falseLabel="Not available" />
      <CheckRow label="HTTP redirects to HTTPS"      value={ssl.http_redirects_to_https} trueLabel="Redirects" falseLabel="No redirect" />
      {ssl.www_fallback_used && (
        <div className="px-6 py-3 text-xs text-amber-600 bg-amber-50">
          HTTPS only available via www. subdomain — bare domain did not respond.
        </div>
      )}
    </div>
  )
}

// ── Headers Module Panel ─────────────────────────────────────────────────────

const HEADER_LABELS = {
  'strict-transport-security': 'Strict-Transport-Security (HSTS)',
  'content-security-policy':   'Content-Security-Policy',
  'x-frame-options':           'X-Frame-Options',
  'x-content-type-options':    'X-Content-Type-Options',
  'referrer-policy':           'Referrer-Policy',
  'permissions-policy':        'Permissions-Policy',
}

function HeadersPanel({ headers }) {
  if (!headers || headers.error) {
    return <div className="px-6 py-4 text-sm text-gray-400">{headers?.error || 'No header data'}</div>
  }
  if (!headers.accessible) {
    return <div className="px-6 py-4 text-sm text-gray-400">Site was not reachable for header analysis.</div>
  }

  const allHeaders = Object.keys(HEADER_LABELS)
  return (
    <div className="divide-y divide-gray-50">
      {allHeaders.map(h => {
        const present = headers.present?.includes(h)
        const val     = headers.values?.[h]
        return (
          <div key={h} className="px-6 py-3">
            <div className="flex items-center justify-between mb-0.5">
              <span className="text-sm text-gray-700 font-medium">{HEADER_LABELS[h]}</span>
              {present
                ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full"><CheckCircle className="w-3 h-3" />Present</span>
                : <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-50 border border-red-100 px-2 py-0.5 rounded-full"><XCircle className="w-3 h-3" />Missing</span>
              }
            </div>
            {val && <p className="text-[11px] text-gray-400 mono mt-1 break-all">{val}</p>}
          </div>
        )
      })}
    </div>
  )
}

// ── Email Security Panel ─────────────────────────────────────────────────────

function EmailPanel({ email }) {
  if (!email || email.error) {
    return <div className="px-6 py-4 text-sm text-gray-400">{email?.error || 'No email security data'}</div>
  }
  const { spf, dmarc, dkim } = email

  const dmarcPolicyColor =
    dmarc?.policy === 'reject'      ? 'text-brand-700 bg-brand-50 border-brand-100' :
    dmarc?.policy === 'quarantine'  ? 'text-amber-700 bg-amber-50 border-amber-100' :
    dmarc?.policy === 'none'        ? 'text-red-700 bg-red-50 border-red-100'       :
    'text-gray-500 bg-gray-100 border-gray-200'

  return (
    <div className="divide-y divide-gray-50">
      {/* SPF */}
      <div className="px-6 py-3">
        <div className="flex items-center justify-between mb-0.5">
          <span className="text-sm text-gray-700 font-medium">SPF Record</span>
          {spf?.present
            ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full"><CheckCircle className="w-3 h-3" />Present</span>
            : <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-50 border border-red-100 px-2 py-0.5 rounded-full"><XCircle className="w-3 h-3" />Missing</span>
          }
        </div>
        {spf?.record && <p className="text-[11px] text-gray-400 mono mt-1 break-all">{spf.record}</p>}
      </div>

      {/* DMARC */}
      <div className="px-6 py-3">
        <div className="flex items-center justify-between mb-0.5">
          <span className="text-sm text-gray-700 font-medium">DMARC Policy</span>
          <div className="flex items-center gap-2">
            {dmarc?.policy && (
              <span className={`text-xs font-bold px-2 py-0.5 rounded-full border ${dmarcPolicyColor}`}>
                p={dmarc.policy}
              </span>
            )}
            {dmarc?.present
              ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full"><CheckCircle className="w-3 h-3" />Present</span>
              : <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 bg-red-50 border border-red-100 px-2 py-0.5 rounded-full"><XCircle className="w-3 h-3" />Missing</span>
            }
          </div>
        </div>
        {dmarc?.record && <p className="text-[11px] text-gray-400 mono mt-1 break-all">{dmarc.record}</p>}
      </div>

      {/* DKIM */}
      <div className="px-6 py-3">
        <div className="flex items-center justify-between mb-0.5">
          <span className="text-sm text-gray-700 font-medium">DKIM Signing</span>
          {dkim?.present
            ? <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700 bg-brand-50 border border-brand-100 px-2 py-0.5 rounded-full"><CheckCircle className="w-3 h-3" />Detected</span>
            : <span className="inline-flex items-center gap-1 text-xs font-semibold text-amber-700 bg-amber-50 border border-amber-100 px-2 py-0.5 rounded-full"><AlertCircle className="w-3 h-3" />Not detected</span>
          }
        </div>
        {dkim?.selector && (
          <p className="text-[11px] text-gray-400 mt-1">Selector: <span className="mono">{dkim.selector}</span></p>
        )}
        {!dkim?.present && (
          <p className="text-[11px] text-gray-400 mt-1">Common selectors probed — custom selector may be in use.</p>
        )}
      </div>
    </div>
  )
}

// ── Historical Changes ───────────────────────────────────────────────────────

/**
 * A row of labelled pills showing changed items (new subdomains, findings, etc.)
 * tone: 'bad' (red) | 'good' (green/brand) | 'neutral' (amber)
 */
function ChangeList({ title, items, total, renderItem, tone }) {
  const toneStyle = {
    bad:     'bg-red-50 text-red-700',
    good:    'bg-brand-50 text-brand-700',
    neutral: 'bg-amber-50 text-amber-700',
  }[tone] || 'bg-gray-100 text-gray-600'

  const overflow = (total ?? items.length) - items.length

  return (
    <div className="px-6 py-3 border-b border-gray-50 last:border-0">
      <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide mb-2">
        {title}{' '}
        <span className="font-normal text-gray-300 normal-case tracking-normal">({total ?? items.length})</span>
      </p>
      <div className="flex flex-wrap gap-1.5">
        {items.map((item, i) => (
          <span key={i} className={`inline-flex items-center px-2 py-0.5 rounded mono text-xs ${toneStyle}`}>
            {renderItem(item)}
          </span>
        ))}
        {overflow > 0 && (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs bg-gray-100 text-gray-400">
            +{overflow} more
          </span>
        )}
      </div>
    </div>
  )
}

function ChangesPanel({ changes }) {
  if (!changes) return null

  if (!changes.has_previous) {
    return (
      <div className="px-6 py-5 flex items-center gap-2.5 text-sm text-gray-400">
        <History className="w-4 h-4 flex-shrink-0 text-gray-300" />
        First scan for this domain — no historical data to compare against.
      </div>
    )
  }

  const delta = changes.score_change
  const deltaStr = delta != null
    ? (delta > 0 ? `+${delta}` : String(delta))
    : null
  const deltaColor =
    delta > 0  ? 'text-brand-600' :
    delta < 0  ? 'text-red-500'   : 'text-gray-400'

  const noChanges =
    changes.new_subdomains.length === 0 &&
    changes.removed_subdomains.length === 0 &&
    changes.new_findings.length === 0 &&
    changes.resolved_findings.length === 0 &&
    changes.new_takeover_risks.length === 0 &&
    changes.new_exposed_assets.length === 0

  return (
    <div className="divide-y divide-gray-50">

      {/* Score comparison */}
      <div className="px-6 py-4 flex items-center justify-between gap-4">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-gray-900">Score Comparison</p>
          <p className="text-[11px] text-gray-300 mono mt-0.5 truncate">vs {changes.previous_scan_id}</p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 text-sm">
          <span className="text-gray-400">{changes.previous_score ?? '—'}</span>
          <span className="text-gray-200">→</span>
          <span className="font-bold text-gray-900">{changes.current_score}</span>
          {deltaStr && (
            <span className={`font-bold ${deltaColor}`}>({deltaStr})</span>
          )}
        </div>
      </div>

      {noChanges ? (
        <div className="px-6 py-4 flex items-center gap-2 text-sm text-gray-400">
          <CheckCircle className="w-4 h-4 text-brand-500 flex-shrink-0" />
          No changes detected since the previous scan.
        </div>
      ) : (
        <>
          {changes.new_findings.length > 0 && (
            <ChangeList title="New Findings" items={changes.new_findings.slice(0, 5)}
              total={changes.new_findings.length}
              renderItem={f => f.title} tone="bad" />
          )}
          {changes.resolved_findings.length > 0 && (
            <ChangeList title="Resolved Findings" items={changes.resolved_findings.slice(0, 5)}
              total={changes.resolved_findings.length}
              renderItem={f => f.title} tone="good" />
          )}
          {changes.new_takeover_risks.length > 0 && (
            <ChangeList title="New Takeover Risks" items={changes.new_takeover_risks.slice(0, 5)}
              total={changes.new_takeover_risks.length}
              renderItem={r => r.host} tone="bad" />
          )}
          {changes.new_exposed_assets.length > 0 && (
            <ChangeList title="New Exposed Assets" items={changes.new_exposed_assets.slice(0, 5)}
              total={changes.new_exposed_assets.length}
              renderItem={a => a.host} tone="neutral" />
          )}
          {changes.new_subdomains.length > 0 && (
            <ChangeList title="New Subdomains" items={changes.new_subdomains.slice(0, 5)}
              total={changes.new_subdomains.length}
              renderItem={h => h} tone="neutral" />
          )}
          {changes.removed_subdomains.length > 0 && (
            <ChangeList title="Removed Subdomains" items={changes.removed_subdomains.slice(0, 5)}
              total={changes.removed_subdomains.length}
              renderItem={h => h} tone="good" />
          )}
        </>
      )}
    </div>
  )
}

// ── Business Risk Card ───────────────────────────────────────────────────────

function BusinessRiskCard({ businessRisk }) {
  if (!businessRisk) return null
  const { score, band, summary, categories = {}, top_business_risks: topRisks = [] } = businessRisk

  const bandColor =
    score >= 90 ? 'text-emerald-700 bg-emerald-50 border-emerald-200' :
    score >= 70 ? 'text-blue-700   bg-blue-50   border-blue-200'   :
    score >= 40 ? 'text-amber-700  bg-amber-50  border-amber-100'  :
                  'text-red-700    bg-red-50    border-red-200'

  const scoreColor =
    score >= 90 ? 'text-emerald-600' :
    score >= 70 ? 'text-blue-600'   :
    score >= 40 ? 'text-amber-600'  :
                  'text-red-600'

  const TrendIcon = score >= 70 ? TrendingUp : score >= 40 ? Minus : TrendingDown

  const CAT_LABELS = {
    email_trust:             'Email Trust',
    website_trust:           'Website Trust',
    operational_continuity:  'Continuity',
    attack_surface_exposure: 'Attack Surface',
    brand_reputation_risk:   'Brand Risk',
  }

  const catEntries = Object.entries(CAT_LABELS).map(([key, label]) => ({
    key, label, score: categories[key]?.score ?? null,
  }))

  return (
    <div className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-100 flex items-center gap-2">
        <TrendIcon className={`w-4 h-4 ${scoreColor}`} />
        <h3 className="text-sm font-bold text-gray-900">Business Risk Score</h3>
      </div>

      {/* Score badge */}
      <div className="px-6 pt-4 pb-3">
        <div className={`inline-flex items-center gap-3 rounded-xl border px-4 py-3 w-full ${bandColor}`}>
          <span className={`text-3xl font-black leading-none ${scoreColor}`}>{score}</span>
          <div className="min-w-0">
            <p className="text-[10px] font-semibold uppercase tracking-widest opacity-60 leading-tight">/ 100</p>
            <p className="text-xs font-semibold leading-tight mt-0.5">{band}</p>
          </div>
        </div>
        {summary && (
          <p className="text-xs text-gray-500 mt-2 leading-relaxed line-clamp-3">{summary}</p>
        )}
      </div>

      {/* Category mini-scores */}
      <div className="px-6 pb-3 space-y-1.5">
        {catEntries.map(({ key, label, score: catScore }) => {
          if (catScore === null) return null
          const pct = Math.max(0, Math.min(100, catScore))
          const bar = catScore >= 80 ? 'bg-emerald-500' : catScore >= 60 ? 'bg-blue-500' : catScore >= 40 ? 'bg-amber-500' : 'bg-red-500'
          const txt = catScore >= 80 ? 'text-emerald-700' : catScore >= 60 ? 'text-blue-700' : catScore >= 40 ? 'text-amber-700' : 'text-red-600'
          return (
            <div key={key}>
              <div className="flex justify-between items-center mb-0.5">
                <span className="text-[11px] text-gray-500">{label}</span>
                <span className={`text-[11px] font-bold ${txt}`}>{catScore}</span>
              </div>
              <div className="h-1 rounded-full bg-gray-100 overflow-hidden">
                <div className={`h-full ${bar} transition-all`} style={{ width: `${pct}%` }} />
              </div>
            </div>
          )
        })}
      </div>

      {/* Top 3 risks */}
      {topRisks.length > 0 && (
        <div className="border-t border-gray-100 px-6 py-3 space-y-2">
          <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-400">Top Risks</p>
          {topRisks.slice(0, 3).map((r, i) => {
            const sev = r.severity ?? 'medium'
            const dot = sev === 'critical' ? 'bg-red-500' : sev === 'high' ? 'bg-orange-500' : 'bg-amber-400'
            return (
              <div key={i} className="flex items-start gap-2">
                <div className={`w-1.5 h-1.5 rounded-full ${dot} flex-shrink-0 mt-1.5`} />
                <p className="text-xs text-gray-600 leading-snug">{r.title ?? r.category ?? ''}</p>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Report View ──────────────────────────────────────────────────────────────

function ReportView({ report }) {
  const { cyber_metrics_score: score, risk_level, findings, recommendations, modules, scan_quality } = report
  const duration = durationSeconds(report.started_at, report.completed_at)
  const showQualityWarning = scan_quality?.status === 'degraded' || scan_quality?.status === 'partial'
  const skippedModules = scan_quality?.modules_skipped || []
  const qualityWarnings = scan_quality?.warnings || []

  return (
    <div className="space-y-4">

      {/* Score hero */}
      <div className="card-md overflow-hidden">
        <div className="flex flex-col sm:flex-row items-center sm:items-stretch">
          {/* Ring */}
          <div className="flex flex-col items-center justify-center gap-2 px-8 py-6 sm:border-r border-gray-100 sm:min-w-[180px]">
            <span className="label text-[10px]">Cyber Metrics Score</span>
            <ScoreRing score={score} riskLevel={risk_level} />
          </div>

          {/* Quick counts */}
          <div className="flex-1 grid grid-cols-3 divide-x divide-gray-100">
            {[
              { label: 'Findings',      value: findings?.length ?? 0 },
              { label: 'Actions',       value: recommendations?.length ?? 0 },
              { label: 'Scan Duration', value: duration ?? '—' },
            ].map(({ label, value }) => (
              <div key={label} className="flex flex-col items-center justify-center py-6 gap-1">
                <span className="text-2xl font-bold text-gray-900">{value}</span>
                <span className="text-xs font-medium text-gray-400">{label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {showQualityWarning && (
        <div className="rounded-xl border border-amber-100 bg-amber-50 px-4 py-3 flex items-start gap-3 text-sm text-amber-800">
          <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <div>
            <p className="font-semibold">Scan coverage {scan_quality.status}</p>
            {skippedModules.length > 0 && (
              <p className="text-xs mt-0.5">
                Skipped modules: {skippedModules.slice(0, 4).join(', ')}
              </p>
            )}
            {qualityWarnings.slice(0, 2).map((warning, i) => (
              <p key={i} className="text-xs mt-0.5">{warning}</p>
            ))}
            {skippedModules.length === 0 && qualityWarnings.length === 0 && (
              <p className="text-xs mt-0.5">Some scan coverage may be incomplete.</p>
            )}
          </div>
        </div>
      )}

      {/* Findings */}
      <div className="card overflow-hidden">
        <SectionHeader icon={AlertCircle} title={`Findings (${findings?.length ?? 0})`} />
        <FindingsPanel findings={findings} />
      </div>

      {/* Recommendations */}
      <div className="card overflow-hidden">
        <SectionHeader icon={Shield} title={`Recommended Actions (${recommendations?.length ?? 0})`} />
        <RecommendationsPanel recommendations={recommendations} />
      </div>

      {/* Changes Since Last Scan */}
      {modules?.historical_changes && (
        <div className="card overflow-hidden">
          <SectionHeader icon={History} title="Changes Since Last Scan" />
          <ChangesPanel changes={modules.historical_changes} />
        </div>
      )}

      {/* DNS */}
      <div className="card overflow-hidden">
        <SectionHeader icon={Server} title="DNS Analysis" />
        <DnsPanel dns={modules?.dns} />
      </div>

      {/* SSL */}
      <div className="card overflow-hidden">
        <SectionHeader icon={Lock} title="SSL / HTTPS" />
        <SslPanel ssl={modules?.ssl} />
      </div>

      {/* Security Headers */}
      <div className="card overflow-hidden">
        <SectionHeader icon={FileText} title="Security Headers" />
        <HeadersPanel headers={modules?.headers} />
      </div>

      {/* Email Security */}
      <div className="card overflow-hidden">
        <SectionHeader icon={Mail} title="Email Security (SPF · DMARC · DKIM)" />
        <EmailPanel email={modules?.email_security} />
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────────────────

export default function ScanDetail() {
  const { id }  = useParams()
  const navigate = useNavigate()

  const [scan,          setScan]          = useState(null)
  const [loading,       setLoading]       = useState(true)
  const [error,         setError]         = useState(null)
  const [refreshing,    setRefreshing]    = useState(false)
  const [report,        setReport]        = useState(null)
  const [reportLoading, setReportLoading] = useState(false)
  const [reportError,   setReportError]   = useState(null)
  const pollRef = useRef(null)

  const loadReport = useCallback(async () => {
    setReportLoading(true)
    setReportError(null)
    try {
      const r = await api.getScanReport(id)
      setReport(r)
    } catch (e) {
      setReportError(e.message)
    } finally {
      setReportLoading(false)
    }
  }, [id])

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const data = await api.getScan(id)
      const s    = data.scan || data
      setScan(s)
      if (s.status === 'completed' && !report) {
        loadReport()
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [id, report, loadReport])

  useEffect(() => { load() }, [load])

  // Auto-poll while active; fetch report when transitioning to completed
  useEffect(() => {
    if (!scan) return
    if (ACTIVE.has(scan.status)) {
      pollRef.current = setInterval(() => load(true), POLL_MS)
    } else {
      clearInterval(pollRef.current)
      if (scan.status === 'completed' && !report && !reportLoading) {
        loadReport()
      }
    }
    return () => clearInterval(pollRef.current)
  }, [scan?.status]) // eslint-disable-line react-hooks/exhaustive-deps

  const isActive = scan && ACTIVE.has(scan.status)

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">
      <Link to="/scans" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-brand-600 transition-colors font-medium">
        <ArrowLeft className="w-4 h-4" />
        Back to Scans
      </Link>

      {loading ? (
        <div className="flex items-center justify-center py-32"><Spinner size="lg" /></div>
      ) : error ? (
        <ErrorAlert message={error} onRetry={() => load()} />
      ) : !scan ? null : (
        <>
          {/* Page header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <h1 className="text-xl font-bold text-gray-900 truncate">{scan.domain}</h1>
                <StatusBadge status={scan.status} />
              </div>
              <p className="mono text-xs text-gray-300">{scan.id}</p>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <button onClick={() => navigate(`/domain/${encodeURIComponent(scan.domain)}/history`)} className="btn-secondary">
                <Globe className="w-4 h-4" />
                Domain History
              </button>
              <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
                <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>
          </div>

          {/* Active banner */}
          {isActive && (
            <div className="flex items-center gap-3 px-4 py-3 bg-amber-50 border border-amber-100 rounded-xl text-sm">
              <Spinner size="sm" />
              <span className="text-amber-800 font-medium">
                Scan is {scan.status} — auto-refreshing every {POLL_MS / 1000}s
              </span>
            </div>
          )}

          {/* Main grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Report panel — 2/3 width */}
            <div className="lg:col-span-2">
              {scan.status === 'completed' ? (
                reportLoading ? (
                  <div className="card flex items-center justify-center py-24">
                    <Spinner size="lg" />
                  </div>
                ) : reportError ? (
                  <ErrorAlert message={reportError} onRetry={loadReport} />
                ) : report ? (
                  <ReportView report={report} />
                ) : null
              ) : scan.status === 'failed' ? (
                <div className="card flex items-start gap-3 px-6 py-6 text-red-700">
                  <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-bold text-sm">Scan failed</p>
                    <p className="text-xs text-red-400 mt-1">The scan engine encountered an error. Try re-scanning this domain.</p>
                  </div>
                </div>
              ) : (
                <div className="card flex flex-col items-center gap-4 py-20 text-center">
                  <div className="w-12 h-12 rounded-2xl bg-brand-50 flex items-center justify-center">
                    <ScanLine className="w-5 h-5 text-brand-600" />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-gray-900">Scan in progress</p>
                    <p className="text-xs text-gray-400 mt-1">Results will appear here once complete</p>
                  </div>
                  <Spinner />
                </div>
              )}
            </div>

            {/* Sidebar */}
            <div className="space-y-4">

              {/* Scan info */}
              <div className="card overflow-hidden">
                <SectionHeader icon={Hash} title="Scan Information" />
                <div>
                  <KV label="Scan ID"   value={<span className="mono text-xs text-brand-600">{scan.id}</span>} />
                  <KV label="Domain"    value={scan.domain} />
                  <KV label="Status"    value={<StatusBadge status={scan.status} />} />
                  <KV label="Score"     value={
                    scan.score != null
                      ? <span className="font-bold text-brand-600">{scan.score} / 100</span>
                      : '—'
                  } />
                  <KV label="Risk Level" value={
                    scan.rating
                      ? <span className={`text-xs font-bold px-2 py-0.5 rounded-full border capitalize ${(RISK_CFG[scan.rating] || RISK_CFG.unknown).pill}`}>
                          {scan.rating}
                        </span>
                      : '—'
                  } />
                  <KV label="Created"   value={formatDate(scan.created_at)} />
                  {report?.started_at   && <KV label="Started"   value={formatDate(report.started_at)} />}
                  {report?.completed_at && <KV label="Completed" value={formatDate(report.completed_at)} />}
                </div>
              </div>

              {/* Quick actions */}
              <div className="card overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-100">
                  <h3 className="text-sm font-bold text-gray-900">Quick Actions</h3>
                </div>
                <div className="divide-y divide-gray-50">
                  {[
                    { icon: Globe,    label: 'View domain history',    action: () => navigate(`/domain/${encodeURIComponent(scan.domain)}/history`), color: 'bg-blue-50 text-blue-600'   },
                    { icon: ScanLine, label: 'Scan this domain again', action: () => navigate('/scans/new'), color: 'bg-brand-50 text-brand-600'  },
                    { icon: Clock,    label: 'Back to all scans',      action: () => navigate('/scans'),     color: 'bg-gray-100 text-gray-500'   },
                    { icon: Shield,   label: 'Back to dashboard',      action: () => navigate('/dashboard'), color: 'bg-gray-100 text-gray-500'   },
                  ].map(({ icon: Icon, label, action, color }) => (
                    <button key={label} onClick={action} className="w-full flex items-center gap-3 px-6 py-3.5 text-sm text-gray-700 hover:bg-brand-50 transition-colors group">
                      <div className={`w-7 h-7 rounded-lg ${color} flex items-center justify-center`}>
                        <Icon className="w-3.5 h-3.5" />
                      </div>
                      <span className="flex-1 text-left">{label}</span>
                      <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-brand-500" />
                    </button>
                  ))}
                </div>
              </div>

              {/* Business Risk Score */}
              {report?.business_risk && (
                <BusinessRiskCard businessRisk={report.business_risk} />
              )}

            </div>
          </div>
        </>
      )}
    </div>
  )
}
