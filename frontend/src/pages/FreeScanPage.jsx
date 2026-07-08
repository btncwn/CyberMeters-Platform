/**
 * FreeScanPage — public Cyber MOT lead generation page.
 *
 * Route: /free-scan (public, no auth required, outside Layout shell)
 *
 * The backend contract is owned by Workers:
 *   POST /api/free-scan { domain }
 */
import { useState, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowRight,
  BarChart2,
  CheckCircle,
  ChevronRight,
  ClipboardCheck,
  FileText,
  Globe,
  GraduationCap,
  Lock,
  Mail,
  RefreshCw,
  SearchCheck,
  Shield,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'
import CyberMetersLogo from '../components/CyberMetersLogo'
import { BASE } from '../api'

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']

const SEVERITY_CFG = {
  critical: { dot: 'bg-red-500',    badge: 'bg-red-50 text-red-700 border-red-200',       label: 'Critical', bar: 'bg-red-500' },
  high:     { dot: 'bg-orange-500', badge: 'bg-orange-50 text-orange-700 border-orange-200', label: 'High',     bar: 'bg-orange-500' },
  medium:   { dot: 'bg-amber-400',  badge: 'bg-amber-50 text-amber-700 border-amber-200',    label: 'Medium',   bar: 'bg-amber-400' },
  low:      { dot: 'bg-blue-400',   badge: 'bg-blue-50 text-blue-700 border-blue-200',       label: 'Low',      bar: 'bg-blue-400' },
  info:     { dot: 'bg-gray-300',   badge: 'bg-gray-50 text-gray-600 border-gray-200',       label: 'Info',     bar: 'bg-gray-300' },
}

function sevCfg(severity) {
  return SEVERITY_CFG[severity] ?? SEVERITY_CFG.info
}

const RISK_LEVEL_CFG = {
  excellent: { label: 'Excellent',     text: 'text-brand-700',  ring: 'stroke-brand-500',  bg: 'bg-brand-50',  border: 'border-brand-100' },
  good:      { label: 'Good',          text: 'text-green-700',  ring: 'stroke-green-500',  bg: 'bg-green-50',  border: 'border-green-100' },
  moderate:  { label: 'Moderate',      text: 'text-amber-700',  ring: 'stroke-amber-400',  bg: 'bg-amber-50',  border: 'border-amber-100' },
  critical:  { label: 'Critical Risk', text: 'text-red-700',    ring: 'stroke-red-500',    bg: 'bg-red-50',    border: 'border-red-100' },
  high:      { label: 'High Risk',     text: 'text-orange-700', ring: 'stroke-orange-500', bg: 'bg-orange-50', border: 'border-orange-100' },
  medium:    { label: 'Medium Risk',   text: 'text-amber-700',  ring: 'stroke-amber-400',  bg: 'bg-amber-50',  border: 'border-amber-100' },
  low:       { label: 'Low Risk',      text: 'text-green-700',  ring: 'stroke-green-500',  bg: 'bg-green-50',  border: 'border-green-100' },
  info:      { label: 'No Issues',     text: 'text-brand-700',  ring: 'stroke-brand-500',  bg: 'bg-brand-50',  border: 'border-brand-100' },
}

function riskCfg(riskLevel) {
  return RISK_LEVEL_CFG[riskLevel] ?? RISK_LEVEL_CFG.moderate
}

const LOADING_MESSAGES = [
  'Checking email protection records...',
  'Reviewing website trust signals...',
  'Checking DNS configuration...',
  'Reading security headers...',
  'Preparing your Cyber MOT report...',
]

const EMAIL_KEYWORDS = [
  'dmarc',
  'spf',
  'dkim',
  'mx',
  'mail',
  'email',
  'sender',
  'spoof',
]

const WEBSITE_KEYWORDS = [
  'tls',
  'ssl',
  'certificate',
  'https',
  'header',
  'hsts',
  'csp',
  'dns',
  'domain',
  'subdomain',
  'http',
]

function signupPath(domain) {
  return `/signup${domain ? `?domain=${encodeURIComponent(domain)}` : ''}`
}

function scoreSafe(score) {
  const n = Number(score)
  if (!Number.isFinite(n)) return 0
  return Math.max(0, Math.min(100, n))
}

function findingText(finding) {
  return [
    finding?.module,
    finding?.category,
    finding?.type,
    finding?.title,
    finding?.description,
  ].filter(Boolean).join(' ').toLowerCase()
}

function isEmailFinding(finding) {
  const text = findingText(finding)
  return EMAIL_KEYWORDS.some(keyword => text.includes(keyword))
}

function isWebsiteFinding(finding) {
  const text = findingText(finding)
  return WEBSITE_KEYWORDS.some(keyword => text.includes(keyword))
}

function groupFindings(findings = []) {
  const groups = {
    email: [],
    website: [],
  }

  findings.forEach(finding => {
    if (isEmailFinding(finding)) {
      groups.email.push(finding)
      return
    }
    if (isWebsiteFinding(finding)) {
      groups.website.push(finding)
      return
    }
    groups.website.push(finding)
  })

  return groups
}

function moduleLabel(moduleName) {
  const labels = {
    dns: 'DNS',
    tls: 'TLS',
    ssl: 'TLS',
    headers: 'Headers',
    email: 'Email',
    dmarc: 'DMARC',
    spf: 'SPF',
    dkim: 'DKIM',
  }
  return labels[moduleName] ?? String(moduleName || '').replace(/[_-]/g, ' ')
}

function ScoreGauge({ score, riskLevel }) {
  const cfg = riskCfg(riskLevel)
  const value = scoreSafe(score)
  const radius = 54
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (value / 100) * circumference

  return (
    <div className="flex flex-col items-center">
      <div className="relative h-40 w-40">
        <svg className="h-40 w-40 -rotate-90" viewBox="0 0 128 128" aria-hidden="true">
          <circle cx="64" cy="64" r={radius} fill="none" stroke="#e5e7eb" strokeWidth="11" />
          <circle
            cx="64"
            cy="64"
            r={radius}
            fill="none"
            className={cfg.ring}
            strokeWidth="11"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 700ms ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-4xl font-bold tabular-nums ${cfg.text}`}>{value}</span>
          <span className="text-xs font-semibold text-gray-400">out of 100</span>
        </div>
      </div>
      <span className={`mt-3 inline-flex items-center rounded-full border px-3 py-1 text-sm font-bold ${cfg.text} ${cfg.bg} ${cfg.border}`}>
        {cfg.label}
      </span>
    </div>
  )
}

function SeverityBreakdown({ counts = {} }) {
  const total = SEVERITIES.reduce((sum, severity) => sum + (Number(counts[severity]) || 0), 0)

  if (total === 0) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-green-100 bg-green-50 px-4 py-3 text-sm font-semibold text-green-700">
        <CheckCircle className="h-4 w-4 flex-shrink-0" />
        No issues found in these checks
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {SEVERITIES.map(severity => {
        const count = Number(counts[severity]) || 0
        const cfg = sevCfg(severity)
        return (
          <div key={severity} className="grid grid-cols-[88px_1fr_28px] items-center gap-3">
            <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[11px] font-bold uppercase ${cfg.badge}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${cfg.dot}`} />
              {cfg.label}
            </span>
            <div className="h-2 overflow-hidden rounded-full bg-gray-100">
              <div
                className={`h-full rounded-full ${cfg.bar}`}
                style={{ width: total ? `${(count / total) * 100}%` : '0%' }}
              />
            </div>
            <span className="text-right text-sm font-bold tabular-nums text-gray-700">{count}</span>
          </div>
        )
      })}
    </div>
  )
}

function FindingCard({ finding }) {
  const cfg = sevCfg(finding?.severity)

  return (
    <div className="rounded-xl border border-gray-200 bg-white p-4 shadow-card">
      <div className="flex items-start justify-between gap-3">
        <h4 className="text-sm font-bold leading-snug text-gray-900">{finding?.title || 'Security finding'}</h4>
        <span className={`flex-shrink-0 rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide ${cfg.badge}`}>
          {cfg.label}
        </span>
      </div>
      {finding?.description && (
        <p className="mt-2 text-sm leading-relaxed text-gray-500">{finding.description}</p>
      )}
      {finding?.academy_slug && (
        <Link
          to={`/academy/${finding.academy_slug}`}
          className="mt-3 inline-flex items-center gap-1.5 text-xs font-bold text-brand-600 hover:text-brand-800"
        >
          <GraduationCap className="h-3.5 w-3.5" />
          Plain-English guidance
          <ChevronRight className="h-3 w-3" />
        </Link>
      )}
    </div>
  )
}

function ResultSection({ icon: Icon, title, description, checks, findings }) {
  return (
    <section className="card p-5 sm:p-6">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3">
          <div className="flex h-10 w-10 flex-shrink-0 items-center justify-center rounded-xl bg-brand-50 ring-1 ring-brand-100">
            <Icon className="h-5 w-5 text-brand-600" />
          </div>
          <div>
            <h3 className="text-lg font-bold tracking-tight text-gray-900">{title}</h3>
            <p className="mt-1 text-sm leading-relaxed text-gray-500">{description}</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2 sm:justify-end">
          {checks.map(check => (
            <span key={check} className="rounded-full border border-gray-200 bg-gray-50 px-2.5 py-1 text-[11px] font-semibold text-gray-600">
              {check}
            </span>
          ))}
        </div>
      </div>

      <div className="mt-5 space-y-3">
        {findings.length > 0 ? (
          findings.map((finding, index) => (
            <FindingCard key={finding.id || `${title}-${index}`} finding={finding} />
          ))
        ) : (
          <div className="rounded-xl border border-green-100 bg-green-50 px-4 py-3 text-sm font-semibold text-green-700">
            No preview findings in this section.
          </div>
        )}
      </div>
    </section>
  )
}

function HiddenFindingsCta({ count, domain }) {
  if (!count || count <= 0) return null

  return (
    <div className="card-md overflow-hidden border-brand-200 bg-brand-50">
      <div className="grid gap-5 p-6 sm:grid-cols-[1fr_auto] sm:items-center">
        <div className="flex items-start gap-3">
          <div className="flex h-11 w-11 flex-shrink-0 items-center justify-center rounded-xl bg-white ring-1 ring-brand-100">
            <Lock className="h-5 w-5 text-brand-600" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-gray-900">
              {count} more findings found — create a free account to see them all
            </h3>
            <p className="mt-1 text-sm leading-relaxed text-gray-600">
              Unlock the full report, plain-English fixes, PDF export, and ongoing change alerts for this domain.
            </p>
          </div>
        </div>
        <Link to={signupPath(domain)} className="btn-primary whitespace-nowrap">
          Create free account
          <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
    </div>
  )
}

function LoadingState({ domain, messageIdx }) {
  return (
    <div className="card mx-auto max-w-2xl p-8 text-center sm:p-10">
      <div className="relative mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-2xl bg-brand-50">
        <SearchCheck className="h-8 w-8 text-brand-600" />
        <div className="absolute inset-0 rounded-2xl border-2 border-brand-200 opacity-30 animate-ping" />
      </div>
      <h2 className="text-lg font-bold text-gray-900">Preparing Cyber MOT for {domain}</h2>
      <p className="mt-1 text-sm text-gray-500">This usually takes around two minutes or less.</p>
      <div className="mx-auto mt-6 h-1.5 w-full max-w-xs overflow-hidden rounded-full bg-gray-100">
        <div
          className="h-full rounded-full bg-brand-500 transition-all duration-500"
          style={{ width: `${Math.min(95, ((messageIdx + 1) / LOADING_MESSAGES.length) * 100)}%` }}
        />
      </div>
      <p className="mt-5 text-xs font-semibold text-gray-500">{LOADING_MESSAGES[messageIdx] ?? LOADING_MESSAGES[0]}</p>
    </div>
  )
}

export default function FreeScanPage() {
  const [domain, setDomain] = useState('')
  const [scanning, setScanning] = useState(false)
  const [msgIdx, setMsgIdx] = useState(0)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)

  const timerRef = useRef(null)
  const resultsRef = useRef(null)

  function normaliseDomain(value) {
    return value.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
  }

  function startMessageCycle() {
    let idx = 0
    setMsgIdx(0)
    timerRef.current = setInterval(() => {
      idx = Math.min(idx + 1, LOADING_MESSAGES.length - 1)
      setMsgIdx(idx)
    }, 1400)
  }

  function stopMessageCycle() {
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }
  }

  async function handleScan(e) {
    e?.preventDefault()
    const d = normaliseDomain(domain)
    if (!d) return

    setDomain(d)
    setError(null)
    setResult(null)
    setScanning(true)
    startMessageCycle()

    try {
      const apiBase = BASE || ''
      const res = await fetch(`${apiBase}/api/free-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: d }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'The check could not be completed. Please try again.')
        return
      }
      setResult(data)
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100)
    } catch {
      setError('Connection error. Please check your network and try again.')
    } finally {
      stopMessageCycle()
      setScanning(false)
    }
  }

  function handleRescan() {
    setResult(null)
    setError(null)
  }

  const groupedFindings = groupFindings(result?.preview_findings || [])
  const modules = result?.modules_scanned || []

  return (
    <div className="min-h-screen bg-[#EEF1F6] text-gray-900">
      <header className="sticky top-0 z-40 border-b border-gray-100 bg-white/95 backdrop-blur">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-5">
          <Link to="/" aria-label="CyberMeters home">
            <CyberMetersLogo className="h-7" />
          </Link>
          <div className="flex items-center gap-3">
            <Link to="/login" className="hidden text-sm font-medium text-gray-600 hover:text-gray-900 sm:inline">
              Sign in
            </Link>
            <Link to={signupPath(result?.domain)} className="btn-primary px-4 py-2 text-sm">
              Create free account
            </Link>
          </div>
        </div>
      </header>

      {!result && !scanning && (
        <main>
          <section className="bg-white">
            <div className="mx-auto grid max-w-6xl grid-cols-1 gap-10 px-5 py-12 sm:py-16 lg:grid-cols-[1.08fr_0.92fr] lg:items-center">
              <div>
                <span className="eyebrow inline-flex items-center gap-2 rounded-full border border-brand-100 bg-brand-50 px-3 py-1">
                  <Sparkles className="h-3.5 w-3.5" />
                  Free Cyber MOT
                </span>
                <h1 className="mt-5 max-w-3xl text-[34px] font-bold leading-[1.08] tracking-tight text-gray-900 sm:text-[48px]">
                  Cyber MOT - the 2-minute security check for your business.
                </h1>
                <p className="mt-5 max-w-2xl text-base leading-relaxed text-gray-600 sm:text-lg">
                  Get a clear website and email security report for your domain. Built for UK small businesses that need practical answers without jargon.
                </p>

                <form onSubmit={handleScan} className="mt-8 grid gap-3 sm:max-w-2xl sm:grid-cols-[1fr_auto]">
                  <div className="relative">
                    <Globe className="absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
                    <input
                      type="text"
                      value={domain}
                      onChange={e => setDomain(e.target.value)}
                      placeholder="yourbusiness.co.uk"
                      className="input pl-11"
                      autoFocus
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </div>
                  <button type="submit" disabled={!domain.trim()} className="btn-primary py-3 disabled:cursor-not-allowed disabled:opacity-40">
                    Start free check
                    <ArrowRight className="h-4 w-4" />
                  </button>
                </form>

                {error && (
                  <div className="mt-4 flex max-w-2xl items-center gap-2 rounded-xl border border-red-100 bg-red-50 px-4 py-3 text-sm text-red-700">
                    <AlertTriangle className="h-4 w-4 flex-shrink-0" />
                    {error}
                  </div>
                )}

                <div className="mt-8 grid max-w-2xl grid-cols-1 gap-3 sm:grid-cols-2">
                  {[
                    { icon: Mail, title: 'Email Security', copy: 'DMARC, SPF, DKIM, and spoofing protection signals.' },
                    { icon: Globe, title: 'Website Security', copy: 'TLS, security headers, and DNS trust checks.' },
                  ].map(({ icon: Icon, title, copy }) => (
                    <div key={title} className="rounded-xl border border-gray-200 bg-gray-50 p-4">
                      <Icon className="h-5 w-5 text-brand-600" />
                      <h2 className="mt-3 text-sm font-bold text-gray-900">{title}</h2>
                      <p className="mt-1 text-sm leading-relaxed text-gray-500">{copy}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="card-md p-5 sm:p-6">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <span className="eyebrow">Sample report</span>
                    <h2 className="mt-1 text-xl font-bold tracking-tight text-gray-900">Plain-English Cyber MOT</h2>
                  </div>
                  <ShieldCheck className="h-8 w-8 text-brand-600" />
                </div>
                <div className="mt-6 grid grid-cols-3 gap-3">
                  {[
                    { label: 'Score', value: '78/100' },
                    { label: 'Email', value: 'Review' },
                    { label: 'Website', value: 'Good' },
                  ].map(item => (
                    <div key={item.label} className="rounded-xl border border-gray-200 bg-gray-50 px-3 py-3">
                      <p className="text-[11px] font-bold uppercase tracking-wide text-gray-400">{item.label}</p>
                      <p className="mt-1 text-sm font-bold text-gray-900">{item.value}</p>
                    </div>
                  ))}
                </div>
                <div className="mt-5 space-y-3">
                  {[
                    'Email authentication record needs attention',
                    'Security header missing on website',
                    'TLS certificate is valid',
                  ].map((item, index) => (
                    <div key={item} className="flex items-center gap-3 rounded-xl border border-gray-200 bg-white px-4 py-3 text-sm font-medium text-gray-700">
                      {index === 2 ? <CheckCircle className="h-4 w-4 text-brand-600" /> : <AlertTriangle className="h-4 w-4 text-amber-500" />}
                      {item}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>
        </main>
      )}

      {scanning && (
        <main className="mx-auto max-w-6xl px-5 py-10">
          <LoadingState domain={domain} messageIdx={msgIdx} />
        </main>
      )}

      {result && !scanning && (
        <main ref={resultsRef} className="mx-auto max-w-6xl px-5 py-8 sm:py-10">
          <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
            <div>
              <span className="eyebrow">Cyber MOT report</span>
              <h1 className="mt-1 text-2xl font-bold tracking-tight text-gray-900 sm:text-3xl">{result.domain}</h1>
              <p className="mt-1 text-sm text-gray-500">
                Website and email security check
                {result.scanned_at ? ` completed ${new Date(result.scanned_at).toLocaleString('en-GB')}` : ''}
              </p>
            </div>
            <button onClick={handleRescan} className="btn-secondary justify-center">
              <RefreshCw className="h-4 w-4" />
              Check another domain
            </button>
          </div>

          <section className="card-md p-5 sm:p-6">
            <div className="grid gap-8 lg:grid-cols-[220px_1fr] lg:items-center">
              <ScoreGauge score={result.score} riskLevel={result.risk_level} />
              <div>
                <div className="grid gap-4 sm:grid-cols-3">
                  <div className="rounded-xl border border-gray-200 bg-gray-50 p-4">
                    <ClipboardCheck className="h-5 w-5 text-brand-600" />
                    <p className="mt-3 text-sm font-semibold text-gray-500">Findings found</p>
                    <p className="mt-1 text-2xl font-bold tabular-nums text-gray-900">{result.total_findings ?? 0}</p>
                  </div>
                  <div className="rounded-xl border border-gray-200 bg-gray-50 p-4">
                    <FileText className="h-5 w-5 text-brand-600" />
                    <p className="mt-3 text-sm font-semibold text-gray-500">Preview shown</p>
                    <p className="mt-1 text-2xl font-bold tabular-nums text-gray-900">{result.preview_findings?.length ?? 0}</p>
                  </div>
                  <div className="rounded-xl border border-gray-200 bg-gray-50 p-4">
                    <Lock className="h-5 w-5 text-brand-600" />
                    <p className="mt-3 text-sm font-semibold text-gray-500">Available after signup</p>
                    <p className="mt-1 text-2xl font-bold tabular-nums text-gray-900">{result.hidden_count ?? 0}</p>
                  </div>
                </div>
                <div className="mt-6">
                  <h2 className="mb-3 text-sm font-bold text-gray-900">Severity breakdown</h2>
                  <SeverityBreakdown counts={result.severity_counts} />
                </div>
              </div>
            </div>
          </section>

          {modules.length > 0 && (
            <div className="mt-5 flex flex-wrap gap-2">
              {modules.map(moduleName => (
                <span key={moduleName} className="rounded-full border border-gray-200 bg-white px-3 py-1 text-xs font-semibold capitalize text-gray-600">
                  {moduleLabel(moduleName)}
                </span>
              ))}
            </div>
          )}

          <div className="mt-6 grid gap-5 lg:grid-cols-2">
            <ResultSection
              icon={Mail}
              title="Email Security"
              description="Checks that help stop criminals sending convincing emails that appear to come from your business."
              checks={['DMARC', 'SPF', 'DKIM']}
              findings={groupedFindings.email}
            />
            <ResultSection
              icon={Globe}
              title="Website Security"
              description="Checks that show whether your public website and domain are using common trust and protection settings."
              checks={['TLS', 'Headers', 'DNS']}
              findings={groupedFindings.website}
            />
          </div>

          {result.total_findings === 0 && (
            <div className="mt-6 rounded-2xl border border-green-100 bg-green-50 p-6 text-center">
              <CheckCircle className="mx-auto mb-3 h-10 w-10 text-green-600" />
              <h2 className="text-lg font-bold text-green-900">Your Cyber MOT looks healthy</h2>
              <p className="mx-auto mt-2 max-w-2xl text-sm leading-relaxed text-green-700">
                No issues were found in the preview checks. A free account adds the full report, monitoring, and change alerts.
              </p>
            </div>
          )}

          <div className="mt-6">
            <HiddenFindingsCta count={result.hidden_count} domain={result.domain} />
          </div>

          <section className="mt-6 rounded-2xl bg-gray-900 p-6 text-center sm:p-8">
            <h2 className="text-2xl font-bold tracking-tight text-white">Turn this Cyber MOT into ongoing monitoring</h2>
            <p className="mx-auto mt-3 max-w-2xl text-sm leading-relaxed text-gray-300">
              Create a free account to keep the report, view every finding, receive practical remediation guidance, and track changes over time.
            </p>
            <div className="mt-6 flex flex-col justify-center gap-3 sm:flex-row">
              <Link to={signupPath(result.domain)} className="btn-primary">
                Create free account
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link to="/academy" className="inline-flex items-center justify-center gap-2 rounded-xl border border-gray-700 px-5 py-2.5 text-sm font-semibold text-gray-200 transition-colors hover:bg-gray-800">
                Plain-English guidance
                <GraduationCap className="h-4 w-4" />
              </Link>
            </div>
            <p className="mt-4 text-[11px] font-medium text-gray-500">No credit card required</p>
          </section>

          <section className="mt-6 grid gap-4 sm:grid-cols-3">
            {[
              { icon: Mail, title: 'Email protection', copy: 'Monitor DMARC and sender trust over time.' },
              { icon: BarChart2, title: 'Score history', copy: 'See whether your security posture is improving.' },
              { icon: Shield, title: 'Executive report', copy: 'Share a clear PDF with directors or clients.' },
            ].map(({ icon: Icon, title, copy }) => (
              <div key={title} className="card p-5">
                <Icon className="h-5 w-5 text-brand-600" />
                <h3 className="mt-3 text-sm font-bold text-gray-900">{title}</h3>
                <p className="mt-1 text-sm leading-relaxed text-gray-500">{copy}</p>
              </div>
            ))}
          </section>
        </main>
      )}

      <footer className="mt-12 border-t border-gray-200 bg-white">
        <div className="mx-auto flex max-w-6xl flex-col gap-4 px-5 py-8 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2 text-sm text-gray-500">
            <Shield className="h-4 w-4 text-brand-600" />
            <span>© 2026 CyberMeters. UK cyber-security SaaS.</span>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-sm text-gray-500">
            <Link to="/privacy" className="hover:text-gray-900">Privacy</Link>
            <Link to="/terms" className="hover:text-gray-900">Terms</Link>
            <Link to="/support" className="hover:text-gray-900">Support</Link>
          </div>
        </div>
      </footer>
    </div>
  )
}
