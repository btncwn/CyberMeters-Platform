/**
 * FreeScanPage — public landing page for CyberMeters lead generation.
 *
 * Route: /free-scan  (public, no auth required, outside Layout shell)
 *
 * Flow:
 *   1. Visitor enters domain → clicks "Scan Domain"
 *   2. POST /api/free-scan → loading state (~4–6s)
 *   3. Preview report: score card, top 5 findings, severity breakdown
 *   4. Gated panels for: full findings, remediation, history, monitoring, PDF
 *   5. CTAs: "Start Monitoring This Domain" → /signup?domain=xxx
 *
 * Phase 4–7: Conversion gates + Academy integration + CTA design
 * are all included in this single file per sprint spec.
 */
import { useState, useRef } from 'react'
import { Link } from 'react-router-dom'
import {
  Shield, AlertTriangle, CheckCircle, Lock, ArrowRight,
  Globe, Mail, FileText, Bell, BarChart2,
  ChevronRight, GraduationCap, ScanLine, RefreshCw,
  ShieldAlert, Zap,
} from 'lucide-react'
import { BASE } from '../api'

// ── Constants ─────────────────────────────────────────────────────────────────

const SEVERITY_CFG = {
  critical: { dot: 'bg-red-500',    badge: 'bg-red-100 text-red-700 border-red-200',    label: 'Critical', icon: '🔴' },
  high:     { dot: 'bg-orange-400', badge: 'bg-orange-100 text-orange-700 border-orange-200', label: 'High',     icon: '🟠' },
  medium:   { dot: 'bg-amber-400',  badge: 'bg-amber-100 text-amber-700 border-amber-200',    label: 'Medium',   icon: '🟡' },
  low:      { dot: 'bg-blue-400',   badge: 'bg-blue-100 text-blue-700 border-blue-200',       label: 'Low',      icon: '🔵' },
  info:     { dot: 'bg-gray-300',   badge: 'bg-gray-100 text-gray-600 border-gray-200',       label: 'Info',     icon: '⚪' },
}

function sevCfg(s) { return SEVERITY_CFG[s] ?? SEVERITY_CFG.info }

const RISK_LEVEL_CFG = {
  critical: { label: 'Critical Risk',  color: 'text-red-600',    ring: 'stroke-red-500',    bg: 'bg-red-50'    },
  high:     { label: 'High Risk',      color: 'text-orange-600', ring: 'stroke-orange-400', bg: 'bg-orange-50' },
  medium:   { label: 'Medium Risk',    color: 'text-amber-600',  ring: 'stroke-amber-400',  bg: 'bg-amber-50'  },
  low:      { label: 'Low Risk',       color: 'text-green-600',  ring: 'stroke-green-500',  bg: 'bg-green-50'  },
  info:     { label: 'No Issues',      color: 'text-brand-600',  ring: 'stroke-brand-500',  bg: 'bg-brand-50'  },
}

function riskCfg(r) { return RISK_LEVEL_CFG[r] ?? RISK_LEVEL_CFG.medium }

const LOADING_MESSAGES = [
  'Checking DNS records…',
  'Validating SSL certificate…',
  'Scanning security headers…',
  'Auditing email security (SPF · DMARC · DKIM)…',
  'Computing security score…',
]

// ── Score Ring ────────────────────────────────────────────────────────────────

function ScoreRing({ score, risk_level }) {
  const cfg       = riskCfg(risk_level)
  const radius    = 52
  const circ      = 2 * Math.PI * radius
  const progress  = circ - (score / 100) * circ

  return (
    <div className="flex flex-col items-center">
      <div className="relative w-36 h-36">
        <svg className="w-36 h-36 -rotate-90" viewBox="0 0 120 120">
          {/* Track */}
          <circle cx="60" cy="60" r={radius} fill="none" stroke="#e5e7eb" strokeWidth="10" />
          {/* Progress */}
          <circle
            cx="60" cy="60" r={radius} fill="none"
            className={cfg.ring}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circ}
            strokeDashoffset={progress}
            style={{ transition: 'stroke-dashoffset 1s ease' }}
          />
        </svg>
        {/* Score number */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`text-3xl font-black leading-none ${cfg.color}`}>{score}</span>
          <span className="text-[10px] font-semibold text-gray-400 mt-0.5">/ 100</span>
        </div>
      </div>
      <div className={`mt-3 px-3 py-1 rounded-full text-sm font-bold ${cfg.color} ${cfg.bg}`}>
        {cfg.label}
      </div>
    </div>
  )
}

// ── Severity Bar ──────────────────────────────────────────────────────────────

function SeverityBreakdown({ counts }) {
  const total = Object.values(counts).reduce((s, n) => s + n, 0)
  if (total === 0) return (
    <div className="flex items-center gap-2 text-sm text-green-600 font-semibold">
      <CheckCircle className="w-4 h-4" />
      No issues found in these checks
    </div>
  )
  return (
    <div className="space-y-2">
      {['critical', 'high', 'medium', 'low', 'info'].map(sev => {
        const n = counts[sev] ?? 0
        if (n === 0) return null
        const cfg = sevCfg(sev)
        return (
          <div key={sev} className="flex items-center gap-3">
            <span className={`inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cfg.badge} min-w-[72px]`}>
              <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
              {cfg.label}
            </span>
            <div className="flex-1 bg-gray-100 rounded-full h-1.5 overflow-hidden">
              <div
                className={`h-full rounded-full ${cfg.dot}`}
                style={{ width: `${(n / total) * 100}%`, transition: 'width 0.8s ease' }}
              />
            </div>
            <span className="text-sm font-bold text-gray-700 w-5 text-right">{n}</span>
          </div>
        )
      })}
    </div>
  )
}

// ── Finding Preview Card ──────────────────────────────────────────────────────

function FindingCard({ f, index }) {
  const cfg = sevCfg(f.severity)
  const appBase = window.location.origin

  return (
    <div className="bg-white rounded-xl border border-gray-100 p-4 shadow-sm">
      <div className="flex items-start gap-3">
        <span className={`flex-shrink-0 text-[11px] font-black w-6 h-6 rounded-lg flex items-center justify-center ${cfg.badge} border`}>
          {index + 1}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-3">
            <p className="text-sm font-bold text-gray-900 leading-snug">{f.title}</p>
            <span className={`flex-shrink-0 text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-full border ${cfg.badge}`}>
              {cfg.label}
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-1.5 leading-relaxed">{f.description}</p>
          <div className="flex items-center gap-3 mt-2.5">
            {f.academy_slug ? (
              <Link
                to={`/academy/${f.academy_slug}`}
                className="flex items-center gap-1 text-[11px] font-semibold text-brand-600 hover:text-brand-800 transition-colors"
              >
                <GraduationCap className="w-3 h-3" />
                Learn more in Academy
                <ChevronRight className="w-2.5 h-2.5" />
              </Link>
            ) : null}
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Gated Panel ───────────────────────────────────────────────────────────────

function GatedPanel({ icon: Icon, title, description, domain }) {
  return (
    <div className="relative rounded-xl border border-gray-200 bg-gray-50 overflow-hidden">
      {/* Blurred preview content */}
      <div className="p-4 select-none pointer-events-none" style={{ filter: 'blur(4px)', opacity: 0.4 }}>
        <div className="flex items-center gap-2 mb-3">
          <Icon className="w-4 h-4 text-gray-400" />
          <span className="text-sm font-bold text-gray-700">{title}</span>
        </div>
        <div className="space-y-2">
          <div className="h-3 bg-gray-300 rounded w-3/4" />
          <div className="h-3 bg-gray-200 rounded w-1/2" />
          <div className="h-3 bg-gray-300 rounded w-2/3" />
        </div>
      </div>
      {/* Lock overlay */}
      <div className="absolute inset-0 flex flex-col items-center justify-center bg-white/80 backdrop-blur-[2px]">
        <Lock className="w-5 h-5 text-gray-400 mb-2" />
        <p className="text-xs font-bold text-gray-700 text-center px-4">{description}</p>
        <Link
          to={`/signup${domain ? `?domain=${encodeURIComponent(domain)}` : ''}`}
          className="mt-3 text-[11px] font-bold text-brand-600 hover:text-brand-800 flex items-center gap-1 transition-colors"
        >
          Unlock with a free account
          <ArrowRight className="w-3 h-3" />
        </Link>
      </div>
    </div>
  )
}

// ── Loading State ─────────────────────────────────────────────────────────────

function LoadingState({ domain, messageIdx }) {
  return (
    <div className="flex flex-col items-center py-16 text-center">
      <div className="w-16 h-16 rounded-2xl bg-brand-50 flex items-center justify-center mb-6 relative">
        <ScanLine className="w-8 h-8 text-brand-600" />
        <div className="absolute inset-0 rounded-2xl border-2 border-brand-200 animate-ping opacity-30" />
      </div>
      <h2 className="text-lg font-bold text-gray-900 mb-1">Scanning {domain}</h2>
      <p className="text-sm text-gray-400 mb-6">This takes 5–10 seconds</p>
      <div className="w-64 h-1 bg-gray-100 rounded-full overflow-hidden mb-6">
        <div
          className="h-full bg-brand-500 rounded-full transition-all duration-500"
          style={{ width: `${Math.min(95, ((messageIdx + 1) / LOADING_MESSAGES.length) * 100)}%` }}
        />
      </div>
      <p className="text-xs text-gray-400 font-medium">{LOADING_MESSAGES[messageIdx] ?? LOADING_MESSAGES[0]}</p>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function FreeScanPage() {
  const [domain,     setDomain]     = useState('')
  const [scanning,   setScanning]   = useState(false)
  const [msgIdx,     setMsgIdx]     = useState(0)
  const [result,     setResult]     = useState(null)
  const [error,      setError]      = useState(null)

  const timerRef    = useRef(null)
  const resultsRef  = useRef(null)

  // Domain cleanup — strip protocol/path
  function normaliseDomain(val) {
    return val.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '')
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
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ domain: d }),
      })
      const data = await res.json()
      if (!res.ok) {
        setError(data.error || 'Scan failed. Please try again.')
        return
      }
      setResult(data)
      // Scroll to results
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

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-50">

      {/* ── Header ── */}
      <header className="bg-white border-b border-gray-100 sticky top-0 z-40">
        <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <div className="w-7 h-7 rounded-lg bg-brand-600 flex items-center justify-center">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <span className="text-sm font-black text-gray-900 tracking-tight">CyberMeters</span>
          </Link>
          <div className="flex items-center gap-3">
            <Link to="/login" className="text-sm text-gray-500 hover:text-gray-800 font-medium transition-colors">
              Sign in
            </Link>
            <Link
              to={`/signup${result?.domain ? `?domain=${encodeURIComponent(result.domain)}` : ''}`}
              className="text-sm font-bold text-white bg-brand-600 hover:bg-brand-700 px-4 py-1.5 rounded-lg transition-colors"
            >
              Create free account
            </Link>
          </div>
        </div>
      </header>

      {/* ── Hero ── */}
      {!result && !scanning && (
        <div className="bg-white border-b border-gray-100">
          <div className="max-w-3xl mx-auto px-4 py-16 text-center">
            <div className="inline-flex items-center gap-2 bg-brand-50 text-brand-700 text-xs font-bold uppercase tracking-widest px-3 py-1.5 rounded-full mb-6">
              <Zap className="w-3.5 h-3.5" />
              Free External Security Scan
            </div>
            <h1 className="text-4xl font-black text-gray-900 leading-tight mb-4 tracking-tight">
              See your business the way<br className="hidden sm:block" /> attackers do.
            </h1>
            <p className="text-lg text-gray-500 mb-10 max-w-xl mx-auto leading-relaxed">
              Scan any domain in seconds. No account needed.
              Check your email security, SSL certificate, DNS configuration,
              and security headers — for free.
            </p>

            {/* Scan form */}
            <form onSubmit={handleScan} className="flex gap-2 max-w-lg mx-auto">
              <div className="flex-1 relative">
                <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  value={domain}
                  onChange={e => setDomain(e.target.value)}
                  placeholder="yourdomain.com"
                  className="w-full pl-10 pr-4 py-3 text-sm border border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-brand-300 focus:border-transparent bg-white"
                  autoFocus
                  autoComplete="off"
                  spellCheck={false}
                />
              </div>
              <button
                type="submit"
                disabled={!domain.trim()}
                className="flex items-center gap-2 px-5 py-3 text-sm font-bold text-white bg-brand-600 hover:bg-brand-700 disabled:opacity-40 rounded-xl transition-colors whitespace-nowrap"
              >
                <ScanLine className="w-4 h-4" />
                Scan Domain
              </button>
            </form>

            {error && (
              <div className="flex items-center gap-2 mt-4 text-sm text-red-600 bg-red-50 border border-red-100 px-4 py-3 rounded-xl max-w-lg mx-auto">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                {error}
              </div>
            )}

            {/* What we check */}
            <div className="flex flex-wrap justify-center gap-4 mt-10 text-xs text-gray-400 font-medium">
              {[
                { icon: Mail,         label: 'Email Security (SPF · DMARC · DKIM)' },
                { icon: Lock,         label: 'SSL Certificate' },
                { icon: ShieldAlert,  label: 'Security Headers' },
                { icon: Globe,        label: 'DNS Configuration' },
              ].map(({ icon: Icon, label }) => (
                <span key={label} className="flex items-center gap-1.5">
                  <Icon className="w-3.5 h-3.5 text-brand-400" />
                  {label}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Loading ── */}
      {scanning && (
        <div className="max-w-3xl mx-auto px-4 py-8">
          <LoadingState domain={domain} messageIdx={msgIdx} />
        </div>
      )}

      {/* ── Results ── */}
      {result && !scanning && (
        <div ref={resultsRef} className="max-w-3xl mx-auto px-4 py-8 space-y-6">

          {/* Re-scan header */}
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-400 font-medium mb-0.5">Scan results for</p>
              <h1 className="text-xl font-black text-gray-900">{result.domain}</h1>
            </div>
            <button
              onClick={handleRescan}
              className="flex items-center gap-1.5 text-xs font-semibold text-gray-500 hover:text-gray-800 bg-white border border-gray-200 px-3 py-2 rounded-xl transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Scan another domain
            </button>
          </div>

          {/* ── Score Card ── */}
          <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6">
            <div className="flex flex-col sm:flex-row items-center gap-8">
              <ScoreRing score={result.score} risk_level={result.risk_level} />
              <div className="flex-1 w-full">
                <h2 className="text-sm font-bold text-gray-900 mb-4">
                  {result.total_findings === 0
                    ? 'No issues found in the scanned checks.'
                    : `${result.total_findings} issue${result.total_findings !== 1 ? 's' : ''} found across email, SSL, headers, and DNS.`}
                </h2>
                <SeverityBreakdown counts={result.severity_counts} />
                <p className="text-[11px] text-gray-300 mt-4">
                  Scanned: email security · SSL · security headers · DNS configuration
                </p>
              </div>
            </div>
          </div>

          {/* ── Preview Findings ── */}
          {result.preview_findings?.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-bold text-gray-900">
                  Top {result.preview_findings.length} finding{result.preview_findings.length !== 1 ? 's' : ''}
                </h2>
                {result.hidden_count > 0 && (
                  <span className="text-xs text-gray-400 font-medium">
                    +{result.hidden_count} more hidden
                  </span>
                )}
              </div>
              <div className="space-y-3">
                {result.preview_findings.map((f, i) => (
                  <FindingCard key={f.id} f={f} index={i} />
                ))}
              </div>
            </div>
          )}

          {result.total_findings === 0 && (
            <div className="bg-green-50 border border-green-100 rounded-2xl p-6 text-center">
              <CheckCircle className="w-10 h-10 text-green-500 mx-auto mb-3" />
              <h2 className="text-base font-bold text-green-800 mb-1">Looking good!</h2>
              <p className="text-sm text-green-600">
                No issues found in the scanned checks. Create a free account to run a
                full surface scan including subdomains, cloud storage, and asset exposure.
              </p>
            </div>
          )}

          {/* ── Gated panels ── */}
          <div>
            <div className="flex items-center gap-2 mb-3">
              <Lock className="w-4 h-4 text-gray-300" />
              <h2 className="text-sm font-bold text-gray-400">Unlock with a free account</h2>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <GatedPanel
                icon={Zap}
                title="Step-by-step remediation"
                description="Exact commands and configuration to fix each finding"
                domain={result.domain}
              />
              <GatedPanel
                icon={BarChart2}
                title="Historical score tracking"
                description="See how your security posture changes over time"
                domain={result.domain}
              />
              <GatedPanel
                icon={Bell}
                title="Change detection alerts"
                description="Get alerted the moment your attack surface changes"
                domain={result.domain}
              />
              <GatedPanel
                icon={FileText}
                title="Executive PDF report"
                description="One-click board-ready report for your domain"
                domain={result.domain}
              />
            </div>
          </div>

          {/* ── What a full scan adds ── */}
          <div className="bg-brand-50/50 border border-brand-100 rounded-2xl p-5">
            <h3 className="text-sm font-bold text-brand-900 mb-3 flex items-center gap-2">
              <ScanLine className="w-4 h-4 text-brand-600" />
              Full scan also includes
            </h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {[
                'Subdomain discovery',
                'Subdomain takeover detection',
                'Cloud storage exposure',
                'Admin surface detection',
                'Vendor & supply chain risk',
                'Technology detection',
                'WHOIS intelligence',
                'Asset inventory',
                'Scheduled monitoring',
              ].map(item => (
                <div key={item} className="flex items-center gap-1.5 text-xs text-brand-700 font-medium">
                  <CheckCircle className="w-3 h-3 text-brand-500 flex-shrink-0" />
                  {item}
                </div>
              ))}
            </div>
          </div>

          {/* ── Primary CTA strip ── */}
          <div className="bg-gray-900 rounded-2xl p-7 text-center">
            <h2 className="text-xl font-black text-white mb-2">
              Start monitoring {result.domain}
            </h2>
            <p className="text-sm text-gray-400 mb-6 max-w-sm mx-auto">
              Get alerted when anything changes. Full findings, remediation guidance,
              scheduled scans, and executive reports — free to start.
            </p>
            <div className="flex flex-col sm:flex-row gap-3 justify-center">
              <Link
                to={`/signup?domain=${encodeURIComponent(result.domain)}`}
                className="flex items-center justify-center gap-2 px-6 py-3 text-sm font-bold text-white bg-brand-600 hover:bg-brand-500 rounded-xl transition-colors"
              >
                Start Monitoring This Domain
                <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                to="/signup"
                className="flex items-center justify-center gap-2 px-6 py-3 text-sm font-semibold text-gray-300 bg-white/10 hover:bg-white/20 rounded-xl transition-colors"
              >
                Create free account
              </Link>
            </div>
            <p className="text-[11px] text-gray-500 mt-4">No credit card required · Free to start</p>
          </div>

          {/* ── Academy promo ── */}
          <div className="bg-white border border-gray-100 rounded-2xl p-5 flex items-start gap-4">
            <div className="w-10 h-10 rounded-xl bg-brand-50 flex items-center justify-center flex-shrink-0">
              <GraduationCap className="w-5 h-5 text-brand-600" />
            </div>
            <div className="flex-1">
              <h3 className="text-sm font-bold text-gray-900 mb-1">Learn what these findings mean</h3>
              <p className="text-xs text-gray-400 leading-relaxed mb-3">
                The CyberMeters Academy explains every security concept in plain English —
                from SPF records to subdomain takeovers. No jargon, no assumed knowledge.
              </p>
              <Link
                to="/academy"
                className="inline-flex items-center gap-1.5 text-xs font-bold text-brand-600 hover:text-brand-800 transition-colors"
              >
                Browse the Academy
                <ArrowRight className="w-3 h-3" />
              </Link>
            </div>
          </div>

        </div>
      )}

      {/* ── Footer ── */}
      <footer className="border-t border-gray-100 mt-16 py-8">
        <div className="max-w-5xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <Shield className="w-3.5 h-3.5 text-brand-400" />
            <span>© 2026 CyberMeters. External attack surface monitoring.</span>
          </div>
          <div className="flex items-center gap-4 text-xs text-gray-400">
            <Link to="/privacy" className="hover:text-gray-600 transition-colors">Privacy</Link>
            <Link to="/terms"   className="hover:text-gray-600 transition-colors">Terms</Link>
            <Link to="/support" className="hover:text-gray-600 transition-colors">Support</Link>
            <Link to="/academy" className="hover:text-gray-600 transition-colors">Academy</Link>
          </div>
        </div>
      </footer>

    </div>
  )
}
