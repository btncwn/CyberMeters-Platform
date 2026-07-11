import { useState, useEffect } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import {
  ScanLine, Globe, ArrowLeft, CheckCircle,
  Shield, Mail, FileText, Info,
} from 'lucide-react'
import { api } from '../api'
import ErrorAlert from '../components/ErrorAlert'
import Spinner from '../components/Spinner'

// Framed as Intelligence Engines (business capabilities), not internal detectors.
const CHECKS = [
  { icon: Globe,    label: 'Attack Surface Intelligence',  desc: 'Exposed assets, DNS, certificates and website security'   },
  { icon: Mail,     label: 'Business Email Intelligence',  desc: 'Protection against email spoofing and phishing'           },
  { icon: Shield,   label: 'Brand Intelligence',           desc: 'Lookalike and typosquatting domains impersonating you'    },
  { icon: FileText, label: 'Executive Intelligence',       desc: 'A scored Executive Report with prioritized next steps'    },
]

function isValidDomain(v) {
  return /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v.trim())
}

export default function NewScan() {
  const [domain, setDomain]   = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)
  const [success, setSuccess] = useState(null)
  const navigate = useNavigate()

  // Clicking "New Scan" in the header while already on this page resets the form
  // to a clean state (Router won't remount the same route on its own).
  useEffect(() => {
    const reset = () => {
      setDomain(''); setError(null); setSuccess(null); setLoading(false)
      window.scrollTo({ top: 0, behavior: 'smooth' })
    }
    window.addEventListener('cybermeters:new-scan-reset', reset)
    return () => window.removeEventListener('cybermeters:new-scan-reset', reset)
  }, [])

  const valid = isValidDomain(domain)

  async function handleSubmit(e) {
    e.preventDefault()
    if (!valid) return
    setLoading(true)
    setError(null)
    try {
      const data = await api.createScan(domain.trim().toLowerCase())
      setSuccess(data)
      setTimeout(() => {
        const id = data?.scan?.id || data?.id
        navigate(id ? `/scans/${id}` : '/scans')
      }, 1500)
    } catch (e) {
      // Plan-limit and rate-limit errors are handled by the global UpgradePromptModal
      // (fired via the cybermeters:plan-limit event in api.js). Suppress the inline
      // ErrorAlert so the user sees one clear message, not two conflicting ones.
      if (e.code !== 'plan_limit_exceeded' && e.code !== 'rate_limit_exceeded') {
        setError(e.message)
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <Link to="/dashboard" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-brand-600 transition-colors mb-6 font-medium">
        <ArrowLeft className="w-4 h-4" />
        Back to Dashboard
      </Link>

      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">New Scan</h1>
        <p className="text-sm text-gray-400 mt-1">
          Assess any domain from the outside. We'll map its external exposure and turn it into a clear Executive Report — usually within a few minutes.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Form */}
        <div className="lg:col-span-2 card-md p-8">
          {success ? (
            <div className="flex flex-col items-center justify-center py-12 text-center gap-5">
              <div className="w-16 h-16 rounded-2xl bg-brand-50 border border-brand-100 flex items-center justify-center">
                <CheckCircle className="w-8 h-8 text-brand-600" />
              </div>
              <div>
                <p className="text-gray-900 font-bold text-xl">Scan Queued Successfully</p>
                <p className="text-gray-400 text-sm mt-1">Redirecting to scan details…</p>
              </div>
              <Spinner />
            </div>
          ) : (
            <>
              <h2 className="text-base font-bold text-gray-900 mb-6">Choose a domain</h2>
              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">Domain Name</label>
                  <div className="relative">
                    <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input
                      type="text"
                      value={domain}
                      onChange={e => setDomain(e.target.value)}
                      placeholder="example.com"
                      className="input pl-11 py-3.5 text-base"
                      autoFocus
                      disabled={loading}
                      spellCheck={false}
                      autoCapitalize="off"
                      autoCorrect="off"
                    />
                  </div>
                  <div className="mt-2">
                    {domain === '' ? (
                      <p className="text-gray-400 text-xs flex items-center gap-1">
                        <Info className="w-3 h-3" />
                        Enter the root domain only — no https://, paths, or ports
                      </p>
                    ) : !valid ? (
                      <p className="text-amber-600 text-xs font-medium">⚠ Please enter a valid domain (e.g. example.com)</p>
                    ) : (
                      <p className="text-brand-600 text-xs font-semibold flex items-center gap-1">
                        <CheckCircle className="w-3 h-3" />
                        Valid domain — ready to scan
                      </p>
                    )}
                  </div>
                </div>

                {error && <ErrorAlert message={error} onRetry={() => setError(null)} />}

                <button
                  type="submit"
                  disabled={!valid || loading}
                  className="btn-primary w-full justify-center py-3.5 text-base disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {loading
                    ? <><Spinner size="sm" /><span>Starting scan…</span></>
                    : <><ScanLine className="w-5 h-5" /><span>Start Scan</span></>}
                </button>

                <p className="text-center text-xs text-gray-400 leading-relaxed">
                  Scans are non-intrusive and read-only — we only inspect publicly available data
                  (DNS, certificates, public web signals), the same information any visitor can see.
                  Only scan domains you own or are authorised to assess; you are responsible for
                  ensuring you have the right to scan a domain.
                </p>
              </form>
            </>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          <div className="card p-5">
            <h3 className="text-sm font-bold text-gray-900 mb-4">What's included</h3>
            <ul className="space-y-4">
              {CHECKS.map(({ icon: Icon, label, desc }) => (
                <li key={label} className="flex items-start gap-3">
                  <div className="w-7 h-7 rounded-lg bg-brand-50 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <Icon className="w-3.5 h-3.5 text-brand-600" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-gray-900 leading-tight">{label}</p>
                    <p className="text-xs text-gray-400 mt-0.5">{desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>

          <div className="card p-4">
            <h3 className="label mb-3">Example Domains</h3>
            <div className="space-y-1">
              {['example.com', 'mycompany.io', 'testsite.co.uk'].map(d => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setDomain(d)}
                  className="w-full text-left mono text-xs text-brand-600 hover:text-brand-800 hover:bg-brand-50 px-3 py-2 rounded-lg transition-colors"
                >
                  {d}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
