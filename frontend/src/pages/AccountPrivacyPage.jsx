/**
 * AccountPrivacyPage — /account/privacy
 *
 * Sections:
 *  1. Export my data          — download JSON export of the user's account
 *  2. Request account deletion — type DELETE to confirm
 *  3. Request workspace deletion — per-workspace, type workspace name to confirm
 *  4. Data retention explanation
 *  5. Legal links             — Privacy Policy and DPA
 *
 * Authentication: enforced by ProtectedRoute in App.jsx.
 * All destructive actions require explicit text confirmation.
 */

import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { X, Loader, RefreshCw } from 'lucide-react'
import { api } from '../api'
import InternalIdCopyButton from '../components/InternalIdCopyButton'

// ── Helpers ───────────────────────────────────────────────────────────────────

function SectionCard({ title, subtitle, children }) {
  return (
    <div className="card p-6">
      <div className="flex items-start gap-4 mb-5">
        <div>
          <h2 className="text-base font-bold text-gray-900">{title}</h2>
          {subtitle && <p className="text-sm text-gray-400 mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {children}
    </div>
  )
}

function StatusBanner({ type, children }) {
  const cfg = {
    success: { bg: 'bg-brand-200 border-brand-200',  text: 'text-brand-900' },
    error:   { bg: 'bg-red-50 border-red-100',      text: 'text-red-700'   },
    warning: { bg: 'bg-transparent border-[1.5px] border-brand-700',  text: 'text-brand-700' },
  }[type] ?? { bg: 'bg-gray-50 border-gray-100', text: 'text-gray-700' }
  return (
    <div className={`flex items-start gap-3 px-4 py-3 rounded-xl border text-sm ${cfg.bg} ${cfg.text}`}>
      <span>{children}</span>
    </div>
  )
}

// ── Confirmation Modal ────────────────────────────────────────────────────────

function ConfirmModal({ open, onClose, onConfirm, title, description, confirmWord, confirmLabel = 'Confirm', dangerous = false, loading = false }) {
  const [typed, setTyped] = useState('')
  const matches = typed.trim() === confirmWord

  function handleClose() {
    if (loading) return
    setTyped('')
    onClose()
  }

  async function handleConfirm() {
    if (!matches || loading) return
    await onConfirm()
    setTyped('')
  }

  if (!open) return null

  return (
    <div className="fixed inset-0 z-200 flex items-center justify-center bg-gray-900/40 px-4">
      <div className="w-full max-w-md bg-white rounded-2xl shadow-2xl border border-gray-100 overflow-hidden">
        {/* Header */}
        <div className={`px-6 py-5 flex items-start gap-3 border-b ${dangerous ? 'border-red-100 bg-red-50' : 'border-gray-100'}`}>
          <div className="flex-1 min-w-0">
            <h3 className="text-sm font-bold text-gray-900">{title}</h3>
            <p className="text-sm text-gray-500 mt-1 leading-relaxed">{description}</p>
          </div>
          <button
            onClick={handleClose}
            disabled={loading}
            aria-label={`Close ${title}`}
            className="w-7 h-7 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 flex items-center justify-center shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Confirm input */}
        <div className="px-6 py-5">
          <label className="block text-xs font-semibold text-gray-500 mb-2">
            Type <span className="font-mono font-bold text-gray-800">{confirmWord}</span> to confirm
          </label>
          <input
            type="text"
            className="input w-full font-mono"
            placeholder={confirmWord}
            value={typed}
            onChange={e => setTyped(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') handleConfirm() }}
            autoFocus
            disabled={loading}
          />
        </div>

        {/* Actions */}
        <div className="px-6 pb-5 flex gap-3 justify-end">
          <button
            type="button"
            onClick={handleClose}
            disabled={loading}
            className="btn-secondary"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            disabled={!matches || loading}
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold transition-all ${
              dangerous
                ? 'bg-red-600 hover:bg-red-700 text-white disabled:opacity-40'
                : 'bg-brand-200 hover:bg-brand-300 text-brand-900 disabled:opacity-40'
            }`}
          >
            {loading ? <><Loader className="w-4 h-4 animate-spin" />Processing…</> : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Export Section ────────────────────────────────────────────────────────────

function ExportSection() {
  const [status, setStatus] = useState(null) // null | 'loading' | 'success' | 'error'
  const [errorMsg, setErrorMsg] = useState(null)

  async function handleExport() {
    setStatus('loading')
    setErrorMsg(null)
    try {
      const res = await api.exportAccountData()
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.error || `Export failed (${res.status})`)
      }
      const blob = await res.blob()
      const url  = URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href     = url
      a.download = `cybermeters-export-${new Date().toISOString().slice(0, 10)}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      setStatus('success')
    } catch (err) {
      setErrorMsg(err.message || 'Export failed. Please try again.')
      setStatus('error')
    }
  }

  return (
    <SectionCard
      title="Export my data"
      subtitle="Download a copy of all data associated with your account."
    >
      <p className="text-sm text-gray-500 mb-4 leading-relaxed">
        Your export includes your profile, company info, workspaces, domains, scan history, and report metadata.
        Sensitive findings are included. Store the file securely.
      </p>

      {status === 'success' && (
        <div className="mb-4">
          <StatusBanner type="success">Your data export has been downloaded.</StatusBanner>
        </div>
      )}
      {status === 'error' && (
        <div className="mb-4">
          <StatusBanner type="error">{errorMsg}</StatusBanner>
        </div>
      )}

      <button
        type="button"
        onClick={handleExport}
        disabled={status === 'loading'}
        className="btn-secondary inline-flex items-center gap-2"
      >
        {status === 'loading'
          ? <><Loader className="w-4 h-4 animate-spin" />Preparing export…</>
          : 'Download my account data'
        }
      </button>
    </SectionCard>
  )
}

// ── Account Deletion Section ──────────────────────────────────────────────────

function AccountDeletionSection() {
  const [modalOpen, setModalOpen]     = useState(false)
  const [submitting, setSubmitting]   = useState(false)
  const [submitted, setSubmitted]     = useState(false)
  const [requestId, setRequestId]     = useState(null)
  const [errorMsg, setErrorMsg]       = useState(null)

  async function handleConfirm() {
    setSubmitting(true)
    setErrorMsg(null)
    try {
      const data = await api.requestAccountDeletion()
      setRequestId(data.request_id)
      setSubmitted(true)
      setModalOpen(false)
    } catch (err) {
      // If already submitted, treat as success
      if (err.message?.toLowerCase().includes('already')) {
        setSubmitted(true)
        setModalOpen(false)
      } else {
        setErrorMsg(err.message || 'Unable to submit request. Please try again.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <SectionCard
      title="Request account deletion"
      subtitle="Submit a request to close your account and remove eligible data."
    >
      <div className="space-y-3 mb-5">
        <StatusBanner type="warning">
          Completed account deletion cannot be undone. Eligible workspace data is removed after required checks;
          financial and audit records may be retained where required.
        </StatusBanner>

        <p className="text-sm text-gray-500 leading-relaxed">
          Submitting this request alerts our team. Your account is not deleted immediately.
          Processing may begin after the 30-day restoration window and completes only if required
          checks pass; some cases need manual review. Cancel any active subscription before
          requesting deletion. Keep your reference number and contact support if you need an update.
        </p>
      </div>

      {submitted ? (
        <StatusBanner type="success">
          Your account deletion request has been received{requestId ? ` (ref: ${requestId})` : ''}.
          Processing has not completed. It may begin after the 30-day restoration window, subject
          to required checks; some requests need manual review.
        </StatusBanner>
      ) : (
        <>
          {errorMsg && (
            <div className="mb-4">
              <StatusBanner type="error">{errorMsg}</StatusBanner>
            </div>
          )}
          <button
            type="button"
            onClick={() => setModalOpen(true)}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-semibold text-red-700 bg-red-50 hover:bg-red-100 border border-red-200 transition-colors"
          >
            Request account deletion
          </button>
        </>
      )}

      <ConfirmModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onConfirm={handleConfirm}
        title="Delete your account?"
        description="This submits a request; no data is deleted immediately. Processing after the 30-day restoration window depends on required checks. Cancel any active subscription first."
        confirmWord="DELETE"
        confirmLabel="Request deletion"
        dangerous
        loading={submitting}
      />
    </SectionCard>
  )
}

// ── Workspace Deletion Section ────────────────────────────────────────────────

function WorkspaceRow({ workspace, onRequested }) {
  const [modalOpen, setModalOpen]   = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [submitted, setSubmitted]   = useState(false)
  const [requestId, setRequestId]   = useState(null)
  const [errorMsg, setErrorMsg]     = useState(null)

  async function handleConfirm() {
    setSubmitting(true)
    setErrorMsg(null)
    try {
      const data = await api.requestWorkspaceDeletion(workspace.id)
      setRequestId(data.request_id)
      setSubmitted(true)
      setModalOpen(false)
      if (onRequested) onRequested(workspace.id)
    } catch (err) {
      if (err.message?.toLowerCase().includes('already')) {
        setSubmitted(true)
        setModalOpen(false)
      } else {
        setErrorMsg(err.message || 'Unable to submit request. Please try again.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="flex items-center gap-4 py-3 border-b border-gray-50 last:border-0">
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-gray-900 truncate">{workspace.name}</p>
        <InternalIdCopyButton id={workspace.id} label="workspace" />
      </div>

      {submitted ? (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-brand-700 bg-transparent border border-[1.5px] border-brand-700 rounded-full px-2.5 py-1">
          Deletion requested
        </span>
      ) : (
        <div className="flex flex-col items-end gap-1 shrink-0">
          {errorMsg && <p className="text-xs text-red-700 max-w-[180px] text-right">{errorMsg}</p>}
          <button
            type="button"
            onClick={() => setModalOpen(true)}
            className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-700 hover:text-red-800 hover:bg-red-50 px-3 py-1.5 rounded-lg border border-red-100 transition-colors"
          >
            Request deletion
          </button>
        </div>
      )}

      <ConfirmModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        onConfirm={handleConfirm}
        title={`Delete workspace "${workspace.name}"?`}
        description={`All domains, scans, findings, reports, and members associated with this workspace will be permanently deleted. This cannot be undone.`}
        confirmWord={workspace.name}
        confirmLabel="Request deletion"
        dangerous
        loading={submitting}
      />
    </div>
  )
}

function WorkspaceDeletionSection() {
  const [workspaces, setWorkspaces] = useState([])
  const [loading, setLoading]       = useState(true)
  const [errorMsg, setErrorMsg]     = useState(null)

  useEffect(() => {
    api.getWorkspaces()
      .then(data => setWorkspaces(data.workspaces || []))
      .catch(err => setErrorMsg(err.message || 'Unable to load workspaces.'))
      .finally(() => setLoading(false))
  }, [])

  return (
    <SectionCard
      title="Request workspace deletion"
      subtitle="Submit a deletion request for a specific workspace."
    >
      <p className="text-sm text-gray-500 mb-4 leading-relaxed">
        You can request deletion of individual workspaces. Only workspace owners can submit a deletion request.
        Workspace deletion schedules the removal of all associated domains, scans, findings, and reports.
        Active scans will be cancelled. This cannot be undone.
      </p>

      {loading && (
        <div className="flex items-center gap-2 text-sm text-gray-400 py-4">
          <RefreshCw className="w-4 h-4 animate-spin" />
          Loading workspaces…
        </div>
      )}

      {!loading && errorMsg && (
        <StatusBanner type="error">{errorMsg}</StatusBanner>
      )}

      {!loading && !errorMsg && workspaces.length === 0 && (
        <div className="py-6 text-center text-sm text-gray-400">
          You don't own any workspaces.
        </div>
      )}

      {!loading && workspaces.length > 0 && (
        <div className="divide-y divide-gray-50">
          {workspaces.map(ws => (
            <WorkspaceRow key={ws.id} workspace={ws} />
          ))}
        </div>
      )}
    </SectionCard>
  )
}

// ── Data Retention Section ────────────────────────────────────────────────────

function DataRetentionSection() {
  const rows = [
    { label: 'Profile & company info',  value: 'Retained until account deletion' },
    { label: 'Scan results & findings', value: 'Retained for plan history window (30 days – 7 years by plan)' },
    { label: 'Audit logs',              value: 'Retained for 2 years' },
    { label: 'Billing records',         value: 'Retained for 7 years (legal obligation)' },
    { label: 'Exported data files',     value: 'Not stored — delivered directly to your browser' },
    { label: 'Account deletion requests', value: 'Eligible requests enter processing after the 30-day restoration window; financial and audit records may be retained' },
  ]

  return (
    <SectionCard
      title="Data retention"
      subtitle="How long CyberMeters stores your data."
    >
      <div className="overflow-hidden rounded-xl border border-gray-100">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Data type</th>
              <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Retention</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(({ label, value }, i) => (
              <tr key={i} className="border-b border-gray-50 last:border-0 hover:bg-gray-50/50 transition-colors">
                <td className="px-4 py-3 font-medium text-gray-700">{label}</td>
                <td className="px-4 py-3 text-gray-500">{value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </SectionCard>
  )
}

// ── Legal Links Section ───────────────────────────────────────────────────────

function LegalLinksSection() {
  const links = [
    { to: '/privacy', label: 'Privacy Policy',     desc: 'How we collect, use, and protect your data' },
    { to: '/dpa',     label: 'Data Processing Agreement', desc: 'Data Processing Agreement under UK GDPR Article 28' },
    { to: '/terms',   label: 'Terms of Service',   desc: 'Platform usage terms and conditions' },
  ]

  return (
    <SectionCard
      title="Legal documents"
      subtitle="Privacy and data processing agreements."
    >
      <div className="space-y-2">
        {links.map(({ to, label, desc }) => (
          <Link
            key={to}
            to={to}
            className="flex items-center gap-3 p-3 rounded-xl hover:bg-gray-50 border border-transparent hover:border-gray-100 transition-all group"
          >
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-gray-900">{label}</p>
              <p className="text-xs text-gray-400">{desc}</p>
            </div>
          </Link>
        ))}
      </div>
    </SectionCard>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AccountPrivacyPage({ embedded = false }) {
  // Embedded in the Account page's Privacy & data tab (17 Oct 2026): no page header of its own.
  if (embedded) {
    return (
      <div className="space-y-6">
        <ExportSection />
        <AccountDeletionSection />
        <WorkspaceDeletionSection />
        <DataRetentionSection />
        <LegalLinksSection />
      </div>
    )
  }
  return (
    <div className="max-w-(--breakpoint-lg) mx-auto px-6 py-8">

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-1">
          <Link to="/account" className="text-sm text-gray-400 hover:text-gray-600 transition-colors">Account</Link>
          <span className="text-sm font-medium text-gray-700">Privacy &amp; Data</span>
        </div>
        <h1 className="text-2xl font-bold text-gray-900">Privacy &amp; Data</h1>
        <p className="text-sm text-gray-400 mt-0.5">
          Manage your data, export your information, and request account or workspace deletion.
        </p>
      </div>

      <div className="space-y-6">
        <ExportSection />
        <AccountDeletionSection />
        <WorkspaceDeletionSection />
        <DataRetentionSection />
        <LegalLinksSection />
      </div>

    </div>
  )
}
