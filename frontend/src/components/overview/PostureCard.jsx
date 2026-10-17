// PostureCard — "Your external posture" on the home screen: every area with
// the word the backend's latest assessment allows, nothing more. The states
// are the resolver's (GET /workspaces/:id/cyber-mot-domains) mapped by the
// common vocabulary; a loading, failed or malformed read shows Loading/Error
// on every row, never a settled word.
import { Link } from 'react-router-dom'
import { MODULES, moduleTheme } from '../../lib/moduleRegistry'
import { resolveDisplayDomains } from '../../lib/cyberMotDisplay'
import { domainStatus } from '../../lib/statusVocabulary'
import StatusChip from '../StatusChip'
import { moduleIcon } from '../shell/moduleIcons'
import { domainsRequestState } from './SecurityOverview'

export default function PostureCard({ domains, request = 'ok', workspaceName }) {
  const state = domainsRequestState(domains, request)
  const list = state === 'ok' ? resolveDisplayDomains(domains) : []
  const byKey = new Map(list.map((d) => [d.domain_key, d]))
  return (
    <section className="card p-5 sm:p-6" aria-labelledby="posture-card-heading" data-testid="posture-card">
      <h2 id="posture-card-heading" className="section-title">Your external posture</h2>
      <p className="text-xs text-gray-500 mt-1">
        What the latest assessment could establish for {workspaceName || 'the selected workspace'}, area by area.
      </p>
      <ul className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1">
        {MODULES.map((m) => {
          const theme = moduleTheme(m.domainKey)
          const Icon = moduleIcon(m.colourKey)
          return (
            <li key={m.domainKey} className="flex items-center gap-3 py-2 border-b border-gray-100 last:border-0 md:[&:nth-last-child(2)]:border-0" data-domain-key={m.domainKey}>
              <span className="inline-flex items-center justify-center w-8 h-8 rounded-full shrink-0" style={theme ? { backgroundColor: theme.chip, color: theme.text } : undefined}>
                <Icon className="w-4 h-4" aria-hidden="true" />
              </span>
              <Link to={m.to} className="flex-1 min-w-0 text-[15px] font-semibold text-gray-900 hover:text-brand-800 truncate">{m.title}</Link>
              <StatusChip status={domainStatus(byKey.get(m.domainKey) || null, state)} className="shrink-0" />
            </li>
          )
        })}
      </ul>
    </section>
  )
}
