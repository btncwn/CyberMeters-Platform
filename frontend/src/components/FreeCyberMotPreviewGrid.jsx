import {
  BadgeCheck,
  Building2,
  CloudCog,
  Fingerprint,
  Globe2,
  KeyRound,
  LockKeyhole,
  MailCheck,
  Radar,
  ShieldCheck,
} from 'lucide-react'
import { DOMAIN_STATE_LABELS } from '../lib/freeScanPresentation'

const DOMAIN_ICONS = {
  email_protection: MailCheck,
  brand_protection: BadgeCheck,
  attack_surface: Radar,
  certificates_trust: KeyRound,
  cyber_essentials_readiness: ShieldCheck,
  website_security: Globe2,
  identity_exposure: Fingerprint,
  shadow_it_unmanaged_technology: CloudCog,
}

function countCopy(domain) {
  if (!Number.isFinite(domain.headline_count)) return 'Unlock to assess'
  const count = domain.headline_count
  if (domain.count_kind === 'observation') {
    return `${count} public ${count === 1 ? 'signal' : 'signals'} observed`
  }
  if (domain.count_kind === 'finding') {
    return `${count} ${count === 1 ? 'finding' : 'findings'} in this snapshot`
  }
  return 'Unlock to assess'
}

function SampleRow({ sample }) {
  return (
    <li className="fm-domain-sample">
      <span className={`fm-sample-dot fm-sample-dot--${sample.kind || 'observation'}`} aria-hidden="true" />
      <span>
        <strong>{sample.title}</strong>
        {sample.detail && <small>{sample.detail}</small>}
      </span>
    </li>
  )
}

export default function FreeCyberMotPreviewGrid({ domains = [] }) {
  return (
    <section aria-labelledby="cyber-mot-grid-title">
      <div className="fm-section-heading">
        <div>
          <span className="fm-kicker">Eight-domain snapshot</span>
          <h2 id="cyber-mot-grid-title">Your external Cyber MOT</h2>
        </div>
        <p>Every card stays visible. Incomplete or gated evidence is never shown as healthy.</p>
      </div>

      <div className="fm-domain-grid">
        {domains.map((domain) => {
          const Icon = DOMAIN_ICONS[domain.domain_key] || Building2
          const stateKey = domain.display_state || domain.state
          return (
            <article
              className="fm-domain-card"
              data-state={stateKey}
              key={domain.domain_key}
            >
              <div className="fm-domain-card__top">
                <div className="fm-domain-icon" aria-hidden="true"><Icon /></div>
                <span className="fm-state-chip">
                  {DOMAIN_STATE_LABELS[stateKey] || 'Evidence incomplete'}
                </span>
              </div>
              <h3>{domain.display_name}</h3>
              <p className="fm-domain-count">{countCopy(domain)}</p>

              <ul className="fm-domain-samples">
                {domain.samples.length > 0
                  ? domain.samples.map((sample, index) => (
                    <SampleRow key={sample.id || `${sample.title}-${index}`} sample={sample} />
                  ))
                  : (
                    <li className="fm-domain-empty">
                      No result is exposed for this domain in the bounded snapshot.
                    </li>
                  )}
              </ul>

              {(domain.locked_count > 0 || domain.unlock_required) && (
                <div className="fm-domain-lock">
                  <LockKeyhole aria-hidden="true" />
                  <span>
                    {domain.locked_count > 0
                      ? `+${domain.locked_count} more — unlock with trial`
                      : 'Unlock deeper assessment after verification'}
                  </span>
                </div>
              )}

              <p className="fm-domain-limitation">{domain.limitation}</p>
            </article>
          )
        })}
      </div>
    </section>
  )
}
