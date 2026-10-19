import { DOMAIN_STATE_LABELS, moreInTrialCopy } from '../lib/freeScanPresentation'

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

// What the completed public checks observed for this domain. The wording comes
// from the API (free-scan-observed.js); the page adds no verdict of its own.
function ObservedList({ items }) {
  return (
    <div className="fm-domain-observed">
      <span className="fm-domain-observed__title">Observed in the completed checks</span>
      <ul>
        {items.map((item) => (
          <li key={item.id}>
            <span className="fm-observed-mark" aria-hidden="true">✓</span>
            <span>{item.text}</span>
          </li>
        ))}
      </ul>
    </div>
  )
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

export default function FreeCyberMotPreviewGrid({ domains = [], moreWhere = 'in the trial' }) {
  return (
    <section aria-labelledby="cyber-mot-grid-title">
      <div className="fm-section-heading">
        <div>
          <span className="fm-kicker">External posture snapshot</span>
          <h2 id="cyber-mot-grid-title">Your external Cyber MOT</h2>
        </div>
        <p>Every card stays visible. Incomplete or gated evidence is never shown as healthy.</p>
      </div>

      <div className="fm-domain-grid">
        {domains.map((domain) => {
          const stateKey = domain.display_state || domain.state
          const observed = Array.isArray(domain.observed) ? domain.observed.filter((item) => item?.text) : []
          return (
            <article
              className="fm-domain-card"
              data-state={stateKey}
              key={domain.domain_key}
            >
              <div className="fm-domain-card__top">
                <span className="fm-state-chip">
                  {DOMAIN_STATE_LABELS[stateKey] || 'Evidence incomplete'}
                </span>
              </div>
              <h3>{domain.display_name}</h3>
              <p className="fm-domain-count">{countCopy(domain)}</p>

              {(domain.samples.length > 0 || observed.length === 0) && (
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
              )}

              {observed.length > 0 && <ObservedList items={observed} />}

              {(domain.locked_count > 0 || domain.unlock_required) && (
                <div className="fm-domain-lock">
                  <span>
                    {domain.locked_count > 0
                      ? moreInTrialCopy(domain.locked_count, domain.count_kind, moreWhere)
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
