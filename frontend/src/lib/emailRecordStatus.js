// The status word of each email record, as the scan's email-security and
// mail-transport modules report it. ONE place: the record cards on Findings and
// the Email Summary (What we observed, Evidence by signal) read these, so the two
// can never say different things. Presentation of backend facts only — a record
// that was not read is "No data" / "Not available", never a clean result.
// kind: good | warn | bad | info | na (the record cards' pill tones).

export function dmarcRecordStatus(dmarc, detail) {
  if (!detail && !dmarc) return { label: 'No data', kind: 'na' }
  const present = dmarc?.present ?? Boolean(detail?.raw)
  const policy = detail?.policy || dmarc?.policy
  const label = !present ? 'Not found' : detail?.valid === false ? 'Invalid' : (policy ? `p=${policy}` : 'Published')
  const kind = !present ? 'bad' : detail?.valid === false ? 'warn' : policy === 'reject' ? 'good' : policy === 'none' ? 'warn' : 'info'
  return { label, kind }
}

export function spfRecordStatus(spf, detail) {
  if (!detail && !spf) return { label: 'No data', kind: 'na' }
  const present = spf?.present ?? Boolean(detail?.raw)
  const valid = detail?.valid
  return { label: !present ? 'Not found' : valid ? 'Published' : 'Issues found', kind: !present ? 'bad' : valid ? 'good' : 'warn' }
}

export function dkimRecordStatus(detail) {
  const status = detail?.status
  const label = status === 'detected' ? 'Detected' : status === 'uncertain' ? 'Uncertain' : status === 'not_detected' ? 'Not verified' : 'No data'
  const kind = status === 'detected' ? 'good' : status === 'uncertain' ? 'warn' : 'na'
  return { label, kind }
}

export function mtaStsRecordStatus(detail) {
  if (!detail) return { label: 'Not available', kind: 'na' }
  const enforced = detail.policy_found && detail.mode === 'enforce'
  return { label: detail.policy_found ? (detail.mode || 'Found') : 'No policy', kind: enforced ? 'good' : detail.policy_found ? 'warn' : 'na' }
}

// TLS-RPT record_found is tri-state: true found, false conclusively no valid
// record, null when the lookup did not conclude (or was not run). Unknown is
// never "Not found". A detail from before the field was tri-state keeps its
// original reading.
export function tlsRptNotConcluded(detail) {
  return Boolean(detail) && (detail.record_found === null ||
    detail.observation_state === 'unavailable' || detail.observation_state === 'not_observed')
}

// The module row (email_security_intelligence.tls_rpt), as the Intelligence page
// shows it. observation_state is the backend's own word: present / definitive_absent
// are conclusive, anything else is not known. A row from before the field keeps its
// boolean reading.
export function tlsRptConfiguredStatus(row) {
  if (!row) return { label: 'Not available', kind: 'na' }
  if (row.observation_state == null) return row.enabled ? { label: 'Configured', kind: 'good' } : { label: 'Not configured', kind: 'bad' }
  if (row.observation_state === 'present' && row.enabled === true) return { label: 'Configured', kind: 'good' }
  if (row.observation_state === 'definitive_absent' && row.enabled !== true) return { label: 'Not configured', kind: 'bad' }
  return { label: 'Not available', kind: 'na' }
}

export function tlsRptRecordStatus(detail) {
  if (!detail || tlsRptNotConcluded(detail)) return { label: 'Not available', kind: 'na' }
  return { label: detail.record_found ? 'Found' : 'Not found', kind: detail.record_found ? 'good' : 'na' }
}

// Mail transport encryption: STARTTLS and the TLS handshake on each mail
// server the collector tested. In the mail_transport module a host is 'tested'
// only when STARTTLS was offered AND the TLS handshake finished
// (engines/mail-transport.js projectMailMxReceipt); a rejected upgrade is
// 'not_tested' with reason 'starttls_rejected'. Untested servers are never
// counted as passing.
export function mailTransportStatus(transport) {
  const hosts = Array.isArray(transport?.hosts) ? transport.hosts : []
  if (!hosts.length) return { label: 'Not tested', kind: 'na' }
  const tested = hosts.filter((h) => h?.state === 'tested').length
  const notOffered = hosts.filter((h) => h?.state === 'not_offered').length
  const rejected = hosts.filter((h) => h?.reason === 'starttls_rejected').length
  if (notOffered) return { label: `STARTTLS missing on ${notOffered} of ${hosts.length}`, kind: 'bad' }
  if (rejected) return { label: `STARTTLS rejected on ${rejected} of ${hosts.length}`, kind: 'bad' }
  if (tested === hosts.length) return { label: `STARTTLS on ${tested} of ${hosts.length}`, kind: 'good' }
  return { label: `Tested ${tested} of ${hosts.length}`, kind: 'warn' }
}
