import { formatDate } from '../utils/dates'
import { mtaStsWords, tlsRptWords } from '../../../shared/email/mail-transport-words.js'

// Mail transport encryption: what the private collector observed when it
// connected to each MX host (STARTTLS offered, the TLS handshake and the
// certificate), with MTA-STS and TLS-RPT context. Presentation only: every
// state comes from the scan's mail_transport module.
// Shown under Email Protection and on the scan's Technical Details tab.
// Why no mail server was tested, from the module's reason code.
const NOT_TESTED = {
  verified_workspace_required: 'Mail servers are tested only for a domain verified in a workspace, so this scan did not test them.',
  mx_not_observed: 'No MX record was observed, so there was no mail server to test.',
  probe_unavailable: 'The mail server test was unavailable in this scan. Nothing was concluded about mail encryption.',
}

export function MailTransportCard({ transport, mtaSts, tlsRpt, embedded = false }) {
  const hosts = Array.isArray(transport?.hosts) ? transport.hosts : []
  return <section className={embedded ? 'px-6 py-4' : 'card p-5'} data-testid="mail-transport-encryption">
    {!embedded && <h3 className="text-sm font-semibold text-gray-900">Mail transport encryption</h3>}
    <p className="text-xs text-gray-600 mt-2">One address per mail server is tested. Other addresses are not assessed here. Offering STARTTLS does not prove that all mail delivery is encrypted. Mandatory encrypted delivery requires an active MTA-STS enforce policy.</p>
    {hosts.length === 0 ? <p className="text-sm text-gray-600 mt-3">{NOT_TESTED[transport?.reason] || 'Mail servers were not tested in this scan.'}</p> :
      <ul className="mt-3 space-y-3 text-sm">
        {hosts.map(host => <li key={host.host} className="border-t border-gray-100 pt-3">
          <p className="font-medium text-gray-900 break-all">{host.host}</p>
          {host.tested_address && <p className="text-xs text-gray-500 break-all">Tested address: {host.tested_address}</p>}
          <p className="text-gray-600">{host.state === 'tested' ? 'STARTTLS offered · TLS handshake completed' :
            host.state === 'not_offered' ? 'STARTTLS not offered' :
            host.reason === 'starttls_rejected' ? 'STARTTLS offered; server rejected the upgrade' :
            host.reason === 'mx_host_does_not_exist' ? 'This mail server does not exist in public DNS, so mail sent to this domain cannot be delivered to it.' :
            host.reason === 'mx_host_has_no_address' ? 'This mail server has no address in public DNS, so mail sent to this domain cannot be delivered to it.' :
            'Not tested — connection or TLS evidence unavailable'}</p>
          {host.state === 'tested' && <p className="text-xs text-gray-600 mt-1">
            {({ tls1_2: 'TLS 1.2', tls1_3: 'TLS 1.3' })[host.tls_version] || 'TLS version not recorded'} · {host.cipher || 'Cipher not recorded'}
            {host.cipher_class === 'weak' ? ' · weak cipher' : ''} · Hostname {host.certificate_hostname_match === true ? 'matched' : host.certificate_hostname_match === false ? 'mismatched' : 'not assessed'}
            {' · '}Chain {host.chain_validity || 'not assessed'} · Certificate expires {formatDate(host.certificate_expires_at, 'not recorded', { timeZone: 'UTC' })}
          </p>}
        </li>)}
      </ul>}
    <div className="mt-4 border-t border-gray-100 pt-3 space-y-1 text-xs text-gray-600">
      <p>MTA-STS: {mtaStsWords(mtaSts)}.</p>
      <p>TLS-RPT: {tlsRptWords(tlsRpt)}.</p>
    </div>
  </section>
}

export default MailTransportCard
