import { formatTime } from './ToolResult'

// Presentation of the SSL/TLS result: the certificate as observed on one
// connection, and the issuer chain the checker built. All wording comes from
// the API result; this file only lays it out.
function Row({ label, children }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-[12rem_1fr] gap-1 sm:gap-4 py-2 border-t border-gray-100 first:border-t-0">
      <dt className="text-sm text-gray-500">{label}</dt>
      <dd className="text-sm text-gray-900 break-all">{children}</dd>
    </div>
  )
}

export default function SslDetails({ result }) {
  const cert = result.certificate
  if (!cert) return null
  const names = cert.dns_names || []
  return (
    <div className="space-y-8">
      <section aria-labelledby="cert-heading" className="space-y-3">
        <h2 id="cert-heading" className="text-lg font-bold">The certificate</h2>
        <dl className="rounded-2xl border border-gray-100 bg-white px-4 sm:px-5 py-2">
          <Row label="Issued to">{cert.subject}</Row>
          <Row label="Issued by">{cert.issuer}</Row>
          <Row label="Valid from">{formatTime(cert.not_before)}</Row>
          <Row label="Valid until">{formatTime(cert.not_after)}{Number.isFinite(cert.days_left) && cert.days_left >= 0 ? ` (${cert.days_left} days left)` : ''}</Row>
          <Row label="Names covered">{names.length ? names.slice(0, 20).join(', ') + (names.length > 20 ? ` and ${names.length - 20} more` : '') : 'None listed'}</Row>
          <Row label="Connection">{result.protocol ? result.protocol.replace('TLSv', 'TLS ') : 'Not recorded'}{result.endpoint?.address ? ` to ${result.endpoint.address}` : ''}</Row>
          <Row label="Fingerprint (SHA-256)"><span className="font-mono text-xs">{cert.sha256}</span></Row>
        </dl>
      </section>

      {result.chain?.length > 0 && (
        <section aria-labelledby="chain-heading" className="space-y-3">
          <h2 id="chain-heading" className="text-lg font-bold">Issuer chain we built</h2>
          <p className="text-sm text-gray-600">This is the chain our checker built from its trust store. It is not necessarily the list of certificates your server sends.</p>
          <ol className="rounded-2xl border border-gray-100 bg-white divide-y divide-gray-100">
            {result.chain.map((c, i) => (
              <li key={`${c.subject}-${i}`} className="p-4 text-sm space-y-1">
                <p className="font-semibold text-gray-900 break-all">{c.subject}</p>
                <p className="text-gray-600 break-all">Issued by {c.issuer} · valid until {formatTime(c.not_after)}</p>
              </li>
            ))}
          </ol>
        </section>
      )}
    </div>
  )
}
