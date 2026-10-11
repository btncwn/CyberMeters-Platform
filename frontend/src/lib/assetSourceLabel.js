// How an asset first came to be known, in customer words. The stored value is
// the discovery source code; an unrecognised code is shown as-is rather than
// guessed at.
const SOURCE_LABELS = Object.freeze({
  scan_root:                'Scanned domain',
  certificate_transparency: 'Certificate Transparency',
  dns_bruteforce:           'DNS lookup',
  dns_mx:                   'Mail (MX) record',
  dns_srv:                  'Service (SRV) record',
  html_link:                'Linked from your website',
  cloud_storage_discovery:  'Cloud storage check',
  exposure_probe:           'Web exposure check',
})

export function assetSourceLabel(source) {
  const key = typeof source === 'string' ? source.trim() : ''
  if (!key) return '—'
  return Object.prototype.hasOwnProperty.call(SOURCE_LABELS, key) ? SOURCE_LABELS[key] : key
}
