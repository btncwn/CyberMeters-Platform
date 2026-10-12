// How an asset first came to be known, in customer words. The stored value is
// the discovery source code; an unrecognised code is shown as-is rather than
// guessed at.
const SOURCE_LABELS = Object.freeze({
  scan_root:                'Scanned domain',
  dns_discovery:            'DNS discovery',
  dns_bruteforce:           'DNS lookup',
  dns_mx:                   'Mail (MX) record',
  dns_srv:                  'Service (SRV) record',
  html_link:                'Linked from your website',
  cloud_storage_discovery:  'Cloud storage check',
  exposure_probe:           'Web exposure check',
  // Named in the customer's own configuration and confirmed by DNS.
  tls_certificate_name:     'Named in your website certificate',
  mx_target:                'Your mail server (MX)',
  ns_target:                'Your name server (NS)',
  spf_reference:            'Named in your SPF record',
  dmarc_reference:          'Named in your DMARC record',
  redirect_reference:       'Reached by a website redirect',
  csp_reference:            'Named in your Content-Security-Policy',
  link_header_reference:    'Named in a website Link header',
  cors_reference:           'Allowed by your website CORS policy',
  // Deeper DNS discovery, confirmed by DNS.
  dns_wordlist:             'DNS lookup (extended name list)',
  dns_name_variant:         'Name pattern check',
  dnssec_nsec:              'Listed in your DNSSEC zone records',
  // historical: assets discovered before certificate logs were retired.
  certificate_transparency: 'Certificate log (historical)',
})

export function assetSourceLabel(source) {
  const key = typeof source === 'string' ? source.trim() : ''
  if (!key) return '—'
  return Object.prototype.hasOwnProperty.call(SOURCE_LABELS, key) ? SOURCE_LABELS[key] : key
}
