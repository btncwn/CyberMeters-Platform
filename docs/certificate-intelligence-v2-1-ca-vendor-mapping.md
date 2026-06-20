# Certificate Intelligence v2.1: CA Vendor Mapping

Certificate Intelligence v2.1 maps observed TLS certificate issuers to certificate
authority vendors in the existing vendor inventory. The goal is to make public
TLS trust-chain dependencies visible to Vendor Risk and future Supply Chain Risk
without changing the certificate scanner architecture.

## Issuer Normalization Logic

The worker adds `normalizeCertificateAuthorityVendor(issuer)` in
`workers/scan-api/src/index.js`.

Input is a raw certificate issuer string. The helper trims and normalizes the
string, then matches known CA family patterns. Known matches return:

```json
{
  "vendor_name": "DigiCert",
  "vendor_type": "certificate_authority",
  "confidence": "high",
  "source": "certificate_issuer"
}
```

Unknown or empty issuers return `null`. This avoids polluting vendor inventory
with arbitrary intermediate CA names that cannot be confidently mapped to an
organisation.

## CA Vendor Mapping Examples

| Issuer string | Vendor |
| --- | --- |
| `Let's Encrypt` | `Let's Encrypt` |
| `DigiCert TLS RSA SHA256 2020 CA1` | `DigiCert` |
| `Sectigo RSA Domain Validation Secure Server CA` | `Sectigo` |
| `Cloudflare Inc ECC CA-3` | `Cloudflare` |
| `Google Trust Services` | `Google Trust Services` |
| `GlobalSign GCC R3 DV TLS CA 2020` | `GlobalSign` |
| `Amazon RSA 2048 M02` | `Amazon Trust Services` |
| `Microsoft Azure TLS Issuing CA` | `Microsoft` |
| `ZeroSSL RSA Domain Secure Site CA` | `ZeroSSL` |

## Vendor Inventory Integration

When certificate observations are persisted by `upsertCertificateObservation`,
the issuer is normalized and written to the existing `workspace_vendors` table
through `upsertCertificateAuthorityVendor`.

Rows use the existing vendor inventory structure:

- `vendor_name`: normalized CA vendor name
- `category`: `certificate_authority`
- `source`: `certificate_issuer`
- `confidence`: `high`
- `risk_level`: `medium`
- `evidence`: issuer, subject, SAN count, expiry, and certificate key
- `metadata_json`: trust-chain dependency metadata

The metadata is intentionally basic:

```json
{
  "dependency_type": "certificate_authority",
  "criticality": "high",
  "business_reason": "This organisation issues or validates TLS certificates used by observed public-facing assets."
}
```

No new table is required. The implementation reuses `workspace_vendors` and the
existing vendor API surface. `GET /api/workspaces/:id/vendors` can return and
filter `category=certificate_authority`, and the vendor summary includes a
`certificate_authority` count.

## Limitations

This version maps only known CA families with high confidence. It does not infer
ownership for unknown issuers, private CAs, regional CAs, or rebranded issuers
unless a pattern is explicitly added.

The vendor row represents a trust-chain dependency, not a finding that the CA is
breached, non-compliant, or unsafe. The risk metadata should be read as
dependency context only.

## Future Supply Chain Integration

Future supply chain scoring can use `category=certificate_authority` and
`metadata_json.dependency_type=certificate_authority` to distinguish CA vendors
from SaaS, infrastructure, hosting, and identity providers.

Possible future extensions:

- Track CA concentration across all public-facing assets.
- Flag issuer changes for supply chain review workflows.
- Add curated CA metadata such as operating region or ownership group.
- Correlate CA dependency changes with certificate alerts and asset criticality.
