# Software Bill of Materials (SBOM)

CycloneDX (JSON, spec 1.6) dependency inventories for CyberMeters, one per
workspace. An SBOM lists every third-party component we ship so a newly
disclosed CVE can be matched against our actual dependencies in minutes — a
customer/Trust-Center artifact and a supply-chain control.

| File | Workspace | What it covers |
|---|---|---|
| `scan-api.cdx.json` | `workers/scan-api` | Cloudflare Worker runtime + build deps |
| `frontend.cdx.json` | `frontend` | React/Vite app + build/test deps |

## Regenerating

```bash
# per workspace, with node_modules installed for an accurate tree
cd workers/scan-api && npx @cyclonedx/cyclonedx-npm@6.0.0 --ignore-npm-errors \
  --output-format JSON --output-file ../../sbom/scan-api.cdx.json
cd frontend && npx @cyclonedx/cyclonedx-npm@6.0.0 --ignore-npm-errors \
  --output-format JSON --output-file ../sbom/frontend.cdx.json
```

CI regenerates both on every run (job `validate` → *Generate SBOMs*) and
uploads them as the `sbom-cyclonedx` build artifact, so the artifact is always
accurate for that commit. The committed files here are the point-in-time
snapshot for reference; refresh them when dependencies change materially.

## Notes

- `--ignore-npm-errors` tolerates optional-dependency quirks (e.g. `fsevents`
  is darwin-only) without dropping real components.
- Pair with `npm audit --audit-level=high` (also in CI, 0 vulnerabilities on
  both workspaces) — audit finds *known* CVEs; the SBOM lets us answer
  "are we affected?" for any *future* disclosure.
