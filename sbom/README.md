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

## License policy (CI-enforced)

`scripts/validate-licenses.js` reads these SBOMs and fails CI if any component
ships under a license that isn't permissive (MIT/ISC/BSD/Apache-2.0/CC0/… — the
full allowlist is in the script) and isn't a documented exception. This keeps a
copyleft (GPL/AGPL/LGPL/SSPL/BUSL) or unknown-licensed dependency from silently
entering the product. Runs right after SBOM generation in CI; reads the committed
snapshots locally.

Current exceptions (both safe, both non-shipped):
- **sharp-libvips-\*** (LGPL-3.0-or-later) — optional, platform-specific native
  image lib; dynamically used, unmodified, never bundled into the Worker.
- **caniuse-lite** (CC-BY-4.0) — build-time browser-compatibility data, not
  redistributed in the app bundle.

To add a dependency under a new license: either it's already permissive (nothing
to do), or add a documented `EXCEPTIONS` entry only if it's genuinely safe.

## Notes

- `--ignore-npm-errors` tolerates optional-dependency quirks (e.g. `fsevents`
  is darwin-only) without dropping real components.
- Pair with `npm audit --audit-level=high` (also in CI, 0 vulnerabilities on
  both workspaces) — audit finds *known* CVEs; the SBOM lets us answer
  "are we affected?" for any *future* disclosure.
