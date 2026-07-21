# Dependency Overrides Register

Temporary, tracked `overrides` in `workers/scan-api/package.json`. Every override here
is a **deliberate deviation from a dependency's declared graph** and must carry an owner,
a review date, upstream tracking, and an explicit removal criterion. An override without a
removal criterion is a permanent fork and is not permitted.

---

## OV-1 — `sharp` forced to `0.35.3` (dev-transitive, CI security)

| Field | Value |
| --- | --- |
| **Status** | ACTIVE — temporary compatibility override |
| **Introduced** | 2026-07-22 (branch `fix/sharp-cve-override`, PR #268) |
| **Owner** | CyberMeters engineering (founder-owned) |
| **Review date** | 2026-10-31 (re-check upstream at each quarterly dependency sweep) |
| **Scope** | `workers/scan-api/package.json` `overrides` + `package-lock.json` only. No src/runtime, no `wrangler` version change, no deploy. |

### What it does
```json
"overrides": { "sharp": "0.35.3" }
```
Exact pin (not a range) so the resolved dev-tool graph cannot drift silently on future
installs.

### Why it exists
`npm audit --audit-level=high` (the `validate` CI job) fails on every PR: **sharp <0.35.0**
carries high-severity libvips advisories (GHSA-f88m-g3jw-g9cj — CVE-2026-33327 / -33328 /
-35590 / -35591). sharp is pulled **transitively by the dev toolchain only**:

```
wrangler@4.110.0 (devDependency)
  └─ miniflare@4.20260708.1
       └─ sharp@0.34.5   ← declared EXACT by miniflare; overridden → 0.35.3
```

sharp is **not a production dependency** and is **not imported anywhere in the Worker
`src/`**. There is **no identified production runtime reachability** — the advisory is real
on developer and CI machines (where the dev toolchain is installed), which is precisely why
clearing it is correct; it is not a claim that no risk exists anywhere.

### Compatibility evidence vs Miniflare's declared contract
Miniflare `4.20260708.1` declares `sharp: 0.34.5` as an **exact** pin, so forcing `0.35.3`
is **outside** Miniflare's declared dependency graph. This is a deliberate deviation, and it
is empirically validated rather than asserted:

1. **Miniflare does not statically import sharp.** `grep` of `node_modules/miniflare/dist/`
   finds no `require('sharp')` / `import … from 'sharp'`. Miniflare loads sharp lazily only
   under the **Cloudflare Images binding** simulation path.
2. **CyberMeters registers no Images binding.** `grep -niE "images|sharp"` over
   `wrangler.toml` and `src/` is empty, so that code path is never exercised in local dev
   or CI — Miniflare never invokes sharp for this project.
3. **Bundle still builds** with the override: `npx wrangler deploy --dry-run` succeeds.
4. **sharp 0.35.3 itself is functional** natively on macOS arm64: a `create → png →
   toBuffer` native op produced a valid PNG (95 bytes). 0.34.5 → 0.35.3 is a semver-minor
   sharp release; its dependency graph resolves cleanly (`@img/colour`, `detect-libc`,
   `semver`, `@img/sharp-*` native).
5. **`npm audit --audit-level=high` = 0 vulnerabilities** after the override.
6. **Lockfile diff is scoped**: only the sharp / `@img/*` / libvips graph nodes change; no
   unrelated package node is added or removed.

Conclusion: the override deviates from Miniflare's declared exact pin, but the deviating
component is never invoked by this project and the bundle + audit + native op all pass, so
the deviation has no identified functional or runtime exposure. It remains a **temporary
compatibility override**, not a permanent decision, because we are ahead of Miniflare's own
declared graph.

### Upstream tracking
- Advisory: **GHSA-f88m-g3jw-g9cj** (sharp <0.35.0 / libvips).
- Upstream fix we are waiting on: **wrangler / miniflare (`cloudflare/workers-sdk`)** bumping
  its bundled sharp pin to **≥ 0.35.0**. Miniflare currently declares `sharp 0.34.5` exact.
- Re-check on each `wrangler` upgrade and at the review date above.

### Removal criterion
Remove `OV-1` when a supported `wrangler` (and its bundled `miniflare`) declares
**`sharp ≥ 0.35.0`**. Verify removal safely by:
1. deleting the `sharp` entry from `overrides`,
2. `npm install` + `npm ls sharp` shows a resolved sharp **≥ 0.35.0** with no `overridden`,
3. `npm audit --audit-level=high` stays **0 vulnerabilities**,
4. `npx wrangler deploy --dry-run` still builds.

If all four hold, delete this record's ACTIVE status and note the closing wrangler/miniflare
version.
