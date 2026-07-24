# Item 5 CT-provider blackout — founder live-acceptance procedure

Status: prepared, not executed. This procedure is read-only after the founder
starts a normal scan of a founder-controlled domain. It must not be used on an
unrelated customer workspace.

## Safety boundary

- Do not add a production outage switch, block Worker egress, alter DNS, or
  interfere with crt.sh or CertSpotter.
- Do not classify an empty successful response as an outage. Provider
  unavailability must be explicit in the immutable report's
  `execution_diagnostics.provider_health`.
- Use a naturally observed provider failure, or a separately founder-approved
  isolated canary environment. A local/synthetic fixture is regression evidence,
  not live acceptance.
- The scan may complete. The acceptance criterion is that CT-dependent
  conclusions become evidence-insufficient while unrelated domains retain their
  own evidence-based outcomes.

## Pre-flight

1. Record the deployed Worker version, rollback version, and Git SHA.
2. Confirm `/health` and `/ready` are healthy.
3. Select a founder-controlled workspace and verified domain.
4. Record the latest pre-test scan ID, score presentation, eight-domain states,
   and DNS state. The procedure makes no DNS or configuration changes.

## Reliability matrix

| Scenario | Provider evidence required | Canonical CT state | Required result |
| --- | --- | --- | --- |
| crt.sh down, CertSpotter available | `crt_sh=unavailable`, `certspotter=available` | `monitoring_degraded` | Attack Surface and every other CT-dependent healthy/negative conclusion are evidence-insufficient; unrelated domains are not failed |
| both CT providers down | both providers explicitly `unavailable` | `signal_unavailable` | Same fail-closed conclusion; subdomains is incomplete; overall score is provisional, rating/BRI band suppressed |

Run each row only when its provider evidence is genuinely present. Google,
browser, or shell reachability checks made outside the Worker are contextual
evidence only; the report's per-scan provider telemetry is authoritative for the
scenario.

## Execute a founder-domain scan

1. Start one ordinary manual scan through the authenticated product workflow.
2. Record its scan ID. Do not retry until the first scan reaches a terminal state.
3. Confirm the scan completed and that unrelated modules were not globally
   failed by the CT outage.
4. Hard-stop if provider telemetry does not match either matrix row. A normal
   provider response is not a blackout acceptance test.

## Capture immutable evidence read-only

From `workers/scan-api/`, set explicit task variables (never reuse system
variables):

```bash
export CM_ACCEPT_SCAN_ID='<founder scan id>'
export CM_ACCEPT_REPORT_FILE='/tmp/cybermeters-ct-report.json'
export CM_ACCEPT_SNAPSHOT_FILE='/tmp/cybermeters-ct-snapshot.json'
```

Capture the immutable scan report:

```bash
npm exec -- wrangler r2 object get \
  "cybermeters-reports/reports/${CM_ACCEPT_SCAN_ID}.json" \
  --remote \
  --file="${CM_ACCEPT_REPORT_FILE}"
```

Read the active completed snapshot key without mutating D1:

```bash
npm exec -- wrangler d1 execute cybermeters-db --remote --json \
  --command="SELECT id, r2_key, checksum_sha256, status, resolver_version, scan_quality, assessed_at FROM scan_report_snapshots WHERE scan_id='${CM_ACCEPT_SCAN_ID}' AND status='completed' ORDER BY completed_at DESC LIMIT 1"
```

Copy the returned `r2_key` and `checksum_sha256` exactly, then capture that
object:

```bash
export CM_ACCEPT_SNAPSHOT_KEY='<exact r2_key from the query>'
export CM_ACCEPT_SNAPSHOT_CHECKSUM='<exact checksum_sha256 from the query>'
npm exec -- wrangler r2 object get \
  "cybermeters-reports/${CM_ACCEPT_SNAPSHOT_KEY}" \
  --remote \
  --file="${CM_ACCEPT_SNAPSHOT_FILE}"
```

The offline verifier below checks the captured bytes against that D1 checksum
before interpreting the snapshot. A mismatch is a hard-stop.

## Offline acceptance

For the one-provider row:

```bash
node ../../scripts/verify-live-ct-blackout-acceptance.js \
  --scenario=crt-sh-down \
  --report="${CM_ACCEPT_REPORT_FILE}" \
  --snapshot="${CM_ACCEPT_SNAPSHOT_FILE}" \
  --expected-checksum="${CM_ACCEPT_SNAPSHOT_CHECKSUM}"
```

For the total-blackout row:

```bash
node ../../scripts/verify-live-ct-blackout-acceptance.js \
  --scenario=both-ct-down \
  --report="${CM_ACCEPT_REPORT_FILE}" \
  --snapshot="${CM_ACCEPT_SNAPSHOT_FILE}" \
  --expected-checksum="${CM_ACCEPT_SNAPSHOT_CHECKSUM}"
```

Required PASS evidence:

- the exact provider outcomes match the selected row;
- the canonical CT state is identical in report and snapshot;
- subdomain evidence is incomplete, never a successful empty finding set;
- Attack Surface is `evidence_insufficient`, coverage is not `complete`, and no
  CT-dependent domain earns a healthy conclusion from missing CT evidence;
- the snapshot assessment is provisional/non-authoritative, rating is absent,
  and the Business Risk Indicator band is absent;
- the Executive PDF generated for that same snapshot states the CT monitoring
  limitation and does not print an authoritative healthy/high rating;
- unrelated domain outcomes continue to reflect their own completed evidence.

## Reconciliation and stop conditions

1. Confirm exactly one completed snapshot exists for the scan and its checksum
   matches the R2 object.
2. Confirm the authenticated scan-report and Executive Report APIs expose the
   same `monitoring_states`, domain state, score qualification, and null rating/BRI
   band frozen in the snapshot.
3. Confirm no DNS change, case transition, alert, or customer notification was
   caused merely by provider unavailability.
4. Record the report key, snapshot ID/key/checksum, scan ID, provider outcomes,
   Git SHA, Worker version, PDF evidence, and verifier output.
5. Hard-stop on any missing provenance, state mismatch, snapshot/checksum
   mismatch, healthy Attack Surface, `complete` domain coverage, unqualified
   rating/BRI band, or unrelated-customer impact.

Recovery after providers return is a separate founder-sequenced contract and is
not accepted by this procedure.
