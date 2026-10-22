# sheshire.co.uk batch-1 scan: what to read, and what to say if it is not there

One founder scan of `sheshire.co.uk` proves the batch-1 fixes. After it completes, read each item from the exact place below.

**Sources:**
- **Report:** `reports/<scanId>.json` in R2 `cybermeters-reports`.
- **D1:** `cybermeters-db`.
- **Scan id:** `SELECT id FROM scans WHERE domain='sheshire.co.uk' ORDER BY created_at DESC LIMIT 1`.

If an item does not appear, say exactly the wording in its last line. Never say "passed", "verified" or "accepted" without the evidence named here.

## 1. The scan is complete, and the score is shown (#834, #827)

- **Read:**
  - report `scan_quality.status`;
  - `scan_quality.modules_incomplete`;
  - `scan_quality.stated_limits`.
- **Expect:**
  - `status = "complete"`;
  - `modules_incomplete = []`;
  - `stated_limits` contains `{module: "subdomain_takeover", reason: "origin_access_restricted"}` and `{module: "technology_detection", reason: "origin_access_restricted"}` while the store stays closed.
- **If not:** "The scan is still partial because of `<module>: <incomplete_reason>`; the score stays provisional."

## 2. The takeover candidate is an observation (#834)

- **Read:** report `findings[]` where `id = "subdomain_takeover_unconfirmed"`.
- **Expect:**
  - `finding_type = "observation"`, `severity = "low"`, `confidence = 50`, `score_impact = 0`;
  - the description names `www.sheshire.co.uk`, `shops.myshopify.com` and `Shopify`, and contains "could not confirm either way";
  - no `managed_cases` row with `finding_id = 'subdomain_takeover_unconfirmed'` for the workspace.
- **If not:**
  - provider answered: "The provider answered the confirming probe this time; the takeover module's own result is `<unconfirmed[].reason or risks[]>`";
  - nothing at all: "The candidate was not reported."

## 3. The HSTS case can verify-close

- **Read:**
  - `managed_cases WHERE workspace_id=<ws> AND source_finding_type='header_missing_strict_transport_security'`: `status`, `verified_at`;
  - `managed_case_events` for that case, ordered by `created_at`;
  - report `findings[]`: the HSTS finding is absent.
- **Expect:**
  - the finding is absent and the scan is complete (item 1);
  - if the customer had asked for verification, the case moves to `verified`/`resolved` with a system event naming this scan.
- **If not:**
  - finding still present: "HSTS is still missing on `<host>`; the case stays open";
  - case not asked for verification: "The fix is observed; the case closes when verification is requested";
  - scan partial: "Not verified: the scan was partial."

## 4. CE recovery is an improvement, never "worsened" (#829)

- **Read:** `cyber_essentials_events WHERE workspace_id=<ws> ORDER BY created_at DESC` (`event_type`).
- **Expect:**
  - `control_evidence_improved` (non-alerting) or `control_recovered`;
  - no `ce_control_worsened` (recurrence `externally_observed_control_worsened`) for a control whose evidence set only shrank;
  - no CE alert claiming "worsened".
- **If not:** "CE recorded `<event_type>` for `<control>`; evidence before `<set>`, after `<set>`." Treat it as a P1 if it says worsened.

## 5. Remote-admin ports (#844)

- **Read:** report `modules.remote_admin_exposure`: `state`, `reason`, `coverage`, `exposures[]`, `incomplete_reason`.
- **Expect:**
  - `state = "observed"`, with `coverage.checked_addresses ≥ 1` and `completed_pairs = planned_pairs`;
  - no `remote_admin_service_reachable` finding unless a listed port really answered.
  - sheshire's apex is behind shared hosting, so `no_owned_address_observed` is also an honest result.
- **If not:**
  - not assessed: "Remote-admin ports were not assessed: `<reason>`";
  - module missing: "The module did not run."
- **This is not live acceptance.** That needs Seat 2's company-owned address with an open port.

## 6. DANE states (#846)

- **Read:** report `modules.dane`: `mail[].state`, `web.state`.
- **Expect:**
  - the MX host `sheshire-co-uk.mail.protection.outlook.com` reads `not_assessable`;
  - `web.state = "not_assessable"` (no DNSSEC);
  - a `dane_status_observed` observation, and no `email_dane_tlsa_ineffective` finding.
- **If not:** "DANE was `<state>`/`<reason>`."

## 7. Signed-in scan (#841, proof site)

- **Read:** `website_sign_in_attempts WHERE domain_id=<sheshire domain> AND source='scan' AND scan_id=<scanId>`: `outcome`, `coverage`, `summary_json`.
- **Expect:**
  - the sign-in `outcome` is a success;
  - `coverage` is `complete` (or `partial` with `partial_reasons`);
  - `summary_json.pages[]` includes `/account` with `outcome = "observed"`.
- **If not:**
  - no row: "No signed-in scan ran (no profile or not entitled)";
  - row present: "Sign-in outcome `<outcome>`; signed-in pages not checked."

## Also visible in the same scan (already live)

| Item | PR | What to look for |
|---|---|---|
| Business Risk sentence | #843 | Names the band and the top risks; never "low risk / no major gaps" under a Moderate header |
| Dead MX | #831 | The Email card reads "This mail server does not exist in public DNS…" |
| DKIM note | #823 | Names the SPF and MX providers by source |
| DMARC example | #825 | Says to replace `dmarc-reports@sheshire.co.uk` |
| TLS | #819 | Report `modules.tls_assessment` present with `quality` |
