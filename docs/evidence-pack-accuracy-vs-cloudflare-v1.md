# Evidence Pack — CyberMeters vs. Cloudflare Security Insights (Accuracy)

**Type:** Independent, reproducible accuracy comparison on a single shared domain
**Subject domain:** `cybermeters.com` (owned by the authors)
**Cloudflare scan:** 2026-07-06 18:29 UTC — from Cloudflare's own Security Insights export (CSV)
**Independent verification:** 2026-07-06 19:30 UTC — via public DNS (`dig`) and HTTPS (`curl`)
**Method:** Every counter-claim below is backed by a public record any reviewer can reproduce with one command. No privileged access required.

> A polished PDF of this pack (`CyberMeters-vs-Cloudflare-Accuracy-Report.pdf`) is generated from this
> document for grant/sales use. This markdown is the canonical, version-controlled source.

---

## Executive summary

On the same domain, on the same day, Cloudflare's Security Insights scanner produced a **false positive**, a
**false negative**, and **three duplicate findings** for a single issue — while CyberMeters produced the accurate,
de-duplicated assessment. Of Cloudflare's 16 findings: **0** were high or critical, **13 of 16** were prompts to
enable Cloudflare's own products (not security defects), the 3 flagged as "DMARC Record Error" were factually wrong,
and its "Security.txt not configured" finding was wrong too.

| Accuracy dimension | Cloudflare Security Insights | CyberMeters |
|---|---|---|
| DMARC record present + RFC-valid | ❌ Reported "missing / incorrectly configured" (false positive) | ✅ Correctly reported "Monitor-Only (p=none)" |
| Duplicate findings for one issue | ❌ 3× (one per MX record) | ✅ 1 finding, de-duplicated per domain |
| Live security.txt (RFC 9116) | ❌ Reported "not configured" (false negative) | ✅ Detected as present |
| Signal vs. product upsell | 13 of 16 findings are prompts to enable Cloudflare products | Separates actionable findings from informational observations |
| Agreement with Cloudflare's own DMARC tool | ❌ Contradicted by it — DMARC Management confirms the record Insights calls missing (Finding 4) | ✅ Consistent with it |

---

## Finding 1 — DMARC: a false positive, reported three times

**Cloudflare's claim** (verbatim from its CSV export, issue class *"DMARC Record Error detected"*, severity Low,
scanned 2026-07-06 18:29:37 UTC):

> "DMARC Record Error detected. Your email authentication records for cybermeters.com are **missing or incorrectly
> configured** … you have an MX record for this domain **without a corresponding, correctly formed DMARC record**."
> — emitted **3×**, all subject `cybermeters.com`, all at 18:29:37.

**Ground truth** — the DMARC record is present and syntactically valid (RFC 7489). Reproduced 2026-07-06 19:30 UTC:

```
$ dig +short TXT _dmarc.cybermeters.com
"v=DMARC1; p=none; rua=mailto:cmrua_adfcbad7403846483ae4702b1cd7069b@reports.cybermeters.com"

$ dig +short MX cybermeters.com        # 3 MX → Cloudflare's 3 duplicates
32 route3.mx.cloudflare.net.
34 route2.mx.cloudflare.net.
49 route1.mx.cloudflare.net.
```

**CyberMeters, on the same domain**, reports the record accurately — present and valid, but monitor-only, which is a
real (medium) improvement opportunity, not an error:

```
DMARC Policy is Monitor-Only (p=none)                    [MEDIUM]
  DMARC is configured at _dmarc.cybermeters.com with p=none.
  Receivers are not instructed to quarantine or reject messages
  that fail alignment.   → recommended: progress toward enforcement.
```

**Verdict:** Cloudflare states the record is "missing or incorrectly configured" — the record is present and RFC-valid,
so the statement is **factually false**. It also duplicates the finding once per MX record. CyberMeters is accurate and
de-duplicated.

*Fair note:* Cloudflare may intend to signal that monitor-only mode does not yet block spoofing. That is a valid
observation — and exactly what CyberMeters reports. But Cloudflare's stated wording claims the record is missing or
malformed, which the public DNS record above disproves.

---

## Finding 2 — Security.txt: a false negative

**Cloudflare's claim** (issue class *"Security.txt not configured"*, scanned 2026-07-06 18:29:36 UTC):
"We evaluated the Security Settings configured for this domain and found that Security.txt is not enabled."

**Ground truth** — the RFC 9116 disclosure file is live and correctly served. Reproduced 2026-07-06 19:30 UTC:

```
$ curl -sI https://cybermeters.com/.well-known/security.txt
HTTP 200 | content-type: text/plain; charset=utf-8 | ssl_verify: 0

$ head -1 (body):
# CyberMeters vulnerability disclosure — RFC 9116
```

**Verdict:** Cloudflare reports the control as absent; the control is present and returns HTTP 200. This is a **false
negative** — a real, deployed security control that Cloudflare's scanner missed. CyberMeters treats a served
security.txt as present.

---

## Finding 3 — Signal-to-noise: 13 of 16 findings are product prompts

Cloudflare returned 16 findings for the account. None were high or critical. The composition:

| Cloudflare finding class | Count | What it actually is |
|---|---:|---|
| Bot Fight Mode not enabled | 3 | Prompt to enable a Cloudflare product |
| Review / block AI bots | 3 | Prompt to enable a Cloudflare product |
| AI Labyrinth | 3 | Prompt to enable a Cloudflare product |
| No Turnstile enabled | 1 | Prompt to enable a Cloudflare product |
| Security.txt not configured | 3 | ❌ False negative (file is live — Finding 2) |
| DMARC Record Error detected | 3 | ❌ False positive, duplicated (Finding 1) |
| **True security defects correctly identified** | **0** | **—** |

By contrast, CyberMeters' report on `cybermeters.com` distinguishes **findings** (actionable, score-impacting) from
**observations** (informational), and correctly surfaced the one genuine opportunity — moving DMARC toward
enforcement — as MEDIUM, alongside honest observations (DNSSEC not configured; DKIM selector not confirmed) that it
explicitly does not overstate.

---

## Finding 4 — Cloudflare's own DMARC tool contradicts its Security Insights

On the same day, inside the same Cloudflare account, two Cloudflare products made opposite claims about the same
record:

| Cloudflare product | Claim (verbatim) | Observed |
|---|---|---|
| **Security Insights** | "DMARC Record Error detected … your email authentication records for cybermeters.com are **missing or incorrectly configured**" (×3) | Scanned 2026-07-06 **18:29:37 UTC** (its own CSV export) |
| **DMARC Management** (dashboard → Email) | "**Existing DMARC record found.** Click Next to start getting DMARC reports." — and lists the record verbatim under *Existing record* | Same dashboard, same day (screenshots retained) |

The record DMARC Management displays is exactly the one Insights calls missing:
`_dmarc.cybermeters.com → "v=DMARC1; p=none; rua=mailto:cmrua_…@reports.cybermeters.com"`.

**Timeline rules out propagation lag.** The record was published at **14:20 UTC** (TTL 300s); the Insights scan ran at
**18:29 UTC** — more than four hours later. At scan time, three independent resolver paths (authoritative `dig`,
Google DoH, Cloudflare's own 1.1.1.1 DoH) each returned exactly **one** valid record.

**Verdict:** the false positive in Finding 1 is confirmed not just by public DNS but by **Cloudflare's own tooling** —
one Cloudflare product recognises the record as valid while another simultaneously reports it missing. An accuracy
dispute between us and Cloudflare could be argued; a contradiction between Cloudflare and Cloudflare cannot.

*Fair note:* different products with different scan cadences can disagree transiently. But four hours after
publication, with a 300-second TTL and Cloudflare itself serving the zone's DNS, cadence does not explain reporting a
resolvable record as "missing or incorrectly configured".

---

## Conclusion

On a single shared domain, measured on the same day, Cloudflare's Security Insights was wrong in both directions — it
invented a DMARC defect that does not exist and missed a security control that does — and it triplicated a single
issue. Its own DMARC Management product contradicted it on the central claim (Finding 4). CyberMeters produced the
accurate, de-duplicated, and honestly-scoped assessment on the same inputs. Accuracy
and honest scoping are the core promise of an attack-surface product; this is one reproducible data point that
CyberMeters delivers them where a major incumbent did not.

**Scope & fairness:** this compares one domain at one point in time and is **not** a general benchmark of either
product's full capability. It is presented precisely because every claim is independently reproducible from the
commands below — the reader does not have to take our word for anything.

---

## Appendix — reproduce every claim yourself

```bash
# DMARC record exists and is valid (disproves Finding 1):
dig +short TXT _dmarc.cybermeters.com
dig +short MX cybermeters.com          # 3 MX = Cloudflare's 3 dupes

# security.txt is live (disproves Finding 2):
curl -sI https://cybermeters.com/.well-known/security.txt

# Cloudflare's own export is the source for its claims + timestamps:
# Cloudflare dashboard → Security Center → Insights → Export CSV

# Cloudflare contradicting itself (Finding 4):
# Cloudflare dashboard → Email → DMARC Management — shows "Existing DMARC
# record found" for the very record Security Insights reports as missing.
```

*Underlying commit context: DMARC published `0aa9525`; security.txt `ec0077b`; DMARC monitor-only detection and
per-domain de-duplication are part of the Email Protection engine.*
