# Founder Conditional HOLD Pre-Authorisation — 30 August 2026

**Record type:** append-only reserved-decision receipt
**Scope:** the two bounded HOLD stages for the rebuilt PR #449 rescue candidate
**Authority:** the Founder's explicit current instruction under
`docs/AI-EXECUTIVE-OPERATING-MODEL.md` §1 and §3
**Current state:** recorded but not consumed; production/customer `HOLD` remains
in force

This receipt preserves one bounded Founder decision. It is not a parallel
constitution, successor governance package, release record or technical
acceptance. The operating model remains the sole active governance authority;
the current execution order remains in `docs/PRE-BETA-EXECUTION-BACKLOG.md`.

## Verbatim Founder decision

> “Founder kararı — HOLD kaldırma: koşullu ön-yetki (30 Ağustos 2026)
>
> Production/customer HOLD'un kaldırılması için ekip bana geri gelmeyecek. Aşağıdaki koşullar sağlandığında Claude Desktop (Executive) kararı kendi kaydeder, Codex Desktop (Integration) uygular. Koşullar hard gate'dir; biri eksikse durulur ve bana yalnız o eksik bildirilir. Bu metin operating-model §3 pilot-HOLD sınırı için verilmiş Founder kararıdır.
>
> Kademe 1 — kontrollü canlı: #449 merge + Worker deploy. GO koşulları:
>
> 1. #449 yeniden inşa edilmiş (audit-recovery series → F1 → C2′ → C3 → F2), exact head'inde tam sharded CI yeşil, closure restamp 60/60 ve Candidate-A 30/30, Governance composite changed-path PASS, CX aynı head'de yeniden imzalı.
> 2. Rollback kimlikleri dondurulmuş: önceki Worker Version ID'leri ve Pages deployment id'si tek komutluk geri dönüşle kayıtlı; migration yok.
> 3. A3 production kök-neden sorgusu ya çalıştırılmış ya da 'çalıştırılamadı, A3 tasarımı iki mekanizmayı da kapatıyor' diye açıkça kaydedilmiş.
> 4. Executive karar kaydı yazılmış: HEAD, dosya listesi, CI/timing, rollback, residual, 'müşteri ne görecek'. Dördü tamam → merge et, Pages'in otomatik yenilendiğini bayt bazında doğrula, Worker'ları deploy et, tag'i at, CHANGELOG'u yaz. Bana sormadan.
>
> Kademe 2 — müşteri/pilot HOLD kaldırma. GO koşulları: Üç founder domain'inde canlı kabul: üç seri normal scan, her birinde tek scan_completed audit satırı, snapshot/PDF/frontend paritesi, MTA-STS/CSP/DMARC/sertifika bulgularının ekranda ve PDF'te dürüst görünmesi, en az bir gün hata/duplicate/cron sapması yok. Sağlandı → pilot aktivasyonu ve müşteri iletişimi serbest. Bana sormadan. Tek istisna: üç domain taramasını başlatmak için giriş gerekiyorsa bu benim human-only işim; bana 'şu saatte giriş yap, üç scan çalıştır' diye tek satır gelsin, onay değil.
>
> Her iki kademede STOP ve bana bildirim: herhangi bir kapı kırmızı; rollback yapılmak zorunda kaldı; müşteri verisi/tenant sınırı şüphesi; dış müşteri/regülatör iletişimi gerekiyor (§3); koşulların yorumunda tereddüt.
>
> Kaldırılmayacak durumlar: herhangi bir kapı kırmızıyken; yalnız CI yeşil diye; yorgun/gece saatinde deploy (Integration pencereyi rollback'i yapabileceği saate koyar).
>
> Koşullar sağlanana kadar HOLD sürer; sağlandığı an bekleme yok.”

## Governance normalisation appendix

This appendix records how the decision is applied to the current exact rescue
contracts. It does not rewrite or weaken the verbatim decision.

### 1. Existing technical gates remain cumulative

The short sequence in the Founder text is tranche shorthand. The accepted full
rebuild order remains:

```text
audit-recovery series
→ F1
→ C1′ (the exact two F004 paths)
→ C2′ (the 376-validator re-pin plus four non-validate carrier hardenings)
→ CX-A (one single-owner atomic CX-acceptance corrective)
→ C3 (the five-path corrective)
→ F2 (the final closure-restamp tail)
```

Neither C1′ nor CX-A may be omitted. F2 remains the final source-bearing commit;
any later closure-member change invalidates the restamp and requires exact-head
revalidation.

Before Kademe 1 can be recorded `GO`, the exact candidate must have all required
focused, tenant/security, build, full sharded CI, timing, same-head CX and
rollback evidence. A single consolidated Governance decision may cover both
reviews, but it must explicitly record:

- composite changed-path `PASS`; and
- the preserved cumulative nine-condition audit-recovery verdict `ACCEPT`.

An old-head pass, local-only evidence, deployment, or this Founder decision
cannot replace either result. Any missing condition or a Governance
`HOLD/REJECT` is a hard `STOP`.

### 2. Closure-count fact normalisation

The `60/60` wording in the verbatim decision is the historical acceptance-ledger
count. The accepted current closure carrier has five additional assertions.
Kademe 1 therefore requires the current complete, unskipped
`validate-b-scorecard-canonical` result — presently **65/65**, including
`SAN_B_F20` — plus Candidate-A **30/30**. No `--skip-closure` run is acceptance
evidence. This is a measured-count correction, not a change to the Founder's
full-pass requirement. If the exact rebuilt head changes the count, every
assertion must be inventoried and the complete current carrier must pass; the
gate may never be reduced back to 60.

### 3. Kademe 1 consequence

Kademe 1 consumes only the bounded controlled-live technical authority. After
every hard gate is green, Claude Desktop records the exact Executive decision
and Codex Desktop may execute the recorded merge, byte-identity check, Worker
deploys, tag and CHANGELOG sequence without returning for Founder approval.
The record must include the exact head/tree and path list, CI/timing, the prior
scan-api and email-ingest Worker Version IDs, the prior Pages deployment ID,
the executable rollback, migration state (`none`), residuals and what the
customer will see.

The A3 production root-cause query must either be run or use the exact permitted
unavailable statement in the Founder decision. Contradictory audit or tenant
evidence still stops the release. Kademe 1 does not release the customer/pilot
HOLD and does not mark the release `LIVE-ACCEPTED`.

### 4. Kademe 2 consequence

Kademe 2 requires one normal authenticated scan for each of the three
Founder-controlled domains, run serially on the same deployed release. Each
scan must have exactly one owner-scoped `scan_completed` occurrence and honest
report/snapshot/PDF/Executive/frontend parity across all eight canonical
domains.

For MTA-STS, CSP, DMARC and certificate evidence, every admitted finding must
remain identical and visible across the customer surfaces. Genuine absence,
partial, unavailable or unknown evidence must remain explicit; no signal may be
manufactured or converted to healthy merely to satisfy acceptance. The
stability observation is at least 24 continuous hours after the last of the
three scans, with no relevant error, duplicate completion/audit occurrence or
cron/scheduling drift.

When all Kademe 2 evidence is green, the bounded pilot activation and its
ordinary pilot communication are pre-authorised. This does not declare public
beta, close or reorder preserved P1/FD-007/FD-008/Items 12–19, or authorise
unrelated customer, regulator or public communication. A required Founder login
is requested in the one-line human-only form in the decision and is execution,
not approval.

### 5. Fail-closed STOP conditions and current state

Both stages stop when any gate is red, rollback becomes necessary, customer
data or tenant isolation is in doubt, communication outside the bounded pilot
would enter operating-model §3, the conditions are ambiguous, or Integration
cannot operate in a window where it can safely roll back. Green CI alone never
opens either stage. A rollback reimposes the applicable HOLD and is reported.

At the time of this receipt, neither stage has been consumed. Production and
customer/pilot `HOLD` remain active. Later evidence is appended to the current
tracker and canonical measured status; this receipt is not rewritten.
