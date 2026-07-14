// ── Cloud-storage exposure scan module ──
// Evidence-based detection of externally referenced AWS S3 / Azure Blob / Google Cloud
// Storage endpoints (no bucket guessing, no credentials, no object-key collection).
// Extracted verbatim from index.js (monolith decomposition, Phase 1c). Only
// runCloudStorageModule + hostnameFromValue are public; the other 9 are module-internal.

// Cloud Storage Exposure Discovery v1 — evidence-based detection of externally
// referenced AWS S3, Azure Blob Storage, and Google Cloud Storage endpoints.
// No bucket guessing, no SDK/API credentials, no object-key collection.

export function hostnameFromValue(value) {
  if (!value) return null;
  try {
    const raw = String(value).trim();
    const url = raw.includes("://") ? new URL(raw) : new URL(`https://${raw}`);
    return url.hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return String(value).trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#:]/)[0].replace(/\.$/, "") || null;
  }
}

function firstPathSegment(value) {
  if (!value) return null;
  try {
    const raw = String(value).trim();
    const url = raw.includes("://") ? new URL(raw) : new URL(`https://${raw}`);
    return url.pathname.split("/").filter(Boolean)[0] || null;
  } catch {
    return null;
  }
}

function cloudProviderHeadersPresent(provider, headers) {
  const h = (name) => headers.get(name) || "";
  const server = h("server").toLowerCase();
  if (provider === "AWS S3") {
    return Boolean(h("x-amz-request-id") || h("x-amz-id-2") || h("x-amz-bucket-region") || server.includes("amazons3"));
  }
  if (provider === "Azure Blob Storage") {
    return Boolean(h("x-ms-request-id") || h("x-ms-version") || server.includes("windows-azure-blob"));
  }
  if (provider === "Google Cloud Storage") {
    return Boolean(h("x-guploader-uploadid") || h("x-goog-storage-class") || server.includes("uploadserver"));
  }
  return false;
}

function detectCloudStorageCandidateFromValue(value, source, sourceHostname, evidenceLabel) {
  const host = hostnameFromValue(value);
  if (!host) return null;
  const pathBucket = firstPathSegment(value);
  const sourceHost = hostnameFromValue(sourceHostname) || host;
  let provider = null;
  let bucket = null;
  let matchedPattern = null;

  const s3Match = host.match(/^([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/i)
    || host.match(/^([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$/i);
  if (s3Match) {
    provider = "AWS S3";
    bucket = s3Match[1];
    matchedPattern = "bucket.s3.amazonaws.com";
  } else if (/^s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/i.test(host) && pathBucket) {
    provider = "AWS S3";
    bucket = pathBucket;
    matchedPattern = "s3.amazonaws.com/bucket";
  }

  const azureMatch = host.match(/^([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.blob\.core\.windows\.net$/i);
  if (!provider && azureMatch) {
    provider = "Azure Blob Storage";
    bucket = azureMatch[1];
    matchedPattern = "container.blob.core.windows.net";
  }

  const gcsMatch = host.match(/^([a-z0-9][a-z0-9._-]{1,220}[a-z0-9])\.storage\.googleapis\.com$/i);
  if (!provider && gcsMatch) {
    provider = "Google Cloud Storage";
    bucket = gcsMatch[1];
    matchedPattern = "bucket.storage.googleapis.com";
  } else if (!provider && host === "storage.googleapis.com" && pathBucket) {
    provider = "Google Cloud Storage";
    bucket = pathBucket;
    matchedPattern = "storage.googleapis.com/bucket";
  }

  if (!provider || !bucket) return null;
  const evidence = host === "storage.googleapis.com" || /^s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com$/i.test(host)
    ? `https://${host}/${bucket}`
    : `https://${host}`;
  const confidence = source === "cname" ? 90 : source === "asset_redirect" ? 80 : source === "http_header" ? 60 : 70;
  return {
    provider,
    bucket_or_container: bucket,
    source,
    source_hostname: sourceHost,
    evidence: { observed_value: evidence, evidence_label: evidenceLabel, matched_pattern: matchedPattern },
    confidence,
    business_context: "asm",
  };
}

function buildCloudStorageValidationUrl(candidate, listing = false) {
  const host = candidate.source_hostname || null;
  if (!host) return null;
  const base = `https://${host}/`;
  if (!listing) return base;
  if (candidate.provider === "AWS S3") return `${base}?list-type=2&max-keys=5`;
  if (candidate.provider === "Azure Blob Storage") return `${base}?restype=container&comp=list&maxresults=5`;
  if (candidate.provider === "Google Cloud Storage") return `${base}?max-keys=5`;
  return base;
}

function parseCloudStorageListing(provider, text) {
  const sample = String(text || "").slice(0, 8192);
  if (!sample) return { listing_enabled: false, object_count_observed: null, listing_indicator: null };
  if (provider === "AWS S3" && /<ListBucketResult[\s>]/i.test(sample)) {
    const count = (sample.match(/<Contents>/gi) || []).length;
    return { listing_enabled: true, object_count_observed: Math.min(count, 5), listing_indicator: "ListBucketResult" };
  }
  if (provider === "Azure Blob Storage" && /<EnumerationResults[\s>]/i.test(sample)) {
    const count = (sample.match(/<Blob>/gi) || []).length;
    return { listing_enabled: true, object_count_observed: Math.min(count, 5), listing_indicator: "EnumerationResults" };
  }
  if (provider === "Google Cloud Storage" && /<ListBucketResult[\s>]/i.test(sample)) {
    const count = (sample.match(/<Contents>/gi) || []).length;
    return { listing_enabled: true, object_count_observed: Math.min(count, 5), listing_indicator: "ListBucketResult" };
  }
  return { listing_enabled: false, object_count_observed: null, listing_indicator: null };
}

function cloudStorageNotFound(provider, status, text) {
  const sample = String(text || "").slice(0, 4096).toLowerCase();
  if (provider === "AWS S3") return status === 404 && (sample.includes("nosuchbucket") || sample.includes("the specified bucket does not exist"));
  if (provider === "Azure Blob Storage") return status === 404 && (sample.includes("containernotfound") || sample.includes("the specified container does not exist"));
  if (provider === "Google Cloud Storage") return status === 404 && (sample.includes("nosuchbucket") || sample.includes("not found"));
  return false;
}

async function readResponseTextLimit(response, limit = 8192) {
  if (!response?.body?.getReader) {
    const text = await response.text();
    return text.slice(0, limit);
  }
  const reader = response.body.getReader();
  const chunks = [];
  let bytes = 0;
  try {
    while (bytes < limit) {
      const { done, value } = await reader.read();
      if (done || !value) break;
      const slice = value.slice(0, Math.max(0, limit - bytes));
      chunks.push(slice);
      bytes += slice.byteLength;
    }
  } finally {
    try { await reader.cancel(); } catch { /* ignore */ }
  }
  const out = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(out);
}

async function validateCloudStorageCandidate(candidate) {
  const result = {
    validation_method: "HEAD",
    status_code: null,
    provider_headers_present: false,
    listing_enabled: "unknown",
    object_count_observed: null,
    listing_indicator: null,
    resource_exists: "unknown",
  };
  const headUrl = buildCloudStorageValidationUrl(candidate, false);
  if (!headUrl) return result;
  let headRes = null;
  try {
    headRes = await fetch(headUrl, { method: "HEAD", redirect: "manual", signal: AbortSignal.timeout(6_000) });
    result.status_code = headRes.status;
    result.provider_headers_present = cloudProviderHeadersPresent(candidate.provider, headRes.headers);
  } catch {
    return result;
  }

  const listUrl = buildCloudStorageValidationUrl(candidate, true);
  if (!listUrl) return result;
  try {
    const getRes = await fetch(listUrl, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(6_000) });
    result.validation_method = "HEAD+GET";
    result.status_code = getRes.status;
    result.provider_headers_present = result.provider_headers_present || cloudProviderHeadersPresent(candidate.provider, getRes.headers);
    const text = await readResponseTextLimit(getRes, 8192);
    if (cloudStorageNotFound(candidate.provider, getRes.status, text)) {
      result.resource_exists = false;
      result.listing_enabled = false;
      return result;
    }
    result.resource_exists = getRes.status < 500 ? true : "unknown";
    const listing = parseCloudStorageListing(candidate.provider, text);
    result.listing_enabled = listing.listing_enabled;
    result.object_count_observed = listing.object_count_observed;
    result.listing_indicator = listing.listing_indicator;
  } catch {
    result.resource_exists = headRes.status && headRes.status < 500 ? true : "unknown";
  }
  return result;
}

function cloudStorageFindingFromCandidate(candidate) {
  const validation = candidate.validation || {};
  if (candidate.confidence < 50) return null;
  if (validation.resource_exists === false) {
    return {
      id: "cloud_storage_takeover_risk",
      severity: candidate.source === "cname" ? "high" : "medium",
      title: `${candidate.provider} storage takeover risk observed`,
      description: `${candidate.source_hostname} points to ${candidate.provider} storage resource ${candidate.bucket_or_container}, but provider validation indicates the bucket/container does not exist.`,
      risk_level: candidate.source === "cname" ? "high" : "medium",
    };
  }
  if (validation.listing_enabled === true) {
    return {
      id: "cloud_storage_public_listing",
      severity: "high",
      title: `${candidate.provider} public storage listing confirmed`,
      description: `${candidate.provider} storage resource ${candidate.bucket_or_container} appears to allow public listing through ${candidate.source_hostname}.`,
      risk_level: "high",
    };
  }
  if (validation.resource_exists === true && validation.provider_headers_present) {
    return {
      id: "cloud_storage_exposure_observed",
      severity: candidate.confidence >= 80 ? "medium" : "info",
      title: `${candidate.provider} storage endpoint externally reachable`,
      description: `${candidate.source_hostname} references a reachable ${candidate.provider} storage endpoint. Public listing was not confirmed.`,
      risk_level: candidate.confidence >= 80 ? "medium" : "low",
    };
  }
  return null;
}

export async function runCloudStorageModule(domain, modules) {
  try {
    const candidates = [];
    const seenCandidates = new Set();

    function addCandidate(candidate) {
      if (!candidate || candidate.confidence < 50) return;
      const key = `${candidate.provider}::${candidate.bucket_or_container}::${candidate.source_hostname}`;
      if (seenCandidates.has(key)) return;
      seenCandidates.add(key);
      candidates.push(candidate);
    }

    // ── 1. Scan subdomain hostnames ───────────────────────────────────────
    const subItems = modules?.subdomains?.items || [];
    for (const hostname of subItems) {
      addCandidate(detectCloudStorageCandidateFromValue(hostname, "ct_subdomain", hostname, "certificate transparency hostname"));
    }
    for (const obs of modules?.subdomain_takeover?.cname_observations || []) {
      addCandidate(detectCloudStorageCandidateFromValue(obs.cname, "cname", obs.host, `CNAME ${obs.host} -> ${obs.cname}`));
    }

    // ── 2. Scan exposure asset URLs and redirects already observed ───────
    const exposureAssets = modules?.asset_exposure?.assets || [];
    for (const asset of exposureAssets) {
      addCandidate(detectCloudStorageCandidateFromValue(asset.url, "asm_asset", asset.host || asset.hostname || asset.url, "observed asset URL"));
      addCandidate(detectCloudStorageCandidateFromValue(asset.redirect_to, "asset_redirect", asset.host || asset.hostname || asset.redirect_to, "observed redirect target"));
      const headerValue = [asset.server, asset.content_type].filter(Boolean).join(" ");
      if (/amazons3|windows-azure-blob|storage\.googleapis\.com/i.test(headerValue)) {
        addCandidate(detectCloudStorageCandidateFromValue(asset.url, "http_header", asset.host || asset.hostname || asset.url, "observed HTTP response header"));
      }
    }

    // ── 3. Scan takeover-risk CNAMEs ─────────────────────────────────────
    const takeoverRisks = modules?.subdomain_takeover?.risks || [];
    for (const risk of takeoverRisks) {
      addCandidate(detectCloudStorageCandidateFromValue(risk.cname, "cname", risk.host || risk.hostname || risk.cname, `takeover CNAME ${risk.cname}`));
    }

    const findings = [];
    const validatedCandidates = [];
    for (const candidate of candidates.slice(0, 5)) {
      const validation = await validateCloudStorageCandidate(candidate);
      const enriched = { ...candidate, validation };
      validatedCandidates.push(enriched);
      const findingBase = cloudStorageFindingFromCandidate(enriched);
      if (!findingBase) continue;
      const checkedAt = new Date().toISOString();
      // Sprint 9D: confidence and validation_quality based on HTTP validation outcome
      const csConf = findingBase.id === "cloud_storage_public_listing"    ? 95
                   : findingBase.id === "cloud_storage_exposure_observed"  ? 90
                   : findingBase.id === "cloud_storage_takeover_risk"      ? 80
                   : 60;
      const csVQ   = findingBase.id === "cloud_storage_public_listing"    ? "excellent"
                   : findingBase.id === "cloud_storage_exposure_observed"  ? "good"
                   : findingBase.id === "cloud_storage_takeover_risk"      ? "good"
                   : "weak";
      findings.push({
        id: findingBase.id,
        module: "cloud_storage_discovery",
        severity: findingBase.severity,
        // The customer-side DNS name that references the storage endpoint — the host
        // they would actually change. Recorded so a managed case carries an accurate
        // affected host instead of falling back to the apex domain. The storage
        // endpoint itself is third-party infrastructure and is NOT a probe target:
        // cloud_storage_* is deliberately absent from the verification dispatch.
        affected_hosts: [enriched.source_hostname].filter(Boolean),
        confidence:         csConf,
        validation_quality: csVQ,
        score_impact: 0,
        title: findingBase.title,
        description: findingBase.description,
        recommendation: findingBase.id === "cloud_storage_public_listing"
          ? "Disable anonymous listing and restrict storage access to explicitly authorised principals."
          : findingBase.id === "cloud_storage_takeover_risk"
            ? "Remove the DNS reference or create and claim the referenced storage resource before re-enabling the hostname."
            : "Verify the storage endpoint is intentionally public and contains no sensitive data.",
        asset: enriched.source_hostname,
        provider: enriched.provider,
        bucket_or_container: enriched.bucket_or_container,
        category: "storage",
        service_type: "object_storage",
        type: findingBase.id,
        risk_level: findingBase.risk_level,
        source: enriched.source,
        source_hostname: enriched.source_hostname,
        business_context: enriched.business_context,
        validation,
        evidence: {
          provider: enriched.provider,
          bucket_or_container: enriched.bucket_or_container,
          source_hostname: enriched.source_hostname,
          discovery_source: enriched.source,
          validation_method: validation.validation_method,
          status_code: validation.status_code,
          provider_headers_present: validation.provider_headers_present,
          confidence: enriched.confidence,
          observed_value: enriched.evidence.observed_value,
          expected_value: findingBase.id === "cloud_storage_public_listing" ? "No public listing" : "Storage endpoint intentionally owned and access-controlled",
          listing_enabled: validation.listing_enabled,
          object_count_observed: validation.object_count_observed,
          listing_indicator: validation.listing_indicator,
          checked_at: checkedAt,
          manual_verification_command: `curl -I https://${enriched.source_hostname}/`,
        },
        evidence_quality: "good",
      });
    }

    const riskOrder = { high: 0, medium: 1, low: 2 };
    findings.sort((a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3));

    return {
      checked:  subItems.length + exposureAssets.length + (modules?.subdomain_takeover?.cname_observations || []).length,
      candidates: validatedCandidates,
      total:    findings.length,
      findings,
      assets:   findings,
      source:   "evidence_based_cloud_storage_discovery",
      error:    null,
    };
  } catch (err) {
    return {
      checked:  0,
      total:    0,
      candidates: [],
      findings: [],
      assets:   [],
      source:   "evidence_based_cloud_storage_discovery",
      error:    err?.message ?? "Cloud asset discovery failed",
    };
  }
}
