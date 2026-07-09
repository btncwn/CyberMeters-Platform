// ── DNS operational-resilience engine ──
// Nameserver-provider classification + DNS resilience scoring. Extracted verbatim
// from index.js (monolith decomposition, Phase 1c). Behavior-preserving — no logic change.

function normalizeDnsProviderFromNs(ns) {
  const value = String(ns || "").toLowerCase().replace(/\.$/, "");
  if (!value) return "unknown";
  if (/cloudflare\.com$/.test(value)) return "Cloudflare";
  if (/awsdns-/.test(value) || /route53/.test(value)) return "AWS Route53";
  if (/azure-dns\.(com|net|org|info)$/.test(value)) return "Azure DNS";
  if (/googledomains\.com$|google\.com$/.test(value)) return "Google Cloud DNS";
  if (/akam\.net$|akamai/.test(value)) return "Akamai";
  if (/fastly\.net$/.test(value)) return "Fastly";
  if (/dnsmadeeasy\.com$/.test(value)) return "DNS Made Easy";
  if (/domaincontrol\.com$/.test(value)) return "GoDaddy DNS";
  if (/registrar-servers\.com$/.test(value)) return "Namecheap DNS";
  if (/digitalocean\.com$/.test(value)) return "DigitalOcean DNS";
  return value.split(".").slice(-2).join(".");
}

function classifyResilience(score) {
  if (score >= 80) return "High resilience";
  if (score >= 55) return "Medium resilience";
  return "Low resilience";
}

export function buildDnsOperationalResilience({ nameservers = [], dnssec = null, certificateAuthority = null } = {}) {
  const providers = nameservers.map((ns) => normalizeDnsProviderFromNs(ns));
  const uniqueProviders = [...new Set(providers.filter((p) => p && p !== "unknown"))];
  const providerCounts = {};
  for (const provider of providers) providerCounts[provider] = (providerCounts[provider] || 0) + 1;

  const nsCount = nameservers.length;
  const nsScore = nsCount >= 4 ? 25 : nsCount >= 2 ? 15 : nsCount === 1 ? 5 : 0;
  const providerScore = uniqueProviders.length >= 2 ? 30 : uniqueProviders.length === 1 ? 15 : 0;
  const dnssecScore = dnssec?.enabled ? 25 : dnssec ? 10 : 0;
  const caScore =
    certificateAuthority?.dependency === "multiple_ca_usage" ? 20 :
    certificateAuthority?.dependency === "single_ca_dependency" ? 10 :
    10;
  const score = Math.max(0, Math.min(100, nsScore + providerScore + dnssecScore + caScore));

  return {
    score,
    resilience_level: classifyResilience(score),
    nameserver_diversity: {
      nameserver_count: nsCount,
      provider_count: uniqueProviders.length,
      providers: uniqueProviders,
      provider_counts: providerCounts,
      future_signals: ["asn_diversity", "geographic_diversity"],
    },
    dns_provider_concentration: {
      dependency:
        uniqueProviders.length === 0 ? "unknown" :
        uniqueProviders.length === 1 ? "single-provider dependency" : "multi-provider dependency",
      label:
        uniqueProviders.length === 1 ? `${uniqueProviders[0]}-only` :
        uniqueProviders.length > 1 ? "Multi-provider" : "Unknown",
      observations: uniqueProviders.length === 1
        ? [`All observed nameservers resolve to ${uniqueProviders[0]}.`]
        : uniqueProviders.length > 1
          ? [`Observed nameservers span ${uniqueProviders.length} DNS providers.`]
          : ["No authoritative nameserver provider could be classified."],
    },
    certificate_authority_concentration: certificateAuthority || {
      dependency: "unknown",
      issuers: [],
      observations: ["Certificate authority concentration requires certificate intelligence output."],
    },
    factors: {
      dnssec_enabled: !!dnssec?.enabled,
      dnssec_points: dnssecScore,
      nameserver_points: nsScore,
      provider_concentration_points: providerScore,
      certificate_authority_points: caScore,
    },
    source: "dns_operational_resilience",
  };
}
