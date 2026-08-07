// CT-R2 PR-3: shared, provider-neutral first-success-wins orchestration.
//
// Both physical provider requests are launched through the existing per-scan
// cache. The first SUCCESS may release this consumer; the first settlement may
// not. Consumer release never cancels the shared physical request. The returned
// provider projection is detached and frozen so later terminal telemetry cannot
// mutate evidence already released to a module/customer result.
import {
  CT_PROVIDER_FIRST_SUCCESS_RELEASE_CUSTOMER_WORDING,
} from "./ct-provider-cache.js";

const PROVIDERS = Object.freeze(["crt_sh", "certspotter"]);

function freezeProviderResult(result) {
  return Object.freeze({ ...result });
}

function excludedSuccessfulResult(result, provider, domain) {
  if (result?.status !== "available") return result;
  return {
    provider,
    domain,
    status: "unavailable",
    data: null,
    error: CT_PROVIDER_FIRST_SUCCESS_RELEASE_CUSTOMER_WORDING,
    physical_attempt_state: result?.physical_attempt_state || "terminal_success",
  };
}

function isTerminalConsumerState(state) {
  return state === "received_success" || state === "received_failure";
}

export async function raceCertificateTransparencyFirstSuccess({
  ctCache,
  domain,
  module,
  accounting = null,
  signal = null,
  observeTerminal = null,
  wrapProviderWait = (_provider, promise) => promise,
} = {}) {
  if (!ctCache || typeof ctCache.get !== "function") {
    throw new TypeError("First-success CT orchestration requires a CT provider cache");
  }
  if (!module) throw new TypeError("First-success CT orchestration requires a consumer module");

  const terminalResults = new Map();
  const consumerResults = new Map();
  let settledCount = 0;
  let winner = null;
  let releaseQueued = false;
  let finalized = false;
  let resolveOutput;
  let rejectOutput;
  const output = new Promise((resolve, reject) => {
    resolveOutput = resolve;
    rejectOutput = reject;
  });

  let waits = null;
  const finalize = async (reason) => {
    if (finalized) return;
    finalized = true;
    if (reason === "first_success" && typeof ctCache.releaseConsumer === "function") {
      ctCache.releaseConsumer(domain, module, "first_success");
    }
    await Promise.all(waits);

    const includedTerminalProviders = PROVIDERS.filter((provider) => terminalResults.has(provider));
    const included = new Set(includedTerminalProviders);
    const providers = {};
    for (const provider of PROVIDERS) {
      const terminal = terminalResults.get(provider);
      const consumed = consumerResults.get(provider);
      // `included` is authoritative. This keeps the slower provider when it was
      // genuinely terminal before release, but makes an accidentally omitted
      // terminal success explicit rather than silently laundering it through the
      // consumer result map.
      const released = included.has(provider)
        ? terminal
        : excludedSuccessfulResult(consumed, provider, domain);
      providers[provider] = freezeProviderResult(released);
    }

    resolveOutput(Object.freeze({
      providers: Object.freeze(providers),
      release: Object.freeze({
        reason,
        winner,
        included_terminal_providers: Object.freeze([...includedTerminalProviders]),
      }),
    }));
  };

  waits = PROVIDERS.map((provider) => {
    const consumerWait = ctCache.get(domain, provider, {
      accounting,
      module,
      signal,
    });
    let wrapped;
    try {
      wrapped = wrapProviderWait(provider, consumerWait);
    } catch (error) {
      wrapped = Promise.reject(error);
    }
    return Promise.resolve(wrapped).then((result) => {
      consumerResults.set(provider, result);
      settledCount += 1;
      const state = ctCache.consumerSnapshot?.(domain, module)?.providers?.[provider]
        ?.consumer_wait_state;
      if (typeof ctCache.consumerSnapshot !== "function" || isTerminalConsumerState(state)) {
        terminalResults.set(provider, result);
        try { observeTerminal?.(provider, result); } catch { /* observational only */ }
      }

      if (result?.status === "available") {
        if (winner == null) winner = provider;
        if (!releaseQueued) {
          releaseQueued = true;
          // Two microtasks admit sibling results that were already terminal at
          // this release boundary without waiting for genuinely slower work.
          queueMicrotask(() => queueMicrotask(() => {
            if (typeof ctCache.releaseConsumer === "function"
              || settledCount === PROVIDERS.length) {
              finalize("first_success").catch(rejectOutput);
            } else {
              // Minimal all-terminal test doubles have no consumer-release API.
              // Their second immediate settlement will finalize below; production
              // always takes the consumer-aware branch above.
              releaseQueued = false;
            }
          }));
        }
      }
      if (settledCount === PROVIDERS.length && !finalized
        && (!releaseQueued || typeof ctCache.releaseConsumer !== "function")) {
        const allPhysicalTerminal = terminalResults.size === PROVIDERS.length;
        const reason = winner != null
          ? "first_success"
          : (allPhysicalTerminal ? "all_terminal_failure" : "consumer_released");
        finalize(reason)
          .catch(rejectOutput);
      }
      return result;
    }, (error) => {
      rejectOutput(error);
      throw error;
    });
  });

  return output;
}
