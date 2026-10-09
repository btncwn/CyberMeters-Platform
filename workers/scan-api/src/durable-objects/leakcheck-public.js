import { DurableObject } from 'cloudflare:workers';
import { breachFailure, LEAKCHECK_TIMEOUT_MS, queryLeakCheck } from '../engines/identity-breach-checks.js';

// One object deliberately represents ONE upstream quota shared by all tenants.
// No public Worker route exposes it. No address/hash is stored or logged here.
export class LeakCheckPublic extends DurableObject {
  constructor(ctx, env) { super(ctx, env); this.busy = false; }

  async lookup(hash) {
    if (typeof hash !== 'string' || !/^[a-f0-9]{24}$/.test(hash)) return breachFailure('invalid_subject');
    if (this.busy) return breachFailure('provider_busy', 'rate_limited');
    this.busy = true;
    let reserved = false;
    try {
      const stored = await this.ctx.storage.get('next_allowed_at');
      const next = stored === undefined ? 0 : stored;
      if (!Number.isFinite(next)) return breachFailure('limiter_unavailable');
      if (Date.now() < next) return breachFailure('provider_busy', 'rate_limited');
      // Persist before I/O: eviction/crash must not forget the in-flight call.
      await this.ctx.storage.put('next_allowed_at', Date.now() + LEAKCHECK_TIMEOUT_MS + 1000);
      reserved = true;
      const result = await queryLeakCheck(hash);
      // Completion + 1 second (not fixed windows), also persisted before return.
      await this.ctx.storage.put('next_allowed_at', Date.now() + 1000);
      return result;
    } catch { return breachFailure(reserved ? 'provider_unavailable' : 'limiter_unavailable'); }
    finally { this.busy = false; }
  }
}
