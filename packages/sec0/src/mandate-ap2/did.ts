import { Resolver } from "did-resolver";
import { getResolver as webDidResolver } from "web-did-resolver";
import { DID_CACHE_TTL_MS } from "./constants";
import { logger } from "./logger";

interface CacheEntry {
  ts: number;
  ok: boolean;
}

/**
 * Encapsulates DID resolution with a time-based in-memory cache.
 */
export class DidResolver {
  private readonly resolver: Resolver;
  private readonly cache = new Map<string, CacheEntry>();
  private readonly ttlMs: number;

  constructor(ttlMs: number = DID_CACHE_TTL_MS) {
    this.resolver = new Resolver({ ...webDidResolver() });
    this.ttlMs = ttlMs;
  }

  async resolve(did: string): Promise<boolean> {
    try {
      const now = Date.now();
      const cached = this.cache.get(did);
      if (cached && (now - cached.ts) < this.ttlMs) return cached.ok;

      const doc = await this.resolver.resolve(did);
      const ok = !!doc?.didDocument;
      this.cache.set(did, { ts: now, ok });
      return ok;
    } catch (err) {
      logger.warn("DID resolution failed", { did, error: (err as Error)?.message });
      this.cache.set(did, { ts: Date.now(), ok: false });
      return false;
    }
  }
}

// Shared package-level DID resolver instance.
export const didResolver = new DidResolver();
