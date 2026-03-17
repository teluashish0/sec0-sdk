// Shared interfaces + adapters that back the gateway's rate/quota enforcement.

// Snapshot of remaining quota tokens returned to callers.
export interface QuotaState {
  remainingDaily?: number;
  remainingRate?: number;
  resetAt?: string;
}

// Adapter contract implemented by different storage backends.
export interface QuotaAdapter {
  incrDaily(tenant: string, tool: string, limit: number, now: Date): Promise<{ count: number; resetAt: string }>;
  takeToken(tenant: string, tool: string, ratePerSec: number, burst?: number, now?: Date): Promise<{ tokens: number; resetAt: string }>;
}

/**
 * Simple process-local adapter used for tests and single-node dev.
 */
export class InMemoryAdapter implements QuotaAdapter {
  private daily = new Map<string, { count: number; resetAt: number }>();
  private bucket = new Map<string, { tokens: number; last: number; cap: number }>();
  // Increment a tenant's daily count and return the new total.
  async incrDaily(tenant: string, tool: string, limit: number, now = new Date()): Promise<{ count: number; resetAt: string }> {
    const key = `${tenant}:${tool}:${now.toISOString().slice(0,10)}`;
    const resetTs = new Date(now);
    resetTs.setUTCDate(resetTs.getUTCDate() + 1);
    const rec = this.daily.get(key) ?? { count: 0, resetAt: resetTs.getTime() };
    rec.count += 1;
    this.daily.set(key, rec);
    return { count: rec.count, resetAt: new Date(rec.resetAt).toISOString() };
  }
  // Token-bucket implementation for per-second limits.
  async takeToken(tenant: string, tool: string, ratePerSec: number, burst = ratePerSec * 2, now = new Date()): Promise<{ tokens: number; resetAt: string }> {
    const key = `${tenant}:${tool}`;
    const rec = this.bucket.get(key) ?? { tokens: burst, last: now.getTime(), cap: burst };
    const elapsed = (now.getTime() - rec.last) / 1000;
    const refill = Math.floor(elapsed * ratePerSec);
    rec.tokens = Math.min(rec.cap, rec.tokens + (refill > 0 ? refill : 0));
    rec.last = now.getTime();
    if (rec.tokens > 0) rec.tokens -= 1;
    this.bucket.set(key, rec);
    const resetAt = new Date(now.getTime() + (rec.tokens === 0 ? 1000 : 0)).toISOString();
    return { tokens: rec.tokens, resetAt };
  }
}

import Redis from "ioredis";

/**
 * Production adapter that persists counters in Redis for horizontal scaling.
 */
export class RedisAdapter implements QuotaAdapter {
  private redis: Redis;
  constructor(redis: Redis) { this.redis = redis; }
  // Increment a per-day counter stored in Redis with TTL rollover.
  async incrDaily(tenant: string, tool: string, limit: number, now = new Date()): Promise<{ count: number; resetAt: string }> {
    const day = now.toISOString().slice(0,10).replace(/-/g,"");
    const key = `q:${tenant}:${tool}:day:${day}`;
    const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()+1, 0, 0, 0));
    const ttl = Math.floor((end.getTime() - now.getTime())/1000);
    const multi = this.redis.multi();
    multi.incr(key);
    multi.expire(key, ttl, "NX");
    const execRes = await multi.exec();
    const incrTuple = execRes && execRes[0];
    const count = Number((incrTuple as any)?.[1] ?? 0);
    return { count, resetAt: end.toISOString() };
  }
  // Approximate per-second rate limiting using fixed-window counters.
  async takeToken(tenant: string, tool: string, ratePerSec: number, burst = ratePerSec * 2, now = new Date()): Promise<{ tokens: number; resetAt: string }> {
    // Approximate token bucket using per-second fixed window counter
    const sec = Math.floor(now.getTime()/1000);
    const key = `r:${tenant}:${tool}:sec:${sec}`;
    const multi = this.redis.multi();
    multi.incr(key);
    multi.expire(key, 2, "NX");
    const execRes2 = await multi.exec();
    const incrRes = execRes2 && execRes2[0];
    const count = Number((incrRes as any)?.[1] ?? 0);
    const remaining = ratePerSec - count;
    const resetAt = new Date((sec+1)*1000).toISOString();
    return { tokens: remaining, resetAt };
  }
}


