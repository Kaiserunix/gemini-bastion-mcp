import type { Context } from 'hono';
import type { RateLimiter } from './store.js';

export const MAX_AUTH_BODY_BYTES = 65_536;

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSec: number;
}

export type LimitedBodyResult =
  | { ok: true; text: string }
  | { ok: false; status: 413 };

/**
 * Reads a request body as UTF-8 text while enforcing a strict byte ceiling (`maxBytes`, default 64KB)
 * before buffering the payload in memory.
 */
export async function readLimitedBodyText(
  c: Context,
  maxBytes = MAX_AUTH_BODY_BYTES,
): Promise<LimitedBodyResult> {
  const contentLengthHeader = c.req.header('content-length');
  if (contentLengthHeader !== undefined) {
    const declaredLength = Number(contentLengthHeader);
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
      return { ok: false, status: 413 };
    }
  }

  const bodyStream = c.req.raw.body;
  if (!bodyStream) {
    return { ok: true, text: '' };
  }

  const reader = bodyStream.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value || value.byteLength === 0) continue;

      totalBytes += value.byteLength;
      if (totalBytes > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return { ok: false, status: 413 };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const merged = Buffer.concat(chunks.map((chunk) => Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength)));
  return { ok: true, text: merged.toString('utf8') };
}

/**
 * Extracts the client IP for rate limiting.
 * Respects `CF-Connecting-IP` and `X-Real-IP` ONLY when `trustCfConnectingIp` is true,
 * avoiding spoofable leftmost `X-Forwarded-For` values.
 */
export function getClientIp(c: Context, trustCfConnectingIp: boolean): string {
  if (trustCfConnectingIp) {
    const cfIp = c.req.header('cf-connecting-ip')?.trim();
    if (cfIp) return cfIp;

    const realIp = c.req.header('x-real-ip')?.trim();
    if (realIp) return realIp;
  }

  const envObj = c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined;
  const socketIp = envObj?.incoming?.socket?.remoteAddress?.trim();
  return socketIp && socketIp.length > 0 ? socketIp : 'direct';
}

/**
 * In-memory fixed-window rate limiter keyed by client IP.
 */
export class IpRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, { count: number; resetAt: number }>();

  constructor(
    private readonly maxAttempts = 10,
    private readonly windowMs = 60_000,
  ) {}

  consume(key: string, now = Date.now()): RateLimitResult {
    const existing = this.buckets.get(key);
    if (!existing || existing.resetAt <= now) {
      const resetAt = now + this.windowMs;
      this.buckets.set(key, { count: 1, resetAt });
      this.pruneIfLarge(now);
      return {
        allowed: true,
        remaining: Math.max(0, this.maxAttempts - 1),
        retryAfterSec: Math.ceil(this.windowMs / 1000),
      };
    }

    if (existing.count >= this.maxAttempts) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterSec: Math.max(1, Math.ceil((existing.resetAt - now) / 1000)),
      };
    }

    existing.count += 1;
    return {
      allowed: true,
      remaining: Math.max(0, this.maxAttempts - existing.count),
      retryAfterSec: Math.max(1, Math.ceil((existing.resetAt - now) / 1000)),
    };
  }

  reset(key?: string): void {
    if (key) {
      this.buckets.delete(key);
    } else {
      this.buckets.clear();
    }
  }

  private pruneIfLarge(now: number): void {
    if (this.buckets.size < 1000) return;
    for (const [k, v] of this.buckets) {
      if (v.resetAt <= now) {
        this.buckets.delete(k);
      }
    }
  }
}
