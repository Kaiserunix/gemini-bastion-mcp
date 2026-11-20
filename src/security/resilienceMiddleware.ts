import type { Context, MiddlewareHandler } from 'hono';
import type { OAuthAuthContext } from '../auth/middleware.js';
import { getClientIp } from '../auth/rateLimit.js';
import type { AuditEventPublisher } from './auditSink.js';

// ============================================================================
// Decoupled Rate Limiter Port & Implementations
// ============================================================================

export interface RateLimitDecision {
  allowed: boolean;
  key: string;
  limit: number;
  remaining: number;
  resetAtMs: number;
  retryAfterSec: number;
}

export interface RateLimiterPort {
  consume(key: string, cost?: number, now?: number): RateLimitDecision;
  peek(key: string, now?: number): RateLimitDecision;
  reset(key?: string): void;
}

export interface TokenBucketRateLimiterOptions {
  capacity: number;
  refillRatePerSec: number;
  maxBuckets?: number;
  nowFn?: () => number;
}

interface TokenBucketState {
  tokens: number;
  lastRefillMs: number;
}

/**
 * Burst-friendly token-bucket rate limiter with continuous refill, fractional precision,
 * weighted request costs, and bounded bucket eviction.
 */
export class TokenBucketRateLimiter implements RateLimiterPort {
  private readonly capacity: number;
  private readonly refillRatePerMs: number;
  private readonly maxBuckets: number;
  private readonly nowFn: () => number;
  private readonly buckets = new Map<string, TokenBucketState>();

  constructor(options: TokenBucketRateLimiterOptions) {
    if (!Number.isFinite(options.capacity) || options.capacity <= 0) {
      throw new Error(`TokenBucketRateLimiter capacity must be > 0 (got ${options.capacity})`);
    }
    if (!Number.isFinite(options.refillRatePerSec) || options.refillRatePerSec <= 0) {
      throw new Error(
        `TokenBucketRateLimiter refillRatePerSec must be > 0 (got ${options.refillRatePerSec})`,
      );
    }
    this.capacity = options.capacity;
    this.refillRatePerMs = options.refillRatePerSec / 1000;
    this.maxBuckets = Math.max(16, options.maxBuckets ?? 4096);
    this.nowFn = options.nowFn ?? Date.now;
  }

  consume(key: string, cost = 1, now = this.nowFn()): RateLimitDecision {
    const normalizedCost = Math.max(0, cost);
    if (normalizedCost > this.capacity) {
      const retryMs = Math.ceil(normalizedCost / this.refillRatePerMs);
      return {
        allowed: false,
        key,
        limit: this.capacity,
        remaining: 0,
        resetAtMs: now + retryMs,
        retryAfterSec: Math.max(1, Math.ceil(retryMs / 1000)),
      };
    }

    const bucket = this.getRefilledBucket(key, now);
    // Refresh insertion order for LRU eviction
    this.buckets.delete(key);

    if (bucket.tokens + 1e-9 < normalizedCost) {
      this.buckets.set(key, bucket);
      this.evictIfNeeded(now);
      const deficit = Math.max(0, normalizedCost - bucket.tokens);
      const waitMs = Math.ceil(deficit / this.refillRatePerMs);
      const fullResetMs = Math.ceil((this.capacity - bucket.tokens) / this.refillRatePerMs);
      return {
        allowed: false,
        key,
        limit: this.capacity,
        remaining: Math.max(0, Math.floor(bucket.tokens)),
        resetAtMs: now + fullResetMs,
        retryAfterSec: Math.max(1, Math.ceil(waitMs / 1000)),
      };
    }

    bucket.tokens = Math.max(0, bucket.tokens - normalizedCost);
    this.buckets.set(key, bucket);
    this.evictIfNeeded(now);

    const missingTokens = Math.max(0, this.capacity - bucket.tokens);
    const fullResetMs = Math.ceil(missingTokens / this.refillRatePerMs);

    return {
      allowed: true,
      key,
      limit: this.capacity,
      remaining: Math.max(0, Math.floor(bucket.tokens)),
      resetAtMs: now + fullResetMs,
      retryAfterSec: fullResetMs > 0 ? Math.max(1, Math.ceil(fullResetMs / 1000)) : 0,
    };
  }

  peek(key: string, now = this.nowFn()): RateLimitDecision {
    const existing = this.buckets.get(key);
    const tokens = existing
      ? Math.min(this.capacity, existing.tokens + Math.max(0, now - existing.lastRefillMs) * this.refillRatePerMs)
      : this.capacity;
    const missingTokens = Math.max(0, this.capacity - tokens);
    const fullResetMs = Math.ceil(missingTokens / this.refillRatePerMs);
    return {
      allowed: tokens >= 1,
      key,
      limit: this.capacity,
      remaining: Math.max(0, Math.floor(tokens)),
      resetAtMs: now + fullResetMs,
      retryAfterSec: tokens >= 1 ? 0 : Math.max(1, Math.ceil((1 - tokens) / this.refillRatePerMs / 1000)),
    };
  }

  reset(key?: string): void {
    if (key !== undefined) {
      this.buckets.delete(key);
    } else {
      this.buckets.clear();
    }
  }

  private getRefilledBucket(key: string, now: number): TokenBucketState {
    const existing = this.buckets.get(key);
    if (!existing) {
      return { tokens: this.capacity, lastRefillMs: now };
    }
    const elapsedMs = Math.max(0, now - existing.lastRefillMs);
    const replenished = Math.min(this.capacity, existing.tokens + elapsedMs * this.refillRatePerMs);
    return { tokens: replenished, lastRefillMs: now };
  }

  private evictIfNeeded(now: number): void {
    if (this.buckets.size <= this.maxBuckets) return;
    const fullIdleThresholdMs = Math.ceil(this.capacity / this.refillRatePerMs);
    for (const [k, state] of this.buckets) {
      if (now - state.lastRefillMs >= fullIdleThresholdMs) {
        this.buckets.delete(k);
      }
      if (this.buckets.size <= this.maxBuckets) return;
    }
    while (this.buckets.size > this.maxBuckets) {
      const oldestKey = this.buckets.keys().next().value as string | undefined;
      if (oldestKey === undefined) break;
      this.buckets.delete(oldestKey);
    }
  }
}

export interface SlidingWindowRateLimiterOptions {
  maxRequests: number;
  windowMs: number;
  maxBuckets?: number;
  nowFn?: () => number;
}

interface SlidingWindowState {
  windowStartMs: number;
  currCount: number;
  prevCount: number;
}

/**
 * Sliding-window counter rate limiter preventing fixed-window boundary double-burst spikes.
 */
export class SlidingWindowRateLimiter implements RateLimiterPort {
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private readonly maxBuckets: number;
  private readonly nowFn: () => number;
  private readonly windows = new Map<string, SlidingWindowState>();

  constructor(options: SlidingWindowRateLimiterOptions) {
    if (!Number.isInteger(options.maxRequests) || options.maxRequests <= 0) {
      throw new Error(
        `SlidingWindowRateLimiter maxRequests must be a positive integer (got ${options.maxRequests})`,
      );
    }
    if (!Number.isInteger(options.windowMs) || options.windowMs <= 0) {
      throw new Error(
        `SlidingWindowRateLimiter windowMs must be a positive integer (got ${options.windowMs})`,
      );
    }
    this.maxRequests = options.maxRequests;
    this.windowMs = options.windowMs;
    this.maxBuckets = Math.max(16, options.maxBuckets ?? 4096);
    this.nowFn = options.nowFn ?? Date.now;
  }

  consume(key: string, cost = 1, now = this.nowFn()): RateLimitDecision {
    const normalizedCost = Math.max(0, cost);
    const state = this.rollState(key, now);
    const elapsedInWindow = now - state.windowStartMs;
    const prevWeight = Math.max(0, (this.windowMs - elapsedInWindow) / this.windowMs);
    const effectiveCount = state.prevCount * prevWeight + state.currCount;
    const resetAtMs = state.windowStartMs + this.windowMs;

    this.windows.delete(key);

    if (effectiveCount + normalizedCost > this.maxRequests + 1e-9) {
      this.windows.set(key, state);
      this.evictIfNeeded(now);
      const retryMs = Math.max(1, resetAtMs - now);
      return {
        allowed: false,
        key,
        limit: this.maxRequests,
        remaining: 0,
        resetAtMs,
        retryAfterSec: Math.max(1, Math.ceil(retryMs / 1000)),
      };
    }

    state.currCount += normalizedCost;
    this.windows.set(key, state);
    this.evictIfNeeded(now);

    const newEffective = state.prevCount * prevWeight + state.currCount;
    const remaining = Math.max(0, Math.floor(this.maxRequests - newEffective));
    return {
      allowed: true,
      key,
      limit: this.maxRequests,
      remaining,
      resetAtMs,
      retryAfterSec: Math.max(1, Math.ceil((resetAtMs - now) / 1000)),
    };
  }

  peek(key: string, now = this.nowFn()): RateLimitDecision {
    const state = this.rollState(key, now, false);
    const elapsedInWindow = now - state.windowStartMs;
    const prevWeight = Math.max(0, (this.windowMs - elapsedInWindow) / this.windowMs);
    const effectiveCount = state.prevCount * prevWeight + state.currCount;
    const resetAtMs = state.windowStartMs + this.windowMs;
    const remaining = Math.max(0, Math.floor(this.maxRequests - effectiveCount));
    const allowed = effectiveCount + 1 <= this.maxRequests + 1e-9;
    return {
      allowed,
      key,
      limit: this.maxRequests,
      remaining,
      resetAtMs,
      retryAfterSec: allowed ? 0 : Math.max(1, Math.ceil((resetAtMs - now) / 1000)),
    };
  }

  reset(key?: string): void {
    if (key !== undefined) {
      this.windows.delete(key);
    } else {
      this.windows.clear();
    }
  }

  private rollState(key: string, now: number, mutate = true): SlidingWindowState {
    const alignedStart = Math.floor(now / this.windowMs) * this.windowMs;
    const existing = this.windows.get(key);
    if (!existing) {
      return { windowStartMs: alignedStart, currCount: 0, prevCount: 0 };
    }

    const windowsElapsed = Math.floor((alignedStart - existing.windowStartMs) / this.windowMs);
    let next: SlidingWindowState;
    if (windowsElapsed <= 0) {
      next = { ...existing };
    } else if (windowsElapsed === 1) {
      next = {
        windowStartMs: alignedStart,
        currCount: 0,
        prevCount: existing.currCount,
      };
    } else {
      next = {
        windowStartMs: alignedStart,
        currCount: 0,
        prevCount: 0,
      };
    }

    if (mutate) {
      this.windows.set(key, next);
    }
    return next;
  }

  private evictIfNeeded(now: number): void {
    if (this.windows.size <= this.maxBuckets) return;
    const staleBefore = now - this.windowMs * 2;
    for (const [k, state] of this.windows) {
      if (state.windowStartMs < staleBefore) {
        this.windows.delete(k);
      }
      if (this.windows.size <= this.maxBuckets) return;
    }
    while (this.windows.size > this.maxBuckets) {
      const oldestKey = this.windows.keys().next().value as string | undefined;
      if (oldestKey === undefined) break;
      this.windows.delete(oldestKey);
    }
  }
}

// ============================================================================
// Circuit Breaker State Machine & Registry
// ============================================================================

export type CircuitState = 'closed' | 'open' | 'half_open';

export interface CircuitStateTransition {
  name: string;
  from: CircuitState;
  to: CircuitState;
  timestamp: number;
  reason: string;
}

export interface CircuitBreakerSnapshot {
  name: string;
  state: CircuitState;
  consecutiveFailures: number;
  halfOpenInFlight: number;
  halfOpenSuccesses: number;
  totalSuccesses: number;
  totalFailures: number;
  totalRejected: number;
  openedAt: number | null;
  lastFailureAt: number | null;
  lastErrorMessage: string | null;
  retryAfterSec: number;
}

export class CircuitOpenError extends Error {
  readonly circuitName: string;
  readonly state: CircuitState;
  readonly retryAfterSec: number;

  constructor(circuitName: string, state: CircuitState, retryAfterSec: number) {
    super(
      `Circuit breaker "${circuitName}" is ${state}; fast-failing for ${retryAfterSec}s to protect upstream stability.`,
    );
    this.name = 'CircuitOpenError';
    this.circuitName = circuitName;
    this.state = state;
    this.retryAfterSec = retryAfterSec;
  }
}

export interface CircuitBreakerOptions {
  name: string;
  failureThreshold?: number;
  failureWindowMs?: number;
  resetTimeoutMs?: number;
  halfOpenMaxCalls?: number;
  halfOpenSuccessThreshold?: number;
  isFailure?: (error: unknown) => boolean;
  nowFn?: () => number;
  onStateChange?: (transition: CircuitStateTransition) => void;
}

export interface CircuitBeforeCallResult {
  allowed: boolean;
  state: CircuitState;
  retryAfterSec: number;
  probeAcquired: boolean;
}

/**
 * Standalone 3-state (`closed` -> `open` -> `half_open`) circuit breaker with rolling failure
 * window, bounded `half_open` probe concurrency, and custom failure classification.
 */
export class CircuitBreaker {
  readonly name: string;
  private readonly failureThreshold: number;
  private readonly failureWindowMs: number;
  private readonly resetTimeoutMs: number;
  private readonly halfOpenMaxCalls: number;
  private readonly halfOpenSuccessThreshold: number;
  private readonly isFailureFn: (error: unknown) => boolean;
  private readonly nowFn: () => number;
  private readonly onStateChange?: (transition: CircuitStateTransition) => void;

  private state: CircuitState = 'closed';
  private failureTimestamps: number[] = [];
  private halfOpenInFlight = 0;
  private halfOpenSuccesses = 0;
  private totalSuccesses = 0;
  private totalFailures = 0;
  private totalRejected = 0;
  private openedAt: number | null = null;
  private lastFailureAt: number | null = null;
  private lastErrorMessage: string | null = null;

  constructor(options: CircuitBreakerOptions) {
    this.name = options.name;
    this.failureThreshold = Math.max(1, options.failureThreshold ?? 5);
    this.failureWindowMs = Math.max(1000, options.failureWindowMs ?? 60_000);
    this.resetTimeoutMs = Math.max(500, options.resetTimeoutMs ?? 30_000);
    this.halfOpenMaxCalls = Math.max(1, options.halfOpenMaxCalls ?? 1);
    this.halfOpenSuccessThreshold = Math.max(1, options.halfOpenSuccessThreshold ?? 1);
    this.isFailureFn =
      options.isFailure ?? ((err: unknown) => !(err instanceof CircuitOpenError));
    this.nowFn = options.nowFn ?? Date.now;
    this.onStateChange = options.onStateChange;
  }

  getState(now = this.nowFn()): CircuitState {
    this.evaluateCooldown(now);
    return this.state;
  }

  getSnapshot(now = this.nowFn()): CircuitBreakerSnapshot {
    this.evaluateCooldown(now);
    this.pruneOldFailures(now);
    return {
      name: this.name,
      state: this.state,
      consecutiveFailures: this.failureTimestamps.length,
      halfOpenInFlight: this.halfOpenInFlight,
      halfOpenSuccesses: this.halfOpenSuccesses,
      totalSuccesses: this.totalSuccesses,
      totalFailures: this.totalFailures,
      totalRejected: this.totalRejected,
      openedAt: this.openedAt,
      lastFailureAt: this.lastFailureAt,
      lastErrorMessage: this.lastErrorMessage,
      retryAfterSec: this.computeRetryAfterSec(now),
    };
  }

  beforeCall(now = this.nowFn()): CircuitBeforeCallResult {
    this.evaluateCooldown(now);

    if (this.state === 'open') {
      this.totalRejected += 1;
      return {
        allowed: false,
        state: 'open',
        retryAfterSec: this.computeRetryAfterSec(now),
        probeAcquired: false,
      };
    }

    if (this.state === 'half_open') {
      if (this.halfOpenInFlight >= this.halfOpenMaxCalls) {
        this.totalRejected += 1;
        return {
          allowed: false,
          state: 'half_open',
          retryAfterSec: Math.max(1, Math.ceil(this.resetTimeoutMs / 1000)),
          probeAcquired: false,
        };
      }
      this.halfOpenInFlight += 1;
      return {
        allowed: true,
        state: 'half_open',
        retryAfterSec: 0,
        probeAcquired: true,
      };
    }

    return {
      allowed: true,
      state: 'closed',
      retryAfterSec: 0,
      probeAcquired: false,
    };
  }

  recordSuccess(now = this.nowFn(), probeAcquired = false): void {
    this.totalSuccesses += 1;

    if (probeAcquired && this.halfOpenInFlight > 0) {
      this.halfOpenInFlight -= 1;
    }

    if (this.state === 'half_open') {
      this.halfOpenSuccesses += 1;
      if (this.halfOpenSuccesses >= this.halfOpenSuccessThreshold) {
        this.failureTimestamps = [];
        this.halfOpenInFlight = 0;
        this.halfOpenSuccesses = 0;
        this.openedAt = null;
        this.transitionTo('closed', now, 'Half-open probe threshold succeeded');
      }
      return;
    }

    if (this.state === 'closed') {
      this.failureTimestamps = [];
    }
  }

  recordFailure(error?: unknown, now = this.nowFn(), probeAcquired = false): void {
    if (probeAcquired && this.halfOpenInFlight > 0) {
      this.halfOpenInFlight -= 1;
    }

    if (error !== undefined && !this.isFailureFn(error)) {
      if (this.state === 'half_open') {
        this.halfOpenSuccesses += 1;
        if (this.halfOpenSuccesses >= this.halfOpenSuccessThreshold) {
          this.failureTimestamps = [];
          this.halfOpenInFlight = 0;
          this.halfOpenSuccesses = 0;
          this.openedAt = null;
          this.transitionTo('closed', now, 'Half-open non-infra response restored circuit');
        }
      }
      return;
    }

    this.totalFailures += 1;
    this.lastFailureAt = now;
    this.lastErrorMessage =
      error instanceof Error ? error.message : error !== undefined ? String(error) : 'failure';

    if (this.state === 'half_open') {
      this.halfOpenInFlight = 0;
      this.halfOpenSuccesses = 0;
      this.openedAt = now;
      this.transitionTo('open', now, `Half-open probe failed: ${this.lastErrorMessage}`);
      return;
    }

    this.pruneOldFailures(now);
    this.failureTimestamps.push(now);

    if (this.state === 'closed' && this.failureTimestamps.length >= this.failureThreshold) {
      this.openedAt = now;
      this.halfOpenInFlight = 0;
      this.halfOpenSuccesses = 0;
      this.transitionTo(
        'open',
        now,
        `Failure threshold reached (${this.failureTimestamps.length}/${this.failureThreshold}): ${this.lastErrorMessage}`,
      );
    }
  }

  async execute<T>(fn: () => Promise<T> | T): Promise<T> {
    const gate = this.beforeCall();
    if (!gate.allowed) {
      throw new CircuitOpenError(this.name, gate.state, gate.retryAfterSec);
    }

    try {
      const result = await fn();
      this.recordSuccess(this.nowFn(), gate.probeAcquired);
      return result;
    } catch (err) {
      this.recordFailure(err, this.nowFn(), gate.probeAcquired);
      throw err;
    }
  }

  reset(): void {
    this.state = 'closed';
    this.failureTimestamps = [];
    this.halfOpenInFlight = 0;
    this.halfOpenSuccesses = 0;
    this.openedAt = null;
    this.lastFailureAt = null;
    this.lastErrorMessage = null;
  }

  private evaluateCooldown(now: number): void {
    if (this.state === 'open' && this.openedAt !== null && now - this.openedAt >= this.resetTimeoutMs) {
      this.halfOpenInFlight = 0;
      this.halfOpenSuccesses = 0;
      this.transitionTo('half_open', now, `Cooldown ${this.resetTimeoutMs}ms elapsed`);
    }
  }

  private pruneOldFailures(now: number): void {
    const cutoff = now - this.failureWindowMs;
    while (this.failureTimestamps.length > 0 && this.failureTimestamps[0]! <= cutoff) {
      this.failureTimestamps.shift();
    }
  }

  private computeRetryAfterSec(now: number): number {
    if (this.state !== 'open' || this.openedAt === null) {
      return 0;
    }
    const remainingMs = Math.max(0, this.openedAt + this.resetTimeoutMs - now);
    return Math.max(1, Math.ceil(remainingMs / 1000));
  }

  private transitionTo(next: CircuitState, now: number, reason: string): void {
    const prev = this.state;
    if (prev === next) return;
    this.state = next;
    this.onStateChange?.({
      name: this.name,
      from: prev,
      to: next,
      timestamp: now,
      reason,
    });
  }
}

export interface CircuitBreakerRegistryOptions {
  defaults?: Omit<CircuitBreakerOptions, 'name'>;
  auditPublisher?: AuditEventPublisher;
}

/**
 * Registry of named CircuitBreakers for HTTP routes, MCP transport, and external SDK integrations.
 */
export class CircuitBreakerRegistry {
  private readonly breakers = new Map<string, CircuitBreaker>();
  private readonly defaults: Omit<CircuitBreakerOptions, 'name'>;
  private readonly auditPublisher?: AuditEventPublisher;

  constructor(options: CircuitBreakerRegistryOptions = {}) {
    this.defaults = options.defaults ?? {};
    this.auditPublisher = options.auditPublisher;
  }

  getOrCreate(name: string, overrides: Partial<Omit<CircuitBreakerOptions, 'name'>> = {}): CircuitBreaker {
    const existing = this.breakers.get(name);
    if (existing) return existing;

    const mergedOnStateChange = (transition: CircuitStateTransition) => {
      this.defaults.onStateChange?.(transition);
      overrides.onStateChange?.(transition);
      this.auditPublisher?.emit({
        actor: 'system:circuit-breaker',
        action: `circuit_breaker.${transition.to}`,
        target: transition.name,
        status: transition.to === 'open' ? 'failure' : 'success',
        category: 'resilience',
        severity: transition.to === 'open' ? 'high' : 'info',
        created_at: transition.timestamp,
        details: {
          from: transition.from,
          to: transition.to,
          reason: transition.reason,
        },
      });
    };

    const created = new CircuitBreaker({
      ...this.defaults,
      ...overrides,
      name,
      onStateChange: mergedOnStateChange,
    });
    this.breakers.set(name, created);
    return created;
  }

  execute<T>(name: string, fn: () => Promise<T> | T): Promise<T> {
    return this.getOrCreate(name).execute(fn);
  }

  listSnapshots(now?: number): CircuitBreakerSnapshot[] {
    return Array.from(this.breakers.values()).map((b) => b.getSnapshot(now));
  }

  resetAll(): void {
    for (const breaker of this.breakers.values()) {
      breaker.reset();
    }
  }
}

// ============================================================================
// Hono Rate-Limiter & Circuit-Breaker Middleware
// ============================================================================

export type ResilienceResponseFormat = 'rest' | 'jsonrpc';

export interface RateLimitMiddlewareOptions {
  limiter: RateLimiterPort;
  trustCfConnectingIp?: boolean;
  keyPrefix?: string;
  keyExtractor?: (c: Context) => string;
  costExtractor?: (c: Context) => number;
  responseFormat?: ResilienceResponseFormat;
  auditPublisher?: AuditEventPublisher;
}

export function defaultResilienceKeyExtractor(
  c: Context,
  trustCfConnectingIp = true,
  prefix = 'http',
): string {
  const oauthAuth = c.get('oauthAuth') as OAuthAuthContext | undefined;
  if (oauthAuth?.clientId) {
    return `${prefix}:client:${oauthAuth.clientId}`;
  }
  const ip = getClientIp(c, trustCfConnectingIp);
  return `${prefix}:ip:${ip}`;
}

function applyHeadersSafe(c: Context, headers: Record<string, string>): void {
  for (const [k, v] of Object.entries(headers)) {
    c.header(k, v);
  }
  if (c.res) {
    try {
      for (const [k, v] of Object.entries(headers)) {
        c.res.headers.set(k, v);
      }
    } catch {
      const clonedHeaders = new Headers(c.res.headers);
      for (const [k, v] of Object.entries(headers)) {
        clonedHeaders.set(k, v);
      }
      c.res = new Response(c.res.body, {
        status: c.res.status,
        statusText: c.res.statusText,
        headers: clonedHeaders,
      });
    }
  }
}

function buildRateLimitHeaders(decision: RateLimitDecision): Record<string, string> {
  return {
    'X-RateLimit-Limit': String(decision.limit),
    'X-RateLimit-Remaining': String(decision.remaining),
    'X-RateLimit-Reset': String(Math.ceil(decision.resetAtMs / 1000)),
  };
}

/**
 * Hono middleware enforcing decoupled `RateLimiterPort` budgets with standard `X-RateLimit-*`
 * and `Retry-After` headers plus optional structured audit emission on 429 rejections.
 */
export function createRateLimitMiddleware(options: RateLimitMiddlewareOptions): MiddlewareHandler {
  const trustCf = options.trustCfConnectingIp ?? true;
  const prefix = options.keyPrefix ?? 'mcp';
  const format = options.responseFormat ?? 'rest';

  return async (c, next) => {
    const key = options.keyExtractor
      ? options.keyExtractor(c)
      : defaultResilienceKeyExtractor(c, trustCf, prefix);
    const cost = options.costExtractor ? options.costExtractor(c) : 1;
    const decision = options.limiter.consume(key, cost);
    const rateHeaders = buildRateLimitHeaders(decision);

    applyHeadersSafe(c, rateHeaders);

    if (!decision.allowed) {
      c.header('Retry-After', String(decision.retryAfterSec));
      const oauthAuth = c.get('oauthAuth') as OAuthAuthContext | undefined;
      const ip = getClientIp(c, trustCf);

      options.auditPublisher?.emit({
        actor: oauthAuth?.clientId ?? `ip:${ip}`,
        action: 'rate_limit.exceeded',
        target: c.req.path,
        status: 'denied',
        category: 'resilience',
        severity: 'warn',
        clientId: oauthAuth?.clientId,
        ip,
        details: {
          key,
          limit: decision.limit,
          retry_after_sec: decision.retryAfterSec,
          method: c.req.method,
        },
      });

      if (format === 'jsonrpc') {
        return c.json(
          {
            jsonrpc: '2.0',
            error: {
              code: -32005,
              message: `Rate limit exceeded. Retry after ${decision.retryAfterSec}s.`,
              data: {
                retryAfterSec: decision.retryAfterSec,
                limit: decision.limit,
              },
            },
            id: null,
          },
          429,
        );
      }

      return c.json(
        {
          error: 'rate_limit_exceeded',
          message: `Too many requests. Retry after ${decision.retryAfterSec}s.`,
          retry_after_sec: decision.retryAfterSec,
        },
        429,
      );
    }

    await next();
    applyHeadersSafe(c, rateHeaders);
  };
}

export interface CircuitBreakerMiddlewareOptions {
  breaker: CircuitBreaker | CircuitBreakerRegistry;
  circuitName?: string | ((c: Context) => string);
  responseFormat?: ResilienceResponseFormat;
  statusFailurePredicate?: (status: number) => boolean;
  trustCfConnectingIp?: boolean;
  auditPublisher?: AuditEventPublisher;
}

/**
 * Hono middleware guarding downstream routes with a 3-state `CircuitBreaker`.
 * Treats HTTP >= 500 and unhandled exceptions as upstream failures while letting 4xx client
 * errors pass through without tripping the circuit.
 */
export function createCircuitBreakerMiddleware(
  options: CircuitBreakerMiddlewareOptions,
): MiddlewareHandler {
  const format = options.responseFormat ?? 'rest';
  const trustCf = options.trustCfConnectingIp ?? true;
  const isStatusFailure = options.statusFailurePredicate ?? ((status: number) => status >= 500);

  return async (c, next) => {
    const resolvedBreaker =
      options.breaker instanceof CircuitBreaker
        ? options.breaker
        : options.breaker.getOrCreate(
            typeof options.circuitName === 'function'
              ? options.circuitName(c)
              : (options.circuitName ?? 'mcp:http'),
          );

    const gate = resolvedBreaker.beforeCall();
    applyHeadersSafe(c, { 'X-Circuit-State': gate.state });

    if (!gate.allowed) {
      c.header('Retry-After', String(gate.retryAfterSec));
      const oauthAuth = c.get('oauthAuth') as OAuthAuthContext | undefined;
      const ip = getClientIp(c, trustCf);

      options.auditPublisher?.emit({
        actor: oauthAuth?.clientId ?? `ip:${ip}`,
        action: 'circuit_breaker.rejected',
        target: resolvedBreaker.name,
        status: 'denied',
        category: 'resilience',
        severity: 'warn',
        clientId: oauthAuth?.clientId,
        ip,
        details: {
          state: gate.state,
          retry_after_sec: gate.retryAfterSec,
          path: c.req.path,
        },
      });

      if (format === 'jsonrpc') {
        return c.json(
          {
            jsonrpc: '2.0',
            error: {
              code: -32006,
              message: `Service temporarily unavailable (circuit "${resolvedBreaker.name}" is ${gate.state}). Retry after ${gate.retryAfterSec}s.`,
              data: {
                circuit: resolvedBreaker.name,
                state: gate.state,
                retryAfterSec: gate.retryAfterSec,
              },
            },
            id: null,
          },
          503,
        );
      }

      return c.json(
        {
          error: 'circuit_open',
          circuit: resolvedBreaker.name,
          state: gate.state,
          retry_after_sec: gate.retryAfterSec,
        },
        503,
      );
    }

    try {
      await next();
      if (isStatusFailure(c.res.status)) {
        resolvedBreaker.recordFailure(
          new Error(`Upstream handler returned HTTP ${c.res.status}`),
          undefined,
          gate.probeAcquired,
        );
      } else {
        resolvedBreaker.recordSuccess(undefined, gate.probeAcquired);
      }
      applyHeadersSafe(c, { 'X-Circuit-State': resolvedBreaker.getState() });
    } catch (err) {
      resolvedBreaker.recordFailure(err, undefined, gate.probeAcquired);
      throw err;
    }
  };
}

export interface ResilienceMiddlewareOptions {
  limiter?: RateLimiterPort;
  breaker?: CircuitBreaker | CircuitBreakerRegistry;
  circuitName?: string | ((c: Context) => string);
  trustCfConnectingIp?: boolean;
  keyPrefix?: string;
  keyExtractor?: (c: Context) => string;
  costExtractor?: (c: Context) => number;
  responseFormat?: ResilienceResponseFormat;
  statusFailurePredicate?: (status: number) => boolean;
  auditPublisher?: AuditEventPublisher;
}

/**
 * Unified Hono middleware composing decoupled rate limiting + circuit breaking in sequence.
 */
export function createResilienceMiddleware(options: ResilienceMiddlewareOptions): MiddlewareHandler {
  const middlewares: MiddlewareHandler[] = [];

  if (options.limiter) {
    middlewares.push(
      createRateLimitMiddleware({
        limiter: options.limiter,
        trustCfConnectingIp: options.trustCfConnectingIp,
        keyPrefix: options.keyPrefix,
        keyExtractor: options.keyExtractor,
        costExtractor: options.costExtractor,
        responseFormat: options.responseFormat,
        auditPublisher: options.auditPublisher,
      }),
    );
  }

  if (options.breaker) {
    middlewares.push(
      createCircuitBreakerMiddleware({
        breaker: options.breaker,
        circuitName: options.circuitName,
        responseFormat: options.responseFormat,
        statusFailurePredicate: options.statusFailurePredicate,
        trustCfConnectingIp: options.trustCfConnectingIp,
        auditPublisher: options.auditPublisher,
      }),
    );
  }

  return async (c, next) => {
    let index = -1;
    const dispatch = async (i: number): Promise<void> => {
      if (i <= index) {
        throw new Error('next() called multiple times in resilience middleware');
      }
      index = i;
      const fn = i < middlewares.length ? middlewares[i] : undefined;
      if (!fn) {
        await next();
        return;
      }
      const res = await fn(c, async () => {
        await dispatch(i + 1);
      });
      if (res instanceof Response) {
        c.res = res;
      }
    };

    await dispatch(0);
  };
}
