/**
 * Fixed-window rate limiter for auth endpoints.
 *
 * The NestJS migration removed the module's `utils/` directory while
 * `auth.controller.ts` kept importing `limited` from it, so the module did not
 * compile. This is the missing implementation: a per-key counter with a rolling
 * window, in memory, no dependencies — the same semantics the controller already
 * expects (`limited(key, limit)` returns true once the key is over its budget).
 *
 * In-memory is deliberate: auth throttling must not depend on the database being
 * reachable, and losing counters on restart is an acceptable trade for that.
 */

interface Bucket {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Bucket>();

/** Deletes expired buckets so a long-lived process cannot grow this map forever. */
function sweep(now: number): void {
  if (buckets.size < 1_000) return;
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) buckets.delete(key);
  }
}

/**
 * Counts one hit for `key` and reports whether the caller is now over budget.
 *
 * @param key     what is being limited, e.g. `login:1.2.3.4`
 * @param limit   allowed hits inside the window
 * @param windowMs window length, 60 seconds by default
 */
export function limited(key: string, limit: number, windowMs = 60_000): boolean {
  const now = Date.now();
  sweep(now);

  const existing = buckets.get(key);
  if (!existing || existing.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return limit <= 0;
  }

  existing.count += 1;
  return existing.count > limit;
}

/** Test helper: forget every counter. */
export function _resetRateLimiter(): void {
  buckets.clear();
}
