/**
 * RPC / Horizon fallback policy for payment-proof verification.
 *
 * x402 proof verification is a classic-ledger Horizon READ (see
 * `lib/x402/stellar-scheme.ts`). A single Horizon outage must not fail-close a
 * funded settle when the operator has configured an independent mirror — but a
 * later endpoint must NEVER override a definitive ledger answer from an earlier
 * one. Shopping for a "better" answer across mirrors would invent conflicting
 * state.
 *
 * Rules, in order:
 *
 *  1. **Try endpoints in configured order** — primary
 *     (`NEXT_PUBLIC_STELLAR_HORIZON_URL` / `STELLAR_HORIZON_URL`) first, then
 *     `STELLAR_HORIZON_FALLBACK_URLS` (comma-separated).
 *  2. **Availability failures advance** — network errors, timeouts, HTTP 429 /
 *     5xx, and empty responses are `unavailable` and the next URL is tried.
 *  3. **Definitive answers stop the walk** — HTTP 404 (`not_found`) and any
 *     successful body are final for that proof. We do not ask a mirror to
 *     contradict a 404 or a successful read.
 *  4. **Exhaustion fails closed** — if every endpoint is unavailable, callers
 *     report `horizon_unavailable`. Money movement stays paused rather than
 *     guessing.
 *  5. **Malformed / duplicate URLs are dropped** — empty strings, non-http(s)
 *     schemes, and repeats of an earlier URL never enter the list.
 *
 * Pure decision helpers live here; the Horizon client construction stays in
 * `lib/stellar.ts`. Callers own the actual HTTP.
 */

/** How a single endpoint answered a proof-verification read. */
export type HorizonEndpointFailureClass =
  /** Transaction genuinely absent on this mirror (HTTP 404). */
  | "not_found"
  /** Transport / capacity / server failure — safe to try the next URL. */
  | "unavailable";

export type HorizonFallbackDecision =
  /** Stop: this endpoint's 404 is authoritative for the walk. */
  | "stop_not_found"
  /** Stop: the read succeeded; do not consult further mirrors. */
  | "stop_success"
  /** Advance to the next configured URL. */
  | "try_next"
  /** No URLs remain; fail closed as unavailable. */
  | "exhausted_unavailable";

export interface HorizonFallbackStep {
  url: string;
  /** Zero-based index in the ordered endpoint list. */
  index: number;
  remainingAfter: number;
}

/**
 * Classify a Horizon SDK / fetch error for fallback purposes.
 *
 * Only `unavailable` may advance. A 404 is definitive: replication lag is
 * possible, but retrying another mirror on 404 would also let a partitioned
 * stale mirror invent a payment that the primary correctly denied — fail closed
 * on absence unless a later operator policy explicitly opts in.
 */
export function classifyHorizonReadError(cause: unknown): HorizonEndpointFailureClass {
  const status = (cause as { response?: { status?: number } })?.response?.status;
  if (status === 404) return "not_found";
  return "unavailable";
}

/** True when the failure class is allowed to advance to the next endpoint. */
export function shouldAdvanceHorizonFallback(
  failure: HorizonEndpointFailureClass,
): boolean {
  return failure === "unavailable";
}

/**
 * Decide what to do after one endpoint attempt.
 *
 * `success` short-circuits. `not_found` short-circuits. `unavailable` advances
 * while URLs remain, otherwise exhausts.
 */
export function decideHorizonFallback(args: {
  outcome: "success" | HorizonEndpointFailureClass;
  remainingAfter: number;
}): HorizonFallbackDecision {
  if (args.outcome === "success") return "stop_success";
  if (args.outcome === "not_found") return "stop_not_found";
  if (args.remainingAfter > 0) return "try_next";
  return "exhausted_unavailable";
}

/**
 * Parse a comma / whitespace separated URL list into ordered unique http(s) URLs.
 */
export function parseHorizonEndpointList(
  raw: string | undefined | null,
): string[] {
  if (!raw) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const part of raw.split(/[,|\s]+/)) {
    const url = part.trim().replace(/\/+$/, "");
    if (!url) continue;
    if (!/^https?:\/\//i.test(url)) continue;
    const key = url.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(url);
  }
  return out;
}

/**
 * Ordered Horizon URLs for proof verification: primary, then configured fallbacks.
 *
 * Fallbacks are server-only (`STELLAR_HORIZON_FALLBACK_URLS`) so browser bundles
 * do not ship operator mirror topology. The primary still comes from the public
 * getter so quote generation and verification share one source of truth.
 */
export function resolveProofVerificationHorizonUrls(args: {
  primaryUrl: string;
  fallbackRaw?: string | null;
}): string[] {
  const primary = parseHorizonEndpointList(args.primaryUrl);
  const fallbacks = parseHorizonEndpointList(args.fallbackRaw);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const url of [...primary, ...fallbacks]) {
    const key = url.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(url);
  }
  return out;
}

/**
 * Walk the endpoint list under the policy. `read` throws on failure; its errors
 * are classified. Returns the first successful value plus an audit trail.
 */
export async function readWithHorizonFallback<T>(args: {
  urls: readonly string[];
  read: (url: string) => Promise<T>;
}): Promise<
  | {
      ok: true;
      value: T;
      url: string;
      attempts: Array<{ url: string; outcome: "success" | HorizonEndpointFailureClass; detail?: string }>;
    }
  | {
      ok: false;
      reason: "not_found" | "unavailable";
      message: string;
      attempts: Array<{ url: string; outcome: "success" | HorizonEndpointFailureClass; detail?: string }>;
    }
> {
  const attempts: Array<{
    url: string;
    outcome: "success" | HorizonEndpointFailureClass;
    detail?: string;
  }> = [];

  if (args.urls.length === 0) {
    return {
      ok: false,
      reason: "unavailable",
      message: "no Horizon endpoints configured for proof verification",
      attempts,
    };
  }

  for (let i = 0; i < args.urls.length; i++) {
    const url = args.urls[i]!;
    const remainingAfter = args.urls.length - i - 1;
    try {
      const value = await args.read(url);
      attempts.push({ url, outcome: "success" });
      const decision = decideHorizonFallback({ outcome: "success", remainingAfter });
      if (decision === "stop_success") {
        return { ok: true, value, url, attempts };
      }
    } catch (cause) {
      const failure = classifyHorizonReadError(cause);
      const detail = cause instanceof Error ? cause.message : String(cause);
      attempts.push({ url, outcome: failure, detail });
      const decision = decideHorizonFallback({ outcome: failure, remainingAfter });
      if (decision === "stop_not_found") {
        return {
          ok: false,
          reason: "not_found",
          message: detail || `Horizon returned 404 from ${url}`,
          attempts,
        };
      }
      if (decision === "try_next") continue;
      return {
        ok: false,
        reason: "unavailable",
        message: detail || `Horizon unavailable at ${url}`,
        attempts,
      };
    }
  }

  return {
    ok: false,
    reason: "unavailable",
    message: "all Horizon endpoints unavailable for proof verification",
    attempts,
  };
}
