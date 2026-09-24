import assert from "node:assert/strict";
import test from "node:test";

import {
  classifyHorizonReadError,
  decideHorizonFallback,
  parseHorizonEndpointList,
  readWithHorizonFallback,
  resolveProofVerificationHorizonUrls,
  shouldAdvanceHorizonFallback,
} from "../../lib/x402/rpc-fallback";

// ── Parsing / resolution ──────────────────────────────────────────────────────

test("parseHorizonEndpointList drops empty, non-http, and duplicates", () => {
  assert.deepEqual(
    parseHorizonEndpointList(
      " https://a.example/ ,https://b.example, ftp://nope, https://a.example/, ,https://B.example ",
    ),
    ["https://a.example", "https://b.example"],
  );
  assert.deepEqual(parseHorizonEndpointList(""), []);
  assert.deepEqual(parseHorizonEndpointList(undefined), []);
});

test("resolveProofVerificationHorizonUrls keeps primary first and dedupes fallbacks", () => {
  assert.deepEqual(
    resolveProofVerificationHorizonUrls({
      primaryUrl: "https://horizon-testnet.stellar.org",
      fallbackRaw: "https://horizon-backup.example, https://horizon-testnet.stellar.org/",
    }),
    ["https://horizon-testnet.stellar.org", "https://horizon-backup.example"],
  );
});

test("resolveProofVerificationHorizonUrls with no fallbacks is primary only", () => {
  assert.deepEqual(
    resolveProofVerificationHorizonUrls({
      primaryUrl: "https://horizon-testnet.stellar.org",
      fallbackRaw: null,
    }),
    ["https://horizon-testnet.stellar.org"],
  );
});

// ── Classification / decisions ────────────────────────────────────────────────

test("classifyHorizonReadError treats only 404 as not_found", () => {
  assert.equal(classifyHorizonReadError({ response: { status: 404 } }), "not_found");
  assert.equal(classifyHorizonReadError({ response: { status: 503 } }), "unavailable");
  assert.equal(classifyHorizonReadError({ response: { status: 429 } }), "unavailable");
  assert.equal(classifyHorizonReadError(new Error("socket hang up")), "unavailable");
  assert.equal(classifyHorizonReadError({}), "unavailable");
});

test("shouldAdvanceHorizonFallback only for unavailable", () => {
  assert.equal(shouldAdvanceHorizonFallback("unavailable"), true);
  assert.equal(shouldAdvanceHorizonFallback("not_found"), false);
});

test("decideHorizonFallback stops on success and not_found; advances on unavailable", () => {
  assert.equal(
    decideHorizonFallback({ outcome: "success", remainingAfter: 3 }),
    "stop_success",
  );
  assert.equal(
    decideHorizonFallback({ outcome: "not_found", remainingAfter: 3 }),
    "stop_not_found",
  );
  assert.equal(
    decideHorizonFallback({ outcome: "unavailable", remainingAfter: 1 }),
    "try_next",
  );
  assert.equal(
    decideHorizonFallback({ outcome: "unavailable", remainingAfter: 0 }),
    "exhausted_unavailable",
  );
});

// ── Runner: positive / negative / boundary / conservation ─────────────────────

test("readWithHorizonFallback returns primary success without consulting fallbacks", async () => {
  const seen: string[] = [];
  const result = await readWithHorizonFallback({
    urls: ["https://primary.example", "https://fallback.example"],
    read: async (url) => {
      seen.push(url);
      return { tx: "abc" };
    },
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.url, "https://primary.example");
  assert.deepEqual(result.value, { tx: "abc" });
  assert.deepEqual(seen, ["https://primary.example"]);
  assert.equal(result.attempts.length, 1);
});

test("readWithHorizonFallback advances on unavailable and succeeds on fallback", async () => {
  const seen: string[] = [];
  const result = await readWithHorizonFallback({
    urls: ["https://primary.example", "https://fallback.example"],
    read: async (url) => {
      seen.push(url);
      if (url.includes("primary")) {
        const err = new Error("503");
        (err as { response?: { status: number } }).response = { status: 503 };
        throw err;
      }
      return { ok: true };
    },
  });
  assert.equal(result.ok, true);
  if (!result.ok) return;
  assert.equal(result.url, "https://fallback.example");
  assert.deepEqual(seen, ["https://primary.example", "https://fallback.example"]);
  assert.equal(result.attempts[0]?.outcome, "unavailable");
  assert.equal(result.attempts[1]?.outcome, "success");
});

test("readWithHorizonFallback does not shop past a 404 (fail closed on absence)", async () => {
  const seen: string[] = [];
  const result = await readWithHorizonFallback({
    urls: ["https://primary.example", "https://fallback.example"],
    read: async (url) => {
      seen.push(url);
      const err = new Error("404");
      (err as { response?: { status: number } }).response = { status: 404 };
      throw err;
    },
  });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.reason, "not_found");
  assert.deepEqual(seen, ["https://primary.example"]);
});

test("readWithHorizonFallback exhausts unavailable endpoints fail-closed", async () => {
  const result = await readWithHorizonFallback({
    urls: ["https://a.example", "https://b.example"],
    read: async () => {
      throw new Error("ECONNRESET");
    },
  });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.reason, "unavailable");
  assert.equal(result.attempts.length, 2);
  assert.ok(result.attempts.every((a) => a.outcome === "unavailable"));
});

test("readWithHorizonFallback with empty URL list fails closed", async () => {
  const result = await readWithHorizonFallback({
    urls: [],
    read: async () => {
      throw new Error("should not run");
    },
  });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.reason, "unavailable");
  assert.match(result.message, /no Horizon endpoints/i);
});

test("regression: network error then 404 on fallback stays not_found", async () => {
  const result = await readWithHorizonFallback({
    urls: ["https://primary.example", "https://fallback.example"],
    read: async (url) => {
      if (url.includes("primary")) throw new Error("timeout");
      const err = new Error("missing");
      (err as { response?: { status: number } }).response = { status: 404 };
      throw err;
    },
  });
  assert.equal(result.ok, false);
  if (result.ok) return;
  assert.equal(result.reason, "not_found");
  assert.equal(result.attempts.length, 2);
});
