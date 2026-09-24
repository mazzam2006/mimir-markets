/**
 * Stellar Testnet configuration — the app-facing chain layer.
 *
 * Replaces the EVM-era `lib/base.ts` for everything Mimir itself does:
 * RPC/Horizon construction, network identity, explorer links, contract ids and
 * event scanning.
 *
 * Market stakes / payouts are USDC via its Stellar Asset Contract (7 decimals —
 * see `lib/usdc.ts`). Transaction fees are native XLM, denominated in stroops
 * (1 XLM = 10^7 stroops), which is why the gas-unit helpers at the bottom
 * mirror `weiToEth`/`formatEthAmount` rather than reusing them.
 *
 * Env vars are the ones `deploy/deploy.ts` writes into `.env.local`, read with
 * the same precedence as `scripts/lib/stellar-env.ts`: `NEXT_PUBLIC_*` first (so
 * the browser bundle sees them), then the server-only variant. Deliberately no
 * `fs` access here — this module is imported by client components.
 */
import { Horizon, rpc, StrKey } from "@stellar/stellar-sdk";
import type { SignAuthEntry, SignTransaction } from "@stellar/stellar-sdk/contract";

// ── Env plumbing ──────────────────────────────────────────────────────────────

/**
 * `.env` values in this repo carry trailing `# comment` notes, and a value
 * pasted into a dashboard — or read from a CRLF `.env` by a shell that drops the
 * newline but keeps the carriage return — arrives with invisible whitespace.
 * A `C…`/`G…` address with a stray `\r` is rejected by StrKey as malformed while
 * looking perfectly correct in the logs, so every read is normalised here.
 */
function cleanEnv(raw: string | undefined): string | undefined {
  if (!raw) return undefined;
  const withoutComment = raw.includes("#") ? raw.split(/\s+#/)[0] : raw;
  const value = withoutComment.trim();
  return value.length > 0 ? value : undefined;
}

/**
 * Every `NEXT_PUBLIC_`-prefixed config value, read on demand.
 *
 * A FUNCTION, not a module-level const object, and the difference matters twice:
 *
 *  - The literal `process.env.NEXT_PUBLIC_…` accesses still have to be written
 *    out, because Next.js substitutes them textually at build time and a dynamic
 *    `process.env[key]` lookup resolves to `undefined` in the browser bundle. They
 *    are just as literal inside a function body, so inlining is unaffected.
 *  - Reading LAZILY means a process that configures itself after its first import
 *    — a worker loading `.env.local` late, a test setting one var before calling
 *    one getter — sees the value it set. Captured in a const, the object froze at
 *    import and `getUsdcSacId()` could return a stale empty string forever, which
 *    surfaced as spend permissions being rejected as `wrong_token` against a
 *    perfectly well-configured deployment.
 *
 * The derived module-level constants below (`STELLAR_NETWORK`, `NETWORK_PASSPHRASE`
 * and friends) are still resolved once at import: they are baked into the browser
 * bundle and into explorer URLs, and a value that changed mid-process would be
 * worse than one that is fixed.
 */
function publicEnvAll() {
  return {
    network: process.env.NEXT_PUBLIC_STELLAR_NETWORK,
    networkPassphrase: process.env.NEXT_PUBLIC_STELLAR_NETWORK_PASSPHRASE,
    rpcUrl: process.env.NEXT_PUBLIC_STELLAR_RPC_URL,
    horizonUrl: process.env.NEXT_PUBLIC_STELLAR_HORIZON_URL,
    marketId: process.env.NEXT_PUBLIC_STELLAR_MARKET_CONTRACT_ID,
    squadId: process.env.NEXT_PUBLIC_STELLAR_SQUAD_CONTRACT_ID,
    usdcSac: process.env.NEXT_PUBLIC_STELLAR_USDC_SAC_ID,
    usdcIssuer: process.env.NEXT_PUBLIC_STELLAR_USDC_ISSUER,
    deployLedger: process.env.NEXT_PUBLIC_STELLAR_DEPLOY_LEDGER,
    eventPageLimit: process.env.NEXT_PUBLIC_STELLAR_EVENT_PAGE_LIMIT,
    eventMaxPages: process.env.NEXT_PUBLIC_STELLAR_EVENT_MAX_PAGES,
    readConcurrency: process.env.NEXT_PUBLIC_STELLAR_READ_CONCURRENCY,
  } as const;
}

function publicEnv(key: keyof ReturnType<typeof publicEnvAll>): string | undefined {
  return cleanEnv(publicEnvAll()[key]);
}

function envInt(raw: string | undefined, fallback: number): number {
  const value = Number(cleanEnv(raw) ?? fallback);
  return Number.isFinite(value) && value > 0 ? Math.floor(value) : fallback;
}

// ── Network identity ──────────────────────────────────────────────────────────

/** Stellar public Testnet. Mirrors `scripts/lib/stellar-env.ts`. */
export const STELLAR_NETWORK = publicEnv("network") ?? "testnet";

export const NETWORK_PASSPHRASE =
  publicEnv("networkPassphrase") ?? "Test SDF Network ; September 2015";

const DEFAULT_RPC_URL = "https://soroban-testnet.stellar.org";
const DEFAULT_HORIZON_URL = "https://horizon-testnet.stellar.org";

let warnedPublicRpc = false;

/**
 * Soroban RPC endpoint. The SDF-run `soroban-testnet.stellar.org` is rate
 * limited and keeps only a short event-retention window: fine for local dev,
 * not for a deployed app. Deployments must set NEXT_PUBLIC_STELLAR_RPC_URL to a
 * provider endpoint.
 */
export function getStellarRpcUrl(): string {
  const configured =
    publicEnv("rpcUrl") ??
    (typeof window === "undefined" ? cleanEnv(process.env.STELLAR_RPC_URL) : undefined);
  if (configured) return configured;

  if (process.env.NODE_ENV === "production" && !warnedPublicRpc) {
    warnedPublicRpc = true;
    console.warn(
      `[stellar] falling back to the public ${DEFAULT_RPC_URL} in production — set NEXT_PUBLIC_STELLAR_RPC_URL to a provider endpoint.`,
    );
  }
  return DEFAULT_RPC_URL;
}

export function getHorizonUrl(): string {
  return (
    publicEnv("horizonUrl") ??
    (typeof window === "undefined" ? cleanEnv(process.env.STELLAR_HORIZON_URL) : undefined) ??
    DEFAULT_HORIZON_URL
  );
}

/**
 * Optional comma-separated Horizon mirrors for proof-verification fallback.
 * Server-only — browser code keeps talking to the single public primary URL.
 */
export function getHorizonFallbackUrlsRaw(): string | undefined {
  if (typeof window !== "undefined") return undefined;
  return cleanEnv(process.env.STELLAR_HORIZON_FALLBACK_URLS);
}

// ── Contract ids ──────────────────────────────────────────────────────────────

/**
 * Soroban contract ids are `C…` StrKeys, not 32-byte hex, so there is no zero
 * address to fall back to. An unset id resolves to the empty string and
 * `isMarketConfigured()` is false, which is the signal callers use to skip chain
 * reads instead of throwing on every render.
 */
export function getMarketContractId(): string {
  return publicEnv("marketId") ?? "";
}

export function getSquadContractId(): string {
  return publicEnv("squadId") ?? "";
}

export function getUsdcSacId(): string {
  return publicEnv("usdcSac") ?? "";
}

export function getUsdcIssuer(): string {
  return publicEnv("usdcIssuer") ?? "";
}

/** True when the id looks like a real Soroban contract StrKey. */
export function isContractAddress(value: string): boolean {
  return Boolean(value) && StrKey.isValidContract(value);
}

/** True when the value looks like a real Stellar account StrKey (`G…`). */
export function isAccountAddress(value: string): boolean {
  return Boolean(value) && StrKey.isValidEd25519PublicKey(value);
}

/** False when the market contract id is unset or malformed — skip chain reads. */
export function isMarketConfigured(): boolean {
  return isContractAddress(getMarketContractId());
}

export function isSquadConfigured(): boolean {
  return isContractAddress(getSquadContractId());
}

export function isUsdcConfigured(): boolean {
  return isContractAddress(getUsdcSacId());
}

/** Throwing accessor for paths that cannot degrade to "not configured". */
export function requireMarketContractId(): string {
  const id = getMarketContractId();
  if (!isContractAddress(id)) {
    throw new Error(
      "NEXT_PUBLIC_STELLAR_MARKET_CONTRACT_ID is not a valid contract id — run: npm run deploy:contract",
    );
  }
  return id;
}

export function requireSquadContractId(): string {
  const id = getSquadContractId();
  if (!isContractAddress(id)) {
    throw new Error(
      "NEXT_PUBLIC_STELLAR_SQUAD_CONTRACT_ID is not a valid contract id — run: npm run deploy:contract",
    );
  }
  return id;
}

// ── Explorer links ────────────────────────────────────────────────────────────

/**
 * stellar.expert is network-scoped in the path, not by subdomain, so the network
 * segment has to be part of the base URL.
 */
export const STELLAR_EXPLORER_URL = `https://stellar.expert/explorer/${STELLAR_NETWORK}`;

export function getExplorerTxUrl(txHash: string): string {
  return `${STELLAR_EXPLORER_URL}/tx/${txHash}`;
}

export function getExplorerAccountUrl(publicKey: string): string {
  return `${STELLAR_EXPLORER_URL}/account/${publicKey}`;
}

export function getExplorerContractUrl(contractId: string): string {
  return `${STELLAR_EXPLORER_URL}/contract/${contractId}`;
}

export function getExplorerLedgerUrl(ledger: number | string): string {
  return `${STELLAR_EXPLORER_URL}/ledger/${ledger}`;
}

/**
 * Address link that picks the right route for the StrKey it was given.
 *
 * stellar.expert has no single `/address/…` route the way an EVM explorer does:
 * `G…` accounts and `C…` contracts live under different paths and each 404s on
 * the other. Callers hold a plain string (a claim creator could be either a user
 * account or a smart-contract account), so the discrimination happens here
 * rather than at every call site.
 */
export function getExplorerAddressUrl(address: string): string {
  if (isContractAddress(address)) return getExplorerContractUrl(address);
  return getExplorerAccountUrl(address);
}

// ── Clients ───────────────────────────────────────────────────────────────────

/**
 * Soroban RPC client. Cheap to construct (a thin URL wrapper, no socket), but
 * memoised per URL so repeated feed renders share one instance.
 */
const rpcServers = new Map<string, rpc.Server>();

export function createSorobanRpcServer(url = getStellarRpcUrl()): rpc.Server {
  const cached = rpcServers.get(url);
  if (cached) return cached;
  const server = new rpc.Server(url, { allowHttp: url.startsWith("http://") });
  rpcServers.set(url, server);
  return server;
}

const horizonServers = new Map<string, Horizon.Server>();

/**
 * Horizon is only needed for classic-ledger questions Soroban RPC does not
 * answer: account existence, trustlines, and payment history. Contract reads and
 * writes go through Soroban RPC.
 */
export function createHorizonServer(url = getHorizonUrl()): Horizon.Server {
  const cached = horizonServers.get(url);
  if (cached) return cached;
  const server = new Horizon.Server(url, { allowHttp: url.startsWith("http://") });
  horizonServers.set(url, server);
  return server;
}

/** Options every generated `Client` needs. Read-only unless a signer is added. */
export function stellarClientOptions(contractId: string) {
  const rpcUrl = getStellarRpcUrl();
  return {
    contractId,
    rpcUrl,
    networkPassphrase: NETWORK_PASSPHRASE,
    allowHttp: rpcUrl.startsWith("http://"),
  };
}

// ── Signing identity ──────────────────────────────────────────────────────────

/**
 * What a write call needs from a wallet.
 *
 * Shaped to be exactly what `@creit.tech/stellar-wallets-kit` already hands back
 * (`signTransaction(xdr, opts) => { signedTxXdr, signerAddress? }`) and what the
 * generated bindings' `ClientOptions` already accept, so the wallet layer can
 * pass its kit object straight through without an adapter. `basicNodeSigner`
 * from `@stellar/stellar-sdk/contract` satisfies it too, which is how the
 * server-side agent paths sign.
 *
 * `signAuthEntry` is not optional in practice for Mimir: `create_claim` and
 * `challenge_claim` both `require_auth()` and then invoke the USDC SAC's
 * `transfer` on the caller's behalf, so the caller signs a SorobanAuth entry as
 * well as the envelope. It stays optional in the type because read-only and
 * self-invoked calls (`withdraw`, `claim_fees`) do not need it, and a wallet
 * that lacks it should fail at the call that needs it with a real message.
 */
export interface StellarSigner {
  publicKey: string;
  signTransaction: SignTransaction;
  signAuthEntry?: SignAuthEntry;
}

/** Narrow a `string | StellarSigner` wallet argument. */
export function isStellarSigner(value: unknown): value is StellarSigner {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as StellarSigner).publicKey === "string" &&
    typeof (value as StellarSigner).signTransaction === "function"
  );
}

// ── Transaction watching ──────────────────────────────────────────────────────

export interface StellarTxOutcome {
  hash: string;
  status: rpc.Api.GetTransactionStatus;
  succeeded: boolean;
  /** Still `NOT_FOUND` when the poll budget ran out. */
  pending: boolean;
  explorerUrl: string;
  response: rpc.Api.GetTransactionResponse | null;
}

/**
 * Wait for a submitted transaction to land.
 *
 * Stellar closes a ledger every ~5s and a transaction is final the moment it is
 * included — there are no reorgs and no confirmation count to wait for, so a
 * single `pollTransaction` is the whole story. A budget that expires is reported
 * as `pending` rather than thrown: the transaction may still be in flight and a
 * caller must not tell the user it failed.
 */
export async function waitForTransaction(
  hash: string,
  opts: { attempts?: number; server?: rpc.Server } = {},
): Promise<StellarTxOutcome> {
  const server = opts.server ?? createSorobanRpcServer();
  const explorerUrl = getExplorerTxUrl(hash);
  try {
    const response = await server.pollTransaction(hash, { attempts: opts.attempts ?? 12 });
    const succeeded = response.status === rpc.Api.GetTransactionStatus.SUCCESS;
    return {
      hash,
      status: response.status,
      succeeded,
      pending: response.status === rpc.Api.GetTransactionStatus.NOT_FOUND,
      explorerUrl,
      response,
    };
  } catch {
    return {
      hash,
      status: rpc.Api.GetTransactionStatus.NOT_FOUND,
      succeeded: false,
      pending: true,
      explorerUrl,
      response: null,
    };
  }
}

// ── Event scanning ────────────────────────────────────────────────────────────

/**
 * Ledger the contracts were deployed at, used as the default scan floor.
 * `NEXT_PUBLIC_STELLAR_DEPLOY_LEDGER` is optional; 0 means "clamp to whatever
 * the RPC still retains", which is the honest default for a public endpoint.
 */
export function getDeployLedger(): number {
  return envInt(publicEnvAll().deployLedger, 0);
}

/**
 * Events per `getEvents` request.
 *
 * This bounds the events RETURNED, not the ledgers SCANNED — see
 * {@link LEDGERS_PER_EVENT_PAGE}. 200 keeps individual responses small enough
 * that a serverless route can stream several pages inside its budget.
 */
export const STELLAR_EVENT_PAGE_LIMIT = envInt(publicEnvAll().eventPageLimit, 200);

/**
 * Ledgers one `getEvents` request scans, measured against Testnet RPC.
 *
 * Not a knob — a server-side property, recorded here because it is what makes the
 * page count predictable: crossing the whole ~120_960-ledger retention window
 * takes ~13 requests no matter how few events are in it.
 */
export const LEDGERS_PER_EVENT_PAGE = 10_000;

/**
 * Ceiling on pages walked in one scan. A scan that hits it returns
 * `truncated: true` plus a resumable cursor rather than looping forever against
 * a busy contract. The default comfortably covers the full retention window
 * (~13 pages) with room for event-dense ranges.
 */
export const STELLAR_EVENT_MAX_PAGES = envInt(publicEnvAll().eventMaxPages, 50);

/**
 * Ledger sequence encoded in a `getEvents` cursor.
 *
 * The cursor is `"<TOID>-<event index>"`, and a Stellar TOID packs the ledger
 * sequence into its high 32 bits. Reading it is what lets the walk below know it
 * has reached the end of the range from the response it already has, instead of
 * spending an extra round trip to discover the cursor stopped moving.
 */
export function eventCursorLedger(cursor: string): number | null {
  const toid = cursor.split("-")[0];
  if (!/^\d+$/.test(toid)) return null;
  return Number(BigInt(toid) >> 32n);
}

/** Concurrency limiter for bulk contract reads. See `lib/contract.ts`. */
export const STELLAR_READ_CONCURRENCY = envInt(publicEnvAll().readConcurrency, 5);

export interface StellarEventScan {
  events: rpc.Api.EventResponse[];
  /** Feed this back as `cursor` to resume; null when the scan reached the end. */
  cursor: string | null;
  latestLedger: number;
  oldestLedger: number;
  /** True when `maxPages` stopped the walk before the end of the range. */
  truncated: boolean;
}

export interface StellarEventScanOptions {
  /** Ignored when `cursor` is set — the RPC rejects mixing the two. */
  startLedger?: number;
  endLedger?: number;
  /** Resume token from a previous scan's `cursor`. */
  cursor?: string;
  limit?: number;
  maxPages?: number;
  server?: rpc.Server;
}

/**
 * Read every contract event in a ledger range, following the RPC's cursor.
 *
 * This is the Soroban analogue of the EVM `paginatedGetLogs`, but the paging
 * model is genuinely different and the difference matters:
 *
 *  - EVM `eth_getLogs` is addressed by `fromBlock`/`toBlock`, so a scan can be
 *    split into independent chunks and fetched CONCURRENTLY. Soroban's
 *    `getEvents` returns an opaque `cursor` that has to be fed into the next
 *    request, so the walk is inherently SEQUENTIAL. There is no chunk fan-out to
 *    tune here, and a `concurrency` knob would be a lie.
 *  - `startLedger`/`endLedger` and `cursor` are mutually exclusive in the
 *    request type; passing both is rejected.
 *  - Soroban RPC only retains a rolling window of events (~120_960 ledgers, about
 *    a week, on Testnet). A `startLedger` below the retained `oldestLedger` is an
 *    error, not an empty result, so the floor is clamped from `getHealth()` before
 *    the first request. This is why the deploy ledger cannot be used blindly as a
 *    floor and why durable history needs the indexer, not this function.
 *  - **An EMPTY PAGE DOES NOT MEAN THE SCAN IS DONE.** This is the trap. One
 *    request scans at most {@link LEDGERS_PER_EVENT_PAGE} ledgers and returns
 *    whatever it found there — frequently nothing — together with a cursor to
 *    carry on from. Terminating on a short or empty page (the natural instinct,
 *    and correct for `eth_getLogs`) silently returns zero events for any contract
 *    whose activity is more than 10_000 ledgers past the scan floor. Verified
 *    against Testnet: scanning the market contract from `oldestLedger` yields 12
 *    consecutive empty pages before the page that holds all 11 of its events.
 *
 * So the walk terminates on the CURSOR, not on the payload: when the cursor stops
 * advancing, when it reaches the end of the requested range, or when it runs out.
 */
export async function paginatedGetEvents(
  filters: rpc.Api.EventFilter[],
  opts: StellarEventScanOptions = {},
): Promise<StellarEventScan> {
  const server = opts.server ?? createSorobanRpcServer();
  const limit = Math.max(1, opts.limit ?? STELLAR_EVENT_PAGE_LIMIT);
  const maxPages = Math.max(1, opts.maxPages ?? STELLAR_EVENT_MAX_PAGES);

  const health = await server.getHealth();
  const oldestLedger = health.oldestLedger;

  const events: rpc.Api.EventResponse[] = [];
  let cursor: string | undefined = opts.cursor;
  let previousCursor = "";
  let latestLedger = health.latestLedger;
  let truncated = false;
  let page = 0;

  for (;;) {
    if (page >= maxPages) {
      truncated = true;
      break;
    }
    page += 1;

    // The two request shapes are a discriminated union on `cursor`, so they are
    // built separately rather than spread into one object.
    const response: rpc.Api.GetEventsResponse = cursor
      ? await server.getEvents({ filters, cursor, limit })
      : await server.getEvents({
          filters,
          startLedger: Math.max(opts.startLedger ?? getDeployLedger(), oldestLedger),
          ...(opts.endLedger !== undefined ? { endLedger: opts.endLedger } : {}),
          limit,
        });

    events.push(...response.events);
    latestLedger = response.latestLedger;

    const nextCursor = response.cursor || "";
    // Out of cursor, or the server stopped moving: nothing left to read.
    if (!nextCursor || nextCursor === previousCursor) {
      cursor = undefined;
      break;
    }

    // The cursor's ledger says how far the scan actually got. Past the end of the
    // requested range — the caller's `endLedger`, or the chain tip — and there is
    // no more to ask for.
    const reached = eventCursorLedger(nextCursor);
    const endLedger = opts.endLedger ?? latestLedger;
    if (reached !== null && reached >= endLedger) {
      cursor = undefined;
      break;
    }

    previousCursor = nextCursor;
    cursor = nextCursor;
  }

  return {
    events,
    cursor: truncated ? (cursor ?? null) : null,
    latestLedger,
    oldestLedger,
    truncated,
  };
}

/** Convenience wrapper: contract events for one contract id. */
export function getContractEvents(
  contractId: string,
  opts: StellarEventScanOptions & { topics?: string[][] } = {},
): Promise<StellarEventScan> {
  const { topics, ...scan } = opts;
  return paginatedGetEvents(
    [{ type: "contract", contractIds: [contractId], ...(topics ? { topics } : {}) }],
    scan,
  );
}

// ── Fee unit helpers (native XLM, 7 decimals) ─────────────────────────────────

/** 1 XLM in stroops. Stellar's native asset has 7 decimals, not 18. */
export const STROOPS_PER_XLM = 10_000_000n;

export function stroopsToXlm(stroops: bigint | number | string): number {
  return Number(BigInt(stroops)) / Number(STROOPS_PER_XLM);
}

export function formatXlmAmount(stroops: bigint | number | string, decimals = 5): string {
  return `${stroopsToXlm(stroops).toFixed(decimals)} XLM`;
}
