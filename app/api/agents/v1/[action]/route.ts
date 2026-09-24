import { randomUUID } from "node:crypto";
import { verifyAgentSignature } from "@/lib/agents/signature";
import { isStellarAccount } from "@/lib/stellar-message";
import { getUserVSDirect } from "@/lib/contract";
import {
  NETWORK_PASSPHRASE,
  STELLAR_NETWORK,
  getMarketContractId,
  isContractAddress,
  isMarketConfigured,
} from "@/lib/stellar";
import { publishReasoning } from "@/lib/reasoning/publish";
import {
  AGENT_API_ACTIONS, AGENT_API_VERSION, MAX_SIGNED_REQUEST_PAYLOAD_BYTES,
  agentRequestMessage, validateAgentRequestEnvelope,
  type AgentApiAction, type SignedAgentRequest,
} from "@/lib/agents/api";
import { authenticateAgentRequest, requiresOwnerSignature } from "@/lib/agents/authenticate";
import {
  apiKeyPrefix, generateApiKey, hashApiKey, type AgentApiKeyRecord,
} from "@/lib/agents/api-keys";
import {
  configuredSpender, currentPeriodStart, evaluateSpend, parseSpendPermissionGrant,
  type SpendPermissionGrant,
} from "@/lib/agents/spend-permissions";
import {
  getActiveSpendPermission, getSpentInPeriod, insertAgentApiKey, listAgentApiKeys,
  revokeAgentApiKey, revokeSpendPermission, upsertSpendPermission,
} from "@/lib/db";
import {
  AUTHORITY_LEVELS, REGISTRY_SCHEMA_VERSION, authorizeAction, defaultLimits,
  evaluateRegistrationReplay, revokeAgent, type AgentRecord, type AgentCapability,
} from "@/lib/agents/registry";
import { auditAgentRequest, loadAgent, loadIdempotentResponse, saveAgent, saveIdempotentResponse } from "@/lib/agents/store";
import { rejectReplayedSignedEnvelope } from "@/lib/agents/envelope-replay";
import { buildAgentDryRun } from "@/lib/agents/dry-run";
import { isFeatureEnabled, checkWriteAllowed, type Pausable } from "@/lib/ops/flags";
import { getUsdcBalanceUnits, usdcToUnits, parseUsdcAtomic } from "@/lib/usdc";
import { getAgentEarningsSummary } from "@/lib/db";
import { gateOrPause, pausedCapabilityError, getCapabilityPauseDetail } from "@/lib/server/pause-registry";
import { apiError } from "@/lib/api/errors";

export const dynamic = "force-dynamic";

/**
 * Wallet identities an agent record can carry.
 *
 * Stellar only now: `G…` for an account, `C…` for a contract account. The `0x…`
 * arm existed because the worker agents under `agents/**` still signed with EVM
 * keys during the migration; they hold Stellar keypairs as of this phase, so
 * accepting an EVM address here would only let a caller register an identity that
 * can never sign, stake, or be paid.
 *
 * Nothing below normalises case. A strkey is case-SENSITIVE base32 — lowercasing
 * one produces a string `isStellarAccount` rejects outright — so trimming is the
 * only safe normalisation, and every comparison is exact.
 */
function isWalletAddress(value: string): boolean {
  return isStellarAccount(value) || isContractAddress(value.trim());
}

/** Trim only: a Stellar strkey has no case-normalised form. */
function normalizeWallet(value: string): string {
  return value.trim();
}

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "cache-control": "no-store" } });
}

/** Convert a structured ApiErrorResult from lib/api/errors into a Response. */
function errorResponse(err: import("@/lib/api/errors").ApiErrorResult): Response {
  return Response.json(err.body, { status: err.status, headers: { ...err.headers, "cache-control": "no-store" } });
}

async function verify(address: string, message: string, signature: string): Promise<boolean> {
  return verifyAgentSignature({ address, message, signature });
}

async function audit(request: SignedAgentRequest, outcome: string, reason?: string) {
  await auditAgentRequest({
    requestId: randomUUID(), agentId: request.agentId, action: request.action,
    idempotencyKey: request.idempotencyKey, signedAt: request.signedAt,
    nonce: request.nonce, outcome, reason, createdAt: Date.now(),
  });
}

/**
 * Actions that put an owner's USDC at risk. Gated on byoa_funded_actions so the
 * launch-gate document and the code agree: until an operator enables it, an agent
 * can register, read and dry-run but cannot move money.
 */
const FUNDED_ACTIONS: readonly AgentApiAction[] = ["createMarket", "stake", "vote"];

async function register(request: SignedAgentRequest<Record<string, any>>): Promise<Response> {
  // Pause check first: "registration is paused" is more accurate than "not enabled"
  // when the feature is on but the capability is temporarily stopped.
  const pauseErr = gateOrPause({ feature: "byoa_registry", capability: "agent_registration" });
  if (pauseErr) return errorResponse(pauseErr);

  if (!isFeatureEnabled("byoa_registry")) {
    return json({ error: { message: "agent registration is not enabled" } }, 403);
  }
  const body = request.body;
  const owner = normalizeWallet(String(body.ownerWallet ?? ""));
  const operator = normalizeWallet(String(body.operatorWallet ?? ""));
  if (!isWalletAddress(owner) || !isWalletAddress(operator)) {
    return json({ error: { message: "invalid owner/operator wallet" } }, 400);
  }
  // The outer request is the owner's explicit grant over the exact record body.
  if (!(await verify(owner, agentRequestMessage(request), request.signature))) {
    return json({ error: { message: "owner signature rejected" } }, 401);
  }
  const operatorProofMessage = `Mimir agent operator proof\nagent: ${request.agentId}\noperator: ${operator}`;
  if (!(await verify(operator, operatorProofMessage, String(body.operatorSignature ?? "")))) {
    return json({ error: { message: "operator signature rejected" } }, 401);
  }

  // Safe client retries: same idempotency key returns the prior accepted body.
  if (request.idempotencyKey) {
    const prior = await loadIdempotentResponse(request.agentId, "register", request.idempotencyKey);
    if (prior) return json(prior.body, prior.status);
  }

  const payoutWallet = isWalletAddress(normalizeWallet(String(body.payoutWallet ?? "")))
    ? normalizeWallet(String(body.payoutWallet)) : owner;

  // Duplicate register with the same wallets is success, not conflict — check
  // identity BEFORE consuming the nonce so a retry of a successful admission is
  // not rejected as "nonce replay".
  const existing = await loadAgent(request.agentId);
  if (existing) {
    const replay = evaluateRegistrationReplay(existing, {
      ownerWallet: owner, operatorWallet: operator, payoutWallet,
    });
    if (replay.ok) {
      const payload = { agent: existing };
      if (request.idempotencyKey) {
        await saveIdempotentResponse(request.agentId, "register", request.idempotencyKey, payload, 200);
      }
      await audit(request, "registered_idempotent");
      return json(payload);
    }
    await audit(request, "rejected", replay.reason);
    return json({
      error: {
        message: "agent already registered",
        reason: replay.reason,
        detail: "a different owner, operator, or payout wallet claimed this agentId",
      },
    }, 409);
  }

  const registerReplay = await rejectReplayedSignedEnvelope({
    agentId: request.agentId,
    nonce: request.nonce,
    signedAt: request.signedAt,
  });
  if (registerReplay) {
    await audit(request, "rejected", "nonce_replay");
    return errorResponse(registerReplay);
  }
  const now = Date.now();
  const authority = Math.max(0, Math.min(4, Math.floor(Number(body.authorityLevel ?? 0)))) as AgentRecord["authorityLevel"];
  const requestedCapabilities = Array.isArray(body.capabilities) ? body.capabilities : [];
  const capabilities = requestedCapabilities.filter((c: unknown): c is AgentCapability =>
    typeof c === "string" && ["market_creator", "council_juror", "researcher", "copy_source", "x402_seller"].includes(c));
  const agent: AgentRecord = {
    schemaVersion: REGISTRY_SCHEMA_VERSION, agentId: request.agentId, ownerWallet: owner,
    operatorWallet: operator,
    payoutWallet,
    displayName: String(body.displayName ?? request.agentId).slice(0, 80),
    description: String(body.description ?? "").slice(0, 500),
    metadataUri: body.metadataUri ? String(body.metadataUri) : undefined,
    metadataHash: body.metadataHash ? String(body.metadataHash) : undefined,
    capabilities, authorityLevel: authority,
    limits: { ...defaultLimits(), ...(body.limits ?? {}) }, status: "active",
    reputationBps: 0, createdAt: now, updatedAt: now,
  };
  // Capabilities above the owner-granted level are dropped, never silently usable.
  agent.capabilities = agent.capabilities.filter((capability) =>
    authorizeAction(agent, { capability, positionUsdc: 0 }).allowed ||
    (capability === "market_creator" && authority >= AUTHORITY_LEVELS.PROPOSE));
  await saveAgent(agent);
  const payload = { agent };
  if (request.idempotencyKey) {
    await saveIdempotentResponse(request.agentId, "register", request.idempotencyKey, payload, 200);
  }
  await audit(request, "registered");
  return json(payload);
}

function clientIp(req: Request): string | undefined {
  const forwarded = req.headers.get("x-forwarded-for");
  return forwarded?.split(",")[0]?.trim() || req.headers.get("x-real-ip") || undefined;
}

export async function POST(req: Request, context: { params: Promise<{ action: string }> }): Promise<Response> {
  const { action: rawAction } = await context.params;
  if (!(AGENT_API_ACTIONS as readonly string[]).includes(rawAction)) return json({ error: { message: "unknown action" } }, 404);
  const action = rawAction as AgentApiAction;
  // Cap before parse: Content-Length is a cheap fail-closed gate; the body byte
  // check below still applies when the header is absent or wrong.
  const declared = Number(req.headers.get("content-length") ?? NaN);
  if (Number.isFinite(declared) && declared > MAX_SIGNED_REQUEST_PAYLOAD_BYTES) {
    return json({
      error: { message: `payload exceeds ${MAX_SIGNED_REQUEST_PAYLOAD_BYTES} bytes` },
    }, 413);
  }
  let raw: string;
  try { raw = await req.text(); }
  catch { return json({ error: { message: "invalid body" } }, 400); }
  if (new TextEncoder().encode(raw).length > MAX_SIGNED_REQUEST_PAYLOAD_BYTES) {
    return json({
      error: { message: `payload exceeds ${MAX_SIGNED_REQUEST_PAYLOAD_BYTES} bytes` },
    }, 413);
  }
  let request: SignedAgentRequest;
  try { request = JSON.parse(raw) as SignedAgentRequest; }
  catch { return json({ error: { message: "invalid JSON" } }, 400); }

  // An API-key caller writes plain HTTP: `{ "body": {...} }` with the action in the
  // path. Everything the signed envelope carries for its own sake — version, nonce,
  // timestamp — is filled in here rather than demanded of them.
  const auth = await authenticateAgentRequest({
    action,
    authorization: req.headers.get("authorization"),
    ip: clientIp(req),
    claimedAgentId: typeof request.agentId === "string" && request.agentId ? request.agentId : undefined,
  });
  if (auth.error) return Response.json(auth.error.body, { status: auth.error.status, headers: { ...auth.error.headers, "cache-control": "no-store" } });
  const viaApiKey = auth.auth?.kind === "api_key";

  if (viaApiKey && auth.auth?.kind === "api_key") {
    request = {
      ...request,
      version: AGENT_API_VERSION,
      action,
      agentId: auth.auth.agentId,
      idempotencyKey: request.idempotencyKey || randomUUID(),
      nonce: request.nonce || randomUUID(),
      signedAt: Date.now(),
      // Placeholder for the API-key path, where the envelope is not the
      // credential and `validateAgentRequestEnvelope` is told not to require a
      // signature. Base64-shaped rather than `0x`-shaped so it cannot be mistaken
      // for a real Ed25519 signature in an audit row.
      signature: request.signature ?? "",
      body: request.body ?? {},
    };
  }

  if (request.action !== action) return json({ error: { message: "action/path mismatch" } }, 400);
  const envelopeErrors = validateAgentRequestEnvelope(request, Date.now(), { requireSignature: !viaApiKey });
  if (envelopeErrors.length) return json({ error: { message: envelopeErrors.join("; ") } }, 400);
  if (action === "register") return register(request as SignedAgentRequest<Record<string, any>>);

  const agent = await loadAgent(request.agentId);
  if (!agent) return json({ error: { message: "agent not found" } }, 404);
  if (!viaApiKey) {
    const signer = requiresOwnerSignature(action) ? agent.ownerWallet : agent.operatorWallet;
    if (!(await verify(signer, agentRequestMessage(request), request.signature))) {
      await audit(request, "rejected", "signature");
      return json({ error: { message: "signature rejected" } }, 401);
    }
  }
  // A revoked agent keeps read access to its own records but does nothing else;
  // that is what makes revoke a usable emergency stop rather than a data loss.
  if (agent.status === "revoked" && !["heartbeat", "listPositions", "listEarnings", "listKeys", "spendStatus"].includes(action)) {
    await audit(request, "rejected", "agent_revoked");
    return json({ error: { message: "agent is revoked" } }, 403);
  }
  if (FUNDED_ACTIONS.includes(action) && !isFeatureEnabled("byoa_funded_actions")) {
    await audit(request, "rejected", "feature_disabled");
    return json({
      error: {
        message: "byoa funded actions are not enabled",
        detail: "dryRun and proposeMarket work meanwhile; they move no money.",
      },
    }, 403);
  }
  const prior = await loadIdempotentResponse(agent.agentId, action, request.idempotencyKey);
  if (prior) return json(prior.body, prior.status);
  const replayed = await rejectReplayedSignedEnvelope({
    agentId: agent.agentId,
    nonce: request.nonce,
    signedAt: request.signedAt,
  });
  if (replayed) {
    await audit(request, "rejected", "nonce_replay");
    return errorResponse(replayed);
  }

  const body = (request.body ?? {}) as Record<string, any>;
  let result: unknown;
  if (action === "issueKey") {
    // Returned once. There is no endpoint that can show it again, which is the
    // point: a key readable from the API is a key readable from a stolen session.
    const key = generateApiKey(body.environment === "test" ? "test" : "live");
    const record: AgentApiKeyRecord = {
      keyId: randomUUID(), agentId: agent.agentId, keyHash: hashApiKey(key),
      keyPrefix: apiKeyPrefix(key), label: String(body.label ?? "").slice(0, 80),
      createdAt: Date.now(),
    };
    await insertAgentApiKey(record);
    result = {
      apiKey: key, keyId: record.keyId, prefix: record.keyPrefix, label: record.label,
      note: "Store this now — it is not recoverable.",
      usage: `Authorization: Bearer ${record.keyPrefix}...`,
    };
  } else if (action === "listKeys") {
    const keys = await listAgentApiKeys(agent.agentId);
    result = {
      keys: keys.map((k) => ({
        keyId: k.keyId, prefix: k.keyPrefix, label: k.label, createdAt: k.createdAt,
        lastUsedAt: k.lastUsedAt ?? null, revokedAt: k.revokedAt ?? null,
      })),
    };
  } else if (action === "revokeKey") {
    const keyId = String(body.keyId ?? "");
    if (!keyId) return json({ error: { message: "keyId is required" } }, 400);
    const revoked = await revokeAgentApiKey(agent.agentId, keyId, Date.now(), String(body.reason ?? "owner revoked"));
    if (!revoked) return json({ error: { message: "key not found or already revoked" } }, 404);
    result = { keyId, revoked: true };
  } else if (action === "grantSpend") {
    const parsed = parseSpendPermissionGrant({
      agentId: agent.agentId, grant: body as SpendPermissionGrant,
      spender: configuredSpender(), now: Date.now(),
    });
    if (!parsed.ok) return json({ error: { message: parsed.error } }, 400);
    // The owner's own account must be the source of funds; letting an agent point a
    // permission at a third party's account would make this a phishing endpoint.
    // EXACT comparison — see `normalizeWallet` above.
    if (parsed.record.account !== agent.ownerWallet.trim()) {
      return json({ error: { message: "permission account must be the agent owner wallet" } }, 403);
    }
    await upsertSpendPermission(parsed.record);
    result = {
      permissionHash: parsed.record.permissionHash,
      allowanceAtomic: parsed.record.allowanceAtomic.toString(),
      periodSeconds: parsed.record.periodSeconds,
      startAt: parsed.record.startAt, endAt: parsed.record.endAt,
    };
  } else if (action === "revokeSpend") {
    const hash = String(body.permissionHash ?? "");
    if (!hash) return json({ error: { message: "permissionHash is required" } }, 400);
    const revoked = await revokeSpendPermission(agent.agentId, hash, Date.now(), String(body.reason ?? "owner revoked"));
    if (!revoked) return json({ error: { message: "permission not found or already revoked" } }, 404);
    // On-chain revocation is the owner's own call and outranks this record; this only
    // stops Mimir from drawing further.
    result = { permissionHash: hash, revoked: true, note: "Mimir will draw no further; revoke on chain to withdraw the grant itself." };
  } else if (action === "spendStatus") {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const permission = await getActiveSpendPermission(agent.agentId, nowSeconds);
    if (!permission) result = { funded: false, reason: "no active spend permission" };
    else {
      const periodStart = currentPeriodStart(permission, nowSeconds);
      const spent = await getSpentInPeriod(permission.permissionHash, periodStart);
      const decision = evaluateSpend({
        permission, spentThisPeriodAtomic: spent, amountAtomic: 0n,
        nowSeconds, spender: configuredSpender(),
      });
      result = {
        funded: true,
        permissionHash: permission.permissionHash,
        account: permission.account,
        allowanceAtomic: permission.allowanceAtomic.toString(),
        spentThisPeriodAtomic: spent.toString(),
        remainingAtomic: decision.remainingAtomic.toString(),
        periodStart, periodEndsAt: decision.periodEndsAt, endAt: permission.endAt,
        limits: agent.limits,
      };
    }
  } else if (action === "heartbeat") result = { agentId: agent.agentId, status: agent.status, at: Date.now() };
  else if (action === "listPositions") result = { positions: await getUserVSDirect(agent.operatorWallet) };
  else if (action === "listEarnings") {
    const earnings = await getAgentEarningsSummary(agent.payoutWallet).catch(() => ({ ownerFeesAtomic: 0n, unclaimedAtomic: 0n, x402Atomic: 0n }));
    result = { payoutWallet: agent.payoutWallet, ownerFeesAtomic: earnings.ownerFeesAtomic.toString(),
      unclaimedAtomic: earnings.unclaimedAtomic.toString(), x402Atomic: earnings.x402Atomic.toString() };
  }
  else if (action === "revoke") {
    // revoke is in OWNER_SIGNED_ACTIONS, so reaching here means the owner's own
    // signature verified above — an API key is refused before this point.
    const revoked = revokeAgent(agent, { requestedBy: agent.ownerWallet, reason: String(body.reason ?? "owner revoked") });
    if (!revoked.ok) return json({ error: { message: revoked.reason } }, 403);
    await saveAgent(revoked.agent); result = { agent: revoked.agent };
  } else if (action === "publishReasoning") {
    const gate = authorizeAction(agent, { capability: "researcher", requestsThisHour: Number(body.requestsThisHour ?? 0) });
    if (!gate.allowed) {
      await audit(request, "rejected", gate.reason);
      return errorResponse(actionVerdictToError(gate, "researcher"));
    }
    result = await publishReasoning({ ...(body as any), agentId: agent.agentId });
  } else {
    const capability: AgentCapability = action === "proposeMarket" || action === "createMarket" || action === "dryRun"
      ? "market_creator" : "council_juror";
    const proposalOnly = action === "proposeMarket";
    const gate = authorizeAction(agent, {
      capability, category: body.category, settlementMode: body.settlementMode,
      positionAtomic: parseUsdcAtomic(String(body.positionUsdc ?? body.stakeUsdc ?? 0)).toString(),
      exposureTodayAtomic: parseUsdcAtomic(String(body.exposureTodayUsdc ?? 0)).toString(),
      activeMarkets: Number(body.activeMarkets ?? 0), requestsThisHour: Number(body.requestsThisHour ?? 0),
      proposalOnly,
    } as any);
    if (!gate.allowed) return json({ error: { message: gate.reason, detail: gate.detail } }, 403);
    if (action === "dryRun") {
      // ── What "allowance" means now ──────────────────────────────────────────
      // The EVM version read the ERC-20 allowance the agent had granted the
      // market contract, because a stake could not land without one. Soroban has
      // no standing allowance on this path: `challenge_claim` carries auth for
      // exactly the staked amount, so there is nothing to pre-approve and an
      // allowance read would always be zero and always look like a blocker.
      //
      // The question the dry run is actually asking — "would this stake go
      // through?" — is now answered by the agent's own USDC BALANCE, so that is
      // what is reported. Null (no trustline) is deliberately surfaced as zero:
      // an account with no trustline genuinely cannot stake.
      let spendable = 0n;
      if (isMarketConfigured()) {
        try {
          spendable = (await getUsdcBalanceUnits(agent.operatorWallet)) ?? 0n;
        } catch { /* report zero; dry-run stays safe */ }
      }
      result = buildAgentDryRun({
        principalUsdc: Number(body.principalUsdc ?? body.stakeUsdc ?? 0),
        grossPayoutUsdc: Number(body.grossPayoutUsdc ?? body.stakeUsdc ?? 0),
        outcome: body.outcome ?? "creator_wins", allowanceAtomic: spendable,
        requiredAtomic: usdcToUnits(Number(body.stakeUsdc ?? body.positionUsdc ?? 0)),
        platformFeeBps: Number(body.platformFeeBps ?? 0),
        agentOwnerFeeBps: Number(body.agentOwnerFeeBps ?? 0),
        platformRecipient: String(body.platformRecipient ?? agent.ownerWallet),
        ownerRecipient: agent.payoutWallet, policy: gate,
      });
    } else result = action === "proposeMarket"
      ? { disposition: "review", proposal: body, moderationRequired: true }
      : {
          allowed: true, simulated: false, contract: getMarketContractId(),
          // Stellar has no numeric chain id. The network passphrase is the
          // equivalent domain separator — it is what every Stellar signature is
          // bound to at the protocol level — so it is what a caller needs in order
          // to build a transaction this deployment will accept. The short name is
          // sent alongside it because that is the readable half.
          network: STELLAR_NETWORK,
          networkPassphrase: NETWORK_PASSPHRASE,
          requiresExternalWalletSignature: true,
          contractConfigured: isMarketConfigured(),
          // The contract freezes the fee recipient onto the claim at creation, so a
          // market opened without one can never pay this agent's owner — however
          // the policy changes later. Handed back explicitly so a caller cannot omit
          // it by accident and silently forfeit its own revenue.
          agentOwnerRecipient: agent.payoutWallet,
          feeNote: `Pass agent_owner_recipient=${agent.payoutWallet} in CreateParams to earn the agent-owner fee on this market.`,
          preview: { positionUsdc: Number(body.positionUsdc ?? body.stakeUsdc ?? 0) },
        };
  }
  await audit(request, "accepted");
  await saveIdempotentResponse(agent.agentId, action, request.idempotencyKey, result);
  return json(result);
}
