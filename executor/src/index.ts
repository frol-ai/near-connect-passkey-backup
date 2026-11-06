import type { Client } from "near-api-ts";
import { createClient, isNatError } from "near-api-ts";
import { sha256 } from "@noble/hashes/sha2.js";
import { base64 } from "@scure/base";

import { BorshWriter } from "./borsh";
import { CHAIN_ID, DEFAULT_PASSKEY_LABEL, DEFAULT_RPC_URLS } from "./constants";
import { buildAuthorizationBlob, buildOffchainMessage } from "./authEnvelope";
import { registryGet, registryRegister } from "./registry";
import { buildSignedDelegateAction, relayExecuteSigned, relayStateInit } from "./relayer";
import type { PasskeyPublicKey } from "./stateInit";
import {
  deriveAccountId,
  publicKeyFromString,
  publicKeyToString,
  serializeDefaultStateInit,
} from "./stateInit";
import * as storage from "./storage";
import type {
  Account,
  AccountWithSignedMessage,
  ActiveCredential,
  ConnectorAction,
  FinalExecutionOutcome,
  ResolveAuthParams,
  ResolveAuthResponse,
  SignAndSendTransactionParams,
  SignAndSendTransactionsParams,
  SignDelegateActionsParams,
  SignDelegateActionsResponse,
  SignInAndSignMessageParams,
  SignInParams,
  SignMessageParams,
  SignedMessage,
  WebauthnCreateResult,
  WebauthnGetResult,
} from "./types";
import { selector } from "./types";
import * as ui from "./ui";
import type { RequestJson, RequestMessageJson } from "./walletContract";
import {
  buildRequestMessage,
  connectorActionsToPromises,
  requestMessageHash,
} from "./walletContract";
import {
  authenticatorUserVerified,
  b64ToRawId,
  buildProof,
  decodeCbor,
  extractCredentialPublicKey,
  rawIdToB64,
  verifyAssertion,
} from "./webauthn";
import { ceremonyWasBlocked, webauthnCeremonyError } from "./errors";
import { t } from "./i18n";
import { offchainMessageHash } from "./walletContract";

// ─── Environment ─────────────────────────────────────────────────────────────

let cachedClient: Client | null = null;

function rpcUrls(): string[] {
  // dApps often construct NearConnector without custom `providers`, in
  // which case the sandbox injects an EMPTY list — fall back to defaults.
  const urls = selector().providers.mainnet;
  return urls && urls.length > 0 ? urls : [...DEFAULT_RPC_URLS];
}

function rpcUrl(): string {
  const url = rpcUrls()[0];
  if (!url) throw new Error("no mainnet RPC provider configured");
  return url;
}

function getClient(): Client {
  if (!cachedClient) {
    cachedClient = createClient({
      transport: {
        rpcEndpoints: { regular: rpcUrls().map((url) => ({ url })) },
      },
    });
  }
  return cachedClient;
}

function assertMainnet(network?: string): void {
  if (network && network !== CHAIN_ID) {
    throw new Error("Passkey wallet supports mainnet only");
  }
}

async function accountExists(client: Client, accountId: string): Promise<boolean> {
  const info = await client.safeGetAccountInfo({ accountId });
  if (info.success) return true;
  if (isNatError(info.error, "Client.GetAccountInfo.Rpc.Account.NotFound")) return false;
  throw info.error;
}

// ─── WebAuthn ceremonies ─────────────────────────────────────────────────────

function randomBytes(length: number): number[] {
  return Array.from(crypto.getRandomValues(new Uint8Array(length)));
}

// ─── TEMPORARY UV diagnostics ────────────────────────────────────────────────
// Capture the WebAuthn authenticatorData flags, the rpIdHash, and the
// clientDataJSON origin/crossOrigin + browser, to tell WHY Windows/Edge returns
// UV=0 for our ceremony while a direct same-origin get (passkeys-debugger.io)
// returns UV=1 for the same platform/synced credential. Prime suspects: the
// ceremony running cross-origin through the near-connect relay, or an rpId
// mismatch. authenticatorData layout: rpIdHash(32) then flags(1) at index 32 —
// bit0 UP, bit2 UV, bit3 BE, bit4 BS. Remove once diagnosed.
function toHex(bytes: number[]): string {
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
}

function uvDebug(authenticatorData: number[], clientDataJSON: number[], path: string): string {
  const flags = authenticatorData[32] ?? 0;
  const bit = (m: number) => (flags & m ? 1 : 0);
  let origin = "?";
  let crossOrigin: unknown = "?";
  try {
    const cd = JSON.parse(new TextDecoder().decode(new Uint8Array(clientDataJSON)));
    origin = cd.origin;
    crossOrigin = cd.crossOrigin;
  } catch {
    // ignore — diagnostics only
  }
  const info = {
    flags: `0x${flags.toString(16).padStart(2, "0")}`,
    UP: bit(0x01),
    UV: bit(0x04),
    BE: bit(0x08),
    BS: bit(0x10),
    path,
    origin,
    crossOrigin,
    rpIdHash: toHex(authenticatorData.slice(0, 32)),
    ua: typeof navigator !== "undefined" ? navigator.userAgent : "",
  };
  // eslint-disable-next-line no-console
  console.warn("[passkey-uv-debug]", info);
  return (
    `flags=${info.flags} UP=${info.UP} UV=${info.UV} BE=${info.BE} BS=${info.BS} ` +
    `path=${path} origin=${origin} crossOrigin=${String(crossOrigin)} ` +
    `rpIdHash=${info.rpIdHash.slice(0, 16)}… ua=${info.ua}`
  );
}

/** Best-effort flags from a create() attestation, for create-vs-get comparison. */
function createUvDebug(created: WebauthnCreateResult): void {
  try {
    const att = decodeCbor(new Uint8Array(created.attestationObject));
    const authData = att instanceof Map ? att.get("authData") : undefined;
    if (authData instanceof Uint8Array) {
      uvDebug(Array.from(authData), created.clientDataJSON, "create");
    }
  } catch {
    // diagnostics only — never let this affect the create flow
  }
}

async function webauthnCreate(name: string): Promise<WebauthnCreateResult> {
  // Resident key + user verification are BOTH required:
  // - resident (discoverable): the credential must be recoverable by
  //   discovery on any origin the passkey syncs to; a non-resident key would
  //   be permanently unreachable (no rawId to hand to allowCredentials).
  // - userVerification: a wallet must never sign on mere presence (a bare
  //   security-key touch); require biometric / PIN / screen lock.
  //
  // No `excludeCredentials`: the wallet intentionally supports MULTIPLE
  // accounts per device (each additional one is a deliberate, labelled
  // sign-up — see createNewPasskey). Excluding existing credentials would make
  // the authenticator reject every additional account with InvalidStateError.
  let result: WebauthnCreateResult;
  try {
    result = await selector().webauthn.create({
      challenge: randomBytes(32),
      rp: { name },
      user: { id: randomBytes(16), name, displayName: name },
      pubKeyCredParams: [
        { alg: -8, type: "public-key" }, // EdDSA (Ed25519)
        { alg: -7, type: "public-key" }, // ES256 (P-256)
      ],
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true, // legacy L1 field; some browsers honor only this
        userVerification: "required",
      },
      extensions: { credProps: true },
      attestation: "none",
    });
  } catch (e) {
    throw webauthnCeremonyError(e, "create");
  }

  createUvDebug(result); // TEMPORARY: log create flags for create-vs-get comparison

  // If the browser reports credProps, insist the key is actually resident —
  // a non-resident key would leave the account unrecoverable.
  if (result.clientExtensionResults?.credProps?.rk === false) {
    throw new Error(t("errNonResident"));
  }
  return result;
}

/** One WebAuthn assertion. `rawIdB64` set = targeted; unset = discovery. */
async function rawWebauthnGet(
  challenge: Uint8Array,
  rawIdB64: string | undefined,
  path: string,
): Promise<{ result: WebauthnGetResult; debug: string }> {
  const options: Record<string, unknown> = {
    challenge: Array.from(challenge),
    // A wallet signature must always verify the user, never presence-only.
    userVerification: "required",
  };
  if (rawIdB64) {
    options["allowCredentials"] = [
      { id: b64ToRawId(rawIdB64), type: "public-key" },
    ];
  }
  let result: WebauthnGetResult;
  try {
    result = await selector().webauthn.get(options);
  } catch (e) {
    throw webauthnCeremonyError(e, "get");
  }
  // TEMPORARY: capture the assertion flags + browser (UV-on-Windows/Edge).
  const debug = uvDebug(result.authenticatorData, result.clientDataJSON, path);
  return { result, debug };
}

/**
 * Desktop Edge (UA token `Edg/`; NOT Android `EdgA/` / iOS `EdgiOS/`, whose
 * providers behave normally). Edge's Microsoft Password Manager passkey
 * provider performs the biometric on a *targeted* get but returns UV=0 (a
 * provider bug); only a *discovery* get sets UV correctly there.
 */
function isDesktopEdge(): boolean {
  return typeof navigator !== "undefined" && /\bEdg\//.test(navigator.userAgent);
}

/**
 * Get a user-verified assertion.
 *
 * When the credential is known we normally do a *targeted* get
 * (`allowCredentials`), which goes straight to the biometric on platforms that
 * verify (Apple / Android / Windows Hello TPM). Two exceptions push us to a
 * *discovery* get (no `allowCredentials`, which forces the OS account chooser +
 * verification and reliably sets UV):
 *   - On desktop Edge we go discovery FIRST, because a targeted get there runs
 *     the biometric but returns UV=0 — trying targeted first would prompt the
 *     biometric twice (targeted, then the discovery retry).
 *   - On any other platform, if the targeted assertion comes back
 *     user-presence-only, we retry once via discovery as a fallback.
 * Whenever discovery is used for a known credential, the credential the user
 * picks must match the intended one.
 */
async function webauthnGet(
  challenge: Uint8Array,
  rawIdB64?: string,
): Promise<WebauthnGetResult> {
  // Targeted first, EXCEPT on desktop Edge with a known credential (discovery
  // first there to avoid the double biometric).
  const firstTargeted = rawIdB64 != null && !isDesktopEdge();

  let { result, debug } = await rawWebauthnGet(
    challenge,
    firstTargeted ? rawIdB64 : undefined,
    firstTargeted ? "targeted" : rawIdB64 != null ? "edge-discovery" : "discovery",
  );

  // If we ran discovery for a specific account, the user may have picked a
  // different passkey — require a match.
  if (!firstTargeted && rawIdB64 != null && rawIdToB64(result.rawId) !== rawIdB64) {
    throw new Error(t("errWrongPasskey"));
  }
  if (authenticatorUserVerified(new Uint8Array(result.authenticatorData))) {
    return result;
  }

  // Targeted assertion came back user-presence-only on a non-Edge provider.
  // Retry once via discovery, then require the credential to match.
  if (firstTargeted) {
    ({ result, debug } = await rawWebauthnGet(challenge, undefined, "discovery-retry"));
    if (rawIdToB64(result.rawId) !== rawIdB64) {
      throw new Error(t("errWrongPasskey"));
    }
    if (authenticatorUserVerified(new Uint8Array(result.authenticatorData))) {
      return result;
    }
  }

  throw new Error(`${t("errNotVerified")} [debug ${debug}]`);
}

/**
 * `webauthnGet` for the SECOND ceremony of a two-step sign-in: start it right
 * away (no extra tap — the user already acted), and only if the browser
 * refuses it outright show `tapScreen` (a one-button confirm) and retry from
 * that tap. See UX_DECISIONS.md §3b.
 */
async function webauthnGetWithTapFallback(
  challenge: Uint8Array,
  rawIdB64: string,
  tapScreen: () => Promise<void>,
): Promise<WebauthnGetResult> {
  const startedAt = Date.now();
  try {
    return await webauthnGet(challenge, rawIdB64);
  } catch (e) {
    if (!ceremonyWasBlocked(e, Date.now() - startedAt)) throw e;
  }
  await tapScreen();
  return webauthnGet(challenge, rawIdB64);
}

// ─── Credential resolution ───────────────────────────────────────────────────

interface ResolvedCredential {
  rawIdB64: string;
  publicKey: PasskeyPublicKey;
  accountId: string;
}

/**
 * Map an assertion's rawId to its verified public key: local cache first,
 * registry on miss; every candidate is verified against the assertion
 * signature — only the credential's true key is accepted.
 */
async function resolveCredential(assertion: WebauthnGetResult): Promise<ResolvedCredential> {
  const rawIdB64 = rawIdToB64(assertion.rawId);

  const known = await storage.getKnownCredentials();
  const cached = known[rawIdB64];
  const candidates: string[] = cached ? [cached.publicKey] : [];

  if (candidates.length === 0) {
    candidates.push(...(await registryGet(getClient(), rawIdB64)));
  }

  for (const candidate of candidates) {
    let publicKey: PasskeyPublicKey;
    try {
      publicKey = publicKeyFromString(candidate);
    } catch {
      continue;
    }
    if (verifyAssertion(publicKey, assertion)) {
      const accountId = deriveAccountId(publicKey);
      await storage.addKnownCredential(rawIdB64, {
        publicKey: candidate,
        curve: publicKey.curve,
        accountId,
      });
      return { rawIdB64, publicKey, accountId };
    }
  }

  throw new Error(t("errNotRegistered"));
}

function toActiveCredential(resolved: ResolvedCredential): ActiveCredential {
  return {
    rawId: resolved.rawIdB64,
    publicKey: publicKeyToString(resolved.publicKey),
    curve: resolved.publicKey.curve,
    accountId: resolved.accountId,
    registeredAt: Date.now(),
  };
}

function toAccount(active: ActiveCredential): Account {
  return { accountId: active.accountId, publicKey: active.publicKey };
}

// ─── Registration ────────────────────────────────────────────────────────────

/** Register with the on-chain registry; on hard failure offer Retry/Cancel. */
async function registerWithUi(rawIdB64: string, publicKey: string): Promise<void> {
  for (;;) {
    try {
      await registryRegister(getClient(), rawIdB64, publicKey);
      return;
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      const retry = await ui.promptRetryRegistration(message);
      if (!retry) {
        throw new Error(t("errRegistrationCancelled", { message }));
      }
      await ui.showProgress(t("registeringTitle"), t("registeringSubtitle"));
    }
  }
}

/** A pending registration must reach the registry before any new create(). */
async function retryPendingRegistration(): Promise<void> {
  const pending = await storage.getPendingRegistration();
  if (!pending) return;
  await registerWithUi(pending.rawIdB64, pending.publicKey);
  await storage.clearPendingRegistration();
  const publicKey = publicKeyFromString(pending.publicKey);
  await storage.addKnownCredential(pending.rawIdB64, {
    publicKey: pending.publicKey,
    curve: pending.curve,
    accountId: deriveAccountId(publicKey),
  });
}

async function createNewPasskey(ctx?: ui.StepContext): Promise<ActiveCredential> {
  // First account: no prompt at all — default the passkey label and go
  // straight to the device ceremony (Web2-familiar, zero friction). Only when
  // the user already has a passkey here (creating an ADDITIONAL account) do we
  // ask for a username/email label so the accounts stay distinguishable.
  const isFirstAccount = Object.keys(await storage.getKnownCredentials()).length === 0;
  const name = isFirstAccount ? DEFAULT_PASSKEY_LABEL : await ui.promptPasskeyLabel();
  await ui.showProgress(t("createPasskeyTitle"), t("createPasskeySubtitle"), "biometric", ctx);
  const created = await webauthnCreate(name);
  await ui.showProgress(t("registeringTitle"), t("registeringSubtitle"));

  // The passkey now exists in the user's device keychain. If we cannot read
  // its public key (an unsupported key type slipped through, or a malformed
  // attestation) it becomes an orphan — created but unusable by this wallet.
  // Tell the user in plain terms so they can remove the stray passkey.
  let publicKey;
  try {
    publicKey = extractCredentialPublicKey(created);
  } catch {
    throw new Error(t("errOrphan"));
  }
  const publicKeyStr = publicKeyToString(publicKey);
  const rawIdB64 = rawIdToB64(created.rawId);
  const accountId = deriveAccountId(publicKey);

  // Record the rawId -> publicKey mapping locally the MOMENT the credential
  // exists on this device — before the on-chain registration round-trip. Two
  // reasons:
  //  1. It is a local truth: we just extracted (and will use) this key; it is
  //     valid regardless of whether/when registration reaches the registry.
  //  2. It is the signal that makes the NEXT sign-up recognise this device
  //     already has an account and show the passkey-label prompt. Writing it
  //     only after registration meant a deferred/retried/cancelled
  //     registration left `passkey:known` empty, so additional sign-ups were
  //     mis-detected as the first and skipped the label screen.
  await storage.addKnownCredential(rawIdB64, {
    publicKey: publicKeyStr,
    curve: publicKey.curve,
    accountId,
    label: name,
  });

  // Persist the pending registration too, so an interrupted registration is
  // retried on the next signIn.
  await storage.setPendingRegistration({
    rawIdB64,
    publicKey: publicKeyStr,
    curve: publicKey.curve,
  });
  await registerWithUi(rawIdB64, publicKeyStr);
  await storage.clearPendingRegistration();

  const active: ActiveCredential = {
    rawId: rawIdB64,
    publicKey: publicKeyStr,
    curve: publicKey.curve,
    accountId,
    registeredAt: Date.now(),
  };
  await activate(active);
  return active;
}

/** Make `active` the signed-in credential and bump it in the known list. */
async function activate(active: ActiveCredential): Promise<void> {
  await storage.setActiveCredential(active);
  await storage.touchKnownCredential(active.rawId);
}

/** "Welcome back" rows for the entry dialog (UX_DECISIONS.md §3c). */
async function knownAccountOptions(): Promise<ui.KnownAccountOption[]> {
  return (await storage.listKnownCredentials()).map((c) => ({
    rawIdB64: c.rawIdB64,
    accountId: c.accountId,
    label: c.label ?? DEFAULT_PASSKEY_LABEL,
  }));
}

/** The active credential for a known account picked in the entry dialog. */
async function knownCredential(rawIdB64: string): Promise<ActiveCredential> {
  const known = (await storage.getKnownCredentials())[rawIdB64];
  if (!known) throw new Error(t("errNotRegistered"));
  return {
    rawId: rawIdB64,
    publicKey: known.publicKey,
    curve: known.curve,
    accountId: known.accountId,
    registeredAt: Date.now(),
  };
}

/**
 * Sign in with a known account: ONE targeted ceremony (no OS account chooser)
 * proves the user still holds the passkey, verified against the cached key.
 */
async function useKnownPasskey(
  rawIdB64: string,
  ctx?: ui.StepContext,
): Promise<ActiveCredential> {
  const candidate = await knownCredential(rawIdB64);
  await ui.showProgress(t("confirmSignInTitle"), t("confirmSignInSubtitle"), "biometric", {
    ...ctx,
    account: candidate.accountId,
  });
  const assertion = await webauthnGet(new Uint8Array(randomBytes(32)), rawIdB64);
  const active = toActiveCredential(await resolveCredential(assertion));
  await activate(active);
  return active;
}

async function useExistingPasskey(ctx?: ui.StepContext): Promise<ActiveCredential> {
  await ui.showProgress(t("usePasskeyTitle"), t("usePasskeySubtitle"), "biometric", ctx);
  const assertion = await webauthnGet(new Uint8Array(randomBytes(32)));
  await ui.showProgress(t("lookingUpTitle"), t("lookingUpSubtitle"));
  let resolved: ResolvedCredential;
  try {
    resolved = await resolveCredential(assertion);
  } catch (e) {
    await ui.showErrorDialog(
      t("passkeyNotRegisteredTitle"),
      e instanceof Error ? e.message : String(e),
    );
    throw e;
  }
  const active = toActiveCredential(resolved);
  await activate(active);
  return active;
}

// ─── Signing primitives ──────────────────────────────────────────────────────

async function requireActive(): Promise<ActiveCredential> {
  const active = await storage.getActiveCredential();
  if (!active) throw new Error(t("errNotSignedIn"));
  return active;
}

async function signRequestMessage(
  active: ActiveCredential,
  request: RequestJson,
): Promise<{ msg: RequestMessageJson; proof: string }> {
  const msg = buildRequestMessage(active.accountId, await storage.nextNonce(), request);
  // No confirm button: the ceremony's own OS prompt (Face ID / Hello / chooser)
  // is the confirmation, so go straight to it. The button never supplied user
  // activation to the ceremony anyway — the sandbox runs `credentials.get()` in
  // the host window off a postMessage, not off the in-iframe click — so removing
  // it changes no activation behaviour, just drops the extra tap.
  await ui.showProgress(t("approveTxTitle"), t("approveTxSubtitle"), "biometric");
  try {
    const assertion = await webauthnGet(requestMessageHash(msg), active.rawId);
    return { msg, proof: buildProof(active.curve, assertion) };
  } finally {
    await ui.closeUi();
  }
}

async function executeRequest(
  active: ActiveCredential,
  request: RequestJson,
): Promise<FinalExecutionOutcome> {
  const client = getClient();
  const { msg, proof } = await signRequestMessage(active, request);
  const exists = await accountExists(client, active.accountId);
  const stateInit = exists
    ? null
    : serializeDefaultStateInit(publicKeyFromString(active.publicKey));
  return relayExecuteSigned(client, rpcUrl(), active.accountId, msg, proof, stateInit);
}

/** Ensure the deterministic account exists on-chain (StateInit-only relay). */
async function ensureAccountOnChain(active: ActiveCredential): Promise<void> {
  const client = getClient();
  if (await accountExists(client, active.accountId)) return;
  await relayStateInit(
    client,
    rpcUrl(),
    active.accountId,
    serializeDefaultStateInit(publicKeyFromString(active.publicKey)),
  );
}

/**
 * Sign the NEP-641 OffchainMessage for `active`'s account and make sure the
 * account exists on-chain (view calls — `w_resolve_auth` — cannot run against
 * a not-yet-initialized deterministic account).
 */
async function signOffchainAuthorization(
  active: ActiveCredential,
  params: ResolveAuthParams,
  progressSubtitle: "signingInFinalizeSubtitle" | "signingInSetupSubtitle",
  tapScreen?: () => Promise<void>,
): Promise<ResolveAuthResponse> {
  const message = buildOffchainMessage({
    signerId: active.accountId,
    payload: params.payload,
    path: params.path,
  });
  const challenge = offchainMessageHash(message);
  const assertion = tapScreen
    ? await webauthnGetWithTapFallback(challenge, active.rawId, tapScreen)
    : await webauthnGet(challenge, active.rawId);
  await ui.showProgress(t("signingInTitle"), t(progressSubtitle));
  await ensureAccountOnChain(active);
  return {
    accountId: active.accountId,
    authorization: buildAuthorizationBlob(message, buildProof(active.curve, assertion)),
  };
}

// ─── NEP-413 ────────────────────────────────────────────────────────────────

const NEP413_TAG = 2 ** 31 + 413;

function nep413PayloadHash(message: string, recipient: string, nonce: Uint8Array): Uint8Array {
  if (nonce.length !== 32) throw new Error("NEP-413 nonce must be 32 bytes");
  const w = new BorshWriter();
  w.writeU32(NEP413_TAG);
  w.writeString(message);
  w.writeFixedBytes(nonce);
  w.writeString(recipient);
  w.writeU8(0); // callbackUrl: None
  return sha256(w.toBytes());
}

// ─── Wallet ─────────────────────────────────────────────────────────────────

/** Entry dialog → chosen sign-in path. Leaves the UI open for the caller. */
async function signInInteractive(ctx?: ui.StepContext): Promise<ActiveCredential> {
  const choice = await ui.promptSignInChoice(await knownAccountOptions());
  if (choice === "create") return createNewPasskey(ctx);
  if (choice === "existing") return useExistingPasskey(ctx);
  return useKnownPasskey(choice.rawIdB64, ctx);
}

/** NEP-413 signature with `active`; `tapScreen` = two-step auto-continue (§3b). */
async function signNep413(
  active: ActiveCredential,
  params: SignMessageParams,
  tapScreen?: () => Promise<void>,
): Promise<SignedMessage> {
  const nonce =
    params.nonce instanceof Uint8Array ? params.nonce : new Uint8Array(params.nonce);
  const challenge = nep413PayloadHash(params.message, params.recipient, nonce);
  const assertion = tapScreen
    ? await webauthnGetWithTapFallback(challenge, active.rawId, tapScreen)
    : await webauthnGet(challenge, active.rawId);
  const proof = buildProof(active.curve, assertion);
  return {
    accountId: active.accountId,
    publicKey: active.publicKey,
    signature: base64.encode(new TextEncoder().encode(proof)),
  };
}

const wallet = {
  // Overwritten by `selector.ready()` with the real manifest.
  manifest: {} as Record<string, unknown>,

  async signIn(params?: SignInParams): Promise<Account[]> {
    assertMainnet(params?.network);
    if (params?.addFunctionCallKey) {
      throw new Error("Function-call access keys are not supported by passkey wallet accounts");
    }

    await retryPendingRegistration();

    const existing = await storage.getActiveCredential();
    if (existing) return [toAccount(existing)];

    try {
      return [toAccount(await signInInteractive())];
    } finally {
      await ui.closeUi();
    }
  },

  async signInAndSignMessage(
    params: SignInAndSignMessageParams,
  ): Promise<AccountWithSignedMessage[]> {
    const messageParams: SignMessageParams = {
      message: params.messageParams.message,
      recipient: params.messageParams.recipient,
      nonce: params.messageParams.nonce,
      network: params.network,
    };
    if (await storage.getActiveCredential()) {
      const accounts = await this.signIn(params);
      const account = accounts[0];
      if (!account) throw new Error("sign-in produced no account");
      return [{ ...account, signedMessage: await this.signMessage(messageParams) }];
    }

    // Cold sign-in: same two-step treatment as resolveAuth (§3b) — the
    // message signature follows the sign-in without another tap.
    assertMainnet(params.network);
    if (params.addFunctionCallKey) {
      throw new Error("Function-call access keys are not supported by passkey wallet accounts");
    }
    await retryPendingRegistration();
    try {
      const active = await signInInteractive({ step: [1, 2] });
      const step2: ui.StepContext = { step: [2, 2], account: active.accountId };
      await ui.showProgress(t("signMsgTitle"), t("signMsgSubtitle"), "biometric", step2);
      const signedMessage = await signNep413(active, messageParams, () =>
        ui.promptConfirm(t("signMsgTitle"), t("signMsgSubtitle"), t("signBtn"), step2),
      );
      return [{ ...toAccount(active), signedMessage }];
    } finally {
      await ui.closeUi();
    }
  },

  async signOut(): Promise<void> {
    // Keep `passkey:known` — verified rawId -> key mappings stay valid.
    await storage.clearActiveCredential();
  },

  async getAccounts(): Promise<Account[]> {
    const active = await storage.getActiveCredential();
    return active ? [toAccount(active)] : [];
  },

  async signMessage(params: SignMessageParams): Promise<SignedMessage> {
    assertMainnet(params.network);
    const active = await requireActive();

    // Fresh user activation for the ceremony (dApp-initiated, no prior tap).
    await ui.promptConfirm(t("signMsgTitle"), t("signMsgSubtitle"), t("signBtn"));
    try {
      return await signNep413(active, params);
    } finally {
      await ui.closeUi();
    }
  },

  async signAndSendTransaction(
    params: SignAndSendTransactionParams,
  ): Promise<FinalExecutionOutcome> {
    assertMainnet(params.network);
    const active = await requireActive();
    const request: RequestJson = {
      external: connectorActionsToPromises([
        { receiverId: params.receiverId, actions: params.actions },
      ]),
    };
    return executeRequest(active, request);
  },

  async signAndSendTransactions(
    params: SignAndSendTransactionsParams,
  ): Promise<FinalExecutionOutcome[]> {
    assertMainnet(params.network);
    const active = await requireActive();
    // All transactions are bundled into a single wallet-contract request
    // (fan-out promises) and settle atomically in one relayed transaction.
    const request: RequestJson = {
      external: connectorActionsToPromises(params.transactions),
    };
    const outcome = await executeRequest(active, request);
    return params.transactions.map(() => outcome);
  },

  async signDelegateActions(
    params: SignDelegateActionsParams,
  ): Promise<SignDelegateActionsResponse> {
    assertMainnet(params.network);
    const active = await requireActive();

    const request: RequestJson = {
      external: connectorActionsToPromises(
        params.delegateActions.map((d) => ({
          receiverId: d.receiverId,
          actions: d.actions as ConnectorAction[],
        })),
      ),
    };
    const { msg, proof } = await signRequestMessage(active, request);

    // The dApp relays this via nt-be, which replays the inner w_execute_signed
    // as the sponsor and cannot create the account — so it must already exist
    // (the delegate action carries no StateInit).
    await ensureAccountOnChain(active);

    // Standard borsh SignedDelegateAction (NEP-461) wrapping a single
    // w_execute_signed(msg, proof) FunctionCall on the wallet account.
    const signedDelegateAction = await buildSignedDelegateAction(active.accountId, msg, proof);
    return { signedDelegateActions: [signedDelegateAction] };
  },

  async resolveAuth(params: ResolveAuthParams): Promise<ResolveAuthResponse> {
    assertMainnet(params.network);
    if (typeof params.payload !== "string") {
      throw new Error("resolveAuth: `payload` (string) is required");
    }
    if (params.path !== undefined && !params.path.every((id) => typeof id === "string")) {
      throw new Error("resolveAuth: `path` must be an array of account ids");
    }

    const signedIn = await storage.getActiveCredential();
    if (signedIn) {
      // Fresh user activation for the ceremony (dApp-initiated sign-in).
      await ui.promptConfirm(t("confirmSignInTitle"), t("confirmSignInSubtitle"), t("confirmSignInBtn"));
      try {
        return await signOffchainAuthorization(signedIn, params, "signingInFinalizeSubtitle");
      } finally {
        await ui.closeUi();
      }
    }

    // No active credential: guide the user from the very first moment —
    // create a new account or pick an existing passkey, with visible
    // progress for every step after that.
    await retryPendingRegistration();
    const choice = await ui.promptSignInChoice(await knownAccountOptions());

    try {
      // The NEP-641 OffchainMessage is bound to the exact `signer_id`, so the
      // account id MUST be known before the signing ceremony:
      //  - known account (picked from our own list): already known — sign
      //    straight away, ONE device confirmation (§3c);
      //  - "create": derived from the freshly created credential's public key;
      //  - "existing": a discovery get() (random challenge) reveals the
      //    credential, which the registry / local cache maps to its key.
      if (typeof choice === "object") {
        const active = await knownCredential(choice.rawIdB64);
        await activate(active);
        await ui.showProgress(t("confirmSignInTitle"), t("confirmSignInSubtitle"), "biometric", {
          account: active.accountId,
        });
        try {
          return await signOffchainAuthorization(active, params, "signingInFinalizeSubtitle");
        } catch (e) {
          await storage.clearActiveCredential();
          throw e;
        }
      }

      const step1: ui.StepContext = { step: [1, 2] };
      const active =
        choice === "create" ? await createNewPasskey(step1) : await useExistingPasskey(step1);

      // Step 2 starts on its own — the user already acted, and the screen says
      // what step 1 achieved so this never reads as "it didn't work" (§3b).
      // Only if the browser blocks it (no fresh activation after the
      // network-bound step) do we fall back to a one-tap confirm.
      const step2: ui.StepContext = { step: [2, 2], account: active.accountId };
      const step2Title = t(choice === "create" ? "passkeyCreatedTitle" : "accountFoundTitle");
      await ui.showProgress(step2Title, t("finishSignInSubtitle"), "biometric", step2);
      try {
        return await signOffchainAuthorization(active, params, "signingInSetupSubtitle", () =>
          ui.promptConfirm(step2Title, t("finishSignInSubtitle"), t("finishSignInBtn"), step2),
        );
      } catch (e) {
        // Roll back only freshly-established local state (verified `passkey:known`
        // write-through stays — it is true regardless of relay hiccups).
        await storage.clearActiveCredential();
        throw e;
      }
    } finally {
      await ui.closeUi();
    }
  },
};

selector().ready(wallet);
