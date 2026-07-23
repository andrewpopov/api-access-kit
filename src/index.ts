import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export {
  createApiCommandFingerprint,
  createApiCommandReceipt,
  defineApiCommands,
  evaluateApiCommandIdempotency,
  evaluateApiCommandPrecondition,
  type ApiCommandEnvelope,
  type ApiCommandIdempotency,
  type ApiCommandIdempotencyRecord,
  type ApiCommandPrecondition,
  type ApiCommandReceipt,
  type ApiCommandResource,
  type DefinedApiCommands,
  type JsonObject,
  type JsonValue,
} from "./commands.js";

export type ApiAccessScope = string;

/** Legacy: SHA-256 over the pepper and secret joined by a NUL byte. Still verified for existing credentials. */
export const API_ACCESS_HASH_VERSION_V1 = "sha256-peppered-secret-v1";
/** HMAC-SHA256 keyed by the pepper over the secret. The current default. */
export const API_ACCESS_HASH_VERSION_V2 = "hmac-sha256-peppered-secret-v2";
/** Every hash version this package can verify. */
export const SUPPORTED_API_ACCESS_HASH_VERSIONS = Object.freeze([
  API_ACCESS_HASH_VERSION_V1,
  API_ACCESS_HASH_VERSION_V2,
] as const);
/** The hash version new credentials are issued with. */
export const DEFAULT_API_ACCESS_HASH_VERSION = API_ACCESS_HASH_VERSION_V2;
export type ApiAccessHashVersion = (typeof SUPPORTED_API_ACCESS_HASH_VERSIONS)[number];
export function isSupportedHashVersion(value: string): value is ApiAccessHashVersion {
  return (SUPPORTED_API_ACCESS_HASH_VERSIONS as readonly string[]).includes(value);
}

/** Storage-safe credential state. The secret itself never appears in this shape. */
export interface ApiAccessCredential {
  id: string;
  /** Accountable issuer/lifecycle owner. This is not necessarily the runtime authorization principal. */
  ownerId: string;
  /** Public wire-format version. Persisted so format migrations are explicit. */
  formatVersion: 1;
  /** Host-defined secret hash algorithm/version. */
  hashVersion: string;
  /** Identifies the pepper used to create `secretHash`. */
  pepperVersion: string;
  secretHash: string;
  scopes: readonly ApiAccessScope[];
  createdAt: string;
  workspaceId?: string;
  expiresAt?: string;
  revokedAt?: string;
}

/**
 * Host-owned resource-authorization identity for an API credential.
 *
 * The credential package intentionally does not persist this binding or decide
 * what a role can do. It makes the crucial separation explicit: `ownerId`
 * answers who issued/manages a credential; `principalId` answers which user,
 * organization, or service authorization policy applies to its requests.
 */
export interface ApiAccessPrincipalBinding {
  readonly credentialId: string;
  readonly principalType: string;
  readonly principalId: string;
  readonly issuerId: string;
}

export interface CreateApiAccessPrincipalBindingInput {
  credential: Pick<ApiAccessCredential, "id" | "ownerId">;
  principalType: string;
  principalId: string;
  issuerId?: string;
}

/**
 * Creates a validated, immutable authorization binding for host storage or
 * request context. Hosts should bind an organization credential directly to
 * its organization/service principal instead of minting a synthetic user per
 * credential merely to reuse membership checks.
 */
export function createApiAccessPrincipalBinding(input: CreateApiAccessPrincipalBindingInput): ApiAccessPrincipalBinding {
  requireText(input.credential.id, "API credential id");
  requireText(input.issuerId ?? input.credential.ownerId, "API credential issuer id");
  requireText(input.principalType, "API credential principal type");
  requireText(input.principalId, "API credential principal id");
  const credentialId = input.credential.id;
  const issuerId = input.issuerId ?? input.credential.ownerId;
  const principalType = input.principalType;
  const principalId = input.principalId;
  return Object.freeze({ credentialId, issuerId, principalType, principalId });
}

/** The only response shape which may carry a raw credential secret. */
export interface IssuedApiAccessCredential {
  credential: ApiAccessCredential;
  secret: string;
}

export type ApiAccessDenyReason =
  | "REVOKED"
  | "EXPIRED"
  | "WORKSPACE_MISMATCH"
  | "SCOPE_DENIED";

export type ApiAccessDecision =
  | { allowed: true }
  | { allowed: false; reason: ApiAccessDenyReason };

export interface ApiAccessRequest {
  scope: ApiAccessScope;
  workspaceId?: string;
  now?: Date;
}

export interface IssueApiAccessCredentialInput {
  id: string;
  ownerId: string;
  scopes: readonly ApiAccessScope[];
  prefix: string;
  pepper: ApiAccessPepper;
  hashVersion?: ApiAccessHashVersion;
  createdAt?: string;
  workspaceId?: string;
  expiresAt?: string;
  secretBytes?: number;
}

/** A named verification secret. Keep old entries until all old credentials rotate. */
export interface ApiAccessPepper {
  version: string;
  value: string;
}

export interface ApiAccessCredentialStore {
  findById(id: string): Promise<ApiAccessCredential | null>;
}

/**
 * The persistence seam for host-owned credential lifecycle operations.
 *
 * Hosts retain their own transaction, audit, and authorization semantics. In
 * particular, a host may keep a replacement as a new row or replace the
 * credential material inside an existing application record.
 */
export interface ApiAccessCredentialLifecycleStore extends ApiAccessCredentialStore {
  create(credential: ApiAccessCredential): Promise<void>;
  replaceActive(input: ApiAccessCredentialReplacement): Promise<ApiAccessCredentialLifecycleMutation>;
  revokeActive(input: ApiAccessCredentialRevocation): Promise<ApiAccessCredentialLifecycleMutation>;
  touchLastUsed(id: string, lastUsedAt: string): Promise<void>;
}

export interface ApiAccessCredentialReplacement {
  previousCredentialId: string;
  replacement: ApiAccessCredential;
  revokedAt: string;
}

export interface ApiAccessCredentialRevocation {
  credentialId: string;
  revokedAt: string;
}

export type ApiAccessCredentialLifecycleMutation =
  | { applied: true }
  | { applied: false; reason: "NOT_FOUND" | "NOT_ACTIVE" | "CONFLICT" };

/** A sandboxed fixture for proving a host lifecycle adapter honors this contract. */
export interface ApiAccessCredentialLifecycleConformanceInput {
  store: ApiAccessCredentialLifecycleStore;
  active: ApiAccessCredential;
  replacement: ApiAccessCredential;
  now?: string;
}

export interface ApiAccessCredentialLifecycleConformanceResult {
  readonly priorCredentialRetained: boolean;
  readonly replacementCredentialId: string;
}

export type ApiAccessAuthenticationFailure =
  | "MALFORMED"
  | "INVALID_PEPPER_RING"
  | "NOT_FOUND"
  | "HASH_MISMATCH"
  | "REVOKED"
  | "EXPIRED"
  | "UNKNOWN_PEPPER_VERSION"
  | "UNSUPPORTED_HASH_VERSION";

export type ApiAccessAuthentication =
  | { ok: true; credential: ApiAccessCredential }
  | { ok: false; reason: ApiAccessAuthenticationFailure };

export interface AuthenticateApiAccessCredentialInput {
  rawCredential: string;
  prefix: string;
  store: ApiAccessCredentialStore;
  peppers: readonly ApiAccessPepper[];
  now?: Date;
}

export interface DefinedApiAccessPepperRing {
  readonly values: readonly ApiAccessPepper[];
  readonly primary: ApiAccessPepper;
  find(version: string): ApiAccessPepper | undefined;
}

export type ApiAccessCredentialStatus = "ACTIVE" | "REVOKED" | "EXPIRED" | "INVALID";

export interface IssueReplacementApiAccessCredentialInput {
  credential: ApiAccessCredential;
  id: string;
  prefix: string;
  pepper: ApiAccessPepper;
  hashVersion?: ApiAccessHashVersion;
  createdAt?: string;
  now?: Date;
  secretBytes?: number;
}

export interface DefinedApiScopes<Scopes extends string> {
  readonly values: readonly Scopes[];
  has(scope: string): scope is Scopes;
  assert(scope: string): Scopes;
}

/** Define the finite, application-owned scope vocabulary. Matching is exact. */
export function defineApiScopes<const Scopes extends string>(
  scopes: readonly Scopes[],
): DefinedApiScopes<Scopes> {
  const values = [...new Set(scopes)];
  if (values.length === 0) throw new Error("At least one API scope is required.");
  for (const scope of values) requireText(scope, "API scope");
  const known = new Set<string>(values);
  return Object.freeze({
    values: Object.freeze(values),
    has(scope: string): scope is Scopes {
      return known.has(scope);
    },
    assert(scope: string): Scopes {
      if (!known.has(scope)) throw new Error(`Unknown API scope: ${scope}`);
      return scope as Scopes;
    },
  });
}

/**
 * Validate a named pepper ring before a host uses it for issuance or
 * authentication. Environment-variable parsing remains host-owned so this
 * package never dictates configuration names or secret providers.
 */
export function defineApiAccessPepperRing(
  peppers: readonly ApiAccessPepper[],
): DefinedApiAccessPepperRing {
  if (peppers.length === 0) throw new Error("At least one API credential pepper is required.");
  const seen = new Set<string>();
  const values = peppers.map((pepper) => {
    requireText(pepper.version, "Credential pepper version");
    requireText(pepper.value, "Credential pepper");
    if (seen.has(pepper.version)) {
      throw new Error(`Duplicate credential pepper version: ${pepper.version}`);
    }
    seen.add(pepper.version);
    return Object.freeze({ version: pepper.version, value: pepper.value });
  });
  const frozen = Object.freeze(values);
  return Object.freeze({
    values: frozen,
    primary: frozen[0],
    find(version: string): ApiAccessPepper | undefined {
      return frozen.find((candidate) => candidate.version === version);
    },
  });
}

/**
 * Issue a v1 opaque credential once; persist only the public id and a hash of
 * its random secret segment. `prefix` is literal (for example `cairn_`).
 */
export function issueApiAccessCredential(
  input: IssueApiAccessCredentialInput,
): IssuedApiAccessCredential {
  requireText(input.id, "Credential id");
  requireText(input.ownerId, "Credential owner id");
  requireText(input.prefix, "Credential prefix");
  requireText(input.pepper.version, "Credential pepper version");
  requireText(input.pepper.value, "Credential pepper");
  if (!/^[a-z][a-z0-9_-]*$/i.test(input.prefix)) {
    throw new Error("Credential prefix must contain only letters, numbers, underscores, or dashes.");
  }
  if (input.hashVersion !== undefined && !isSupportedHashVersion(input.hashVersion)) {
    throw new Error(
      `Unsupported hash version "${input.hashVersion}"; supported: ${SUPPORTED_API_ACCESS_HASH_VERSIONS.join(", ")}.`,
    );
  }
  const hashVersion = input.hashVersion ?? DEFAULT_API_ACCESS_HASH_VERSION;
  const scopes = normalizeScopes(input.scopes);
  const secretBytes = input.secretBytes ?? 32;
  if (!Number.isInteger(secretBytes) || secretBytes < 16) {
    throw new Error("Credential secrets require at least 16 random bytes.");
  }
  const entropy = randomBytes(secretBytes).toString("base64url");
  const secret = `${input.prefix}${input.id}.${entropy}`;
  const credential: ApiAccessCredential = Object.freeze({
    id: input.id,
    ownerId: input.ownerId,
    formatVersion: 1,
    hashVersion,
    pepperVersion: input.pepper.version,
    secretHash: hashApiAccessSecret(entropy, input.pepper.value, hashVersion),
    scopes,
    createdAt: input.createdAt ?? new Date().toISOString(),
    workspaceId: input.workspaceId,
    expiresAt: input.expiresAt,
  });
  return Object.freeze({ credential, secret });
}

/**
 * Issue fresh material for an active credential while preserving only the
 * portable lifecycle fields. The host atomically applies the replacement and
 * decides whether that means a new application row or an in-place update.
 */
export function issueReplacementApiAccessCredential(
  input: IssueReplacementApiAccessCredentialInput,
): IssuedApiAccessCredential {
  if (getApiAccessCredentialStatus(input.credential, input.now) !== "ACTIVE") {
    throw new Error("Only an active API credential can be replaced.");
  }
  return issueApiAccessCredential({
    id: input.id,
    ownerId: input.credential.ownerId,
    scopes: input.credential.scopes,
    prefix: input.prefix,
    pepper: input.pepper,
    hashVersion: input.hashVersion,
    createdAt: input.createdAt,
    workspaceId: input.credential.workspaceId,
    expiresAt: input.credential.expiresAt,
    secretBytes: input.secretBytes,
  });
}

/**
 * Exercise a host adapter in an isolated store. This performs real lifecycle
 * writes, so consumers must provide a disposable fixture rather than a
 * production store. It deliberately verifies only the portable credential
 * contract; host audit, row lineage, and authorization remain host concerns.
 */
export async function runApiAccessCredentialLifecycleConformance(
  input: ApiAccessCredentialLifecycleConformanceInput,
): Promise<ApiAccessCredentialLifecycleConformanceResult> {
  if (input.active.id === input.replacement.id) {
    throw new Error("Conformance replacement credential id must differ from the active credential id.");
  }
  const now = input.now ?? new Date().toISOString();
  const nowDate = new Date(now);
  if (Number.isNaN(nowDate.getTime())) {
    throw new Error("Conformance timestamp must be an ISO timestamp.");
  }
  if (getApiAccessCredentialStatus(input.active, nowDate) !== "ACTIVE") {
    throw new Error("Conformance active credential must be active.");
  }
  if (getApiAccessCredentialStatus(input.replacement, nowDate) !== "ACTIVE") {
    throw new Error("Conformance replacement credential must be active.");
  }

  await input.store.create(input.active);
  assertCredentialEquivalent(await input.store.findById(input.active.id), input.active, "create");

  const replacement = await input.store.replaceActive({
    previousCredentialId: input.active.id,
    replacement: input.replacement,
    revokedAt: now,
  });
  if (!replacement.applied) {
    throw new Error(`Conformance replacement failed: ${replacement.reason}`);
  }
  assertCredentialEquivalent(await input.store.findById(input.replacement.id), input.replacement, "replacement");

  const prior = await input.store.findById(input.active.id);
  if (prior && !prior.revokedAt) {
    throw new Error("Conformance replacement left the prior credential active.");
  }

  const revocation = await input.store.revokeActive({ credentialId: input.replacement.id, revokedAt: now });
  if (!revocation.applied) {
    throw new Error(`Conformance revocation failed: ${revocation.reason}`);
  }
  const revoked = await input.store.findById(input.replacement.id);
  if (!revoked?.revokedAt) {
    throw new Error("Conformance revocation did not persist a revoked credential.");
  }
  await input.store.touchLastUsed(input.replacement.id, now);

  return Object.freeze({
    priorCredentialRetained: Boolean(prior),
    replacementCredentialId: input.replacement.id,
  });
}

/** A deterministic hash suitable for host-owned credential lookup and storage. */
export function hashApiAccessSecret(
  secret: string,
  pepper: string,
  hashVersion: ApiAccessHashVersion = DEFAULT_API_ACCESS_HASH_VERSION,
): string {
  requireText(secret, "Credential secret");
  requireText(pepper, "Credential pepper");
  switch (hashVersion) {
    case API_ACCESS_HASH_VERSION_V1:
      return createHash("sha256").update(`${pepper}\u0000${secret}`).digest("base64url");
    case API_ACCESS_HASH_VERSION_V2:
      return createHmac("sha256", pepper).update(secret).digest("base64url");
    default:
      throw new Error(`Unsupported hash version "${hashVersion}".`);
  }
}

/** Constant-time comparison for a host's stored credential hash. */
export function verifyApiAccessSecret(
  secret: string,
  storedHash: string,
  pepper: string,
  hashVersion: ApiAccessHashVersion,
): boolean {
  const candidate = Buffer.from(hashApiAccessSecret(secret, pepper, hashVersion));
  const stored = Buffer.from(storedHash);
  return candidate.length === stored.length && timingSafeEqual(candidate, stored);
}

/** Parse the public credential id from an opaque secret for indexed lookup. */
export function parseApiAccessSecret(
  secret: string,
  prefix: string,
): { id: string; secret: string } | undefined {
  if (!secret.startsWith(prefix)) return undefined;
  const rest = secret.slice(prefix.length);
  const dot = rest.indexOf(".");
  if (dot < 1 || dot !== rest.lastIndexOf(".")) return undefined;
  const id = rest.slice(0, dot);
  const entropy = rest.slice(dot + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(id) || !/^[A-Za-z0-9_-]{20,}$/.test(entropy)) return undefined;
  return { id, secret: entropy };
}

/**
 * Perform indexed public-id lookup followed by constant-time secret comparison.
 * This is deliberately lifecycle-only: hosts still apply their resource policy
 * after an allowed credential is mapped to a principal.
 */
export async function authenticateApiAccessCredential(
  input: AuthenticateApiAccessCredentialInput,
): Promise<ApiAccessAuthentication> {
  const parsed = parseApiAccessSecret(input.rawCredential, input.prefix);
  if (!parsed) return { ok: false, reason: "MALFORMED" };
  let peppers: DefinedApiAccessPepperRing;
  try {
    peppers = defineApiAccessPepperRing(input.peppers);
  } catch {
    return { ok: false, reason: "INVALID_PEPPER_RING" };
  }
  const credential = await input.store.findById(parsed.id);
  if (!credential) return { ok: false, reason: "NOT_FOUND" };
  if (credential.formatVersion !== 1) return { ok: false, reason: "MALFORMED" };
  if (!isSupportedHashVersion(credential.hashVersion)) {
    return { ok: false, reason: "UNSUPPORTED_HASH_VERSION" };
  }
  const pepper = peppers.find(credential.pepperVersion);
  if (!pepper) return { ok: false, reason: "UNKNOWN_PEPPER_VERSION" };
  if (!verifyApiAccessSecret(parsed.secret, credential.secretHash, pepper.value, credential.hashVersion)) {
    return { ok: false, reason: "HASH_MISMATCH" };
  }
  switch (getApiAccessCredentialStatus(credential, input.now)) {
    case "REVOKED":
      return { ok: false, reason: "REVOKED" };
    case "EXPIRED":
      return { ok: false, reason: "EXPIRED" };
    case "INVALID":
      return { ok: false, reason: "MALFORMED" };
  }
  return { ok: true, credential };
}

/** Evaluate persisted credential lifecycle state without applying a scope. */
export function getApiAccessCredentialStatus(
  credential: Pick<ApiAccessCredential, "revokedAt" | "expiresAt">,
  now: Date = new Date(),
): ApiAccessCredentialStatus {
  if (credential.revokedAt) return "REVOKED";
  if (!credential.expiresAt) return "ACTIVE";
  const expiresAt = new Date(credential.expiresAt).getTime();
  if (Number.isNaN(expiresAt)) return "INVALID";
  return expiresAt <= now.getTime() ? "EXPIRED" : "ACTIVE";
}

/** Return a safe human-readable representation using only public metadata. */
export function formatApiAccessCredentialMask(prefix: string, credentialId: string): string {
  requireText(prefix, "Credential prefix");
  requireText(credentialId, "Credential id");
  if (!/^[a-z][a-z0-9_-]*$/i.test(prefix) || !/^[A-Za-z0-9_-]+$/.test(credentialId)) {
    throw new Error("Credential prefix or id is malformed.");
  }
  return `${prefix}${credentialId}.…`;
}

/**
 * Evaluates only credential lifecycle, exact scope, and optional workspace
 * binding. A successful decision is not product authorization: callers must
 * still check their own workspace/resource policy for the credential owner.
 */
export function authorizeApiAccess(
  credential: ApiAccessCredential,
  request: ApiAccessRequest,
): ApiAccessDecision {
  const status = getApiAccessCredentialStatus(credential, request.now);
  if (status === "REVOKED") return { allowed: false, reason: "REVOKED" };
  if (status === "EXPIRED" || status === "INVALID") {
    return { allowed: false, reason: "EXPIRED" };
  }
  if (credential.workspaceId && credential.workspaceId !== request.workspaceId) {
    return { allowed: false, reason: "WORKSPACE_MISMATCH" };
  }
  if (!credential.scopes.includes(request.scope)) return { allowed: false, reason: "SCOPE_DENIED" };
  return { allowed: true };
}

/** Remove secret hash material before returning list-safe metadata to a caller. */
export function toApiAccessCredentialMetadata(
  credential: ApiAccessCredential,
): Omit<ApiAccessCredential, "secretHash"> {
  const { secretHash: _secretHash, ...metadata } = credential;
  return Object.freeze({ ...metadata, scopes: Object.freeze([...credential.scopes]) });
}

function normalizeScopes(scopes: readonly ApiAccessScope[]): readonly ApiAccessScope[] {
  const values = [...new Set(scopes)];
  if (values.length === 0) throw new Error("At least one API scope is required.");
  for (const scope of values) requireText(scope, "API scope");
  return Object.freeze(values);
}

function assertCredentialEquivalent(
  actual: ApiAccessCredential | null,
  expected: ApiAccessCredential,
  action: string,
): void {
  if (!actual) throw new Error(`Conformance ${action} did not persist the credential.`);
  const fields: (keyof ApiAccessCredential)[] = [
    "id",
    "ownerId",
    "formatVersion",
    "hashVersion",
    "pepperVersion",
    "secretHash",
    "createdAt",
    "workspaceId",
    "expiresAt",
  ];
  for (const field of fields) {
    if (actual[field] !== expected[field]) {
      throw new Error(`Conformance ${action} changed credential ${field}.`);
    }
  }
  if (actual.scopes.length !== expected.scopes.length || actual.scopes.some((scope, index) => scope !== expected.scopes[index])) {
    throw new Error(`Conformance ${action} changed credential scopes.`);
  }
}

function requireText(value: string, label: string): void {
  if (!value.trim()) throw new Error(`${label} must not be empty.`);
}
