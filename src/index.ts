import { createHash, randomBytes, timingSafeEqual } from "node:crypto";

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

/** Storage-safe credential state. The secret itself never appears in this shape. */
export interface ApiAccessCredential {
  id: string;
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
  hashVersion?: string;
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

export type ApiAccessAuthenticationFailure =
  | "MALFORMED"
  | "NOT_FOUND"
  | "HASH_MISMATCH"
  | "REVOKED"
  | "EXPIRED"
  | "UNKNOWN_PEPPER_VERSION";

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
  const scopes = normalizeScopes(input.scopes);
  const secretBytes = input.secretBytes ?? 32;
  if (!Number.isInteger(secretBytes) || secretBytes < 16) {
    throw new Error("Credential secrets require at least 16 random bytes.");
  }
  const secret = `${input.prefix}${input.id}.${randomBytes(secretBytes).toString("base64url")}`;
  const credential: ApiAccessCredential = Object.freeze({
    id: input.id,
    ownerId: input.ownerId,
    formatVersion: 1,
    hashVersion: input.hashVersion ?? "sha256-peppered-secret-v1",
    pepperVersion: input.pepper.version,
    secretHash: hashApiAccessSecret(parseApiAccessSecret(secret, input.prefix)!.secret, input.pepper.value),
    scopes,
    createdAt: input.createdAt ?? new Date().toISOString(),
    workspaceId: input.workspaceId,
    expiresAt: input.expiresAt,
  });
  return Object.freeze({ credential, secret });
}

/** A deterministic hash suitable for host-owned credential lookup and storage. */
export function hashApiAccessSecret(secret: string, pepper: string): string {
  requireText(secret, "Credential secret");
  requireText(pepper, "Credential pepper");
  return createHash("sha256").update(`${pepper}\u0000${secret}`).digest("base64url");
}

/** Constant-time comparison for a host's stored credential hash. */
export function verifyApiAccessSecret(secret: string, storedHash: string, pepper: string): boolean {
  const candidate = Buffer.from(hashApiAccessSecret(secret, pepper));
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
  const credential = await input.store.findById(parsed.id);
  if (!credential) return { ok: false, reason: "NOT_FOUND" };
  if (credential.formatVersion !== 1) return { ok: false, reason: "MALFORMED" };
  const pepper = input.peppers.find((candidate) => candidate.version === credential.pepperVersion);
  if (!pepper) return { ok: false, reason: "UNKNOWN_PEPPER_VERSION" };
  if (!verifyApiAccessSecret(parsed.secret, credential.secretHash, pepper.value)) {
    return { ok: false, reason: "HASH_MISMATCH" };
  }
  if (credential.revokedAt) return { ok: false, reason: "REVOKED" };
  if (credential.expiresAt && new Date(credential.expiresAt).getTime() <= (input.now ?? new Date()).getTime()) {
    return { ok: false, reason: "EXPIRED" };
  }
  return { ok: true, credential };
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
  if (credential.revokedAt) return { allowed: false, reason: "REVOKED" };
  if (credential.expiresAt && new Date(credential.expiresAt).getTime() <= (request.now ?? new Date()).getTime()) {
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

function requireText(value: string, label: string): void {
  if (!value.trim()) throw new Error(`${label} must not be empty.`);
}
