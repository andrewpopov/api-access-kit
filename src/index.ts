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
  pepper: string;
  createdAt?: string;
  workspaceId?: string;
  expiresAt?: string;
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

/** Issue an opaque secret once; persist only `credential.secretHash`. */
export function issueApiAccessCredential(
  input: IssueApiAccessCredentialInput,
): IssuedApiAccessCredential {
  requireText(input.id, "Credential id");
  requireText(input.ownerId, "Credential owner id");
  requireText(input.prefix, "Credential prefix");
  requireText(input.pepper, "Credential pepper");
  if (!/^[a-z][a-z0-9_-]*$/i.test(input.prefix)) {
    throw new Error("Credential prefix must contain only letters, numbers, underscores, or dashes.");
  }
  const scopes = normalizeScopes(input.scopes);
  const secretBytes = input.secretBytes ?? 32;
  if (!Number.isInteger(secretBytes) || secretBytes < 16) {
    throw new Error("Credential secrets require at least 16 random bytes.");
  }
  const secret = `${input.prefix}.${input.id}.${randomBytes(secretBytes).toString("base64url")}`;
  const credential: ApiAccessCredential = Object.freeze({
    id: input.id,
    ownerId: input.ownerId,
    secretHash: hashApiAccessSecret(secret, input.pepper),
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
export function verifyApiAccessSecret(
  secret: string,
  storedHash: string,
  pepper: string,
): boolean {
  const candidate = Buffer.from(hashApiAccessSecret(secret, pepper));
  const stored = Buffer.from(storedHash);
  return candidate.length === stored.length && timingSafeEqual(candidate, stored);
}

/** Parse the public credential id from an opaque secret for indexed lookup. */
export function parseApiAccessSecret(
  secret: string,
  prefix: string,
): { id: string } | undefined {
  const [foundPrefix, id, entropy, ...rest] = secret.split(".");
  if (foundPrefix !== prefix || !id || !entropy || rest.length > 0 || entropy.length < 20) return undefined;
  return { id };
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
