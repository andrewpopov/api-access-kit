export { createApiCommandFingerprint, createApiCommandReceipt, defineApiCommands, evaluateApiCommandIdempotency, evaluateApiCommandPrecondition, type ApiCommandEnvelope, type ApiCommandIdempotency, type ApiCommandIdempotencyRecord, type ApiCommandPrecondition, type ApiCommandReceipt, type ApiCommandResource, type DefinedApiCommands, type JsonObject, type JsonValue, } from "./commands.js";
export type ApiAccessScope = string;
/** Legacy: SHA-256 over the pepper and secret joined by a NUL byte. Still verified for existing credentials. */
export declare const API_ACCESS_HASH_VERSION_V1 = "sha256-peppered-secret-v1";
/** HMAC-SHA256 keyed by the pepper over the secret. The current default. */
export declare const API_ACCESS_HASH_VERSION_V2 = "hmac-sha256-peppered-secret-v2";
/** Every hash version this package can verify. */
export declare const SUPPORTED_API_ACCESS_HASH_VERSIONS: readonly ["sha256-peppered-secret-v1", "hmac-sha256-peppered-secret-v2"];
/** The hash version new credentials are issued with. */
export declare const DEFAULT_API_ACCESS_HASH_VERSION = "hmac-sha256-peppered-secret-v2";
export type ApiAccessHashVersion = (typeof SUPPORTED_API_ACCESS_HASH_VERSIONS)[number];
export declare function isSupportedHashVersion(value: string): value is ApiAccessHashVersion;
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
export declare function createApiAccessPrincipalBinding(input: CreateApiAccessPrincipalBindingInput): ApiAccessPrincipalBinding;
/** The only response shape which may carry a raw credential secret. */
export interface IssuedApiAccessCredential {
    credential: ApiAccessCredential;
    secret: string;
}
export type ApiAccessDenyReason = "REVOKED" | "EXPIRED" | "WORKSPACE_MISMATCH" | "SCOPE_DENIED";
export type ApiAccessDecision = {
    allowed: true;
} | {
    allowed: false;
    reason: ApiAccessDenyReason;
};
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
export type ApiAccessCredentialLifecycleMutation = {
    applied: true;
} | {
    applied: false;
    reason: "NOT_FOUND" | "NOT_ACTIVE" | "CONFLICT";
};
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
export type ApiAccessAuthenticationFailure = "MALFORMED" | "INVALID_PEPPER_RING" | "NOT_FOUND" | "HASH_MISMATCH" | "REVOKED" | "EXPIRED" | "UNKNOWN_PEPPER_VERSION" | "UNSUPPORTED_HASH_VERSION";
export type ApiAccessAuthentication = {
    ok: true;
    credential: ApiAccessCredential;
} | {
    ok: false;
    reason: ApiAccessAuthenticationFailure;
};
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
export declare function defineApiScopes<const Scopes extends string>(scopes: readonly Scopes[]): DefinedApiScopes<Scopes>;
/**
 * Validate a named pepper ring before a host uses it for issuance or
 * authentication. Environment-variable parsing remains host-owned so this
 * package never dictates configuration names or secret providers.
 */
export declare function defineApiAccessPepperRing(peppers: readonly ApiAccessPepper[]): DefinedApiAccessPepperRing;
/**
 * Issue a v1 opaque credential once; persist only the public id and a hash of
 * its random secret segment. `prefix` is literal (for example `cairn_`).
 */
export declare function issueApiAccessCredential(input: IssueApiAccessCredentialInput): IssuedApiAccessCredential;
/**
 * Issue fresh material for an active credential while preserving only the
 * portable lifecycle fields. The host atomically applies the replacement and
 * decides whether that means a new application row or an in-place update.
 */
export declare function issueReplacementApiAccessCredential(input: IssueReplacementApiAccessCredentialInput): IssuedApiAccessCredential;
/**
 * Exercise a host adapter in an isolated store. This performs real lifecycle
 * writes, so consumers must provide a disposable fixture rather than a
 * production store. It deliberately verifies only the portable credential
 * contract; host audit, row lineage, and authorization remain host concerns.
 */
export declare function runApiAccessCredentialLifecycleConformance(input: ApiAccessCredentialLifecycleConformanceInput): Promise<ApiAccessCredentialLifecycleConformanceResult>;
/** A deterministic hash suitable for host-owned credential lookup and storage. */
export declare function hashApiAccessSecret(secret: string, pepper: string, hashVersion?: ApiAccessHashVersion): string;
/** Constant-time comparison for a host's stored credential hash. */
export declare function verifyApiAccessSecret(secret: string, storedHash: string, pepper: string, hashVersion: ApiAccessHashVersion): boolean;
/** Parse the public credential id from an opaque secret for indexed lookup. */
export declare function parseApiAccessSecret(secret: string, prefix: string): {
    id: string;
    secret: string;
} | undefined;
/**
 * Perform indexed public-id lookup followed by constant-time secret comparison.
 * This is deliberately lifecycle-only: hosts still apply their resource policy
 * after an allowed credential is mapped to a principal.
 */
export declare function authenticateApiAccessCredential(input: AuthenticateApiAccessCredentialInput): Promise<ApiAccessAuthentication>;
/** Evaluate persisted credential lifecycle state without applying a scope. */
export declare function getApiAccessCredentialStatus(credential: Pick<ApiAccessCredential, "revokedAt" | "expiresAt">, now?: Date): ApiAccessCredentialStatus;
/** Return a safe human-readable representation using only public metadata. */
export declare function formatApiAccessCredentialMask(prefix: string, credentialId: string): string;
/**
 * Evaluates only credential lifecycle, exact scope, and optional workspace
 * binding. A successful decision is not product authorization: callers must
 * still check their own workspace/resource policy for the credential owner.
 */
export declare function authorizeApiAccess(credential: ApiAccessCredential, request: ApiAccessRequest): ApiAccessDecision;
/** Remove secret hash material before returning list-safe metadata to a caller. */
export declare function toApiAccessCredentialMetadata(credential: ApiAccessCredential): Omit<ApiAccessCredential, "secretHash">;
