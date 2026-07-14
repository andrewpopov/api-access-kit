export { createApiCommandFingerprint, createApiCommandReceipt, defineApiCommands, evaluateApiCommandIdempotency, evaluateApiCommandPrecondition, type ApiCommandEnvelope, type ApiCommandIdempotency, type ApiCommandIdempotencyRecord, type ApiCommandPrecondition, type ApiCommandReceipt, type ApiCommandResource, type DefinedApiCommands, type JsonObject, type JsonValue, } from "./commands.js";
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
export declare function defineApiScopes<const Scopes extends string>(scopes: readonly Scopes[]): DefinedApiScopes<Scopes>;
/** Issue an opaque secret once; persist only `credential.secretHash`. */
export declare function issueApiAccessCredential(input: IssueApiAccessCredentialInput): IssuedApiAccessCredential;
/** A deterministic hash suitable for host-owned credential lookup and storage. */
export declare function hashApiAccessSecret(secret: string, pepper: string): string;
/** Constant-time comparison for a host's stored credential hash. */
export declare function verifyApiAccessSecret(secret: string, storedHash: string, pepper: string): boolean;
/** Parse the public credential id from an opaque secret for indexed lookup. */
export declare function parseApiAccessSecret(secret: string, prefix: string): {
    id: string;
} | undefined;
/**
 * Evaluates only credential lifecycle, exact scope, and optional workspace
 * binding. A successful decision is not product authorization: callers must
 * still check their own workspace/resource policy for the credential owner.
 */
export declare function authorizeApiAccess(credential: ApiAccessCredential, request: ApiAccessRequest): ApiAccessDecision;
/** Remove secret hash material before returning list-safe metadata to a caller. */
export declare function toApiAccessCredentialMetadata(credential: ApiAccessCredential): Omit<ApiAccessCredential, "secretHash">;
