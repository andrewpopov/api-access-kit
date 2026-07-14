"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.evaluateApiCommandPrecondition = exports.defineApiCommands = exports.createApiCommandReceipt = void 0;
exports.defineApiScopes = defineApiScopes;
exports.issueApiAccessCredential = issueApiAccessCredential;
exports.hashApiAccessSecret = hashApiAccessSecret;
exports.verifyApiAccessSecret = verifyApiAccessSecret;
exports.parseApiAccessSecret = parseApiAccessSecret;
exports.authorizeApiAccess = authorizeApiAccess;
exports.toApiAccessCredentialMetadata = toApiAccessCredentialMetadata;
const node_crypto_1 = require("node:crypto");
var commands_js_1 = require("./commands.js");
Object.defineProperty(exports, "createApiCommandReceipt", { enumerable: true, get: function () { return commands_js_1.createApiCommandReceipt; } });
Object.defineProperty(exports, "defineApiCommands", { enumerable: true, get: function () { return commands_js_1.defineApiCommands; } });
Object.defineProperty(exports, "evaluateApiCommandPrecondition", { enumerable: true, get: function () { return commands_js_1.evaluateApiCommandPrecondition; } });
/** Define the finite, application-owned scope vocabulary. Matching is exact. */
function defineApiScopes(scopes) {
    const values = [...new Set(scopes)];
    if (values.length === 0)
        throw new Error("At least one API scope is required.");
    for (const scope of values)
        requireText(scope, "API scope");
    const known = new Set(values);
    return Object.freeze({
        values: Object.freeze(values),
        has(scope) {
            return known.has(scope);
        },
        assert(scope) {
            if (!known.has(scope))
                throw new Error(`Unknown API scope: ${scope}`);
            return scope;
        },
    });
}
/** Issue an opaque secret once; persist only `credential.secretHash`. */
function issueApiAccessCredential(input) {
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
    const secret = `${input.prefix}.${input.id}.${(0, node_crypto_1.randomBytes)(secretBytes).toString("base64url")}`;
    const credential = Object.freeze({
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
function hashApiAccessSecret(secret, pepper) {
    requireText(secret, "Credential secret");
    requireText(pepper, "Credential pepper");
    return (0, node_crypto_1.createHash)("sha256").update(`${pepper}\u0000${secret}`).digest("base64url");
}
/** Constant-time comparison for a host's stored credential hash. */
function verifyApiAccessSecret(secret, storedHash, pepper) {
    const candidate = Buffer.from(hashApiAccessSecret(secret, pepper));
    const stored = Buffer.from(storedHash);
    return candidate.length === stored.length && (0, node_crypto_1.timingSafeEqual)(candidate, stored);
}
/** Parse the public credential id from an opaque secret for indexed lookup. */
function parseApiAccessSecret(secret, prefix) {
    const [foundPrefix, id, entropy, ...rest] = secret.split(".");
    if (foundPrefix !== prefix || !id || !entropy || rest.length > 0 || entropy.length < 20)
        return undefined;
    return { id };
}
/**
 * Evaluates only credential lifecycle, exact scope, and optional workspace
 * binding. A successful decision is not product authorization: callers must
 * still check their own workspace/resource policy for the credential owner.
 */
function authorizeApiAccess(credential, request) {
    if (credential.revokedAt)
        return { allowed: false, reason: "REVOKED" };
    if (credential.expiresAt && new Date(credential.expiresAt).getTime() <= (request.now ?? new Date()).getTime()) {
        return { allowed: false, reason: "EXPIRED" };
    }
    if (credential.workspaceId && credential.workspaceId !== request.workspaceId) {
        return { allowed: false, reason: "WORKSPACE_MISMATCH" };
    }
    if (!credential.scopes.includes(request.scope))
        return { allowed: false, reason: "SCOPE_DENIED" };
    return { allowed: true };
}
/** Remove secret hash material before returning list-safe metadata to a caller. */
function toApiAccessCredentialMetadata(credential) {
    const { secretHash: _secretHash, ...metadata } = credential;
    return Object.freeze({ ...metadata, scopes: Object.freeze([...credential.scopes]) });
}
function normalizeScopes(scopes) {
    const values = [...new Set(scopes)];
    if (values.length === 0)
        throw new Error("At least one API scope is required.");
    for (const scope of values)
        requireText(scope, "API scope");
    return Object.freeze(values);
}
function requireText(value, label) {
    if (!value.trim())
        throw new Error(`${label} must not be empty.`);
}
