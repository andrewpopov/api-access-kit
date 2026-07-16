"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.evaluateApiCommandPrecondition = exports.evaluateApiCommandIdempotency = exports.defineApiCommands = exports.createApiCommandReceipt = exports.createApiCommandFingerprint = void 0;
exports.defineApiScopes = defineApiScopes;
exports.defineApiAccessPepperRing = defineApiAccessPepperRing;
exports.issueApiAccessCredential = issueApiAccessCredential;
exports.issueReplacementApiAccessCredential = issueReplacementApiAccessCredential;
exports.runApiAccessCredentialLifecycleConformance = runApiAccessCredentialLifecycleConformance;
exports.hashApiAccessSecret = hashApiAccessSecret;
exports.verifyApiAccessSecret = verifyApiAccessSecret;
exports.parseApiAccessSecret = parseApiAccessSecret;
exports.authenticateApiAccessCredential = authenticateApiAccessCredential;
exports.getApiAccessCredentialStatus = getApiAccessCredentialStatus;
exports.formatApiAccessCredentialMask = formatApiAccessCredentialMask;
exports.authorizeApiAccess = authorizeApiAccess;
exports.toApiAccessCredentialMetadata = toApiAccessCredentialMetadata;
const node_crypto_1 = require("node:crypto");
var commands_js_1 = require("./commands.js");
Object.defineProperty(exports, "createApiCommandFingerprint", { enumerable: true, get: function () { return commands_js_1.createApiCommandFingerprint; } });
Object.defineProperty(exports, "createApiCommandReceipt", { enumerable: true, get: function () { return commands_js_1.createApiCommandReceipt; } });
Object.defineProperty(exports, "defineApiCommands", { enumerable: true, get: function () { return commands_js_1.defineApiCommands; } });
Object.defineProperty(exports, "evaluateApiCommandIdempotency", { enumerable: true, get: function () { return commands_js_1.evaluateApiCommandIdempotency; } });
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
/**
 * Validate a named pepper ring before a host uses it for issuance or
 * authentication. Environment-variable parsing remains host-owned so this
 * package never dictates configuration names or secret providers.
 */
function defineApiAccessPepperRing(peppers) {
    if (peppers.length === 0)
        throw new Error("At least one API credential pepper is required.");
    const seen = new Set();
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
        find(version) {
            return frozen.find((candidate) => candidate.version === version);
        },
    });
}
/**
 * Issue a v1 opaque credential once; persist only the public id and a hash of
 * its random secret segment. `prefix` is literal (for example `cairn_`).
 */
function issueApiAccessCredential(input) {
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
    const secret = `${input.prefix}${input.id}.${(0, node_crypto_1.randomBytes)(secretBytes).toString("base64url")}`;
    const credential = Object.freeze({
        id: input.id,
        ownerId: input.ownerId,
        formatVersion: 1,
        hashVersion: input.hashVersion ?? "sha256-peppered-secret-v1",
        pepperVersion: input.pepper.version,
        secretHash: hashApiAccessSecret(parseApiAccessSecret(secret, input.prefix).secret, input.pepper.value),
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
function issueReplacementApiAccessCredential(input) {
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
async function runApiAccessCredentialLifecycleConformance(input) {
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
    if (!secret.startsWith(prefix))
        return undefined;
    const rest = secret.slice(prefix.length);
    const dot = rest.indexOf(".");
    if (dot < 1 || dot !== rest.lastIndexOf("."))
        return undefined;
    const id = rest.slice(0, dot);
    const entropy = rest.slice(dot + 1);
    if (!/^[A-Za-z0-9_-]+$/.test(id) || !/^[A-Za-z0-9_-]{20,}$/.test(entropy))
        return undefined;
    return { id, secret: entropy };
}
/**
 * Perform indexed public-id lookup followed by constant-time secret comparison.
 * This is deliberately lifecycle-only: hosts still apply their resource policy
 * after an allowed credential is mapped to a principal.
 */
async function authenticateApiAccessCredential(input) {
    const parsed = parseApiAccessSecret(input.rawCredential, input.prefix);
    if (!parsed)
        return { ok: false, reason: "MALFORMED" };
    let peppers;
    try {
        peppers = defineApiAccessPepperRing(input.peppers);
    }
    catch {
        return { ok: false, reason: "INVALID_PEPPER_RING" };
    }
    const credential = await input.store.findById(parsed.id);
    if (!credential)
        return { ok: false, reason: "NOT_FOUND" };
    if (credential.formatVersion !== 1)
        return { ok: false, reason: "MALFORMED" };
    const pepper = peppers.find(credential.pepperVersion);
    if (!pepper)
        return { ok: false, reason: "UNKNOWN_PEPPER_VERSION" };
    if (!verifyApiAccessSecret(parsed.secret, credential.secretHash, pepper.value)) {
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
function getApiAccessCredentialStatus(credential, now = new Date()) {
    if (credential.revokedAt)
        return "REVOKED";
    if (!credential.expiresAt)
        return "ACTIVE";
    const expiresAt = new Date(credential.expiresAt).getTime();
    if (Number.isNaN(expiresAt))
        return "INVALID";
    return expiresAt <= now.getTime() ? "EXPIRED" : "ACTIVE";
}
/** Return a safe human-readable representation using only public metadata. */
function formatApiAccessCredentialMask(prefix, credentialId) {
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
function authorizeApiAccess(credential, request) {
    const status = getApiAccessCredentialStatus(credential, request.now);
    if (status === "REVOKED")
        return { allowed: false, reason: "REVOKED" };
    if (status === "EXPIRED" || status === "INVALID") {
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
function assertCredentialEquivalent(actual, expected, action) {
    if (!actual)
        throw new Error(`Conformance ${action} did not persist the credential.`);
    const fields = [
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
function requireText(value, label) {
    if (!value.trim())
        throw new Error(`${label} must not be empty.`);
}
