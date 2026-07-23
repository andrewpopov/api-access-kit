import { describe, expect, it } from "vitest";
import {
  API_ACCESS_HASH_VERSION_V1,
  API_ACCESS_HASH_VERSION_V2,
  authenticateApiAccessCredential,
  authorizeApiAccess,
  defineApiAccessPepperRing,
  getApiAccessCredentialStatus,
  hashApiAccessSecret,
  issueApiAccessCredential,
  MAX_API_ACCESS_SECRET_BYTES,
  issueReplacementApiAccessCredential,
  parseApiAccessSecret,
  verifyApiAccessSecret,
  type ApiAccessCredential,
} from "./index.js";

const pepper = { version: "2026-01", value: "test-pepper-value" };

describe("parseApiAccessSecret adversarial inputs", () => {
  it("rejects empty input", () => {
    expect(parseApiAccessSecret("", "miz_")).toBeUndefined();
  });

  it("rejects a secret with the wrong prefix", () => {
    expect(parseApiAccessSecret("other_credential-1.abcdefghijklmnopqrst", "miz_")).toBeUndefined();
  });

  it("rejects a secret missing the dot separator", () => {
    expect(parseApiAccessSecret("miz_credential-1abcdefghijklmnopqrst", "miz_")).toBeUndefined();
  });

  it("rejects a secret with the id empty (dot immediately after prefix)", () => {
    expect(parseApiAccessSecret("miz_.abcdefghijklmnopqrstuvwx", "miz_")).toBeUndefined();
  });

  it("rejects a secret with more than one dot", () => {
    expect(parseApiAccessSecret("miz_credential-1.abc.def", "miz_")).toBeUndefined();
  });

  it("rejects truncated / undersized entropy (fewer than 20 chars)", () => {
    expect(parseApiAccessSecret("miz_credential-1.short", "miz_")).toBeUndefined();
  });

  it("rejects an id containing illegal characters", () => {
    expect(parseApiAccessSecret("miz_cred ential.abcdefghijklmnopqrstuvwx", "miz_")).toBeUndefined();
  });

  it("rejects entropy containing illegal characters", () => {
    expect(parseApiAccessSecret("miz_credential-1.abc def ghijklmnopqrst!!", "miz_")).toBeUndefined();
  });

  it("accepts a well-formed secret at the minimum entropy length", () => {
    const parsed = parseApiAccessSecret(`miz_credential-1.${"a".repeat(20)}`, "miz_");
    expect(parsed).toEqual({ id: "credential-1", secret: "a".repeat(20) });
  });

  it("handles oversized entropy without throwing", () => {
    const parsed = parseApiAccessSecret(`miz_credential-1.${"a".repeat(5000)}`, "miz_");
    expect(parsed).toEqual({ id: "credential-1", secret: "a".repeat(5000) });
  });
});

describe("verifyApiAccessSecret", () => {
  it("passes for the exact original secret", () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const parsed = parseApiAccessSecret(issued.secret, "miz_")!;
    expect(verifyApiAccessSecret(parsed.secret, issued.credential.secretHash, pepper.value, API_ACCESS_HASH_VERSION_V2)).toBe(true);
  });

  it("fails when the secret is off by a single character", () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const parsed = parseApiAccessSecret(issued.secret, "miz_")!;
    const flipped = parsed.secret.slice(0, -1) + (parsed.secret.at(-1) === "a" ? "b" : "a");
    expect(verifyApiAccessSecret(flipped, issued.credential.secretHash, pepper.value, API_ACCESS_HASH_VERSION_V2)).toBe(false);
  });

  it("fails when hashed with the wrong pepper", () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const parsed = parseApiAccessSecret(issued.secret, "miz_")!;
    expect(verifyApiAccessSecret(parsed.secret, issued.credential.secretHash, "wrong-pepper", API_ACCESS_HASH_VERSION_V2)).toBe(false);
  });

  it("does not throw on hashes of a different length", () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const parsed = parseApiAccessSecret(issued.secret, "miz_")!;
    expect(verifyApiAccessSecret(parsed.secret, "short-hash", pepper.value, API_ACCESS_HASH_VERSION_V2)).toBe(false);
  });

  it("hashApiAccessSecret is deterministic for identical inputs", () => {
    expect(hashApiAccessSecret("secret-a", "pepper-a")).toBe(hashApiAccessSecret("secret-a", "pepper-a"));
    expect(hashApiAccessSecret("secret-a", "pepper-a")).not.toBe(hashApiAccessSecret("secret-a", "pepper-b"));
  });

  it("hashApiAccessSecret rejects empty secret or pepper", () => {
    expect(() => hashApiAccessSecret("", "pepper")).toThrow("Credential secret");
    expect(() => hashApiAccessSecret("secret", "")).toThrow("Credential pepper");
  });
});

describe("pepper rotation and unknown pepper versions", () => {
  const makeStore = (credential: ApiAccessCredential) => ({ findById: async () => credential });

  it("authenticates against an old pepper still present in the ring", async () => {
    const oldPepper = { version: "2025-01", value: "old-pepper-value" };
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper: oldPepper, scopes: ["read"] });
    const store = makeStore(issued.credential);
    await expect(
      authenticateApiAccessCredential({
        rawCredential: issued.secret,
        prefix: "miz_",
        store,
        peppers: [oldPepper, { version: "2026-01", value: "new-pepper-value" }],
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  it("fails closed when the credential's pepper version is missing from the ring", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const store = makeStore(issued.credential);
    await expect(
      authenticateApiAccessCredential({
        rawCredential: issued.secret,
        prefix: "miz_",
        store,
        peppers: [{ version: "some-other-version", value: "unrelated-pepper-value" }],
      }),
    ).resolves.toEqual({ ok: false, reason: "UNKNOWN_PEPPER_VERSION" });
  });

  it("rejects duplicate pepper versions with different values (ambiguous ring) when authenticating", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const store = makeStore(issued.credential);
    await expect(
      authenticateApiAccessCredential({
        rawCredential: issued.secret,
        prefix: "miz_",
        store,
        peppers: [pepper, { version: pepper.version, value: "a-different-value" }],
      }),
    ).resolves.toEqual({ ok: false, reason: "INVALID_PEPPER_RING" });
  });

  it("supports many peppers in the ring simultaneously (multi-rotation)", async () => {
    const p1 = { version: "v1", value: "value-1-padded-pepper" };
    const p2 = { version: "v2", value: "value-2-padded-pepper" };
    const p3 = { version: "v3", value: "value-3-padded-pepper" };
    const issuedUnderP2 = issueApiAccessCredential({ id: "credential-2", ownerId: "user-1", prefix: "miz_", pepper: p2, scopes: ["read"] });
    const store = makeStore(issuedUnderP2.credential);
    await expect(
      authenticateApiAccessCredential({ rawCredential: issuedUnderP2.secret, prefix: "miz_", store, peppers: [p1, p2, p3] }),
    ).resolves.toMatchObject({ ok: true });
  });

  it("defineApiAccessPepperRing.find returns undefined for an unknown version", () => {
    const ring = defineApiAccessPepperRing([pepper]);
    expect(ring.find("does-not-exist")).toBeUndefined();
  });
});

describe("scope matching edge cases (exact-match semantics)", () => {
  it("denies a scope that is a superstring or substring of a granted scope", () => {
    const credential = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] }).credential;
    expect(authorizeApiAccess(credential, { scope: "items.read.extra" })).toEqual({ allowed: false, reason: "SCOPE_DENIED" });
    expect(authorizeApiAccess(credential, { scope: "items" })).toEqual({ allowed: false, reason: "SCOPE_DENIED" });
  });

  it("is case sensitive: differently-cased scope is denied", () => {
    const credential = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] }).credential;
    expect(authorizeApiAccess(credential, { scope: "ITEMS.READ" })).toEqual({ allowed: false, reason: "SCOPE_DENIED" });
  });

  it("rejects issuance with an empty scopes array", () => {
    expect(() =>
      issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: [] }),
    ).toThrow("At least one API scope is required");
  });

  it("de-duplicates repeated scopes on issuance", () => {
    const credential = issueApiAccessCredential({
      id: "credential-1",
      ownerId: "user-1",
      prefix: "miz_",
      pepper,
      scopes: ["items.read", "items.read", "items.write"],
    }).credential;
    expect(credential.scopes).toEqual(["items.read", "items.write"]);
  });

  it("no workspace binding on the credential allows any requested workspace", () => {
    const credential = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] }).credential;
    expect(authorizeApiAccess(credential, { scope: "items.read", workspaceId: "any-workspace" })).toEqual({ allowed: true });
    expect(authorizeApiAccess(credential, { scope: "items.read" })).toEqual({ allowed: true });
  });
});

describe("lifecycle status precedence and expiry boundary", () => {
  it("REVOKED takes precedence over EXPIRED", () => {
    const status = getApiAccessCredentialStatus({
      revokedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2020-01-01T00:00:00.000Z",
    });
    expect(status).toBe("REVOKED");
  });

  it("REVOKED takes precedence over an INVALID expiresAt", () => {
    const status = getApiAccessCredentialStatus({
      revokedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "not-a-date",
    });
    expect(status).toBe("REVOKED");
  });

  it("treats expiry at exactly `now` as EXPIRED (boundary is inclusive)", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const status = getApiAccessCredentialStatus({ expiresAt: now.toISOString() }, now);
    expect(status).toBe("EXPIRED");
  });

  it("treats expiry one millisecond after `now` as still ACTIVE", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    const status = getApiAccessCredentialStatus({ expiresAt: new Date(now.getTime() + 1).toISOString() }, now);
    expect(status).toBe("ACTIVE");
  });

  it("authorizeApiAccess reports INVALID for a malformed expiresAt", () => {
    const credential = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] }).credential;
    const decision = authorizeApiAccess({ ...credential, expiresAt: "not-a-date" }, { scope: "items.read" });
    expect(decision).toEqual({ allowed: false, reason: "INVALID" });
  });

  it("authenticateApiAccessCredential surfaces REVOKED even when also expired", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] });
    const revokedAndExpired: ApiAccessCredential = {
      ...issued.credential,
      revokedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2020-01-01T00:00:00.000Z",
    };
    const store = { findById: async () => revokedAndExpired };
    await expect(
      authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [pepper] }),
    ).resolves.toEqual({ ok: false, reason: "REVOKED" });
  });

  it("authenticateApiAccessCredential reports MALFORMED for an unsupported formatVersion", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] });
    const badFormat = { ...issued.credential, formatVersion: 2 as unknown as 1 };
    const store = { findById: async () => badFormat };
    await expect(
      authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [pepper] }),
    ).resolves.toEqual({ ok: false, reason: "MALFORMED" });
  });

  it("authenticateApiAccessCredential reports NOT_FOUND when the store has no record", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] });
    const store = { findById: async () => null };
    await expect(
      authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [pepper] }),
    ).resolves.toEqual({ ok: false, reason: "NOT_FOUND" });
  });

  it("authenticateApiAccessCredential reports MALFORMED for an unparsable raw credential", async () => {
    const store = { findById: async () => null };
    await expect(
      authenticateApiAccessCredential({ rawCredential: "not-even-close", prefix: "miz_", store, peppers: [pepper] }),
    ).resolves.toEqual({ ok: false, reason: "MALFORMED" });
  });
});

describe("issueReplacementApiAccessCredential invariants", () => {
  it("rejects replacing an already-expired credential", () => {
    const original = issueApiAccessCredential({
      id: "credential-1",
      ownerId: "user-1",
      prefix: "miz_",
      pepper,
      scopes: ["items.read"],
      expiresAt: "2020-01-01T00:00:00.000Z",
    }).credential;
    expect(() =>
      issueReplacementApiAccessCredential({ credential: original, id: "credential-2", prefix: "miz_", pepper }),
    ).toThrow("Only an active API credential");
  });

  it("preserves ownerId, scopes, workspaceId, and expiresAt across a rotation with a new prefix and pepper", () => {
    const original = issueApiAccessCredential({
      id: "credential-1",
      ownerId: "owner-9",
      prefix: "miz_",
      pepper,
      scopes: ["items.read", "items.write"],
      workspaceId: "workspace-9",
      expiresAt: "2030-01-01T00:00:00.000Z",
    }).credential;
    const newPepper = { version: "2027-01", value: "rotated-pepper-value" };
    const replacement = issueReplacementApiAccessCredential({
      credential: original,
      id: "credential-2",
      prefix: "other_",
      pepper: newPepper,
    });
    expect(replacement.secret.startsWith("other_credential-2.")).toBe(true);
    expect(replacement.credential).toMatchObject({
      ownerId: "owner-9",
      scopes: ["items.read", "items.write"],
      workspaceId: "workspace-9",
      expiresAt: "2030-01-01T00:00:00.000Z",
      pepperVersion: "2027-01",
    });
    expect(replacement.credential.secretHash).not.toBe(original.secretHash);
  });

  it("does not carry over revokedAt from the original credential", () => {
    const original = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] }).credential;
    const replacement = issueReplacementApiAccessCredential({ credential: original, id: "credential-2", prefix: "miz_", pepper });
    expect(replacement.credential.revokedAt).toBeUndefined();
  });
});

describe("issueApiAccessCredential input validation", () => {
  it("rejects a prefix containing disallowed characters", () => {
    expect(() =>
      issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz.", pepper, scopes: ["items.read"] }),
    ).toThrow("Credential prefix must contain only letters, numbers, underscores, or dashes.");
  });

  it("rejects secretBytes below the 16-byte floor", () => {
    expect(() =>
      issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"], secretBytes: 8 }),
    ).toThrow("between 16 and 256 random bytes");
  });

  it("rejects a non-integer secretBytes", () => {
    expect(() =>
      issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"], secretBytes: 16.5 }),
    ).toThrow("between 16 and 256 random bytes");
  });

  it("rejects secretBytes above the upper bound", () => {
    expect(() =>
      issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"], secretBytes: 100000 }),
    ).toThrow("between 16 and 256 random bytes");
  });

  it("issues a credential at MAX_API_ACCESS_SECRET_BYTES that still authenticates (raw-credential bound consistency)", async () => {
    const issued = issueApiAccessCredential({
      id: "credential-1",
      ownerId: "user-1",
      prefix: "miz_",
      pepper,
      scopes: ["items.read"],
      secretBytes: MAX_API_ACCESS_SECRET_BYTES,
    });
    const store = { findById: async () => issued.credential };
    await expect(
      authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [pepper] }),
    ).resolves.toEqual({ ok: true, credential: issued.credential });
  });

  it("rejects an empty id, ownerId, or pepper value", () => {
    expect(() => issueApiAccessCredential({ id: "", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] })).toThrow(
      "Credential id",
    );
    expect(() => issueApiAccessCredential({ id: "credential-1", ownerId: "  ", prefix: "miz_", pepper, scopes: ["items.read"] })).toThrow(
      "Credential owner id",
    );
    expect(() =>
      issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper: { version: "v1", value: "" }, scopes: ["items.read"] }),
    ).toThrow("Credential pepper");
  });
});

describe("hash version v1/v2 support", () => {
  const makeStore = (credential: ApiAccessCredential) => ({ findById: async () => credential });

  it("defaults freshly issued credentials to hashVersion v2", () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    expect(issued.credential.hashVersion).toBe(API_ACCESS_HASH_VERSION_V2);
  });

  it("authenticates a v2 credential end-to-end", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const store = makeStore(issued.credential);
    await expect(
      authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [pepper] }),
    ).resolves.toMatchObject({ ok: true });
  });

  it("still authenticates a credential explicitly issued with hashVersion v1 (back-compat)", async () => {
    const issued = issueApiAccessCredential({
      id: "credential-1",
      ownerId: "user-1",
      prefix: "miz_",
      pepper,
      scopes: ["read"],
      hashVersion: API_ACCESS_HASH_VERSION_V1,
    });
    expect(issued.credential.hashVersion).toBe(API_ACCESS_HASH_VERSION_V1);
    const store = makeStore(issued.credential);
    await expect(
      authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [pepper] }),
    ).resolves.toMatchObject({ ok: true });
  });

  it("authenticates a stored v1 credential against a frozen historical hash vector", async () => {
    // Golden vector: secretHash independently computed as base64url(SHA-256(pepper + 0x00 + entropy))
    // for entropy "abcdefghijklmnopqrstuvwxyz012345" and pepper "golden-pepper-value" — the exact
    // v1 algorithm as it shipped. If a future change to v1 hashing breaks this, it silently breaks
    // every already-issued v1 credential, so this constant must never be "updated" to match new code.
    const golden: ApiAccessCredential = Object.freeze({
      id: "cred-v1",
      ownerId: "user-1",
      formatVersion: 1,
      hashVersion: API_ACCESS_HASH_VERSION_V1,
      pepperVersion: "golden",
      secretHash: "rhdX-uNR87ldZTZexFwuzwi3lH8wso4nz2Ak-k-UuOg",
      scopes: Object.freeze(["read"]),
      createdAt: "2026-01-01T00:00:00.000Z",
    });
    const store = makeStore(golden);
    await expect(
      authenticateApiAccessCredential({
        rawCredential: "golden_cred-v1.abcdefghijklmnopqrstuvwxyz012345",
        prefix: "golden_",
        store,
        peppers: [{ version: "golden", value: "golden-pepper-value" }],
      }),
    ).resolves.toMatchObject({ ok: true });
  });

  it("produces different hashes for v1 and v2 given the same secret and pepper", () => {
    const v1Hash = hashApiAccessSecret("secret-a", "pepper-a", API_ACCESS_HASH_VERSION_V1);
    const v2Hash = hashApiAccessSecret("secret-a", "pepper-a", API_ACCESS_HASH_VERSION_V2);
    expect(v1Hash).not.toBe(v2Hash);
  });

  it("verifyApiAccessSecret returns false when given the wrong hashVersion for a stored hash", () => {
    const storedHash = hashApiAccessSecret("secret-a", "pepper-a", API_ACCESS_HASH_VERSION_V1);
    expect(verifyApiAccessSecret("secret-a", storedHash, "pepper-a", API_ACCESS_HASH_VERSION_V2)).toBe(false);
  });

  it("rejects issuance with an unsupported hashVersion", () => {
    expect(() =>
      issueApiAccessCredential({
        id: "credential-1",
        ownerId: "user-1",
        prefix: "miz_",
        pepper,
        scopes: ["read"],
        hashVersion: "argon2id-v2" as unknown as typeof API_ACCESS_HASH_VERSION_V1,
      }),
    ).toThrow('Unsupported hash version "argon2id-v2"');
  });

  it("authenticates to UNSUPPORTED_HASH_VERSION when a stored credential's hashVersion is an unknown string", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const store = makeStore({ ...issued.credential, hashVersion: "argon2id-v2" });
    await expect(
      authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [pepper] }),
    ).resolves.toEqual({ ok: false, reason: "UNSUPPORTED_HASH_VERSION" });
  });
});

describe("minimum pepper strength", () => {
  it("defineApiAccessPepperRing rejects a pepper shorter than 16 characters", () => {
    expect(() => defineApiAccessPepperRing([{ version: "v1", value: "tooshort" }])).toThrow(/at least 16 characters/);
  });

  it("issueApiAccessCredential rejects a pepper shorter than 16 characters", () => {
    expect(() =>
      issueApiAccessCredential({
        id: "credential-1",
        ownerId: "user-1",
        prefix: "miz_",
        pepper: { version: "v1", value: "tooshort" },
        scopes: ["items.read"],
      }),
    ).toThrow(/at least 16 characters/);
  });
});

describe("NOT_FOUND timing mitigation", () => {
  it("still authenticates to NOT_FOUND without throwing when the store misses", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] });
    const store = { findById: async () => null };
    await expect(
      authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [pepper] }),
    ).resolves.toEqual({ ok: false, reason: "NOT_FOUND" });
  });
});

describe("input upper bounds", () => {
  it("authenticateApiAccessCredential reports MALFORMED for an over-length raw credential", async () => {
    const store = { findById: async () => null };
    const oversized = `miz_credential-1.${"a".repeat(5000)}`;
    await expect(
      authenticateApiAccessCredential({ rawCredential: oversized, prefix: "miz_", store, peppers: [pepper] }),
    ).resolves.toEqual({ ok: false, reason: "MALFORMED" });
  });
});

describe("strict ISO timestamp parsing", () => {
  it("treats a date-only expiresAt as INVALID", () => {
    expect(getApiAccessCredentialStatus({ expiresAt: "2026-07-23" })).toBe("INVALID");
  });

  it("treats a nonsense expiresAt as INVALID", () => {
    expect(getApiAccessCredentialStatus({ expiresAt: "not-a-date" })).toBe("INVALID");
  });

  it("authorizeApiAccess reports INVALID for a date-only expiresAt", () => {
    const credential = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] }).credential;
    expect(authorizeApiAccess({ ...credential, expiresAt: "2026-07-23" }, { scope: "items.read" })).toEqual({
      allowed: false,
      reason: "INVALID",
    });
  });

  it("still accepts a full ISO timestamp for ACTIVE and EXPIRED", () => {
    const now = new Date("2026-01-01T00:00:00.000Z");
    expect(getApiAccessCredentialStatus({ expiresAt: "2026-06-01T00:00:00.000Z" }, now)).toBe("ACTIVE");
    expect(getApiAccessCredentialStatus({ expiresAt: "2025-06-01T00:00:00.000Z" }, now)).toBe("EXPIRED");
  });

  it("treats an impossible day-of-month (Feb 30) as INVALID", () => {
    expect(getApiAccessCredentialStatus({ expiresAt: "2026-02-30T00:00:00Z" })).toBe("INVALID");
  });

  it("treats an out-of-range month (13) as INVALID", () => {
    expect(getApiAccessCredentialStatus({ expiresAt: "2026-13-01T00:00:00Z" })).toBe("INVALID");
  });

  it("treats Feb 29 in a non-leap year (2026) as INVALID", () => {
    expect(getApiAccessCredentialStatus({ expiresAt: "2026-02-29T00:00:00Z" })).toBe("INVALID");
  });

  it("accepts Feb 29 in a leap year (2024) as a valid calendar date", () => {
    expect(getApiAccessCredentialStatus({ expiresAt: "2024-02-29T00:00:00Z" })).not.toBe("INVALID");
  });
});
