import { describe, expect, it } from "vitest";
import {
  authenticateApiAccessCredential,
  authorizeApiAccess,
  defineApiAccessPepperRing,
  getApiAccessCredentialStatus,
  hashApiAccessSecret,
  issueApiAccessCredential,
  issueReplacementApiAccessCredential,
  parseApiAccessSecret,
  verifyApiAccessSecret,
  type ApiAccessCredential,
} from "./index.js";

const pepper = { version: "2026-01", value: "test-pepper" };

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
    expect(verifyApiAccessSecret(parsed.secret, issued.credential.secretHash, pepper.value)).toBe(true);
  });

  it("fails when the secret is off by a single character", () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const parsed = parseApiAccessSecret(issued.secret, "miz_")!;
    const flipped = parsed.secret.slice(0, -1) + (parsed.secret.at(-1) === "a" ? "b" : "a");
    expect(verifyApiAccessSecret(flipped, issued.credential.secretHash, pepper.value)).toBe(false);
  });

  it("fails when hashed with the wrong pepper", () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const parsed = parseApiAccessSecret(issued.secret, "miz_")!;
    expect(verifyApiAccessSecret(parsed.secret, issued.credential.secretHash, "wrong-pepper")).toBe(false);
  });

  it("does not throw on hashes of a different length", () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["read"] });
    const parsed = parseApiAccessSecret(issued.secret, "miz_")!;
    expect(verifyApiAccessSecret(parsed.secret, "short-hash", pepper.value)).toBe(false);
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
        peppers: [{ version: "some-other-version", value: "unrelated" }],
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
    const p1 = { version: "v1", value: "value-1" };
    const p2 = { version: "v2", value: "value-2" };
    const p3 = { version: "v3", value: "value-3" };
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

  it("authorizeApiAccess reports EXPIRED (not INVALID) for a malformed expiresAt", () => {
    const credential = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"] }).credential;
    const decision = authorizeApiAccess({ ...credential, expiresAt: "not-a-date" }, { scope: "items.read" });
    expect(decision).toEqual({ allowed: false, reason: "EXPIRED" });
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
    const newPepper = { version: "2027-01", value: "rotated-pepper" };
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
    ).toThrow("at least 16 random bytes");
  });

  it("rejects a non-integer secretBytes", () => {
    expect(() =>
      issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["items.read"], secretBytes: 16.5 }),
    ).toThrow("at least 16 random bytes");
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
