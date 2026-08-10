import { describe, expect, it } from "vitest";
import {
  API_ACCESS_HASH_VERSION_V2,
  authorizeApiAccess,
  authenticateApiAccessCredential,
  createApiAccessPrincipalBinding,
  defineApiAccessPepperRing,
  defineApiScopes,
  formatApiAccessCredentialMask,
  getApiAccessCredentialStatus,
  hashApiAccessSecret,
  issueApiAccessCredential,
  issueReplacementApiAccessCredential,
  parseApiAccessSecret,
  toApiAccessCredentialMetadata,
  runApiAccessCredentialLifecycleConformance,
  verifyApiAccessSecret,
} from "./index.js";
import {
  createApiCommandFingerprint,
  createApiCommandReceipt,
  defineApiCommands,
  evaluateApiCommandIdempotency,
  evaluateApiCommandPrecondition,
  type ApiCommandEnvelope,
} from "./index.js";

const pepper = { version: "2026-01", value: "test-pepper-value" };

describe("api-access-kit", () => {
  it("separates an accountable credential owner from its resource authorization principal", () => {
    const credential = issueApiAccessCredential({
      id: "credential-organization",
      ownerId: "user-issuer",
      prefix: "miz_",
      pepper,
      scopes: ["mizen.items.read"],
    }).credential;

    const binding = createApiAccessPrincipalBinding({
      credential,
      principalType: "organization",
      principalId: "org-1",
    });

    expect(binding).toEqual({
      credentialId: "credential-organization",
      issuerId: "user-issuer",
      principalType: "organization",
      principalId: "org-1",
    });
    expect(Object.isFrozen(binding)).toBe(true);
    expect(() => createApiAccessPrincipalBinding({ credential, principalType: "", principalId: "org-1" })).toThrow("principal type");
  });

  it("issues a one-time opaque secret while retaining only a hash", () => {
    const issued = issueApiAccessCredential({
      id: "credential-1",
      ownerId: "user-1",
      prefix: "miz_",
      pepper,
      scopes: ["mizen.items.read", "mizen.items.write"],
      workspaceId: "workspace-1",
    });
    expect(issued.secret).toMatch(/^miz_credential-1\./);
    expect(issued.credential.secretHash).not.toContain(issued.secret);
    expect(parseApiAccessSecret(issued.secret, "miz_")).toMatchObject({ id: "credential-1" });
    const parsed = parseApiAccessSecret(issued.secret, "miz_")!;
    expect(verifyApiAccessSecret(parsed.secret, issued.credential.secretHash, pepper.value, API_ACCESS_HASH_VERSION_V2)).toBe(true);
    expect(verifyApiAccessSecret(`${parsed.secret}x`, issued.credential.secretHash, pepper.value, API_ACCESS_HASH_VERSION_V2)).toBe(false);
  });

  it("fails closed for lifecycle, scope, and workspace constraints", () => {
    const credential = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.write"], workspaceId: "workspace-1" }).credential;
    expect(authorizeApiAccess(credential, { scope: "mizen.items.write", workspaceId: "workspace-1" })).toEqual({ allowed: true });
    expect(authorizeApiAccess(credential, { scope: "mizen.items.read", workspaceId: "workspace-1" })).toEqual({ allowed: false, reason: "SCOPE_DENIED" });
    expect(authorizeApiAccess(credential, { scope: "mizen.items.write", workspaceId: "workspace-2" })).toEqual({ allowed: false, reason: "WORKSPACE_MISMATCH" });
    expect(authorizeApiAccess({ ...credential, revokedAt: "2026-01-01T00:00:00Z" }, { scope: "mizen.items.write", workspaceId: "workspace-1" })).toEqual({ allowed: false, reason: "REVOKED" });
    expect(authorizeApiAccess({ ...credential, expiresAt: "2026-01-01T00:00:00Z" }, { scope: "mizen.items.write", workspaceId: "workspace-1", now: new Date("2026-01-02T00:00:00Z") })).toEqual({ allowed: false, reason: "EXPIRED" });
  });

  it("keeps scope declaration exact and list metadata secret-safe", () => {
    const scopes = defineApiScopes(["mizen.items.read", "mizen.items.write"] as const);
    expect(scopes.has("mizen.items.write")).toBe(true);
    expect(() => scopes.assert("mizen.items.*")).toThrow("Unknown API scope");
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"] });
    expect(toApiAccessCredentialMetadata(issued.credential)).not.toHaveProperty("secretHash");
    expect(hashApiAccessSecret(parseApiAccessSecret(issued.secret, "miz_")!.secret, pepper.value)).toBe(issued.credential.secretHash);
  });

  it("uses indexed public-id lookup and a pepper key ring without logging or storing the raw secret", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"] });
    const store = { findById: async (id: string) => id === issued.credential.id ? issued.credential : null };
    await expect(authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [{ version: "old", value: "old-pepper-value" }, pepper] })).resolves.toMatchObject({ ok: true, credential: { id: "credential-1" } });
    await expect(authenticateApiAccessCredential({ rawCredential: `${issued.secret}x`, prefix: "miz_", store, peppers: [pepper] })).resolves.toEqual({ ok: false, reason: "HASH_MISMATCH" });
    await expect(authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [] })).resolves.toEqual({ ok: false, reason: "INVALID_PEPPER_RING" });
  });

  it("validates pepper rings and fails closed when authentication receives an invalid ring", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"] });
    const store = { findById: async () => issued.credential };
    const ring = defineApiAccessPepperRing([{ version: "old", value: "old-pepper-value" }, pepper]);
    expect(ring.primary).toEqual({ version: "old", value: "old-pepper-value" });
    expect(ring.find("2026-01")).toEqual(pepper);
    expect(() => defineApiAccessPepperRing([])).toThrow("At least one API credential pepper");
    expect(() => defineApiAccessPepperRing([pepper, pepper])).toThrow("Duplicate credential pepper version");
    await expect(authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [pepper, pepper] })).resolves.toEqual({ ok: false, reason: "INVALID_PEPPER_RING" });
  });

  it("rejects authentication for a credential stamped with an unsupported hashVersion", async () => {
    const issued = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"] });
    expect(issued.credential.hashVersion).toBe(API_ACCESS_HASH_VERSION_V2);
    const store = { findById: async () => ({ ...issued.credential, hashVersion: "argon2id-v2" }) };
    await expect(authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [pepper] })).resolves.toEqual({ ok: false, reason: "UNSUPPORTED_HASH_VERSION" });

    const supportedStore = { findById: async () => issued.credential };
    await expect(authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store: supportedStore, peppers: [pepper] })).resolves.toMatchObject({ ok: true, credential: { id: "credential-1" } });
  });

  it("rejects issuance with an unsupported hashVersion", () => {
    expect(() =>
      issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"], hashVersion: "argon2id-v2" as unknown as typeof API_ACCESS_HASH_VERSION_V2 }),
    ).toThrow('Unsupported hash version "argon2id-v2"');
  });

  it("issues replacement material for active credentials without widening portable fields", () => {
    const original = issueApiAccessCredential({
      id: "credential-1",
      ownerId: "user-1",
      prefix: "miz_",
      pepper,
      scopes: ["mizen.items.read"],
      workspaceId: "workspace-1",
      expiresAt: "2026-12-01T00:00:00.000Z",
    }).credential;
    const replacement = issueReplacementApiAccessCredential({
      credential: original,
      id: "credential-2",
      prefix: "miz_",
      pepper: { version: "2026-02", value: "replacement-pepper" },
      now: new Date("2026-01-01T00:00:00.000Z"),
    });
    expect(replacement.secret).toMatch(/^miz_credential-2\./);
    expect(replacement.credential).toMatchObject({
      id: "credential-2",
      ownerId: "user-1",
      scopes: ["mizen.items.read"],
      workspaceId: "workspace-1",
      expiresAt: "2026-12-01T00:00:00.000Z",
      pepperVersion: "2026-02",
    });
    expect(() => issueReplacementApiAccessCredential({ credential: { ...original, revokedAt: "2026-01-01T00:00:00.000Z" }, id: "credential-3", prefix: "miz_", pepper })).toThrow("Only an active API credential");
  });

  it("reports credential status and produces a secret-safe canonical mask", () => {
    expect(getApiAccessCredentialStatus({})).toBe("ACTIVE");
    expect(getApiAccessCredentialStatus({ revokedAt: "2026-01-01T00:00:00.000Z" })).toBe("REVOKED");
    expect(getApiAccessCredentialStatus({ expiresAt: "2026-01-01T00:00:00.000Z" }, new Date("2026-01-02T00:00:00.000Z"))).toBe("EXPIRED");
    expect(getApiAccessCredentialStatus({ expiresAt: "not-a-date" })).toBe("INVALID");
    expect(formatApiAccessCredentialMask("miz_", "credential-1")).toBe("miz_credential-1.…");
    expect(() => formatApiAccessCredentialMask("miz_", "bad.id")).toThrow("Credential prefix or id is malformed");
  });

  it("proves a host lifecycle adapter replaces, revokes, and touches credentials", async () => {
    const records = new Map<string, ReturnType<typeof issueApiAccessCredential>["credential"]>();
    const store = {
      async findById(id: string) {
        return records.get(id) ?? null;
      },
      async create(credential: ReturnType<typeof issueApiAccessCredential>["credential"]) {
        records.set(credential.id, credential);
      },
      async replaceActive(input: { previousCredentialId: string; replacement: ReturnType<typeof issueApiAccessCredential>["credential"]; revokedAt: string }) {
        const previous = records.get(input.previousCredentialId);
        if (!previous || previous.revokedAt) return { applied: false as const, reason: "NOT_ACTIVE" as const };
        records.set(previous.id, { ...previous, revokedAt: input.revokedAt });
        records.set(input.replacement.id, input.replacement);
        return { applied: true as const };
      },
      async revokeActive(input: { credentialId: string; revokedAt: string }) {
        const credential = records.get(input.credentialId);
        if (!credential || credential.revokedAt) return { applied: false as const, reason: "NOT_ACTIVE" as const };
        records.set(credential.id, { ...credential, revokedAt: input.revokedAt });
        return { applied: true as const };
      },
      async touchLastUsed(id: string, lastUsedAt: string) {
        const credential = records.get(id);
        if (credential) records.set(id, { ...credential, lastUsedAt });
      },
    };
    const active = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"] }).credential;
    const replacement = issueApiAccessCredential({ id: "credential-2", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"] }).credential;
    await expect(runApiAccessCredentialLifecycleConformance({ store, active, replacement, now: "2026-01-01T00:00:00.000Z" })).resolves.toEqual({ priorCredentialRetained: true, replacementCredentialId: "credential-2" });
    expect(records.get("credential-1")?.revokedAt).toBe("2026-01-01T00:00:00.000Z");
    expect(records.get("credential-2")?.revokedAt).toBe("2026-01-01T00:00:00.000Z");
    expect(records.get("credential-2")?.lastUsedAt).toBe("2026-01-01T00:00:00.000Z");
  });

  it("fails conformance when touchLastUsed does not actually persist the timestamp (no-op adapter)", async () => {
    const records = new Map<string, ReturnType<typeof issueApiAccessCredential>["credential"]>();
    const store = {
      async findById(id: string) {
        return records.get(id) ?? null;
      },
      async create(credential: ReturnType<typeof issueApiAccessCredential>["credential"]) {
        records.set(credential.id, credential);
      },
      async replaceActive(input: { previousCredentialId: string; replacement: ReturnType<typeof issueApiAccessCredential>["credential"]; revokedAt: string }) {
        const previous = records.get(input.previousCredentialId);
        if (!previous || previous.revokedAt) return { applied: false as const, reason: "NOT_ACTIVE" as const };
        records.set(previous.id, { ...previous, revokedAt: input.revokedAt });
        records.set(input.replacement.id, input.replacement);
        return { applied: true as const };
      },
      async revokeActive(input: { credentialId: string; revokedAt: string }) {
        const credential = records.get(input.credentialId);
        if (!credential || credential.revokedAt) return { applied: false as const, reason: "NOT_ACTIVE" as const };
        records.set(credential.id, { ...credential, revokedAt: input.revokedAt });
        return { applied: true as const };
      },
      // No-op: a real adapter that "forgets" to persist should not pass conformance.
      async touchLastUsed() {},
    };
    const active = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"] }).credential;
    const replacement = issueApiAccessCredential({ id: "credential-2", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"] }).credential;
    await expect(
      runApiAccessCredentialLifecycleConformance({ store, active, replacement, now: "2026-01-01T00:00:00.000Z" }),
    ).rejects.toThrow(/did not persist/i);
  });

  it("validates a versioned command envelope and preserves its idempotency receipt", () => {
    const commands = defineApiCommands(["blocks.append", "block.update"] as const);
    const command = commands.assert({
      v: 1,
      idempotencyKey: "command-0001",
      operation: "blocks.append",
      resource: { kind: "page", id: "page-1" },
      payload: { blocks: [{ type: "paragraph", text: "Hello" }] },
      expectedVersion: "7",
    });
    expect(evaluateApiCommandPrecondition(command.expectedVersion, "8")).toEqual({ allowed: false, reason: "VERSION_CONFLICT", expectedVersion: "7", actualVersion: "8" });
    const receipt = createApiCommandReceipt(command, { commandId: "receipt-1", version: "8" });
    expect(receipt).toMatchObject({ outcome: "APPLIED", idempotencyKey: "command-0001", version: "8" });
    const fingerprint = createApiCommandFingerprint(command);
    expect(evaluateApiCommandIdempotency(command, { fingerprint, receipt })).toMatchObject({ action: "REPLAY", receipt });
    expect(evaluateApiCommandIdempotency({ ...command, payload: { blocks: [] } }, { fingerprint, receipt })).toMatchObject({ action: "REJECT", reason: "IDEMPOTENCY_KEY_REUSED" });
    expect(() => commands.assert({ ...command, operation: "blocks.erase" })).toThrow("Unknown API command operation");
  });

  it("rejects malformed or non-JSON command payloads", () => {
    const commands = defineApiCommands(["blocks.append"] as const);
    expect(() => commands.assert({ v: 1, idempotencyKey: "short", operation: "blocks.append", resource: { kind: "page", id: "page-1" }, payload: {} })).toThrow("idempotency key");
    expect(() => commands.assert({ v: 2, idempotencyKey: "command-0002", operation: "blocks.append", resource: { kind: "page", id: "page-1" }, payload: {} })).toThrow("Unsupported API command version");
    expect(() => commands.assert({ v: 1, idempotencyKey: "command-0002", operation: "blocks.append", resource: { kind: "page", id: "page-1" }, payload: { now: new Date() } })).toThrow("payload must be a JSON object");
  });

  it("rejects a blank or whitespace-only expectedVersion instead of silently disabling the precondition", () => {
    const commands = defineApiCommands(["block.update"] as const);
    const envelope = { v: 1 as const, idempotencyKey: "command-0003", operation: "block.update", resource: { kind: "page", id: "page-1" }, payload: {} };
    expect(() => commands.assert({ ...envelope, expectedVersion: "" })).toThrow("expected version must not be blank");
    expect(() => commands.assert({ ...envelope, expectedVersion: "   " })).toThrow("expected version must not be blank");
    // Omitting the field entirely remains the correct way to signal "no precondition".
    const withoutPrecondition = commands.assert(envelope);
    expect(withoutPrecondition.expectedVersion).toBeUndefined();
    expect(evaluateApiCommandPrecondition(withoutPrecondition.expectedVersion, "8")).toEqual({ allowed: true });
  });

  it("evaluateApiCommandPrecondition itself fails closed on a blank expectedVersion, not just the assert() validator", () => {
    // The exported evaluator must not silently allow a blank precondition,
    // regardless of how the caller reached it: a direct call, or an envelope
    // built structurally without ever going through defineApiCommands().assert.
    expect(evaluateApiCommandPrecondition("", "8")).toEqual({
      allowed: false,
      reason: "VERSION_CONFLICT",
      expectedVersion: "",
      actualVersion: "8",
    });
    expect(evaluateApiCommandPrecondition("   ", "8")).toEqual({
      allowed: false,
      reason: "VERSION_CONFLICT",
      expectedVersion: "   ",
      actualVersion: "8",
    });

    // Structurally-built envelope: bypasses commands.assert() entirely, so
    // assert()'s own blank-rejection never runs. The evaluator is the only
    // remaining guard, and it must hold.
    const structuralEnvelope: ApiCommandEnvelope<"block.update"> = {
      v: 1,
      idempotencyKey: "command-0004",
      operation: "block.update",
      resource: { kind: "page", id: "page-1" },
      payload: {},
      expectedVersion: "",
    };
    expect(evaluateApiCommandPrecondition(structuralEnvelope.expectedVersion, "8")).toEqual({
      allowed: false,
      reason: "VERSION_CONFLICT",
      expectedVersion: "",
      actualVersion: "8",
    });

    // A real, matching version is unaffected.
    expect(evaluateApiCommandPrecondition("8", "8")).toEqual({ allowed: true });
    // Undefined (no precondition supplied at all) is still a free pass.
    expect(evaluateApiCommandPrecondition(undefined, "8")).toEqual({ allowed: true });
  });
});

describe("last-used touch conformance compares by instant, not by exact string", () => {
  type Credential = ReturnType<typeof issueApiAccessCredential>["credential"];

  function makeLifecycleStore(touchLastUsed: (records: Map<string, Credential>, id: string, lastUsedAt: string) => void) {
    const records = new Map<string, Credential>();
    const store = {
      async findById(id: string) {
        return records.get(id) ?? null;
      },
      async create(credential: Credential) {
        records.set(credential.id, credential);
      },
      async replaceActive(input: { previousCredentialId: string; replacement: Credential; revokedAt: string }) {
        const previous = records.get(input.previousCredentialId);
        if (!previous || previous.revokedAt) return { applied: false as const, reason: "NOT_ACTIVE" as const };
        records.set(previous.id, { ...previous, revokedAt: input.revokedAt });
        records.set(input.replacement.id, input.replacement);
        return { applied: true as const };
      },
      async revokeActive(input: { credentialId: string; revokedAt: string }) {
        const credential = records.get(input.credentialId);
        if (!credential || credential.revokedAt) return { applied: false as const, reason: "NOT_ACTIVE" as const };
        records.set(credential.id, { ...credential, revokedAt: input.revokedAt });
        return { applied: true as const };
      },
      async touchLastUsed(id: string, lastUsedAt: string) {
        touchLastUsed(records, id, lastUsedAt);
      },
    };
    return { records, store };
  }

  const active = issueApiAccessCredential({ id: "credential-1", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"] }).credential;
  const replacement = issueApiAccessCredential({ id: "credential-2", ownerId: "user-1", prefix: "miz_", pepper, scopes: ["mizen.items.read"] }).credential;

  it("passes when the adapter persists an equivalent instant in a different string format", async () => {
    const { store, records } = makeLifecycleStore((records, id, lastUsedAt) => {
      const credential = records.get(id);
      // Simulates a store that normalizes to milliseconds + "Z" on write/read,
      // e.g. a Postgres timestamptz round-trip.
      if (credential) records.set(id, { ...credential, lastUsedAt: new Date(lastUsedAt).toISOString() });
    });
    await expect(
      runApiAccessCredentialLifecycleConformance({ store, active, replacement, now: "2026-01-01T00:00:00Z" }),
    ).resolves.toMatchObject({ replacementCredentialId: "credential-2" });
    expect(records.get("credential-2")?.lastUsedAt).toBe("2026-01-01T00:00:00.000Z");
  });

  it("fails when the adapter persists a genuinely different instant", async () => {
    const { store } = makeLifecycleStore((records, id) => {
      const credential = records.get(id);
      if (credential) records.set(id, { ...credential, lastUsedAt: "2026-01-01T00:00:01.000Z" }); // one second off
    });
    await expect(
      runApiAccessCredentialLifecycleConformance({ store, active, replacement, now: "2026-01-01T00:00:00.000Z" }),
    ).rejects.toThrow(/different instant/i);
  });

  it("fails when the adapter does not persist a lastUsedAt at all (no-op does not regress)", async () => {
    const { store } = makeLifecycleStore(() => {});
    await expect(
      runApiAccessCredentialLifecycleConformance({ store, active, replacement, now: "2026-01-01T00:00:00.000Z" }),
    ).rejects.toThrow(/did not persist/i);
  });

  it("fails when the adapter persists an unparseable timestamp", async () => {
    const { store } = makeLifecycleStore((records, id) => {
      const credential = records.get(id);
      if (credential) records.set(id, { ...credential, lastUsedAt: "not-a-timestamp" });
    });
    await expect(
      runApiAccessCredentialLifecycleConformance({ store, active, replacement, now: "2026-01-01T00:00:00.000Z" }),
    ).rejects.toThrow(/unparseable/i);
  });
});

describe("typed scope vocabulary (compile-time)", () => {
  const typedPepper = { version: "2026-01", value: "typed-scope-test-pepper16" };
  type Scope = "docs.read" | "docs.write";

  it("compiles issuance and authorization against a pinned scope union", () => {
    const credential = issueApiAccessCredential<Scope>({
      id: "credential-typed",
      ownerId: "user-1",
      prefix: "miz_",
      pepper: typedPepper,
      scopes: ["docs.read"],
    }).credential;

    expect(authorizeApiAccess<Scope>(credential, { scope: "docs.write" })).toEqual({ allowed: false, reason: "SCOPE_DENIED" });

    issueApiAccessCredential<Scope>({
      id: "credential-typed-2",
      ownerId: "user-1",
      prefix: "miz_",
      pepper: typedPepper,
      // @ts-expect-error "docs.reed" is not a member of Scope
      scopes: ["docs.reed"],
    });

    // @ts-expect-error "docs.reed" is not a member of Scope
    authorizeApiAccess<Scope>(credential, { scope: "docs.reed" });
  });

  it("still accepts plain strings when no scope type parameter is pinned", () => {
    const credential = issueApiAccessCredential({
      id: "credential-untyped",
      ownerId: "user-1",
      prefix: "miz_",
      pepper: typedPepper,
      scopes: ["anything"],
    }).credential;
    expect(credential.scopes).toEqual(["anything"]);
  });
});
