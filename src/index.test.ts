import { describe, expect, it } from "vitest";
import {
  authorizeApiAccess,
  authenticateApiAccessCredential,
  defineApiScopes,
  hashApiAccessSecret,
  issueApiAccessCredential,
  parseApiAccessSecret,
  toApiAccessCredentialMetadata,
  verifyApiAccessSecret,
} from "./index.js";
import {
  createApiCommandFingerprint,
  createApiCommandReceipt,
  defineApiCommands,
  evaluateApiCommandIdempotency,
  evaluateApiCommandPrecondition,
} from "./index.js";

const pepper = { version: "2026-01", value: "test-pepper" };

describe("api-access-kit", () => {
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
    expect(verifyApiAccessSecret(parsed.secret, issued.credential.secretHash, pepper.value)).toBe(true);
    expect(verifyApiAccessSecret(`${parsed.secret}x`, issued.credential.secretHash, pepper.value)).toBe(false);
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
    await expect(authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [{ version: "old", value: "old-pepper" }, pepper] })).resolves.toMatchObject({ ok: true, credential: { id: "credential-1" } });
    await expect(authenticateApiAccessCredential({ rawCredential: `${issued.secret}x`, prefix: "miz_", store, peppers: [pepper] })).resolves.toEqual({ ok: false, reason: "HASH_MISMATCH" });
    await expect(authenticateApiAccessCredential({ rawCredential: issued.secret, prefix: "miz_", store, peppers: [] })).resolves.toEqual({ ok: false, reason: "UNKNOWN_PEPPER_VERSION" });
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
});
