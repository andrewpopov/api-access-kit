import { createHash } from "node:crypto";

export interface ApiCommandResource {
  kind: string;
  id: string;
}

export interface ApiCommandEnvelope<Operation extends string = string> {
  v: 1;
  idempotencyKey: string;
  operation: Operation;
  resource: ApiCommandResource;
  payload: JsonObject;
  expectedVersion?: string;
}

export type JsonObject = { readonly [key: string]: JsonValue };
export type JsonValue = string | number | boolean | null | JsonObject | readonly JsonValue[];

export interface DefinedApiCommands<Operation extends string> {
  readonly operations: readonly Operation[];
  has(operation: string): operation is Operation;
  assert(input: unknown): ApiCommandEnvelope<Operation>;
}

export type ApiCommandPrecondition =
  | { allowed: true }
  | { allowed: false; reason: "VERSION_CONFLICT"; expectedVersion: string; actualVersion: string };

export interface ApiCommandReceipt<Operation extends string = string> {
  commandId: string;
  idempotencyKey: string;
  operation: Operation;
  resource: ApiCommandResource;
  outcome: "APPLIED" | "REPLAYED";
  version: string;
}

export interface ApiCommandIdempotencyRecord<Operation extends string = string> {
  fingerprint: string;
  receipt: ApiCommandReceipt<Operation>;
}

export type ApiCommandIdempotency<Operation extends string = string> =
  | { action: "APPLY"; fingerprint: string }
  | { action: "REPLAY"; fingerprint: string; receipt: ApiCommandReceipt<Operation> }
  | { action: "REJECT"; reason: "IDEMPOTENCY_KEY_REUSED"; fingerprint: string };

/**
 * Defines a finite application-owned command vocabulary. The kit validates the
 * envelope only; apps validate operation payloads and execute against their own
 * authoritative content model.
 */
export function defineApiCommands<const Operation extends string>(
  operations: readonly Operation[],
): DefinedApiCommands<Operation> {
  const values = [...new Set(operations)];
  if (values.length === 0) throw new Error("At least one API command is required.");
  for (const operation of values) requireText(operation, "API command");
  const known = new Set<string>(values);
  return Object.freeze({
    operations: Object.freeze(values),
    has(operation: string): operation is Operation {
      return known.has(operation);
    },
    assert(input: unknown): ApiCommandEnvelope<Operation> {
      if (!isRecord(input) || input.v !== 1) throw new Error("Unsupported API command version.");
      if (typeof input.operation !== "string" || !known.has(input.operation))
        throw new Error("Unknown API command operation.");
      if (!isRecord(input.resource)) throw new Error("API command resource is required.");
      requireText(input.resource.kind, "API command resource kind");
      requireText(input.resource.id, "API command resource id");
      if (typeof input.idempotencyKey !== "string" || input.idempotencyKey.length < 8 || input.idempotencyKey.length > 200)
        throw new Error("API command idempotency key must be 8-200 characters.");
      if (!isJsonObject(input.payload)) throw new Error("API command payload must be a JSON object.");
      if (input.expectedVersion !== undefined && typeof input.expectedVersion !== "string")
        throw new Error("API command expected version must be a string.");
      return Object.freeze({
        v: 1,
        idempotencyKey: input.idempotencyKey,
        operation: input.operation as Operation,
        resource: Object.freeze({ kind: input.resource.kind, id: input.resource.id }),
        payload: freezeJsonObject(input.payload),
        ...(input.expectedVersion !== undefined ? { expectedVersion: input.expectedVersion } : {}),
      });
    },
  });
}

/** Reject stale writes before the host mutates its authoritative content state. */
export function evaluateApiCommandPrecondition(
  expectedVersion: string | undefined,
  actualVersion: string,
): ApiCommandPrecondition {
  requireText(actualVersion, "Actual resource version");
  if (!expectedVersion || expectedVersion === actualVersion) return { allowed: true };
  return { allowed: false, reason: "VERSION_CONFLICT", expectedVersion, actualVersion };
}

/**
 * Produces a stable request fingerprint for the host's idempotency ledger.
 * Reusing a key for a different command must be rejected, never replayed.
 */
export function createApiCommandFingerprint<Operation extends string>(
  command: ApiCommandEnvelope<Operation>,
): string {
  const canonicalInput: JsonObject = {
    v: command.v,
    operation: command.operation,
    resource: { kind: command.resource.kind, id: command.resource.id },
    payload: command.payload,
    ...(command.expectedVersion !== undefined ? { expectedVersion: command.expectedVersion } : {}),
  };
  return `sha256:${createHash("sha256").update(canonicalJson(canonicalInput)).digest("hex")}`;
}

/**
 * Resolves a host-loaded idempotency record before any authoritative mutation.
 * Hosts persist the returned fingerprint with the receipt under idempotencyKey.
 */
export function evaluateApiCommandIdempotency<Operation extends string>(
  command: ApiCommandEnvelope<Operation>,
  existing: ApiCommandIdempotencyRecord<Operation> | undefined,
): ApiCommandIdempotency<Operation> {
  const fingerprint = createApiCommandFingerprint(command);
  if (!existing) return { action: "APPLY", fingerprint };
  if (existing.fingerprint === fingerprint)
    return { action: "REPLAY", fingerprint, receipt: existing.receipt };
  return { action: "REJECT", reason: "IDEMPOTENCY_KEY_REUSED", fingerprint };
}

/** Builds a storage-safe receipt for a host-owned idempotency ledger. */
export function createApiCommandReceipt<Operation extends string>(
  command: ApiCommandEnvelope<Operation>,
  input: { commandId: string; version: string; outcome?: "APPLIED" | "REPLAYED" },
): ApiCommandReceipt<Operation> {
  requireText(input.commandId, "API command id");
  requireText(input.version, "API command receipt version");
  return Object.freeze({
    commandId: input.commandId,
    idempotencyKey: command.idempotencyKey,
    operation: command.operation,
    resource: Object.freeze({ ...command.resource }),
    outcome: input.outcome ?? "APPLIED",
    version: input.version,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isJsonObject(value: unknown, depth = 0): value is JsonObject {
  if (!isRecord(value) || depth > 20) return false;
  return Object.values(value).every((entry) => isJsonValue(entry, depth + 1));
}

function isJsonValue(value: unknown, depth: number): value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return depth <= 20 && value.every((entry) => isJsonValue(entry, depth + 1));
  return isJsonObject(value, depth + 1);
}

function freezeJsonObject(value: JsonObject): JsonObject {
  return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, freezeJsonValue(entry)])));
}

function freezeJsonValue(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeJsonValue));
  return isJsonObject(value) ? freezeJsonObject(value) : value;
}

function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value === "boolean") return String(value);
  if (typeof value === "number" || typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!isJsonObject(value)) throw new Error("API command fingerprint requires JSON.");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key]!)}`)
    .join(",")}}`;
}

function requireText(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} must not be empty.`);
}
