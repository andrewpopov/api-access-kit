"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.defineApiCommands = defineApiCommands;
exports.evaluateApiCommandPrecondition = evaluateApiCommandPrecondition;
exports.createApiCommandReceipt = createApiCommandReceipt;
/**
 * Defines a finite application-owned command vocabulary. The kit validates the
 * envelope only; apps validate operation payloads and execute against their own
 * authoritative content model.
 */
function defineApiCommands(operations) {
    const values = [...new Set(operations)];
    if (values.length === 0)
        throw new Error("At least one API command is required.");
    for (const operation of values)
        requireText(operation, "API command");
    const known = new Set(values);
    return Object.freeze({
        operations: Object.freeze(values),
        has(operation) {
            return known.has(operation);
        },
        assert(input) {
            if (!isRecord(input) || input.v !== 1)
                throw new Error("Unsupported API command version.");
            if (typeof input.operation !== "string" || !known.has(input.operation))
                throw new Error("Unknown API command operation.");
            if (!isRecord(input.resource))
                throw new Error("API command resource is required.");
            requireText(input.resource.kind, "API command resource kind");
            requireText(input.resource.id, "API command resource id");
            if (typeof input.idempotencyKey !== "string" || input.idempotencyKey.length < 8 || input.idempotencyKey.length > 200)
                throw new Error("API command idempotency key must be 8-200 characters.");
            if (!isJsonObject(input.payload))
                throw new Error("API command payload must be a JSON object.");
            if (input.expectedVersion !== undefined && typeof input.expectedVersion !== "string")
                throw new Error("API command expected version must be a string.");
            return Object.freeze({
                v: 1,
                idempotencyKey: input.idempotencyKey,
                operation: input.operation,
                resource: Object.freeze({ kind: input.resource.kind, id: input.resource.id }),
                payload: freezeJsonObject(input.payload),
                ...(input.expectedVersion !== undefined ? { expectedVersion: input.expectedVersion } : {}),
            });
        },
    });
}
/** Reject stale writes before the host mutates its authoritative content state. */
function evaluateApiCommandPrecondition(expectedVersion, actualVersion) {
    requireText(actualVersion, "Actual resource version");
    if (!expectedVersion || expectedVersion === actualVersion)
        return { allowed: true };
    return { allowed: false, reason: "VERSION_CONFLICT", expectedVersion, actualVersion };
}
/** Builds a storage-safe receipt for a host-owned idempotency ledger. */
function createApiCommandReceipt(command, input) {
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
function isRecord(value) {
    if (typeof value !== "object" || value === null || Array.isArray(value))
        return false;
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}
function isJsonObject(value, depth = 0) {
    if (!isRecord(value) || depth > 20)
        return false;
    return Object.values(value).every((entry) => isJsonValue(entry, depth + 1));
}
function isJsonValue(value, depth) {
    if (value === null || typeof value === "string" || typeof value === "boolean")
        return true;
    if (typeof value === "number")
        return Number.isFinite(value);
    if (Array.isArray(value))
        return depth <= 20 && value.every((entry) => isJsonValue(entry, depth + 1));
    return isJsonObject(value, depth + 1);
}
function freezeJsonObject(value) {
    return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, entry]) => [key, freezeJsonValue(entry)])));
}
function freezeJsonValue(value) {
    if (Array.isArray(value))
        return Object.freeze(value.map(freezeJsonValue));
    return isJsonObject(value) ? freezeJsonObject(value) : value;
}
function requireText(value, label) {
    if (typeof value !== "string" || !value.trim())
        throw new Error(`${label} must not be empty.`);
}
