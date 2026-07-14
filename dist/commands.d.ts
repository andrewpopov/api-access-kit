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
export type JsonObject = {
    readonly [key: string]: JsonValue;
};
export type JsonValue = string | number | boolean | null | JsonObject | readonly JsonValue[];
export interface DefinedApiCommands<Operation extends string> {
    readonly operations: readonly Operation[];
    has(operation: string): operation is Operation;
    assert(input: unknown): ApiCommandEnvelope<Operation>;
}
export type ApiCommandPrecondition = {
    allowed: true;
} | {
    allowed: false;
    reason: "VERSION_CONFLICT";
    expectedVersion: string;
    actualVersion: string;
};
export interface ApiCommandReceipt<Operation extends string = string> {
    commandId: string;
    idempotencyKey: string;
    operation: Operation;
    resource: ApiCommandResource;
    outcome: "APPLIED" | "REPLAYED";
    version: string;
}
/**
 * Defines a finite application-owned command vocabulary. The kit validates the
 * envelope only; apps validate operation payloads and execute against their own
 * authoritative content model.
 */
export declare function defineApiCommands<const Operation extends string>(operations: readonly Operation[]): DefinedApiCommands<Operation>;
/** Reject stale writes before the host mutates its authoritative content state. */
export declare function evaluateApiCommandPrecondition(expectedVersion: string | undefined, actualVersion: string): ApiCommandPrecondition;
/** Builds a storage-safe receipt for a host-owned idempotency ledger. */
export declare function createApiCommandReceipt<Operation extends string>(command: ApiCommandEnvelope<Operation>, input: {
    commandId: string;
    version: string;
    outcome?: "APPLIED" | "REPLAYED";
}): ApiCommandReceipt<Operation>;
