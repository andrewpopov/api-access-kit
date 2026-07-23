# @andrewpopov/api-access-kit

Pure primitives for opaque, lifecycle-owned API credentials. It issues a secret once,
hashes it for host storage, evaluates exact named scopes and lifecycle state, and
keeps workspace binding explicit. It does not own a database, HTTP framework,
request middleware, user session, or product resource authorization.

## Install

This package is distributed through immutable GitHub tags:

```bash
npm install github:andrewpopov/api-access-kit#v0.8.0
```

## Quick start

```ts
import {
  defineApiScopes,
  defineApiAccessPepperRing,
  issueApiAccessCredential,
  authenticateApiAccessCredential,
  authorizeApiAccess,
} from "@andrewpopov/api-access-kit";

const scopes = defineApiScopes(["example.items.read", "example.items.write"] as const);

// The current pepper is `primary`; keep prior versions here until every
// credential hashed under them has rotated.
const pepperRing = defineApiAccessPepperRing([
  { version: "2026-07", value: process.env.API_ACCESS_PEPPER! }, // host-provided
]);

// Issue once; only `secretHash` is persisted, `issued.secret` is shown to the caller once.
const issued = issueApiAccessCredential({
  id: crypto.randomUUID(),
  ownerId: user.id, // host-provided
  prefix: "example_",
  pepper: pepperRing.primary,
  scopes: scopes.values,
});
await credentialStore.create(issued.credential); // host-provided

// Later, on each request:
const authentication = await authenticateApiAccessCredential({
  rawCredential, // host-provided: the raw secret from the request
  prefix: "example_",
  store: credentialStore, // host-provided: implements ApiAccessCredentialStore
  peppers: pepperRing.values,
});
if (!authentication.ok) throw new UnauthorizedError(authentication.reason); // host-provided

const decision = authorizeApiAccess(authentication.credential, {
  scope: "example.items.write",
  workspaceId,
});
if (!decision.allowed) throw new ForbiddenError(decision.reason); // host-provided

// Step 4 (mandatory, not shown above): authorize the credential's bound
// principal against the host's own resource policy. See "Security boundary".
```

## Security boundary

API access is evaluated in this order:

1. Parse the versioned opaque credential's public id and load the host-owned credential record by index.
2. Select the stored record's pepper version and constant-time verify only the random secret segment.
3. Call `authorizeApiAccess` for exact scope and workspace binding.
4. Authorize the credential's explicitly bound **principal** against the host's resource policy.

Step 4 is mandatory. A scope permits an API operation category; it never grants
access to a product resource by itself. `ownerId` is the accountable issuer and
lifecycle owner; it is not automatically the resource authorization principal.

```ts
const exampleScopes = defineApiScopes([
  "example.items.read",
  "example.items.write",
] as const);

const decision = authorizeApiAccess(credential, {
  scope: "example.items.write",
  workspaceId,
});
if (!decision.allowed) throw new ForbiddenError(decision.reason); // host-provided

const principal = createApiAccessPrincipalBinding({
  credential,
  principalType: "organization",
  principalId: organization.id,
});
// host-provided: the product's own resource-authorization path
await authorization.requireSpace("item.edit", workspaceId, principal.principalId, spaceId, itemId);
```

Step 4 always runs through the host's own resource-authorization path. If a
write also has to go through an authoritative content pipeline (an event log,
a CRDT document, a queue), route the write there rather than replacing it with
a projection written directly through this endpoint.

## Reason codes

`authorizeApiAccess` and `authenticateApiAccessCredential` never throw for an
ordinary deny/reject outcome — they return a discriminated result whose
`reason` names why. A malformed lifecycle timestamp is the same underlying
state at both layers; each layer just names it appropriately for its own
result type (`INVALID` for a post-authentication authorization decision,
`MALFORMED` for an authentication attempt that never resolved to a credential).

### `ApiAccessDenyReason` (from `authorizeApiAccess`)

| Reason | Meaning | Suggested host response |
| --- | --- | --- |
| `REVOKED` | The credential's `revokedAt` is set. | 403 Forbidden |
| `EXPIRED` | The credential's `expiresAt` has passed. | 403 Forbidden |
| `INVALID` | The credential's `expiresAt` is not a well-formed ISO 8601 timestamp. | 403 Forbidden (treat as invalid, not retryable) |
| `WORKSPACE_MISMATCH` | The credential is bound to a `workspaceId` that does not match the request. | 403 Forbidden |
| `SCOPE_DENIED` | The request's `scope` is not in the credential's `scopes`. | 403 Forbidden |

### `ApiAccessAuthenticationFailure` (from `authenticateApiAccessCredential`)

| Reason | Meaning | Suggested host response |
| --- | --- | --- |
| `MALFORMED` | `rawCredential` exceeds `MAX_RAW_CREDENTIAL_LENGTH`, does not parse as `<prefix><id>.<secret>`, the stored record's `formatVersion` is unrecognized, or the stored record's `expiresAt` is not a well-formed ISO 8601 timestamp. | 401 Unauthorized |
| `INVALID_PEPPER_RING` | The `peppers` passed in are empty, blank, or contain duplicate versions. | 500 Internal Server Error (host misconfiguration) |
| `NOT_FOUND` | No credential matches the parsed public id. A comparable dummy hash still runs on this path so a missing credential id is not trivially distinguishable by response timing, but exact timing parity with `HASH_MISMATCH` across hash versions is not guaranteed. | 401 Unauthorized |
| `HASH_MISMATCH` | The credential exists but the secret segment does not verify against its stored hash. | 401 Unauthorized |
| `REVOKED` | The credential's `revokedAt` is set. | 401 Unauthorized |
| `EXPIRED` | The credential's `expiresAt` has passed. | 401 Unauthorized |
| `UNKNOWN_PEPPER_VERSION` | The credential's `pepperVersion` is not present in the supplied pepper ring. | 500 Internal Server Error (rotate/restore the missing pepper) |
| `UNSUPPORTED_HASH_VERSION` | The credential's `hashVersion` is not one of `SUPPORTED_API_ACCESS_HASH_VERSIONS`. | 401 Unauthorized (and alert — this should not be issuable) |

## Issuing a credential

### Organization and service principals

Do not create a synthetic bot user for every API key just to route a key through
user-membership authorization. Persist a host-owned
`ApiAccessPrincipalBinding` for each credential and evaluate it directly in
the product's organization and resource policy. The binding records a
credential's authorization principal separately from the accountable issuer:

```ts
const binding = createApiAccessPrincipalBinding({
  credential: issued.credential,
  principalType: "organization",
  principalId: organization.id,
});
await credentialStore.create(issued.credential);
await principalBindingStore.insert({
  ...binding,
  projectScopes: [project.id], // host-defined, immutable resource scope
  projectRole: "MEMBER",      // host-defined role, never inferred from issuer
});
```

At request time, authenticate the credential first, then load the binding and
enforce in order: credential lifecycle → exact operation scope → organization
binding → resource scope → role. The issuer may manage lifecycle actions but
must not silently grant every permission that the issuer personally has. Never
issue `OWNER` to a non-human credential unless the host has an explicit,
reviewed need; prefer named resources and the lowest role. Retire legacy
synthetic users only after preserving any audit/agent history that references
them.

```ts
const issued = issueApiAccessCredential({
  id: crypto.randomUUID(),
  ownerId: user.id,
  workspaceId,
  prefix: "example_",
  pepper: { version: "2026-07", value: process.env.API_ACCESS_PEPPER! },
  scopes: ["example.items.read", "example.items.write"],
  expiresAt,
});

await credentialStore.create(issued.credential); // stores only `secretHash`
return issued.secret; // reveal once, never list it again
```

The v1 wire format is `<prefix><id>.<random-secret>`, for example
`example_credential-1.abc…`. The id is public indexed metadata; only the random
secret segment authenticates the credential. Persist `formatVersion`,
`hashVersion`, and `pepperVersion` with the hash. Keep prior named peppers in
the verification key ring until their credentials have rotated; never rehash or
log a raw credential during rotation. New credentials default to HMAC-SHA256
(`hashVersion` v2); v1 (`sha256-peppered-secret-v1`) credentials remain
verifiable, so keep persisting each credential's own `hashVersion`.

For HTTP, call `authenticateApiAccessCredential` from the host's raw-credential
adapter, then let the HTTP kit map the successful record to its request context.
Do not make an HTTP middleware hash the whole credential before lookup: that
breaks public-id lookup and secret-only verification.

**Guards worth knowing about:**

- A pepper (`ApiAccessPepper.value`) must be at least `MIN_API_ACCESS_PEPPER_LENGTH`
  (16) characters; `defineApiAccessPepperRing` and `issueApiAccessCredential`
  both throw otherwise.
- `secretBytes` at issuance must be an integer between 16 and
  `MAX_API_ACCESS_SECRET_BYTES` (256); out-of-range values throw.
- `rawCredential` presented to `authenticateApiAccessCredential` longer than
  `MAX_RAW_CREDENTIAL_LENGTH` (4096 characters) is rejected as `MALFORMED`
  before any parsing.
- `expiresAt` is parsed as strict ISO 8601 (`YYYY-MM-DDTHH:mm:ss[.sss](Z|±HH:mm)`);
  a date-only string like `"2026-01-01"` or another loose format does not parse
  and surfaces as `INVALID` (`authorizeApiAccess`) or `MALFORMED`
  (`authenticateApiAccessCredential`).

## Lifecycle adapters

Use `defineApiAccessPepperRing` to validate a named key ring before passing its
values into issuance or authentication. Empty, blank, and duplicate versions
are rejected. The host still owns environment-variable parsing and secret
providers.

`issueReplacementApiAccessCredential` creates fresh material for an active
credential while preserving its owner, exact scopes, workspace binding, and
expiry. It does not write a database record or revoke the prior credential.
The host applies both sides atomically through `ApiAccessCredentialLifecycleStore`:

```ts
const replacement = issueReplacementApiAccessCredential({
  credential: current,
  id: crypto.randomUUID(),
  prefix: "example_",
  pepper: pepperRing.primary,
});

const result = await credentialStore.replaceActive({
  previousCredentialId: current.id,
  replacement: replacement.credential,
  revokedAt: new Date().toISOString(),
});
if (!result.applied) throw new Error(`Credential replacement failed: ${result.reason}`);
return replacement.secret; // reveal once
```

The store interface is deliberately small. It does not dictate whether an app
creates a replacement row, changes a credential inside an existing row, adds an
audit record, or uses an ORM transaction. Those are host responsibilities.

Use `runApiAccessCredentialLifecycleConformance` only with a disposable store
fixture. It verifies that create, replacement, prior-credential invalidation,
revocation, and last-used touch honor the portable contract before a host
adopts the package.

## Scope model

Scopes are exact strings. The kit deliberately has no wildcard or implication
rules because those are easy to misinterpret across applications. Define each
application vocabulary locally and use multiple explicit scopes when needed.

### Typed scopes

`issueApiAccessCredential`, `issueReplacementApiAccessCredential`, and
`authorizeApiAccess` (plus their input/result types) are generic over a
`Scopes extends ApiAccessScope = ApiAccessScope` parameter. The default keeps
existing untyped callers working exactly as before; opting in makes an unknown
scope a compile error instead of a runtime `SCOPE_DENIED`:

```ts
const myScopes = defineApiScopes(["example.items.read", "example.items.write"] as const);
type Scope = (typeof myScopes.values)[number];

const issued = issueApiAccessCredential<Scope>({
  id: crypto.randomUUID(),
  ownerId: user.id,
  prefix: "example_",
  pepper: pepperRing.primary,
  scopes: myScopes.values,
});

const decision = authorizeApiAccess<Scope>(issued.credential, {
  scope: "example.items.write", // a typo here is now a compile error
  workspaceId,
});
```

## Content commands

`defineApiCommands` gives an API a small, versioned command wire contract. A
command carries an operation, resource identity, JSON payload, idempotency key,
and an optional expected resource version. The host stores a fingerprint and
receipt under the idempotency key, then executes against its authoritative content model.

```ts
const commands = defineApiCommands(["page.update", "blocks.append", "block.update"] as const);
const command = commands.assert(request.body);
const idempotency = evaluateApiCommandIdempotency(command, await idempotencyStore.get(command.idempotencyKey));
if (idempotency.action === "REPLAY") return ok(idempotency.receipt); // ok(...): host-provided response helper
if (idempotency.action === "REJECT") return conflict(idempotency); // conflict(...): host-provided response helper
const precondition = evaluateApiCommandPrecondition(command.expectedVersion, current.version);
if (!precondition.allowed) return conflict(precondition);

// The host checks credential scope and resource authorization before applying.
const receipt = createApiCommandReceipt(command, { commandId, version: next.version });
```

The package never executes a command, stores an idempotency ledger, or decides
what a block means. One consumer might map these commands to CRDT transactions;
another can adapt them to a different authoritative engine. Its fingerprint
uses canonical JSON, so equivalent object key ordering safely replays.

## API reference

Every export below is derived directly from `src/index.ts` and `src/commands.ts`.

### Functions

| Export | Purpose |
| --- | --- |
| `defineApiScopes` | Define a finite, application-owned scope vocabulary with exact matching (`has`/`assert`). |
| `defineApiAccessPepperRing` | Validate a named pepper key ring (rejects empty, blank, duplicate, or too-short values) before issuance/authentication. |
| `issueApiAccessCredential` | Issue a new opaque credential once; returns the storage-safe credential plus the one-time secret. |
| `issueReplacementApiAccessCredential` | Issue fresh material for an active credential, preserving its owner, scopes, workspace, and expiry. |
| `runApiAccessCredentialLifecycleConformance` | Exercise a host lifecycle store adapter against the portable contract; disposable fixture only. |
| `hashApiAccessSecret` | Deterministic hash of a secret + pepper for a given hash version. |
| `verifyApiAccessSecret` | Constant-time comparison of a secret against a stored hash. |
| `parseApiAccessSecret` | Parse a raw credential string into its public id and random secret segment. |
| `authenticateApiAccessCredential` | Indexed public-id lookup, constant-time secret verification, and lifecycle check. |
| `getApiAccessCredentialStatus` | Compute `ACTIVE` / `REVOKED` / `EXPIRED` / `INVALID` from a credential's lifecycle fields. |
| `formatApiAccessCredentialMask` | Build a safe, human-readable masked display string from a prefix and credential id. |
| `authorizeApiAccess` | Evaluate lifecycle status, exact scope, and workspace binding. |
| `toApiAccessCredentialMetadata` | Strip `secretHash` from a credential to produce list-safe metadata. |
| `isSupportedHashVersion` | Type guard for whether a string is a supported hash version. |
| `createApiAccessPrincipalBinding` | Create a validated, immutable `ApiAccessPrincipalBinding`. |
| `defineApiCommands` | Define a finite, versioned command operation vocabulary with exact matching and envelope validation. |
| `evaluateApiCommandPrecondition` | Optimistic-concurrency check: reject a stale `expectedVersion` before mutation. |
| `createApiCommandFingerprint` | Canonical-JSON fingerprint of a command envelope, for idempotency comparison. |
| `evaluateApiCommandIdempotency` | Resolve `APPLY` / `REPLAY` / `REJECT` against a stored idempotency record. |
| `createApiCommandReceipt` | Build a storage-safe receipt for a host's idempotency ledger. |

### Constants

| Export | Purpose |
| --- | --- |
| `API_ACCESS_HASH_VERSION_V1` | The v1 hash version string (`sha256-peppered-secret-v1`; SHA-256 over pepper + secret). |
| `API_ACCESS_HASH_VERSION_V2` | The v2 hash version string (`hmac-sha256-peppered-secret-v2`; HMAC-SHA256 keyed by pepper). |
| `SUPPORTED_API_ACCESS_HASH_VERSIONS` | Every hash version this package can verify. |
| `DEFAULT_API_ACCESS_HASH_VERSION` | The hash version new credentials are issued with (currently v2). |
| `MIN_API_ACCESS_PEPPER_LENGTH` | Minimum required pepper length, in characters (16). |
| `MAX_RAW_CREDENTIAL_LENGTH` | Maximum accepted `rawCredential` length for authentication, in characters (4096). |
| `MAX_API_ACCESS_SECRET_BYTES` | Maximum accepted `secretBytes` at issuance (256). |

### Types — credentials, authentication, and authorization

| Export | Purpose |
| --- | --- |
| `ApiAccessScope` | Base scope type (`string`); narrow it via the generic `Scopes` parameter for typed scopes. |
| `ApiAccessHashVersion` | Union of the supported hash version literals. |
| `ApiAccessCredential<Scopes>` | Storage-safe credential state; never carries the secret itself. |
| `ApiAccessPrincipalBinding` | Host-owned resource-authorization identity bound to a credential. |
| `CreateApiAccessPrincipalBindingInput` | Input to `createApiAccessPrincipalBinding`. |
| `IssuedApiAccessCredential<Scopes>` | The `{ credential, secret }` shape returned by issuance — the only shape that carries the raw secret. |
| `ApiAccessDenyReason` | Deny-reason union returned by `authorizeApiAccess`. |
| `ApiAccessDecision` | Allowed/denied result returned by `authorizeApiAccess`. |
| `ApiAccessRequest<Scopes>` | Input to `authorizeApiAccess`. |
| `IssueApiAccessCredentialInput<Scopes>` | Input to `issueApiAccessCredential`. |
| `ApiAccessPepper` | A named pepper: `{ version, value }`. |
| `ApiAccessCredentialStore` | Minimal read-only persistence seam (`findById`). |
| `ApiAccessCredentialLifecycleStore` | Full lifecycle persistence seam: `create`, `replaceActive`, `revokeActive`, `touchLastUsed`. |
| `ApiAccessCredentialReplacement` | Input to `replaceActive`. |
| `ApiAccessCredentialRevocation` | Input to `revokeActive`. |
| `ApiAccessCredentialLifecycleMutation` | Applied/not-applied result from a lifecycle store mutation. |
| `ApiAccessCredentialLifecycleConformanceInput` | Input to `runApiAccessCredentialLifecycleConformance`. |
| `ApiAccessCredentialLifecycleConformanceResult` | Result from `runApiAccessCredentialLifecycleConformance`. |
| `ApiAccessAuthenticationFailure` | Failure-reason union returned by `authenticateApiAccessCredential`. |
| `ApiAccessAuthentication` | Ok/failure result returned by `authenticateApiAccessCredential`. |
| `AuthenticateApiAccessCredentialInput` | Input to `authenticateApiAccessCredential`. |
| `DefinedApiAccessPepperRing` | Validated pepper ring returned by `defineApiAccessPepperRing`. |
| `ApiAccessCredentialStatus` | `"ACTIVE" \| "REVOKED" \| "EXPIRED" \| "INVALID"`, returned by `getApiAccessCredentialStatus`. |
| `IssueReplacementApiAccessCredentialInput<Scopes>` | Input to `issueReplacementApiAccessCredential`. |
| `DefinedApiScopes<Scopes>` | Validated scope vocabulary returned by `defineApiScopes`. |

### Types — content commands

| Export | Purpose |
| --- | --- |
| `ApiCommandEnvelope<Operation>` | Versioned command wire envelope. |
| `ApiCommandIdempotency<Operation>` | `APPLY` / `REPLAY` / `REJECT` result from `evaluateApiCommandIdempotency`. |
| `ApiCommandIdempotencyRecord<Operation>` | A stored fingerprint + receipt record for a host's idempotency ledger. |
| `ApiCommandPrecondition` | Allowed/version-conflict result from `evaluateApiCommandPrecondition`. |
| `ApiCommandReceipt<Operation>` | Storage-safe command receipt. |
| `ApiCommandResource` | `{ kind, id }` resource identity referenced by a command. |
| `DefinedApiCommands<Operation>` | Validated command operation vocabulary returned by `defineApiCommands`. |
| `JsonObject` | Readonly JSON object type used by command payloads. |
| `JsonValue` | JSON value union used by command payloads. |

Run `npm test && npm run typecheck && npm run build && npm run verify:pack`.
