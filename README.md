# @andrewpopov/api-access-kit

Pure primitives for opaque, lifecycle-owned API credentials. It issues a secret once,
hashes it for host storage, evaluates exact named scopes and lifecycle state, and
keeps workspace binding explicit. It does not own a database, HTTP framework,
request middleware, user session, or product resource authorization.

## Install

This package is distributed through immutable GitHub tags:

```bash
npm install github:andrewpopov/api-access-kit#v0.5.0
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
if (!decision.allowed) throw new ForbiddenError(decision.reason);

const principal = createApiAccessPrincipalBinding({
  credential,
  principalType: "organization",
  principalId: organization.id,
});
await authorization.requireSpace("item.edit", workspaceId, principal.principalId, spaceId, itemId);
```

Step 4 always runs through the host's own resource-authorization path. If a
write also has to go through an authoritative content pipeline (an event log,
a CRDT document, a queue), route the write there rather than replacing it with
a projection written directly through this endpoint.

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
await credentialStore.insert(issued.credential);
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

await credentialStore.insert(issued.credential); // stores only `secretHash`
return issued.secret; // reveal once, never list it again
```

The v1 wire format is `<prefix><id>.<random-secret>`, for example
`example_credential-1.abc…`. The id is public indexed metadata; only the random
secret segment authenticates the credential. Persist `formatVersion`,
`hashVersion`, and `pepperVersion` with the hash. Keep prior named peppers in
the verification key ring until their credentials have rotated; never rehash or
log a raw credential during rotation.

For HTTP, call `authenticateApiAccessCredential` from the host's raw-credential
adapter, then let the HTTP kit map the successful record to its request context.
Do not make an HTTP middleware hash the whole credential before lookup: that
breaks public-id lookup and secret-only verification.

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

## Content commands

`defineApiCommands` gives an API a small, versioned command wire contract. A
command carries an operation, resource identity, JSON payload, idempotency key,
and an optional expected resource version. The host stores a fingerprint and
receipt under the idempotency key, then executes against its authoritative content model.

```ts
const commands = defineApiCommands(["page.update", "blocks.append", "block.update"] as const);
const command = commands.assert(request.body);
const idempotency = evaluateApiCommandIdempotency(command, await idempotencyStore.get(command.idempotencyKey));
if (idempotency.action === "REPLAY") return ok(idempotency.receipt);
if (idempotency.action === "REJECT") return conflict(idempotency);
const precondition = evaluateApiCommandPrecondition(command.expectedVersion, current.version);
if (!precondition.allowed) return conflict(precondition);

// The host checks credential scope and resource authorization before applying.
const receipt = createApiCommandReceipt(command, { commandId, version: next.version });
```

The package never executes a command, stores an idempotency ledger, or decides
what a block means. One consumer might map these commands to CRDT transactions;
another can adapt them to a different authoritative engine. Its fingerprint
uses canonical JSON, so equivalent object key ordering safely replays.

Run `npm test && npm run typecheck && npm run build && npm run verify:pack`.
