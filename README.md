# @andrewpopov/api-access-kit

Pure primitives for opaque, user-owned API credentials. It issues a secret once,
hashes it for host storage, evaluates exact named scopes and lifecycle state, and
keeps workspace binding explicit. It does not own a database, HTTP framework,
request middleware, user session, or product resource authorization.

## Security boundary

API access is evaluated in this order:

1. Parse the opaque credential id and load the host-owned credential record.
2. Constant-time verify the raw secret against the stored hash.
3. Call `authorizeApiAccess` for revocation, expiry, exact scope, and workspace binding.
4. Authorize the credential **owner** against the host's resource policy.

Step 4 is mandatory. A scope permits an API operation category; it never grants
access to a product resource by itself.

```ts
const mizenScopes = defineApiScopes([
  "mizen.items.read",
  "mizen.items.write",
] as const);

const decision = authorizeApiAccess(credential, {
  scope: "mizen.items.write",
  workspaceId,
});
if (!decision.allowed) throw new ForbiddenError(decision.reason);

await authorization.requireSpace("item.edit", workspaceId, credential.ownerId, spaceId, itemId);
```

For Mizen, a document-content write must then use the same Y.Doc-authoritative
command path as collaboration. Do not replace a JSON, HTML, or search projection
through a REST endpoint.

## Issuing a credential

```ts
const issued = issueApiAccessCredential({
  id: crypto.randomUUID(),
  ownerId: user.id,
  workspaceId,
  prefix: "miz",
  pepper: process.env.API_ACCESS_PEPPER!,
  scopes: ["mizen.items.read", "mizen.items.write"],
  expiresAt,
});

await credentialStore.insert(issued.credential); // stores only `secretHash`
return issued.secret; // reveal once, never list it again
```

`prefix`, `id`, and secret entropy are separated by dots so a host can parse the
credential id for indexed lookup. The id is public metadata; only the random
secret segment authenticates the credential.

## Scope model

Scopes are exact strings. The kit deliberately has no wildcard or implication
rules because those are easy to misinterpret across applications. Define each
application vocabulary locally and use multiple explicit scopes when needed.

Run `npm test && npm run typecheck && npm run build && npm run verify:pack`.
