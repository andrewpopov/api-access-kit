# Changelog

## 0.8.0

- Add opt-in typed scopes: `ApiAccessCredential`, `IssuedApiAccessCredential`,
  `IssueApiAccessCredentialInput`, `ApiAccessRequest`,
  `IssueReplacementApiAccessCredentialInput`, `issueApiAccessCredential`,
  `issueReplacementApiAccessCredential`, and `authorizeApiAccess` are now
  generic over a `Scopes extends ApiAccessScope = ApiAccessScope` parameter.
  Non-breaking: the default type parameter preserves the prior `string`
  behavior for callers who do not opt in.
- **Breaking:** enforce a minimum pepper length
  (`MIN_API_ACCESS_PEPPER_LENGTH = 16`) in `defineApiAccessPepperRing` and
  `issueApiAccessCredential`. A host pepper shorter than 16 characters now
  throws instead of silently issuing a weakly-keyed credential.
- **Breaking:** add `"INVALID"` to `ApiAccessDenyReason`. `authorizeApiAccess`
  now returns this distinct reason for a malformed lifecycle timestamp, which
  was previously mislabeled `"EXPIRED"`. An exhaustive `switch` over
  `ApiAccessDenyReason` must add a case for it.
- Mitigate a timing oracle on the not-found path: `authenticateApiAccessCredential`
  performs a constant-time dummy hash when no credential matches the parsed id,
  so response timing does not distinguish an unknown id from a hash mismatch.
- `authenticateApiAccessCredential` now rejects a `rawCredential` longer than
  `MAX_RAW_CREDENTIAL_LENGTH` (4096 characters) as `MALFORMED` before parsing.
- `issueApiAccessCredential` now bounds `secretBytes` to between 16 and
  `MAX_API_ACCESS_SECRET_BYTES` (256), throwing outside that range. 256 bytes
  keeps the base64url-encoded secret well under `MAX_RAW_CREDENTIAL_LENGTH`, so
  an issued credential is always authenticatable.
- Parse `expiresAt` with strict ISO 8601 (`authorizeApiAccess` and
  `authenticateApiAccessCredential`); a date-only or otherwise loose string no
  longer resolves as a valid timestamp — it now surfaces as `INVALID` from
  `authorizeApiAccess` and `MALFORMED` from `authenticateApiAccessCredential`.
  Calendar components are also range-checked (month, day-of-month accounting
  for leap years, hour, minute, second), so an impossible date like
  `2026-02-30` no longer silently normalizes via `Date` and is rejected as
  `INVALID`/`MALFORMED` instead.
- Add `"sideEffects": false` to `package.json` so consumer bundlers can
  tree-shake unused exports.
- Add coverage tooling: a `coverage` script (`vitest run --coverage`) and
  `vitest.config.ts` with v8 coverage thresholds over `src`.
- Overhaul the README for accuracy: a Quick start section, a full API
  reference table, a reason-code reference for `ApiAccessDenyReason` and
  `ApiAccessAuthenticationFailure`, a typed-scopes example, and clearer
  labeling of host-provided pseudocode in existing examples.
- Fix `tsconfig.typecheck.json` so it actually typechecks the test files.

## 0.7.0

- Add HMAC-SHA256 as `hashVersion` v2 (`API_ACCESS_HASH_VERSION_V2`), now the
  default for newly issued credentials (`DEFAULT_API_ACCESS_HASH_VERSION`); v1
  (`API_ACCESS_HASH_VERSION_V1`, SHA-256) remains fully verifiable for existing
  stored credentials, and `authenticateApiAccessCredential` dispatches on each
  credential's own stored `hashVersion`.
- **Breaking:** `verifyApiAccessSecret` now requires a `hashVersion` argument
  so callers cannot silently mis-verify a hash against the wrong algorithm.
- **Breaking:** remove the single-version `SUPPORTED_API_ACCESS_HASH_VERSION`
  constant in favor of `SUPPORTED_API_ACCESS_HASH_VERSIONS`,
  `DEFAULT_API_ACCESS_HASH_VERSION`, and `isSupportedHashVersion`.
- Fix the README install pin (`#v0.5.0` → `#v0.7.0`) and its
  `credentialStore.insert` doc bug (the lifecycle store method is `create`).

## 0.6.0

- Fail closed with a new `UNSUPPORTED_HASH_VERSION` authentication reason when
  a stored credential's `hashVersion` does not match the package's supported
  hash algorithm, checked before any secret hashing or comparison work; reject
  unsupported hash versions at issuance so such credentials cannot be minted.
- Add host-owned `ApiAccessPrincipalBinding`/`createApiAccessPrincipalBinding`
  to separate a credential's accountable owner from the resource-authorization
  principal its requests should be evaluated against.

## 0.5.0

- Add validated named pepper rings, canonical lifecycle status, and safe masked
  credential metadata helpers.
- Add active-only replacement issuance and persistence-agnostic lifecycle store
  contracts for create, replacement, revocation, and last-used tracking.
- Fail closed when authentication receives an empty, malformed, or duplicate
  pepper ring.

## 0.4.0

- Define the canonical v1 credential format, indexed public-id lookup, and
  secret-only constant-time verification.
- Persist credential format, hash, and pepper versions and support a named
  pepper verification key ring during rotation.

## 0.3.0

- Add canonical command fingerprints and replay/reuse detection for idempotency ledgers.

## 0.2.0

- Add a versioned, engine-neutral API command envelope with operation allowlists.
- Add optimistic-concurrency preconditions and idempotency receipt helpers.

## 0.1.0

- Add opaque API credential creation, verification, lifecycle policy, and storage-safe metadata.
