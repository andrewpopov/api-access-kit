# Changelog

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
