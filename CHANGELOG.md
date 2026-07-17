# Changelog

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
