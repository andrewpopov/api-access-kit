# Changelog

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
