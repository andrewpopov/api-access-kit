---
kind: fixed
summary: the aggregate verification gate now rejects stale committed build output
---

`npm run verify` now carries the same committed-`dist/` freshness protection as
the pre-push hook instead of relying on callers to remember a separate command.
