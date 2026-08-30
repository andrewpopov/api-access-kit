---
kind: added
summary: Add the fleet-standard aggregate `verify` npm script
---

`npm run verify` now runs typecheck, tests, build, and the packed-consumer
check in one authoritative local gate, matching the convention used by every
other kit in the fleet.
