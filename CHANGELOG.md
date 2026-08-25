# Changelog

## 0.1.0 - 2026-08-24

- Replaced misleading broad threat-detection/incident-response claims with a bounded offline triage core.
- Corrected the old behavior that labeled ordinary access to ports such as 80/443 as a port scan.
- Added validated, capacity-limited event ingestion and duplicate rejection.
- Added sensitive-port, large-transfer, and actual source-burst heuristics with deterministic finding IDs.
- Removed the fake automated-response method; the library performs no network or response actions.
- Added strict TypeScript compilation, deterministic Node tests, and dependency-audit CI.
- Documented defensive-use, privacy, false-positive, and production boundaries.
