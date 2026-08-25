# Security Policy

Sky Threat Triage Core is a defensive engineering-beta library. It only analyzes telemetry supplied by its caller and does not initiate network activity or incident-response actions.

## Current controls

- bounded event and finding capacities
- strict event identifiers, ports, protocol, byte counts, and timestamps
- duplicate event rejection
- deterministic rule output
- no dynamic code execution
- no socket/network access in application code
- no credential handling
- strict TypeScript compilation and deterministic tests
- dependency audit in CI

## Boundaries

Heuristic findings can be false positives or false negatives and must not be treated as proof of compromise. The library does not authenticate telemetry sources, protect log confidentiality, redact personal data, maintain a durable audit trail, deliver alerts, block traffic, isolate hosts, or provide production incident response.

Only analyze telemetry you are authorized to process. Production adoption requires identity, authorization, retention/privacy controls, encrypted transport/storage, trusted clocks/sensors, review workflows, monitoring, and an independently validated response process.

Report vulnerabilities privately through GitHub security reporting when available. Do not publish credentials, private telemetry, or sensitive incident data in public issues.
