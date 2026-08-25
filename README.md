# Sky Threat Triage Core

**Status: engineering beta / defensive security lab.** This repository is a bounded TypeScript library for triaging caller-supplied network-event telemetry with simple deterministic heuristics. It does not monitor networks by itself and does not perform response actions.

## Implemented

- strict event ID, address-label, port, protocol, byte-count, and timestamp validation
- bounded in-memory event and indicator capacity
- duplicate event rejection
- configurable sensitive-port heuristic
- configurable large-transfer heuristic
- real source-event burst detection within a bounded time window
- deterministic finding IDs derived from rule and source event
- severity summaries
- defensive copies of stored telemetry/results
- strict TypeScript build and Node built-in tests
- dependency audit in CI

## Use

```bash
npm install --ignore-scripts --no-fund
npm test
```

```ts
import { ThreatDetectionEngine } from './src';

const engine = new ThreatDetectionEngine();
engine.logNetworkEvent({
  id: 'evt-1',
  sourceIP: '10.0.0.1',
  destIP: '10.0.0.2',
  port: 22,
  protocol: 'tcp',
  bytesTransferred: 512,
  timestamp: 1_725_000_000_000,
});

console.log(engine.getThreats());
```

## Detection boundary

These findings are **heuristics**, not proof of an attack. A sensitive-port event is labeled `sensitive_port_access`, not falsely called a port scan. A large transfer alone is not proof of exfiltration. A burst indicator means a configured number of events from one source occurred within the configured time window.

The library intentionally has no `respondToThreat`, firewall, quarantine, process-kill, network-scan, credential, exploit, or remote-execution capability.

## SKYCOIN4444 integration

Use this core behind a separately authenticated telemetry ingestion boundary for local triage, observability enrichment, or security dashboards. Production integration must add durable event storage, privacy/data-retention policy, trusted sensor identity, time normalization, alert review, false-positive handling, observability, and explicitly authorized response workflows.

## Explicit limitations

This is process-local and in-memory. It does not capture packets, open sockets, scan hosts, probe services, query external reputation systems, inspect malware, perform SIEM correlation, use ML, provide threat intelligence, isolate tenants, authenticate callers, maintain durable audit history, deliver alerts, execute incident response, provide HA, or prove production deployment.

A clean result is not a security certification, and a finding is not confirmation of compromise.

See `SECURITY.md` and `CHANGELOG.md`.
