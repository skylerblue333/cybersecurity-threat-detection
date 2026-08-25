import assert from 'node:assert/strict';
import test from 'node:test';
import { NetworkEvent, ThreatDetectionEngine } from '../src/index';

function event(overrides: Partial<NetworkEvent> = {}): NetworkEvent {
  return {
    id: 'evt-1',
    sourceIP: '10.0.0.1',
    destIP: '10.0.0.2',
    port: 443,
    protocol: 'tcp',
    bytesTransferred: 100,
    timestamp: 1_000,
    outcome: 'allowed',
    ...overrides,
  };
}

test('ordinary HTTPS event is not mislabeled as a port scan', () => {
  const engine = new ThreatDetectionEngine();
  assert.deepEqual(engine.logNetworkEvent(event()), []);
  assert.equal(engine.summary().indicators, 0);
});

test('flags configured sensitive port and large transfer heuristics', () => {
  const engine = new ThreatDetectionEngine();
  const indicators = engine.logNetworkEvent(
    event({ port: 22, bytesTransferred: 1_000_000 }),
  );
  assert.deepEqual(indicators.map((item) => item.ruleId), [
    'sensitive_port_access',
    'large_transfer',
  ]);
  assert.deepEqual(engine.summary().bySeverity, {
    low: 0,
    medium: 1,
    high: 1,
    critical: 0,
  });
});

test('detects an exact source burst once at the configured threshold', () => {
  const engine = new ThreatDetectionEngine({ burstCount: 3, burstWindowMs: 1_000 });
  engine.logNetworkEvent(event({ id: 'evt-1', timestamp: 1_000 }));
  engine.logNetworkEvent(event({ id: 'evt-2', timestamp: 1_100, port: 443 }));
  const created = engine.logNetworkEvent(event({ id: 'evt-3', timestamp: 1_200, port: 443 }));
  assert.equal(created.length, 1);
  assert.equal(created[0].ruleId, 'connection_burst');
  assert.deepEqual(created[0].eventIds, ['evt-1', 'evt-2', 'evt-3']);
});

test('rejects duplicate and malformed telemetry', () => {
  const engine = new ThreatDetectionEngine();
  engine.logNetworkEvent(event());
  assert.throws(() => engine.logNetworkEvent(event()), /duplicate event id/);
  assert.throws(() => engine.logNetworkEvent(event({ id: 'evt-2', port: 0 })), /invalid port/);
  assert.throws(
    () => engine.logNetworkEvent(event({ id: 'evt-3', bytesTransferred: -1 })),
    /invalid byte count/,
  );
});

test('enforces event and indicator capacity without claiming response action', () => {
  const engine = new ThreatDetectionEngine({ maxEvents: 1, maxIndicators: 1 });
  engine.logNetworkEvent(event({ port: 22 }));
  assert.throws(
    () => engine.logNetworkEvent(event({ id: 'evt-2', timestamp: 2_000 })),
    /event capacity reached/,
  );
  assert.equal('respondToThreat' in engine, false);
});

test('returns defensive copies of collected telemetry', () => {
  const engine = new ThreatDetectionEngine();
  engine.logNetworkEvent(event({ port: 22 }));
  const events = engine.getNetworkEvents();
  events[0].port = 1;
  const threats = engine.getThreats();
  threats[0].eventIds.push('mutated');
  assert.equal(engine.getNetworkEvents()[0].port, 22);
  assert.deepEqual(engine.getThreats()[0].eventIds, ['evt-1']);
});
