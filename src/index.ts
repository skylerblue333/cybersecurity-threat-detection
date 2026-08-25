export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface NetworkEvent {
  id: string;
  sourceIP: string;
  destIP: string;
  port: number;
  protocol: 'tcp' | 'udp';
  bytesTransferred: number;
  timestamp: number;
  outcome?: 'allowed' | 'blocked' | 'failed';
}

export interface ThreatIndicator {
  id: string;
  ruleId: 'sensitive_port_access' | 'large_transfer' | 'connection_burst';
  severity: Severity;
  description: string;
  eventIds: string[];
  timestamp: number;
}

export interface DetectionConfig {
  maxEvents: number;
  maxIndicators: number;
  largeTransferBytes: number;
  burstWindowMs: number;
  burstCount: number;
  sensitivePorts: ReadonlySet<number>;
}

const DEFAULT_CONFIG: DetectionConfig = {
  maxEvents: 10_000,
  maxIndicators: 10_000,
  largeTransferBytes: 1_000_000,
  burstWindowMs: 60_000,
  burstCount: 20,
  sensitivePorts: new Set([22, 23, 3306, 5432, 6379, 27017]),
};

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const IP_LABEL_PATTERN = /^[A-Fa-f0-9.:]{2,64}$/;

/**
 * Deterministic, process-local triage for caller-supplied network telemetry.
 * This class never opens sockets, scans a target, blocks traffic, or executes a response.
 */
export class ThreatDetectionEngine {
  private readonly events: NetworkEvent[] = [];
  private readonly threats: ThreatIndicator[] = [];
  private readonly seenEventIds = new Set<string>();
  private readonly config: DetectionConfig;

  constructor(config: Partial<DetectionConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    if (this.config.maxEvents < 1 || this.config.maxEvents > 100_000) throw new Error('maxEvents out of range');
    if (this.config.maxIndicators < 1 || this.config.maxIndicators > 100_000) throw new Error('maxIndicators out of range');
    if (this.config.largeTransferBytes < 1 || !Number.isSafeInteger(this.config.largeTransferBytes)) {
      throw new Error('largeTransferBytes must be a positive safe integer');
    }
    if (this.config.burstWindowMs < 1 || this.config.burstWindowMs > 3_600_000) throw new Error('burstWindowMs out of range');
    if (this.config.burstCount < 2 || this.config.burstCount > 10_000) throw new Error('burstCount out of range');
  }

  logNetworkEvent(event: NetworkEvent): ThreatIndicator[] {
    this.validateEvent(event);
    if (this.seenEventIds.has(event.id)) throw new Error('duplicate event id');
    if (this.events.length >= this.config.maxEvents) throw new Error('event capacity reached');

    this.events.push({ ...event });
    this.seenEventIds.add(event.id);
    const created = this.analyzeEvent(event);
    if (this.threats.length + created.length > this.config.maxIndicators) {
      this.events.pop();
      this.seenEventIds.delete(event.id);
      throw new Error('indicator capacity reached');
    }
    this.threats.push(...created);
    return created.map((indicator) => ({ ...indicator, eventIds: [...indicator.eventIds] }));
  }

  getThreats(): ThreatIndicator[] {
    return this.threats.map((indicator) => ({ ...indicator, eventIds: [...indicator.eventIds] }));
  }

  getNetworkEvents(): NetworkEvent[] {
    return this.events.map((event) => ({ ...event }));
  }

  summary(): { events: number; indicators: number; bySeverity: Record<Severity, number> } {
    const bySeverity: Record<Severity, number> = { low: 0, medium: 0, high: 0, critical: 0 };
    for (const indicator of this.threats) bySeverity[indicator.severity] += 1;
    return { events: this.events.length, indicators: this.threats.length, bySeverity };
  }

  private analyzeEvent(event: NetworkEvent): ThreatIndicator[] {
    const created: ThreatIndicator[] = [];

    if (this.config.sensitivePorts.has(event.port)) {
      created.push(this.indicator('sensitive_port_access', 'medium', `Access to monitored port ${event.port}`, [event]));
    }

    if (event.bytesTransferred >= this.config.largeTransferBytes) {
      created.push(this.indicator('large_transfer', 'high', 'Transfer exceeded configured byte threshold', [event]));
    }

    const windowStart = event.timestamp - this.config.burstWindowMs;
    const related = this.events.filter(
      (candidate) =>
        candidate.sourceIP === event.sourceIP &&
        candidate.timestamp >= windowStart &&
        candidate.timestamp <= event.timestamp,
    );
    if (related.length === this.config.burstCount) {
      created.push(
        this.indicator(
          'connection_burst',
          'high',
          `Source produced ${related.length} events inside the configured window`,
          related,
        ),
      );
    }

    return created;
  }

  private indicator(
    ruleId: ThreatIndicator['ruleId'],
    severity: Severity,
    description: string,
    events: NetworkEvent[],
  ): ThreatIndicator {
    const last = events[events.length - 1];
    return {
      id: `${ruleId}:${last.id}`,
      ruleId,
      severity,
      description,
      eventIds: events.map((event) => event.id),
      timestamp: last.timestamp,
    };
  }

  private validateEvent(event: NetworkEvent): void {
    if (!ID_PATTERN.test(event.id)) throw new Error('invalid event id');
    if (!IP_LABEL_PATTERN.test(event.sourceIP) || !IP_LABEL_PATTERN.test(event.destIP)) throw new Error('invalid IP address label');
    if (!Number.isInteger(event.port) || event.port < 1 || event.port > 65_535) throw new Error('invalid port');
    if (event.protocol !== 'tcp' && event.protocol !== 'udp') throw new Error('invalid protocol');
    if (!Number.isSafeInteger(event.bytesTransferred) || event.bytesTransferred < 0) throw new Error('invalid byte count');
    if (!Number.isSafeInteger(event.timestamp) || event.timestamp < 0) throw new Error('invalid timestamp');
  }
}

export default ThreatDetectionEngine;
