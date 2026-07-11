/**
 * Cybersecurity Threat Detection System
 * Network monitoring, anomaly detection, incident response
 */

export interface NetworkEvent {
  id: string;
  sourceIP: string;
  destIP: string;
  port: number;
  protocol: string;
  bytesTransferred: number;
  timestamp: number;
}

export interface ThreatIndicator {
  id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  timestamp: number;
  relatedEvents: NetworkEvent[];
}

export class ThreatDetectionEngine {
  private events: NetworkEvent[] = [];
  private threats: ThreatIndicator[] = [];
  private suspiciousPatterns = [
    { name: 'port_scan', ports: new Set([22, 23, 80, 443, 3306, 5432]) },
    { name: 'data_exfiltration', minBytes: 1000000 },
    { name: 'brute_force', maxAttemptsPerMinute: 100 },
  ];

  logNetworkEvent(event: NetworkEvent): void {
    this.events.push(event);
    this.analyzeEvent(event);
  }

  private analyzeEvent(event: NetworkEvent): void {
    // Check for suspicious patterns
    if (this.suspiciousPatterns[0].ports.has(event.port)) {
      this.createThreatIndicator('port_scan', 'medium', `Suspicious port access: ${event.port}`, [event]);
    }

    if (event.bytesTransferred > this.suspiciousPatterns[1].minBytes) {
      this.createThreatIndicator('data_exfiltration', 'high', 'Large data transfer detected', [event]);
    }
  }

  private createThreatIndicator(type: string, severity: string, description: string, events: NetworkEvent[]): void {
    const threat: ThreatIndicator = {
      id: `threat-${Date.now()}`,
      type,
      severity: severity as any,
      description,
      timestamp: Date.now(),
      relatedEvents: events,
    };

    this.threats.push(threat);
  }

  getThreats(): ThreatIndicator[] {
    return this.threats;
  }

  getNetworkEvents(): NetworkEvent[] {
    return this.events;
  }

  respondToThreat(threatId: string): void {
    const threat = this.threats.find((t) => t.id === threatId);
    if (threat) {
      console.log(`Automated response initiated for threat: ${threat.type}`);
      // Automated response logic
    }
  }
}

export default ThreatDetectionEngine;
