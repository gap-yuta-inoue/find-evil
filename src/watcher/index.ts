/**
 * Watcher — real-time anomaly detection.
 *
 * Monitors system logs, file changes, network connections, and processes
 * using event-driven mechanisms (not polling) for sub-second detection.
 *
 * Detection sources:
 * - syslog / auth.log: tail -f (event-driven) → ~1s latency
 * - File system: inotifywait (event-driven) → ~1s latency
 * - Network: conntrack (event-driven, recommended) → ~2s latency
 * - Process: auditd / proc connector (event-driven) → ~2s latency
 *
 * Target: Attack → Detection < 15 seconds (all sources)
 */

import type { AuditLogger } from "../audit/logger.js";

export interface DetectionRule {
  id: string;
  name: string;
  source: "syslog" | "auth" | "filesystem" | "network" | "process";
  pattern: RegExp | ((event: WatcherEvent) => boolean);
  severity: "low" | "medium" | "high" | "critical";
  description: string;
}

export interface WatcherEvent {
  timestamp: string;
  source: DetectionRule["source"];
  raw: string;
  parsed?: Record<string, unknown>;
}

export interface ThreatScore {
  score: number; // 0-100
  events: WatcherEvent[];
  matchedRules: DetectionRule[];
  shouldTrigger: boolean;
}

const DEFAULT_RULES: DetectionRule[] = [
  {
    id: "auth-brute-force",
    name: "Authentication brute force",
    source: "auth",
    pattern: /Failed password|authentication failure/i,
    severity: "high",
    description: "Multiple authentication failures detected",
  },
  {
    id: "priv-escalation",
    name: "Privilege escalation",
    source: "auth",
    pattern: /sudo.*COMMAND|su\s+root|pkexec/i,
    severity: "critical",
    description: "Privilege escalation attempt detected",
  },
  {
    id: "suspicious-file-change",
    name: "Suspicious file modification",
    source: "filesystem",
    pattern: /\/(etc\/(crontab|passwd|shadow|sudoers)|\.ssh\/authorized_keys)/,
    severity: "critical",
    description: "Critical system file modification detected",
  },
  {
    id: "unknown-outbound",
    name: "Unknown outbound connection",
    source: "network",
    pattern: /NEW.*dst=(?!10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/,
    severity: "medium",
    description: "New connection to non-private IP address",
  },
  {
    id: "suspicious-process",
    name: "Suspicious process execution",
    source: "process",
    pattern: /\/(tmp|dev\/shm)\/.+|nc\s+-[el]|python.*-c\s+['"]import socket/,
    severity: "high",
    description: "Execution from suspicious path or known attacker tool pattern",
  },
];

const TRIGGER_THRESHOLD = 60;

export function calculateThreatScore(events: WatcherEvent[], rules: DetectionRule[] = DEFAULT_RULES): ThreatScore {
  const matchedRules: DetectionRule[] = [];

  for (const event of events) {
    for (const rule of rules) {
      if (event.source !== rule.source) continue;

      const matches = rule.pattern instanceof RegExp
        ? rule.pattern.test(event.raw)
        : rule.pattern(event);

      if (matches) {
        matchedRules.push(rule);
      }
    }
  }

  const severityWeights = { low: 10, medium: 25, high: 50, critical: 80 };
  const score = Math.min(100, matchedRules.reduce((sum, r) => sum + severityWeights[r.severity], 0));

  return {
    score,
    events,
    matchedRules,
    shouldTrigger: score >= TRIGGER_THRESHOLD,
  };
}

export class Watcher {
  private rules: DetectionRule[];
  private logger: AuditLogger;
  private running = false;

  constructor(logger: AuditLogger, rules: DetectionRule[] = DEFAULT_RULES) {
    this.rules = rules;
    this.logger = logger;
  }

  addRule(rule: DetectionRule): void {
    this.rules.push(rule);
    this.logger.log("watcher_rule_added", { ruleId: rule.id, name: rule.name });
  }

  async start(): Promise<void> {
    this.running = true;
    this.logger.log("watcher_start", { ruleCount: this.rules.length });

    // TODO: Implement actual event source connections
    // - tail -f /var/log/syslog, /var/log/auth.log
    // - inotifywait -m -r /etc /home
    // - conntrack -E
    // - auditd / proc connector
    console.log(`[watcher] Started with ${this.rules.length} rules (trigger threshold: ${TRIGGER_THRESHOLD})`);
    console.log("[watcher] Event sources not yet connected — coming in Phase 1");
  }

  stop(): void {
    this.running = false;
    this.logger.log("watcher_stop", {});
  }

  isRunning(): boolean {
    return this.running;
  }
}
