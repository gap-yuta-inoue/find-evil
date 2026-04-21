import { mkdirSync, appendFileSync } from "node:fs";
import { join } from "node:path";

export type ConfidenceLevel = "confirmed" | "inferred" | "uncertain";

export interface AuditEntry {
  timestamp: string;
  event: string;
  data: Record<string, unknown>;
  tokenUsage?: { input: number; output: number };
  confidence?: ConfidenceLevel;
  durationMs?: number;
}

export class AuditLogger {
  private logDir: string;
  private logFile: string;
  private sessionId: string;
  private startTime: number;

  constructor(logDir: string) {
    this.logDir = logDir;
    this.sessionId = crypto.randomUUID();
    this.startTime = Date.now();

    mkdirSync(logDir, { recursive: true });
    this.logFile = join(logDir, `session-${this.sessionId}.jsonl`);
  }

  log(event: string, data: Record<string, unknown>, options?: {
    tokenUsage?: { input: number; output: number };
    confidence?: ConfidenceLevel;
    durationMs?: number;
  }): void {
    const entry: AuditEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      ...options,
    };

    const line = JSON.stringify(entry) + "\n";
    appendFileSync(this.logFile, line, "utf-8");
  }

  logToolExecution(tool: string, args: Record<string, unknown>, result: unknown, durationMs: number): void {
    this.log("tool_execution", {
      tool,
      args,
      resultSummary: typeof result === "string" ? result.slice(0, 500) : JSON.stringify(result).slice(0, 500),
    }, { durationMs });
  }

  logFinding(finding: string, confidence: ConfidenceLevel, evidence: string[]): void {
    this.log("finding", { finding, evidence }, { confidence });
  }

  logSelfCorrection(original: string, corrected: string, reason: string): void {
    this.log("self_correction", { original, corrected, reason });
  }

  logCrossCheck(source1: string, source2: string, consistent: boolean, detail: string): void {
    this.log("cross_check", { source1, source2, consistent, detail });
  }

  getSessionId(): string {
    return this.sessionId;
  }

  getLogFile(): string {
    return this.logFile;
  }

  getElapsedMs(): number {
    return Date.now() - this.startTime;
  }
}
