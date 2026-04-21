/**
 * Orchestrator — manages cases and plans analysis phases.
 *
 * Responsibilities:
 * - Auto-generate cases from detection events or manual input
 * - Plan analysis phases based on evidence type
 * - Execute phases sequentially, passing findings between phases
 * - Coordinate with Reasoning Engine for hypothesis-driven analysis
 */

import type { AuditLogger, ConfidenceLevel } from "../audit/logger.js";

export interface Evidence {
  path: string;
  type: "disk_image" | "memory_capture" | "log_directory" | "pcap" | "unknown";
  sizeBytes?: number;
}

export interface Finding {
  id: string;
  description: string;
  confidence: ConfidenceLevel;
  evidence: string[];
  timestamp: string;
  relatedFindings: string[];
}

export interface Case {
  id: string;
  createdAt: string;
  trigger: "manual" | "watcher" | "benchmark";
  evidence: Evidence[];
  phases: AnalysisPhase[];
  findings: Finding[];
  status: "created" | "triaging" | "analyzing" | "validating" | "complete";
}

export interface AnalysisPhase {
  name: string;
  tools: string[];
  status: "pending" | "running" | "complete" | "failed";
  findings: Finding[];
}

export function detectEvidenceType(path: string): Evidence["type"] {
  const lower = path.toLowerCase();
  if (lower.endsWith(".dd") || lower.endsWith(".raw") || lower.endsWith(".e01")) return "disk_image";
  if (lower.endsWith(".vmem") || lower.endsWith(".mem") || lower.endsWith(".dmp")) return "memory_capture";
  if (lower.endsWith(".pcap") || lower.endsWith(".pcapng")) return "pcap";
  // TODO: check if directory for log_directory type
  return "unknown";
}

export function planAnalysis(evidence: Evidence[]): AnalysisPhase[] {
  const phases: AnalysisPhase[] = [];
  const types = new Set(evidence.map(e => e.type));

  // Phase 1: Triage — identify what we have
  phases.push({
    name: "triage",
    tools: ["disk_list_partitions", "memory_info"],
    status: "pending",
    findings: [],
  });

  // Phase 2: Disk analysis (if applicable)
  if (types.has("disk_image")) {
    phases.push({
      name: "disk_analysis",
      tools: ["disk_list_files", "disk_create_timeline", "disk_bulk_extract"],
      status: "pending",
      findings: [],
    });
  }

  // Phase 3: Memory analysis (if applicable)
  if (types.has("memory_capture")) {
    phases.push({
      name: "memory_analysis",
      tools: ["memory_pslist", "memory_netscan", "memory_malfind", "memory_cmdline"],
      status: "pending",
      findings: [],
    });
  }

  // Phase 4: Log analysis
  phases.push({
    name: "log_analysis",
    tools: ["log_search", "log_parse_json"],
    status: "pending",
    findings: [],
  });

  // Phase 5: Cross-source correlation (if multiple evidence types)
  if (types.size > 1) {
    phases.push({
      name: "cross_source_correlation",
      tools: [],
      status: "pending",
      findings: [],
    });
  }

  return phases;
}

export function createCase(trigger: Case["trigger"], evidencePaths: string[], logger: AuditLogger): Case {
  const evidence = evidencePaths.map(path => ({
    path,
    type: detectEvidenceType(path),
  }));

  const caseObj: Case = {
    id: crypto.randomUUID(),
    createdAt: new Date().toISOString(),
    trigger,
    evidence,
    phases: planAnalysis(evidence),
    findings: [],
    status: "created",
  };

  logger.log("case_created", {
    caseId: caseObj.id,
    trigger,
    evidenceCount: evidence.length,
    evidenceTypes: [...new Set(evidence.map(e => e.type))],
    plannedPhases: caseObj.phases.map(p => p.name),
  });

  return caseObj;
}
