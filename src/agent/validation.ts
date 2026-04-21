/**
 * Validation Layer — confidence scoring and cross-checking.
 *
 * Responsibilities:
 * - Assign confidence levels to findings (confirmed / inferred / uncertain)
 * - Cross-check Disk ↔ Memory findings for contradictions
 * - Detect potential hallucinations by requiring tool evidence
 * - Flag inconsistencies for self-correction
 */

import type { Finding } from "./orchestrator.js";
import type { AuditLogger, ConfidenceLevel } from "../audit/logger.js";

export interface ValidationResult {
  finding: Finding;
  originalConfidence: ConfidenceLevel;
  validatedConfidence: ConfidenceLevel;
  crossCheckResults: CrossCheckResult[];
  requiresSelfCorrection: boolean;
  correctionHint?: string;
}

export interface CrossCheckResult {
  source1: string;
  source2: string;
  consistent: boolean;
  detail: string;
}

/**
 * Score confidence based on evidence quantity and diversity.
 */
export function scoreConfidence(evidence: string[]): ConfidenceLevel {
  if (evidence.length === 0) return "uncertain";

  const sources = new Set(evidence.map(e => classifyEvidenceSource(e)));

  // Multiple independent sources → confirmed
  if (sources.size >= 2) return "confirmed";

  // Single source but multiple data points → inferred
  if (evidence.length >= 2) return "inferred";

  // Single piece of evidence → uncertain
  return "uncertain";
}

function classifyEvidenceSource(evidence: string): string {
  if (evidence.includes("disk") || evidence.includes("fls") || evidence.includes("icat") || evidence.includes("mmls")) return "disk";
  if (evidence.includes("memory") || evidence.includes("vol3") || evidence.includes("pslist") || evidence.includes("malfind")) return "memory";
  if (evidence.includes("log") || evidence.includes("grep") || evidence.includes("syslog") || evidence.includes("auth.log")) return "log";
  if (evidence.includes("network") || evidence.includes("pcap") || evidence.includes("zeek") || evidence.includes("tshark")) return "network";
  return "unknown";
}

/**
 * Cross-check a finding between disk and memory evidence.
 * Returns inconsistencies that may indicate hallucination or require self-correction.
 */
export function crossCheckDiskMemory(
  diskFindings: Finding[],
  memoryFindings: Finding[],
  logger: AuditLogger,
): CrossCheckResult[] {
  const results: CrossCheckResult[] = [];

  // Check: processes found in memory should have corresponding disk artifacts
  const memoryProcesses = memoryFindings
    .filter(f => f.description.includes("process"))
    .map(f => f.description);

  for (const proc of memoryProcesses) {
    const hasDiskEvidence = diskFindings.some(f =>
      f.description.includes(proc) || f.evidence.some(e => e.includes(proc))
    );

    const result: CrossCheckResult = {
      source1: "memory",
      source2: "disk",
      consistent: hasDiskEvidence,
      detail: hasDiskEvidence
        ? `Process "${proc}" found in both memory and disk evidence`
        : `Process "${proc}" found in memory but no corresponding disk artifact — potential fileless malware or memory-only activity`,
    };

    results.push(result);
    logger.logCrossCheck(result.source1, result.source2, result.consistent, result.detail);
  }

  // Check: timestamps should be consistent across sources
  // TODO: Implement timestamp consistency checking

  return results;
}

/**
 * Validate a finding and assign confidence.
 */
export function validateFinding(
  finding: Finding,
  allFindings: Finding[],
  logger: AuditLogger,
): ValidationResult {
  const originalConfidence = finding.confidence;
  const validatedConfidence = scoreConfidence(finding.evidence);

  const crossCheckResults: CrossCheckResult[] = [];
  let requiresSelfCorrection = false;
  let correctionHint: string | undefined;

  // If confidence dropped, flag for review
  const confidenceRank = { confirmed: 3, inferred: 2, uncertain: 1 };
  if (confidenceRank[validatedConfidence] < confidenceRank[originalConfidence]) {
    requiresSelfCorrection = true;
    correctionHint = `Confidence downgraded from ${originalConfidence} to ${validatedConfidence} — gather more evidence from additional tools/sources`;
  }

  // Check for contradicting findings
  const contradictions = allFindings.filter(f =>
    f.id !== finding.id && isContradicting(finding, f)
  );

  if (contradictions.length > 0) {
    requiresSelfCorrection = true;
    correctionHint = `Finding contradicts ${contradictions.length} other finding(s) — re-examine with additional tools`;
  }

  return {
    finding: { ...finding, confidence: validatedConfidence },
    originalConfidence,
    validatedConfidence,
    crossCheckResults,
    requiresSelfCorrection,
    correctionHint,
  };
}

function isContradicting(a: Finding, b: Finding): boolean {
  // Basic contradiction detection — same subject, different conclusions
  // TODO: Implement more sophisticated contradiction detection using NLP
  return false;
}
