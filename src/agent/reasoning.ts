/**
 * Reasoning Engine — hypothesis-driven analysis loop with self-correction.
 *
 * The core analysis loop:
 * 1. Generate hypothesis based on current findings
 * 2. Select tools to test the hypothesis
 * 3. Execute tools and interpret results
 * 4. Validate — check for contradictions and score confidence
 * 5. Self-correct if validation fails, otherwise record finding
 * 6. Repeat until no new hypotheses or max iterations reached
 */

import type { Finding, AnalysisPhase } from "./orchestrator.js";
import type { AuditLogger, ConfidenceLevel } from "../audit/logger.js";
import { validateFinding } from "./validation.js";

export interface Hypothesis {
  id: string;
  description: string;
  toolsToTest: string[];
  status: "pending" | "testing" | "confirmed" | "refuted" | "uncertain";
  evidence: string[];
  iterations: number;
}

export interface ReasoningState {
  hypotheses: Hypothesis[];
  findings: Finding[];
  iterations: number;
  maxIterations: number;
  selfCorrections: number;
}

export function createReasoningState(maxIterations: number = 20): ReasoningState {
  return {
    hypotheses: [],
    findings: [],
    iterations: 0,
    maxIterations,
    selfCorrections: 0,
  };
}

/**
 * Generate initial hypotheses based on evidence type and triage results.
 */
export function generateInitialHypotheses(
  phase: AnalysisPhase,
  triageFindings: Finding[],
): Hypothesis[] {
  const hypotheses: Hypothesis[] = [];

  if (phase.name === "disk_analysis") {
    hypotheses.push(
      {
        id: crypto.randomUUID(),
        description: "Malicious files or scripts exist on disk",
        toolsToTest: ["disk_list_files", "disk_bulk_extract"],
        status: "pending",
        evidence: [],
        iterations: 0,
      },
      {
        id: crypto.randomUUID(),
        description: "Timeline shows suspicious file creation/modification patterns",
        toolsToTest: ["disk_create_timeline"],
        status: "pending",
        evidence: [],
        iterations: 0,
      },
    );
  }

  if (phase.name === "memory_analysis") {
    hypotheses.push(
      {
        id: crypto.randomUUID(),
        description: "Suspicious or injected processes are running",
        toolsToTest: ["memory_pslist", "memory_malfind"],
        status: "pending",
        evidence: [],
        iterations: 0,
      },
      {
        id: crypto.randomUUID(),
        description: "Unusual network connections indicate C2 communication",
        toolsToTest: ["memory_netscan"],
        status: "pending",
        evidence: [],
        iterations: 0,
      },
      {
        id: crypto.randomUUID(),
        description: "Suspicious command-line arguments reveal attacker intent",
        toolsToTest: ["memory_cmdline"],
        status: "pending",
        evidence: [],
        iterations: 0,
      },
    );
  }

  return hypotheses;
}

/**
 * Process a tool execution result and update the reasoning state.
 */
export function processToolResult(
  state: ReasoningState,
  hypothesis: Hypothesis,
  toolName: string,
  result: string,
  logger: AuditLogger,
): { newFindings: Finding[]; needsSelfCorrection: boolean; correctionHint?: string } {
  state.iterations++;
  hypothesis.iterations++;

  // Parse result into potential findings
  // TODO: Integrate with Claude API for intelligent result interpretation
  const newFindings: Finding[] = [];

  // Validate each finding
  let needsSelfCorrection = false;
  let correctionHint: string | undefined;

  for (const finding of newFindings) {
    const validation = validateFinding(finding, state.findings, logger);
    if (validation.requiresSelfCorrection) {
      needsSelfCorrection = true;
      correctionHint = validation.correctionHint;
      state.selfCorrections++;
      logger.logSelfCorrection(
        finding.description,
        `Re-examining: ${correctionHint}`,
        correctionHint ?? "Validation failed"
      );
    } else {
      state.findings.push(validation.finding);
    }
  }

  return { newFindings, needsSelfCorrection, correctionHint };
}

/**
 * Check if the reasoning loop should continue.
 */
export function shouldContinue(state: ReasoningState): boolean {
  if (state.iterations >= state.maxIterations) return false;
  return state.hypotheses.some(h => h.status === "pending" || h.status === "testing");
}
