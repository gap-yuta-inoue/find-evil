/**
 * Analysis Runner — executes a complete IR analysis pipeline.
 *
 * This is the programmatic orchestrator that runs without Claude.
 * It executes tools in a fixed sequence, collects results, and
 * produces a structured JSON report. For the full autonomous
 * agent experience, use Claude Code with the CLAUDE.md instructions.
 */

import { statSync } from "node:fs";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { execInSift } from "../mcp-server/executor.js";
import { AuditLogger } from "../audit/logger.js";
import { createCase, detectEvidenceType, type Case, type Finding } from "./orchestrator.js";
import { scoreConfidence } from "./validation.js";

export interface AnalysisReport {
  caseId: string;
  evidence: { path: string; type: string; sizeBytes: number }[];
  startedAt: string;
  completedAt: string;
  durationMs: number;
  phases: PhaseResult[];
  findings: Finding[];
  auditLogFile: string;
}

interface PhaseResult {
  name: string;
  tools: ToolResult[];
  durationMs: number;
}

interface ToolResult {
  tool: string;
  command: string;
  exitCode: number;
  durationMs: number;
  outputLines: number;
  outputPreview: string;
}

function containerPath(localPath: string): string {
  // Map local evidence/ paths to container /cases/ paths
  const filename = localPath.split("/").pop()!;
  return `/cases/${filename}`;
}

async function runTool(command: string, logger: AuditLogger, timeout?: number): Promise<ToolResult> {
  const result = await execInSift(command, logger, { timeout });
  const output = result.stdout || result.stderr;
  const lines = output.split("\n").filter(l => l.trim()).length;
  return {
    tool: command.split(" ")[0],
    command,
    exitCode: result.exitCode,
    durationMs: result.durationMs,
    outputLines: lines,
    outputPreview: output.slice(0, 2000),
  };
}

async function runDiskTriage(evidencePath: string, logger: AuditLogger): Promise<PhaseResult> {
  const start = Date.now();
  const cp = containerPath(evidencePath);
  const tools: ToolResult[] = [];

  console.log("  [triage] Running img_stat...");
  tools.push(await runTool(`img_stat ${cp}`, logger));

  console.log("  [triage] Running mmls...");
  tools.push(await runTool(`mmls ${cp}`, logger));

  console.log("  [triage] Running fls (recursive)...");
  tools.push(await runTool(`fls -r -p ${cp}`, logger));

  return { name: "disk_triage", tools, durationMs: Date.now() - start };
}

async function runDiskAnalysis(evidencePath: string, logger: AuditLogger): Promise<PhaseResult> {
  const start = Date.now();
  const cp = containerPath(evidencePath);
  const tools: ToolResult[] = [];

  console.log("  [disk] Looking for deleted files...");
  tools.push(await runTool(`fls -r -p -d ${cp}`, logger));

  console.log("  [disk] Creating bodyfile for timeline...");
  await execInSift("mkdir -p /analysis/timeline", logger);
  tools.push(await runTool(`fls -r -m / ${cp} > /analysis/timeline/bodyfile.txt && wc -l /analysis/timeline/bodyfile.txt`, logger));

  console.log("  [disk] Generating MAC timeline...");
  tools.push(await runTool(`mactime -b /analysis/timeline/bodyfile.txt -z UTC -d | head -100`, logger));

  return { name: "disk_analysis", tools, durationMs: Date.now() - start };
}

async function runMemoryTriage(evidencePath: string, logger: AuditLogger): Promise<PhaseResult> {
  const start = Date.now();
  const cp = containerPath(evidencePath);
  const tools: ToolResult[] = [];

  console.log("  [triage] Running vol windows.info...");
  tools.push(await runTool(`vol -f ${cp} windows.info`, logger, 120_000));

  console.log("  [triage] Running vol windows.pslist...");
  tools.push(await runTool(`vol -f ${cp} windows.pslist`, logger, 120_000));

  console.log("  [triage] Running vol windows.psscan...");
  tools.push(await runTool(`vol -f ${cp} windows.psscan`, logger, 120_000));

  return { name: "memory_triage", tools, durationMs: Date.now() - start };
}

async function runMemoryAnalysis(evidencePath: string, logger: AuditLogger): Promise<PhaseResult> {
  const start = Date.now();
  const cp = containerPath(evidencePath);
  const tools: ToolResult[] = [];

  console.log("  [memory] Running vol windows.netscan...");
  tools.push(await runTool(`vol -f ${cp} windows.netscan`, logger, 120_000));

  console.log("  [memory] Running vol windows.malfind...");
  tools.push(await runTool(`vol -f ${cp} windows.malfind`, logger, 120_000));

  console.log("  [memory] Running vol windows.cmdline...");
  tools.push(await runTool(`vol -f ${cp} windows.cmdline`, logger, 120_000));

  console.log("  [memory] Running vol windows.svcscan...");
  tools.push(await runTool(`vol -f ${cp} windows.svcscan`, logger, 120_000));

  return { name: "memory_analysis", tools, durationMs: Date.now() - start };
}

export async function runAnalysis(
  evidencePaths: string[],
  logger: AuditLogger,
  verbose: boolean,
): Promise<AnalysisReport> {
  const startedAt = new Date().toISOString();
  const startMs = Date.now();

  // Create case
  const caseObj = createCase("manual", evidencePaths, logger);
  console.log(`[find-evil] Case ${caseObj.id} created`);
  console.log(`[find-evil] Evidence types: ${caseObj.evidence.map(e => e.type).join(", ")}`);
  console.log(`[find-evil] Planned phases: ${caseObj.phases.map(p => p.name).join(" → ")}`);
  console.log("");

  const phases: PhaseResult[] = [];
  const findings: Finding[] = [];

  for (const ev of evidencePaths) {
    const type = detectEvidenceType(ev);
    const size = (() => { try { return statSync(ev).size; } catch { return 0; } })();

    console.log(`[find-evil] === Analyzing: ${ev} (${type}, ${(size / 1024 / 1024).toFixed(1)}MB) ===`);

    if (type === "disk_image") {
      console.log("[phase 1] Disk Triage");
      phases.push(await runDiskTriage(ev, logger));

      console.log("[phase 2] Disk Deep Analysis");
      phases.push(await runDiskAnalysis(ev, logger));
    }

    if (type === "memory_capture" || ev.endsWith(".img")) {
      console.log("[phase 1] Memory Triage");
      phases.push(await runMemoryTriage(ev, logger));

      console.log("[phase 2] Memory Deep Analysis");
      phases.push(await runMemoryAnalysis(ev, logger));
    }

    if (type === "unknown" && !ev.endsWith(".img")) {
      console.log(`[warning] Unknown evidence type for ${ev}, skipping`);
    }
  }

  const completedAt = new Date().toISOString();
  const durationMs = Date.now() - startMs;

  const report: AnalysisReport = {
    caseId: caseObj.id,
    evidence: evidencePaths.map(p => ({
      path: p,
      type: detectEvidenceType(p),
      sizeBytes: (() => { try { return statSync(p).size; } catch { return 0; } })(),
    })),
    startedAt,
    completedAt,
    durationMs,
    phases,
    findings,
    auditLogFile: logger.getLogFile(),
  };

  // Save report
  mkdirSync("reports", { recursive: true });
  const reportPath = join("reports", `case-${caseObj.id}.json`);
  writeFileSync(reportPath, JSON.stringify(report, null, 2));

  console.log("");
  console.log(`[find-evil] Analysis complete in ${(durationMs / 1000).toFixed(1)}s`);
  console.log(`[find-evil] ${phases.length} phases, ${phases.reduce((s, p) => s + p.tools.length, 0)} tool executions`);
  console.log(`[find-evil] Report: ${reportPath}`);
  console.log(`[find-evil] Audit log: ${logger.getLogFile()}`);

  return report;
}
