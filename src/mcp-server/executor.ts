/**
 * Docker Executor — runs forensic commands inside the SIFT container.
 *
 * All tool executions go through this layer, which:
 * 1. Passes through the Guardrail check
 * 2. Executes via `docker exec` against the SIFT container
 * 3. Logs execution to the Audit Logger
 * 4. Returns structured output
 */

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { checkCommand } from "./guardrails.js";
import type { AuditLogger } from "../audit/logger.js";

const execFileAsync = promisify(execFile);

const CONTAINER_NAME = "find-evil-sift";
const DEFAULT_TIMEOUT = 300_000; // 5 minutes

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  blocked?: boolean;
  blockReason?: string;
}

export async function execInSift(
  command: string,
  logger: AuditLogger,
  options?: { timeout?: number; workingDir?: string },
): Promise<ExecResult> {
  const startTime = Date.now();

  // Guardrail check
  const check = checkCommand(command);
  if (!check.allowed) {
    const result: ExecResult = {
      stdout: "",
      stderr: `GUARDRAIL BLOCKED: ${check.reason}`,
      exitCode: -1,
      durationMs: Date.now() - startTime,
      blocked: true,
      blockReason: check.reason,
    };
    logger.log("guardrail_block", { command, reason: check.reason });
    return result;
  }

  const args = ["exec"];
  if (options?.workingDir) {
    args.push("-w", options.workingDir);
  }
  args.push(CONTAINER_NAME, "bash", "-c", command);

  try {
    const { stdout, stderr } = await execFileAsync("docker", args, {
      timeout: options?.timeout ?? DEFAULT_TIMEOUT,
      maxBuffer: 50 * 1024 * 1024, // 50MB
    });

    const durationMs = Date.now() - startTime;
    logger.logToolExecution(command, {}, stdout.slice(0, 500), durationMs);

    return { stdout, stderr, exitCode: 0, durationMs };
  } catch (err: unknown) {
    const durationMs = Date.now() - startTime;
    const error = err as { stdout?: string; stderr?: string; code?: number };

    logger.logToolExecution(command, {}, error.stderr?.slice(0, 500) ?? "error", durationMs);

    return {
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? String(err),
      exitCode: error.code ?? 1,
      durationMs,
    };
  }
}
