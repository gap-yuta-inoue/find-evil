#!/usr/bin/env node

import { parseArgs } from "node:util";
import { startMcpServer } from "./mcp-server/index.js";
import { AuditLogger } from "./audit/logger.js";

const HELP = `
find-evil — AI-Driven Autonomous Incident Response Agent

USAGE
  find-evil <command> [options]

COMMANDS
  analyze <path>    Analyze evidence at the given path (disk image, memory capture, log directory)
  watch             Start real-time monitoring mode (continuous anomaly detection)
  benchmark         Run accuracy benchmarks against sample case data
  mcp-server        Start the MCP server standalone (for Claude Code integration)

OPTIONS
  --help, -h        Show this help message
  --version, -v     Show version
  --verbose         Enable verbose output
  --log-dir <dir>   Directory for audit logs (default: ./logs)
  --sift <host>     SIFT Workstation host (default: localhost)

EXAMPLES
  # Analyze a disk image
  find-evil analyze ./evidence/disk.dd

  # Analyze a memory capture
  find-evil analyze ./evidence/memory.vmem

  # Start real-time monitoring
  find-evil watch --sift 192.168.1.100

  # Run benchmarks
  find-evil benchmark

  # Start MCP server for Claude Code
  find-evil mcp-server
`.trim();

interface CliOptions {
  help: boolean;
  version: boolean;
  verbose: boolean;
  logDir: string;
  sift: string;
}

function parseCliArgs(): { command: string; args: string[]; options: CliOptions } {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
      verbose: { type: "boolean", default: false },
      "log-dir": { type: "string", default: "./logs" },
      sift: { type: "string", default: "localhost" },
    },
  });

  return {
    command: positionals[0] ?? "",
    args: positionals.slice(1),
    options: {
      help: values.help ?? false,
      version: values.version ?? false,
      verbose: values.verbose ?? false,
      logDir: values["log-dir"] ?? "./logs",
      sift: values.sift ?? "localhost",
    },
  };
}

async function main(): Promise<void> {
  const { command, args, options } = parseCliArgs();

  if (options.version) {
    console.log("find-evil v0.1.0");
    return;
  }

  if (options.help || !command) {
    console.log(HELP);
    return;
  }

  const logger = new AuditLogger(options.logDir);

  switch (command) {
    case "analyze": {
      const evidencePath = args[0];
      if (!evidencePath) {
        console.error("Error: evidence path required\n");
        console.error("Usage: find-evil analyze <path>");
        process.exit(1);
      }
      console.log(`[find-evil] Analyzing evidence: ${evidencePath}`);
      console.log(`[find-evil] SIFT host: ${options.sift}`);
      console.log(`[find-evil] Audit logs: ${options.logDir}`);
      logger.log("case_start", { evidencePath, mode: "analyze", siftHost: options.sift });
      // TODO: Orchestrator integration
      console.log("[find-evil] Orchestrator not yet implemented — coming in Phase 1");
      break;
    }

    case "watch": {
      console.log(`[find-evil] Starting real-time monitoring...`);
      console.log(`[find-evil] SIFT host: ${options.sift}`);
      logger.log("watcher_start", { mode: "watch", siftHost: options.sift });
      // TODO: Watcher integration
      console.log("[find-evil] Watcher not yet implemented — coming in Phase 1");
      break;
    }

    case "benchmark": {
      console.log(`[find-evil] Running benchmarks...`);
      logger.log("benchmark_start", { mode: "benchmark" });
      // TODO: Benchmark runner
      console.log("[find-evil] Benchmark runner not yet implemented — skeleton ready");
      break;
    }

    case "mcp-server": {
      console.log(`[find-evil] Starting MCP server...`);
      await startMcpServer({ siftHost: options.sift, logger });
      break;
    }

    default:
      console.error(`Error: unknown command '${command}'\n`);
      console.log(HELP);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
