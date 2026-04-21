import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { checkCommand, checkToolArgs } from "./guardrails.js";
import type { AuditLogger } from "../audit/logger.js";

interface McpServerOptions {
  siftHost: string;
  logger: AuditLogger;
}

export async function startMcpServer(options: McpServerOptions): Promise<void> {
  const { siftHost, logger } = options;
  const server = new McpServer({
    name: "find-evil",
    version: "0.1.0",
  });

  // --- Disk Analysis Tools ---

  server.tool(
    "disk_list_partitions",
    "List partitions in a disk image using mmls (sleuthkit)",
    { imagePath: z.string().describe("Path to disk image file (.dd, .raw, .E01)") },
    async ({ imagePath }) => {
      const check = checkToolArgs("disk_list_partitions", { imagePath });
      if (!check.allowed) {
        return { content: [{ type: "text", text: `GUARDRAIL BLOCKED: ${check.reason}` }] };
      }
      logger.logToolExecution("disk_list_partitions", { imagePath }, "pending", 0);
      // TODO: Execute mmls via SSH to SIFT VM
      return { content: [{ type: "text", text: `[STUB] mmls ${imagePath} — SIFT host: ${siftHost}` }] };
    }
  );

  server.tool(
    "disk_list_files",
    "List files in a disk image partition using fls (sleuthkit)",
    {
      imagePath: z.string().describe("Path to disk image file"),
      offset: z.number().optional().describe("Partition offset in sectors"),
      path: z.string().optional().describe("Directory path to list"),
    },
    async ({ imagePath, offset, path }) => {
      logger.logToolExecution("disk_list_files", { imagePath, offset, path }, "pending", 0);
      return { content: [{ type: "text", text: `[STUB] fls -o ${offset ?? 0} ${imagePath} ${path ?? "/"}` }] };
    }
  );

  server.tool(
    "disk_extract_file",
    "Extract a file from disk image using icat (sleuthkit)",
    {
      imagePath: z.string().describe("Path to disk image file"),
      inode: z.number().describe("Inode number of the file to extract"),
      offset: z.number().optional().describe("Partition offset in sectors"),
    },
    async ({ imagePath, inode, offset }) => {
      logger.logToolExecution("disk_extract_file", { imagePath, inode, offset }, "pending", 0);
      return { content: [{ type: "text", text: `[STUB] icat -o ${offset ?? 0} ${imagePath} ${inode}` }] };
    }
  );

  server.tool(
    "disk_create_timeline",
    "Generate a filesystem timeline using plaso (log2timeline + psort)",
    {
      imagePath: z.string().describe("Path to disk image file"),
      outputDir: z.string().describe("Directory to write timeline output"),
    },
    async ({ imagePath, outputDir }) => {
      const check = checkToolArgs("disk_create_timeline", { output_path: outputDir });
      if (!check.allowed) {
        return { content: [{ type: "text", text: `GUARDRAIL BLOCKED: ${check.reason}` }] };
      }
      logger.logToolExecution("disk_create_timeline", { imagePath, outputDir }, "pending", 0);
      return { content: [{ type: "text", text: `[STUB] log2timeline.py ${outputDir}/plaso.dump ${imagePath}` }] };
    }
  );

  server.tool(
    "disk_bulk_extract",
    "Run bulk_extractor to carve artifacts (emails, URLs, credit cards, etc.)",
    {
      imagePath: z.string().describe("Path to disk image file"),
      outputDir: z.string().describe("Directory to write extracted artifacts"),
    },
    async ({ imagePath, outputDir }) => {
      logger.logToolExecution("disk_bulk_extract", { imagePath, outputDir }, "pending", 0);
      return { content: [{ type: "text", text: `[STUB] bulk_extractor -o ${outputDir} ${imagePath}` }] };
    }
  );

  // --- Memory Analysis Tools ---

  server.tool(
    "memory_info",
    "Get OS and kernel info from memory capture using volatility3",
    { memoryPath: z.string().describe("Path to memory capture file (.vmem, .mem, .raw)") },
    async ({ memoryPath }) => {
      logger.logToolExecution("memory_info", { memoryPath }, "pending", 0);
      return { content: [{ type: "text", text: `[STUB] vol3 -f ${memoryPath} windows.info` }] };
    }
  );

  server.tool(
    "memory_pslist",
    "List running processes from memory capture",
    { memoryPath: z.string().describe("Path to memory capture file") },
    async ({ memoryPath }) => {
      logger.logToolExecution("memory_pslist", { memoryPath }, "pending", 0);
      return { content: [{ type: "text", text: `[STUB] vol3 -f ${memoryPath} windows.pslist` }] };
    }
  );

  server.tool(
    "memory_netscan",
    "List network connections from memory capture",
    { memoryPath: z.string().describe("Path to memory capture file") },
    async ({ memoryPath }) => {
      logger.logToolExecution("memory_netscan", { memoryPath }, "pending", 0);
      return { content: [{ type: "text", text: `[STUB] vol3 -f ${memoryPath} windows.netscan` }] };
    }
  );

  server.tool(
    "memory_malfind",
    "Detect injected/hollowed code in process memory",
    {
      memoryPath: z.string().describe("Path to memory capture file"),
      pid: z.number().optional().describe("Filter by process ID"),
    },
    async ({ memoryPath, pid }) => {
      logger.logToolExecution("memory_malfind", { memoryPath, pid }, "pending", 0);
      const pidArg = pid ? `--pid ${pid}` : "";
      return { content: [{ type: "text", text: `[STUB] vol3 -f ${memoryPath} windows.malfind ${pidArg}` }] };
    }
  );

  server.tool(
    "memory_cmdline",
    "Extract command line arguments for processes",
    { memoryPath: z.string().describe("Path to memory capture file") },
    async ({ memoryPath }) => {
      logger.logToolExecution("memory_cmdline", { memoryPath }, "pending", 0);
      return { content: [{ type: "text", text: `[STUB] vol3 -f ${memoryPath} windows.cmdline` }] };
    }
  );

  // --- Log Analysis Tools ---

  server.tool(
    "log_search",
    "Search log files for patterns using grep",
    {
      logPath: z.string().describe("Path to log file or directory"),
      pattern: z.string().describe("Search pattern (regex)"),
      context: z.number().optional().describe("Lines of context around matches"),
    },
    async ({ logPath, pattern, context }) => {
      logger.logToolExecution("log_search", { logPath, pattern, context }, "pending", 0);
      const ctxArg = context ? `-C ${context}` : "";
      return { content: [{ type: "text", text: `[STUB] grep -rn ${ctxArg} '${pattern}' ${logPath}` }] };
    }
  );

  server.tool(
    "log_parse_json",
    "Parse and query JSON-formatted logs using jq",
    {
      logPath: z.string().describe("Path to JSON log file"),
      query: z.string().describe("jq query expression"),
    },
    async ({ logPath, query }) => {
      logger.logToolExecution("log_parse_json", { logPath, query }, "pending", 0);
      return { content: [{ type: "text", text: `[STUB] jq '${query}' ${logPath}` }] };
    }
  );

  // --- Guardrailed Shell Execution ---

  server.tool(
    "execute_command",
    "Execute a shell command on the SIFT VM (guardrailed — destructive commands are blocked)",
    {
      command: z.string().describe("Shell command to execute"),
      workingDir: z.string().optional().describe("Working directory"),
    },
    async ({ command, workingDir }) => {
      const check = checkCommand(command);
      if (!check.allowed) {
        logger.log("guardrail_block", { command, reason: check.reason });
        return { content: [{ type: "text", text: `GUARDRAIL BLOCKED: ${check.reason}` }] };
      }
      logger.logToolExecution("execute_command", { command, workingDir }, "pending", 0);
      return { content: [{ type: "text", text: `[STUB] ssh ${siftHost} '${command}'` }] };
    }
  );

  // Start server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.log("mcp_server_start", { siftHost });
}
