import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { checkCommand, checkToolArgs } from "./guardrails.js";
import { execInSift } from "./executor.js";
import type { AuditLogger } from "../audit/logger.js";

interface McpServerOptions {
  siftHost: string;
  logger: AuditLogger;
}

function textResult(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

export async function startMcpServer(options: McpServerOptions): Promise<void> {
  const { logger } = options;
  const server = new McpServer({
    name: "find-evil",
    version: "0.1.0",
  });

  // --- Disk Analysis Tools (sleuthkit) ---

  server.tool(
    "disk_list_partitions",
    "List partitions in a disk image using mmls (sleuthkit). Returns partition table with sector offsets.",
    { imagePath: z.string().describe("Path to disk image file in /cases/ (.dd, .raw, .E01)") },
    async ({ imagePath }) => {
      const result = await execInSift(`mmls ${imagePath}`, logger);
      if (result.blocked) return textResult(`GUARDRAIL BLOCKED: ${result.blockReason}`);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "disk_image_info",
    "Get disk image metadata including sector size using img_stat (sleuthkit)",
    { imagePath: z.string().describe("Path to disk image file in /cases/") },
    async ({ imagePath }) => {
      const result = await execInSift(`img_stat ${imagePath}`, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "disk_list_files",
    "List files/directories in a disk image partition using fls (sleuthkit). Deleted files are prefixed with *.",
    {
      imagePath: z.string().describe("Path to disk image file"),
      offset: z.number().optional().describe("Partition offset in sectors (from mmls output)"),
      recursive: z.boolean().optional().describe("List recursively with full paths (-r -p)"),
      deletedOnly: z.boolean().optional().describe("Show only deleted files (-d)"),
      inode: z.number().optional().describe("Start from specific inode/directory"),
    },
    async ({ imagePath, offset, recursive, deletedOnly, inode }) => {
      let cmd = "fls";
      if (recursive) cmd += " -r -p";
      if (deletedOnly) cmd += " -d";
      if (offset) cmd += ` -o ${offset}`;
      cmd += ` ${imagePath}`;
      if (inode) cmd += ` ${inode}`;
      const result = await execInSift(cmd, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "disk_extract_file",
    "Extract a file from disk image by inode number using icat (sleuthkit)",
    {
      imagePath: z.string().describe("Path to disk image file"),
      inode: z.number().describe("Inode number of the file to extract"),
      offset: z.number().optional().describe("Partition offset in sectors"),
      outputPath: z.string().describe("Output file path (must be under /analysis/ or /exports/)"),
    },
    async ({ imagePath, inode, offset, outputPath }) => {
      const check = checkToolArgs("disk_extract_file", { output_path: outputPath });
      if (!check.allowed) return textResult(`GUARDRAIL BLOCKED: ${check.reason}`);
      let cmd = "icat";
      if (offset) cmd += ` -o ${offset}`;
      cmd += ` ${imagePath} ${inode} > ${outputPath}`;
      const result = await execInSift(cmd, logger);
      return textResult(result.exitCode === 0 ? `Extracted inode ${inode} to ${outputPath}` : result.stderr);
    }
  );

  server.tool(
    "disk_inode_info",
    "Get detailed inode metadata (MAC times, size, blocks) using istat (sleuthkit)",
    {
      imagePath: z.string().describe("Path to disk image file"),
      inode: z.number().describe("Inode number"),
      offset: z.number().optional().describe("Partition offset in sectors"),
    },
    async ({ imagePath, inode, offset }) => {
      let cmd = "istat";
      if (offset) cmd += ` -o ${offset}`;
      cmd += ` ${imagePath} ${inode}`;
      const result = await execInSift(cmd, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "disk_create_bodyfile",
    "Generate a bodyfile (MAC timeline) from a disk image using fls -m (sleuthkit)",
    {
      imagePath: z.string().describe("Path to disk image file"),
      offset: z.number().optional().describe("Partition offset in sectors"),
      outputPath: z.string().describe("Output bodyfile path (must be under /analysis/)"),
    },
    async ({ imagePath, offset, outputPath }) => {
      const check = checkToolArgs("disk_create_bodyfile", { output_path: outputPath });
      if (!check.allowed) return textResult(`GUARDRAIL BLOCKED: ${check.reason}`);
      let cmd = "fls -r -m /";
      if (offset) cmd += ` -o ${offset}`;
      cmd += ` ${imagePath} > ${outputPath}`;
      const result = await execInSift(cmd, logger);
      return textResult(result.exitCode === 0 ? `Bodyfile written to ${outputPath}` : result.stderr);
    }
  );

  server.tool(
    "disk_mactime",
    "Generate a timeline from a bodyfile using mactime (sleuthkit)",
    {
      bodyfilePath: z.string().describe("Path to bodyfile (from fls -m)"),
      startDate: z.string().optional().describe("Start date filter (YYYY-MM-DD)"),
      endDate: z.string().optional().describe("End date filter (YYYY-MM-DD)"),
    },
    async ({ bodyfilePath, startDate, endDate }) => {
      let cmd = `mactime -b ${bodyfilePath} -z UTC -d`;
      if (startDate) cmd += ` ${startDate}`;
      if (endDate) cmd += `..${endDate}`;
      const result = await execInSift(cmd, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "disk_bulk_extract",
    "Carve artifacts (emails, URLs, domains, credit cards) using bulk_extractor",
    {
      imagePath: z.string().describe("Path to disk image file"),
      outputDir: z.string().describe("Output directory (must be under /analysis/)"),
    },
    async ({ imagePath, outputDir }) => {
      const check = checkToolArgs("disk_bulk_extract", { output_path: outputDir });
      if (!check.allowed) return textResult(`GUARDRAIL BLOCKED: ${check.reason}`);
      const result = await execInSift(`bulk_extractor -o ${outputDir} ${imagePath}`, logger, { timeout: 600_000 });
      return textResult(result.stdout || result.stderr);
    }
  );

  // --- Memory Analysis Tools (volatility3) ---

  server.tool(
    "memory_info",
    "Get OS and kernel info from memory capture using volatility3 windows.info",
    { memoryPath: z.string().describe("Path to memory capture file in /cases/ (.vmem, .mem, .raw)") },
    async ({ memoryPath }) => {
      const result = await execInSift(`vol -f ${memoryPath} -r json windows.info`, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "memory_pslist",
    "List processes via EPROCESS linked list (fast, may miss hidden processes). Use with memory_psscan for complete picture.",
    {
      memoryPath: z.string().describe("Path to memory capture file"),
      outputFormat: z.enum(["json", "csv", "pretty"]).optional().describe("Output format (default: json)"),
    },
    async ({ memoryPath, outputFormat }) => {
      const fmt = outputFormat ?? "json";
      const result = await execInSift(`vol -f ${memoryPath} -r ${fmt} windows.pslist`, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "memory_psscan",
    "Find processes via pool tag scan (finds hidden/exited processes). Compare with pslist — processes in psscan but NOT in pslist are suspicious.",
    {
      memoryPath: z.string().describe("Path to memory capture file"),
    },
    async ({ memoryPath }) => {
      const result = await execInSift(`vol -f ${memoryPath} -r json windows.psscan`, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "memory_netscan",
    "Find network connections via pool scan (includes historical/closed connections)",
    { memoryPath: z.string().describe("Path to memory capture file") },
    async ({ memoryPath }) => {
      const result = await execInSift(`vol -f ${memoryPath} -r json windows.netscan`, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "memory_malfind",
    "Detect injected/hollowed code in process memory (RWX regions with PE headers/shellcode). Note: may produce false positives from JIT/.NET CLR.",
    {
      memoryPath: z.string().describe("Path to memory capture file"),
      pid: z.number().optional().describe("Filter by process ID"),
      dump: z.boolean().optional().describe("Dump suspicious regions to /analysis/"),
    },
    async ({ memoryPath, pid, dump }) => {
      let cmd = `vol -f ${memoryPath} -r json windows.malfind`;
      if (pid) cmd += ` --pid ${pid}`;
      if (dump) cmd += " --dump --output-dir /analysis/malfind";
      const result = await execInSift(cmd, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "memory_cmdline",
    "Extract command line arguments for all processes",
    { memoryPath: z.string().describe("Path to memory capture file") },
    async ({ memoryPath }) => {
      const result = await execInSift(`vol -f ${memoryPath} -r json windows.cmdline`, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "memory_handles",
    "List open handles (files, registry keys, mutexes) for a process",
    {
      memoryPath: z.string().describe("Path to memory capture file"),
      pid: z.number().optional().describe("Filter by process ID"),
      objectType: z.enum(["File", "Mutant", "Key"]).optional().describe("Filter by object type"),
    },
    async ({ memoryPath, pid, objectType }) => {
      let cmd = `vol -f ${memoryPath} -r json windows.handles`;
      if (pid) cmd += ` --pid ${pid}`;
      if (objectType) cmd += ` --object-type ${objectType}`;
      const result = await execInSift(cmd, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "memory_dlllist",
    "List loaded DLLs for all or specific processes",
    {
      memoryPath: z.string().describe("Path to memory capture file"),
      pid: z.number().optional().describe("Filter by process ID"),
    },
    async ({ memoryPath, pid }) => {
      let cmd = `vol -f ${memoryPath} -r json windows.dlllist`;
      if (pid) cmd += ` --pid ${pid}`;
      const result = await execInSift(cmd, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "memory_svcscan",
    "Enumerate Windows services from memory (pool scan)",
    { memoryPath: z.string().describe("Path to memory capture file") },
    async ({ memoryPath }) => {
      const result = await execInSift(`vol -f ${memoryPath} -r json windows.svcscan`, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  // --- Timeline Tools (plaso) ---

  server.tool(
    "timeline_create",
    "Generate a super timeline from a disk image using log2timeline.py (plaso). Long-running — use targeted parsers for speed.",
    {
      imagePath: z.string().describe("Path to disk image file"),
      outputFile: z.string().describe("Output .plaso file path (must be under /analysis/)"),
      parsers: z.string().optional().describe("Parser preset: win10, win7, linux, webhist (default: auto-detect)"),
      hashers: z.boolean().optional().describe("Enable MD5+SHA256 hashing of files"),
    },
    async ({ imagePath, outputFile, parsers, hashers }) => {
      const check = checkToolArgs("timeline_create", { output_path: outputFile });
      if (!check.allowed) return textResult(`GUARDRAIL BLOCKED: ${check.reason}`);
      let cmd = `log2timeline.py --storage-file ${outputFile} --timezone UTC`;
      if (parsers) cmd += ` --parsers ${parsers}`;
      if (hashers) cmd += " --hashers md5,sha256";
      cmd += ` ${imagePath}`;
      const result = await execInSift(cmd, logger, { timeout: 600_000 });
      return textResult(result.stdout || result.stderr);
    }
  );

  server.tool(
    "timeline_search",
    "Filter and export timeline events using psort.py (plaso)",
    {
      plasoFile: z.string().describe("Path to .plaso file"),
      outputFile: z.string().describe("Output file path (must be under /analysis/)"),
      outputFormat: z.enum(["l2tcsv", "dynamic", "json"]).optional().describe("Output format (default: l2tcsv)"),
      filter: z.string().optional().describe("Filter expression, e.g. \"message contains 'powershell'\""),
      sliceTime: z.string().optional().describe("Show events within 5 min of this timestamp (ISO 8601)"),
    },
    async ({ plasoFile, outputFile, outputFormat, filter, sliceTime }) => {
      const check = checkToolArgs("timeline_search", { output_path: outputFile });
      if (!check.allowed) return textResult(`GUARDRAIL BLOCKED: ${check.reason}`);
      let cmd = `psort.py -z UTC -o ${outputFormat ?? "l2tcsv"} -w ${outputFile}`;
      if (sliceTime) cmd += ` --slice "${sliceTime}"`;
      cmd += ` ${plasoFile}`;
      if (filter) cmd += ` "${filter}"`;
      const result = await execInSift(cmd, logger, { timeout: 300_000 });
      return textResult(result.stdout || result.stderr);
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
      recursive: z.boolean().optional().describe("Search recursively in directories"),
    },
    async ({ logPath, pattern, context, recursive }) => {
      let cmd = "grep -n";
      if (recursive) cmd += " -r";
      if (context) cmd += ` -C ${context}`;
      cmd += ` '${pattern.replace(/'/g, "'\\''")}' ${logPath}`;
      const result = await execInSift(cmd, logger);
      return textResult(result.stdout || result.stderr);
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
      const result = await execInSift(`jq '${query.replace(/'/g, "'\\''")}' ${logPath}`, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  // --- YARA Scanning ---

  server.tool(
    "yara_scan",
    "Scan files or directories with YARA rules for malware/IOC detection",
    {
      rulesPath: z.string().describe("Path to YARA rules file (.yar)"),
      targetPath: z.string().describe("File or directory to scan"),
      recursive: z.boolean().optional().describe("Scan directories recursively"),
      printStrings: z.boolean().optional().describe("Print matching strings"),
    },
    async ({ rulesPath, targetPath, recursive, printStrings }) => {
      let cmd = "yara";
      if (recursive) cmd += " -r";
      if (printStrings) cmd += " -s";
      cmd += ` ${rulesPath} ${targetPath}`;
      const result = await execInSift(cmd, logger);
      return textResult(result.stdout || result.stderr);
    }
  );

  // --- Guardrailed Shell Execution ---

  server.tool(
    "execute_command",
    "Execute a shell command in the SIFT container (guardrailed — destructive commands are blocked). Use this for tools not covered by specific tool definitions.",
    {
      command: z.string().describe("Shell command to execute"),
      workingDir: z.string().optional().describe("Working directory (default: /analysis)"),
      timeout: z.number().optional().describe("Timeout in seconds (default: 300)"),
    },
    async ({ command, workingDir, timeout }) => {
      const result = await execInSift(command, logger, {
        workingDir: workingDir ?? "/analysis",
        timeout: timeout ? timeout * 1000 : undefined,
      });
      if (result.blocked) return textResult(`GUARDRAIL BLOCKED: ${result.blockReason}`);
      return textResult(result.stdout || result.stderr);
    }
  );

  // Start server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.log("mcp_server_start", { toolCount: 22 });
}
