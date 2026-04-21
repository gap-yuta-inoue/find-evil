/**
 * Guardrail Layer — blocks destructive commands at the architecture level.
 *
 * All tool executions pass through this layer before reaching the SIFT VM.
 * Destructive operations are blocked regardless of the agent's intent.
 */

const BLOCKED_COMMANDS = new Set([
  "rm", "rmdir", "unlink",
  "dd",
  "mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.ntfs",
  "fdisk", "parted", "gdisk",
  "shred", "wipe",
  "kill", "killall", "pkill",
  "shutdown", "reboot", "halt", "poweroff",
  "iptables", "ip6tables", "nft",
  "useradd", "userdel", "usermod", "passwd",
  "chmod", "chown",
  "mount", "umount",
  "systemctl start", "systemctl stop", "systemctl restart",
]);

const BLOCKED_PATTERNS = [
  />\s*\/dev\//, // redirect to device
  /\|\s*sudo/, // pipe to sudo
  /;\s*rm\s/, // chained rm
  /&&\s*rm\s/, // chained rm
  /mkfs\.\w+/, // any mkfs variant
  /dd\s+.*of=\/dev\//, // dd to device
];

export interface GuardrailResult {
  allowed: boolean;
  reason?: string;
  command: string;
}

export function checkCommand(command: string): GuardrailResult {
  const trimmed = command.trim();
  const firstWord = trimmed.split(/\s+/)[0];

  // Check blocked commands
  if (firstWord && BLOCKED_COMMANDS.has(firstWord)) {
    return {
      allowed: false,
      reason: `Blocked: '${firstWord}' is a destructive command`,
      command: trimmed,
    };
  }

  // Check blocked patterns
  for (const pattern of BLOCKED_PATTERNS) {
    if (pattern.test(trimmed)) {
      return {
        allowed: false,
        reason: `Blocked: command matches destructive pattern ${pattern}`,
        command: trimmed,
      };
    }
  }

  return { allowed: true, command: trimmed };
}

export function checkToolArgs(toolName: string, args: Record<string, unknown>): GuardrailResult {
  // Tool-specific guardrails
  if (toolName === "execute_command") {
    const cmd = args["command"];
    if (typeof cmd === "string") {
      return checkCommand(cmd);
    }
  }

  // File path guardrails — prevent writing to evidence
  if (args["output_path"] && typeof args["output_path"] === "string") {
    const outputPath = args["output_path"];
    if (outputPath.startsWith("/evidence/") || outputPath.includes("..")) {
      return {
        allowed: false,
        reason: `Blocked: cannot write to evidence directory or use path traversal`,
        command: `${toolName}(output_path=${outputPath})`,
      };
    }
  }

  return { allowed: true, command: `${toolName}(${JSON.stringify(args)})` };
}
