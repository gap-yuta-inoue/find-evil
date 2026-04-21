# Find Evil — AI-Driven Autonomous Incident Response Agent

An autonomous incident response agent that uses [SIFT Workstation](https://www.sans.org/tools/sift-workstation/) (200+ IR tools) via MCP to investigate security incidents like a senior analyst.

Built for the [FIND EVIL! Hackathon](https://findevil.devpost.com/) by SANS Institute.

## Quick Start

```bash
# Install dependencies
npm install

# Build
npm run build

# Analyze evidence (manual mode)
./find-evil analyze <evidence_path>

# Start real-time monitoring (watch mode)
./find-evil watch

# Run benchmarks against sample case data
./find-evil benchmark
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Analyst / CLI                      │
│              ./find-evil analyze <path>              │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│              SIFT Agent (Claude Code)                │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────┐ │
│  │ Orchestrator  │  │   Reasoning   │  │Validation│ │
│  │ Case mgmt +   │→│   Hypothesis  │→│ Halluc.  │ │
│  │ analysis plan │  │   driven loop │  │ detection│ │
│  └──────────────┘  └───────────────┘  └──────────┘ │
│  ┌──────────────┐                                    │
│  │ Audit Logger  │  Timestamps + token tracking      │
│  └──────────────┘                                    │
└──────────────────────┬──────────────────────────────┘
                       │ MCP Protocol
┌──────────────────────▼──────────────────────────────┐
│             Custom MCP Server                        │
│  ┌──────────────────────────────────────────────┐   │
│  │           Guardrail Layer                     │   │
│  │  Type-safe tool exposure + destructive cmd    │   │
│  │  blocking (rm, dd, mkfs → BLOCKED)            │   │
│  └──────────────────────┬───────────────────────┘   │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐ │
│  │  Disk   │ │ Memory  │ │   Log   │ │ Network  │ │
│  │Analysis │ │Analysis │ │Analysis │ │ Analysis │ │
│  │sleuthkit│ │volatil. │ │grep, jq │ │zeek,tshk │ │
│  │plaso    │ │         │ │timeline │ │          │ │
│  └─────────┘ └─────────┘ └─────────┘ └──────────┘ │
└──────────────────────┬──────────────────────────────┘
                       │ SSH / Local
┌──────────────────────▼──────────────────────────────┐
│           SIFT Workstation (VM)                      │
│           200+ IR Tools + Evidence Data              │
└─────────────────────────────────────────────────────┘
```

## Operating Modes

| Mode | Trigger | Use Case |
|------|---------|----------|
| **Watch** | Watcher detects anomaly → auto-analysis | Production — detect & respond in seconds |
| **Analyze** | Analyst specifies evidence via CLI | Forensics — post-incident investigation |
| **Benchmark** | Sample case data auto-injected | Accuracy evaluation & demo |

## Confidence Scoring

Every finding is tagged with a confidence level:

- **confirmed** — corroborated by multiple tools/sources
- **inferred** — supported by evidence but not independently verified
- **uncertain** — single-source or contradictory evidence exists

## Detection Latency Targets

| Step | Target |
|------|--------|
| Attack → Detection | < 15 seconds |
| Detection → Analysis start | < 15 seconds |
| Detection → First response recommendation | < 5 minutes |

## Project Structure

```
find-evil/
├── src/
│   ├── cli.ts                  # CLI entry point (./find-evil)
│   ├── mcp-server/
│   │   ├── index.ts            # MCP server main
│   │   ├── guardrails.ts       # Destructive command blocking
│   │   └── tools/              # IR tool definitions
│   │       ├── disk.ts         # sleuthkit, plaso, bulk_extractor
│   │       ├── memory.ts       # volatility3
│   │       ├── log.ts          # grep, jq, timeline
│   │       └── network.ts      # zeek, tshark (Phase 2)
│   ├── agent/
│   │   ├── orchestrator.ts     # Case management + analysis planning
│   │   ├── reasoning.ts        # Hypothesis-driven reasoning loop
│   │   └── validation.ts       # Confidence scoring + cross-checking
│   ├── watcher/
│   │   └── index.ts            # Real-time anomaly detection
│   └── audit/
│       └── logger.ts           # Structured audit logging
├── benchmarks/                 # Accuracy benchmark framework
├── docs/                       # Additional documentation
└── evidence/                   # Evidence data (gitignored)
```

## Tech Stack

- **Agent Runtime**: Claude Code + Claude API
- **MCP Server**: TypeScript + @modelcontextprotocol/sdk
- **IR Platform**: SANS SIFT Workstation (Ubuntu VM)
- **Key Tools**: sleuthkit, plaso, volatility3, bulk_extractor, zeek, tshark

## License

MIT
