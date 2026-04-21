# Benchmarks

Accuracy benchmark framework for the Find Evil agent.

## Structure

```
benchmarks/
├── cases/              # Test case definitions (JSONL)
│   ├── disk-basic.jsonl
│   ├── memory-basic.jsonl
│   └── multi-source.jsonl
├── expected/           # Expected findings per case
│   └── *.json
├── results/            # Benchmark run results (gitignored)
└── README.md
```

## Case Definition Format

```json
{
  "id": "case-001",
  "name": "Basic disk analysis — malware on desktop",
  "evidence": [{"path": "evidence/sample-disk.dd", "type": "disk_image"}],
  "expected_findings": [
    {"description": "Malicious executable at /Users/victim/Desktop/update.exe", "confidence": "confirmed"},
    {"description": "Suspicious scheduled task created at 2024-03-15T02:30:00Z", "confidence": "inferred"}
  ],
  "expected_no_findings": [
    "Legitimate system processes should not be flagged as malicious"
  ]
}
```

## Metrics

| Metric | Definition |
|--------|-----------|
| True Positive Rate | Correct findings / Expected findings |
| False Positive Rate | Incorrect findings / Total findings |
| Hallucination Rate | Findings without tool evidence / Total findings |
| Evidence Completeness | Findings with multi-source evidence / Total findings |
| Mean Time to Finding | Average seconds from case start to first correct finding |

## Running Benchmarks

```bash
# Run all benchmark cases
npm run benchmark

# Output: benchmarks/results/run-<timestamp>.json
```

## Sample Case Data

Download from: https://sansorg.egnyte.com/fl/HhH7crTYT4JK
Place in `evidence/` directory (gitignored).
