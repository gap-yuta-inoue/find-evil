#!/bin/bash
set -e

echo "[setup] Installing npm dependencies..."
npm install

echo "[setup] Building TypeScript..."
npm run build

echo "[setup] Building Docker image (SIFT tools)..."
docker compose build

echo "[setup] Starting SIFT container..."
docker compose up -d

echo "[setup] Verifying tools..."
docker exec find-evil-sift mmls -V
docker exec find-evil-sift vol3 --help 2>&1 | head -1 || docker exec find-evil-sift python3 -c "import volatility3; print('volatility3 OK')"
docker exec find-evil-sift log2timeline.py --version 2>&1 | head -1

echo ""
echo "[setup] Done! Available commands:"
echo "  node dist/cli.js analyze <path>   — Analyze evidence"
echo "  node dist/cli.js watch            — Start monitoring"
echo "  node dist/cli.js benchmark        — Run benchmarks"
echo "  node dist/cli.js mcp-server       — Start MCP server"
