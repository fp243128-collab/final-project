#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

PORT="${PORT:-8501}"
PROVIDER="${AI_PROVIDER:-grok}"
LOG_FILE="${PROJECT_DIR}/.streamlit.log"
PID_FILE="${PROJECT_DIR}/.streamlit.pid"
URL="http://localhost:${PORT}"

if curl -fsS "${URL}/_stcore/health" >/dev/null 2>&1; then
    echo "Sentinel is already running: ${URL}"
    exit 0
fi

if [[ ! -x "${PROJECT_DIR}/.venv/bin/streamlit" ]]; then
    echo "Installing project dependencies..."
    uv sync
fi

rm -f "$PID_FILE"
echo "Starting Sentinel with provider: ${PROVIDER}"
AI_PROVIDER="$PROVIDER" nohup uv run streamlit run \
    src/devsecops_ai_security_audit_tool/ui.py \
    --server.headless true \
    --server.port "$PORT" \
    >"$LOG_FILE" 2>&1 &

PID=$!
echo "$PID" > "$PID_FILE"

for _ in {1..30}; do
    if curl -fsS "${URL}/_stcore/health" >/dev/null 2>&1; then
        echo "Sentinel is running: ${URL}"
        echo "Log file: ${LOG_FILE}"
        exit 0
    fi
    sleep 1
done

echo "Sentinel did not start. Check: ${LOG_FILE}" >&2
exit 1
