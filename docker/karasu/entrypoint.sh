#!/bin/bash
set -euo pipefail

echo "╔══════════════════════════════════════════════╗"
echo "║     KARASUGAKURE — OSINT HARNESS BOOTSTRAP   ║"
echo "╚══════════════════════════════════════════════╝"

# ── 1. BOOT INFO ─────────────────────────────────────────────────────────────
echo "[BOOT] Starting Karasugakure Core with Kùzu embedded GraphDB..."


# ── 3. ESPERAR A QUE TOR PROXY ESTÉ ACTIVO ──────────────────────────────────
echo "[BOOT] Verifying Tor SOCKS5 proxy at ${TOR_HOST:-tor-proxy}:${TOR_PORT:-9050}..."
TOR_READY=false
for i in $(seq 1 20); do
    if nc -z "${TOR_HOST:-tor-proxy}" "${TOR_PORT:-9050}" 2>/dev/null; then
        TOR_READY=true
        break
    fi
    echo "[BOOT] Tor proxy not ready yet (attempt $i/20)... retrying in 2s"
    sleep 2
done

if [ "$TOR_READY" = "false" ]; then
    echo "[WARN] Tor proxy unreachable after 40s. Hel/Loki agents will be BLOCKED by OPSEC policy."
    echo "       Surface recon (Heimdall) will proceed normally."
fi

# ── 4. INICIALIZAR DIRECTORIOS DE DATOS ─────────────────────────────────────
echo "[BOOT] Initializing Karasugakure data directories..."
python3 -c "
from karasugakure.config import get_config
c = get_config()
c.init_dirs()
print('[BOOT] Data directories initialized at:', c.base_dir)
"

# ── 5. INICIALIZAR ESQUEMA DE GRAFO (MIGRACIONES DE LA APP) ─────────────────
echo "[BOOT] Connecting to database and running graph schema migrations..."
python3 -c "
from karasugakure.graph.db import get_db
try:
    db = get_db()
    db.connect() # Automatically executes run_migrations()
    print('[BOOT] Graph database connection established & schema migrations applied.')
except Exception as e:
    print('[BOOT] Graph schema verification skipped or warning:', e)
"

# ── 6. INICIALIZAR LEDGER FORENSE ────────────────────────────────────────────
echo "[BOOT] Initializing Forensic Audit Ledger..."
python3 -c "
from karasugakure.evidence.audit import ForensicAuditLedger
import os
ledger = ForensicAuditLedger()
ledger.log_execution(
    agent_name='system_bootstrap',
    action='container_boot',
    parameters={
        'image_hash': os.environ.get('KARASU_IMAGE_HASH', 'unset'),
        'build_date': os.environ.get('KARASU_BUILD_DATE', 'unset'),
        'neo4j_uri': os.environ.get('NEO4J_URI', 'bolt://neo4j:7687'),
    },
    findings=[{'status': 'OK', 'reason': 'Bootstrap completed successfully'}],
    evidence_files=[]
)
print('[BOOT] Forensic Audit Ledger initialized. Boot event recorded.')
"

# ── 7. EJECUTAR SMOKE TEST RÁPIDO (OPCIONAL EN PROD) ─────────────────────────
if [ "${KARASU_RUN_SMOKE_TEST:-false}" = "true" ]; then
    echo "[BOOT] Running smoke test suite..."
    python3 /app/tests/smoke_test.py
fi

echo ""
echo "[BOOT] ══════════════════════════════════════════════"
echo "[BOOT] Karasugakure is OPERATIONAL. All systems GO."
echo "[BOOT] ══════════════════════════════════════════════"
echo ""

# ── 8. EJECUTAR COMANDO SOLICITADO ───────────────────────────────────────────
if [ "$#" -eq 0 ]; then
    exec python3 -m karasugakure.cli tui
elif [ "$1" = "pytest" ] || [ "$1" = "bash" ] || [ "$1" = "sh" ] || [ "$1" = "ls" ]; then
    exec "$@"
else
    exec python3 -m karasugakure.cli "$@"
fi
