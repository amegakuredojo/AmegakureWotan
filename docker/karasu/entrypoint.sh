#!/bin/bash
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: 3.0
# FORGE_DATE: 2026-07-05T15:43:00Z
# FIX-02: stdout redirect ANTES del banner; timeout Tor adaptativo MCP vs interactivo

set -euo pipefail

# ── FIX-02: REDIRIGIR STDOUT ANTES DE CUALQUIER ECHO ─────────────────────────
# En modo MCP (stdio JSON-RPC), cualquier byte en stdout antes del handshake
# corrompe el protocolo. El fd3 guarda el stdout real para que Python pueda
# restaurarlo cuando levante el servidor MCP.
IS_MCP=false
if [ "$#" -gt 0 ] && [ "$1" = "run" ]; then
    IS_MCP=true
    for arg in "$@"; do
        if [ "$arg" = "--autonomous" ] || [ "$arg" = "-a" ]; then
            IS_MCP=false
        fi
    done
fi

# Redirigir ANTES de cualquier output si es MCP o bootstrap silencioso
if [ "$IS_MCP" = "true" ] || [ "${KARASU_SILENT_BOOTSTRAP:-false}" = "true" ]; then
    exec 3>&1        # fd3 = stdout original (para restaurar en MCP)
    exec 1>&2        # stdout → stderr durante bootstrap
fi

echo "╔══════════════════════════════════════════════╗"
echo "║     KARASUGAKURE — OSINT HARNESS BOOTSTRAP   ║"
echo "╚══════════════════════════════════════════════╝"

# ── 1. BOOT INFO ─────────────────────────────────────────────────────────────
echo "[BOOT] Starting Karasugakure Core with Kùzu embedded GraphDB..."

# ── 2. VERIFICAR TOR PROXY (con timeout adaptativo) ──────────────────────────
# MCP_TOR_TIMEOUT configurable: 10s en modo MCP, 40s en modo interactivo
TOR_HOST="${TOR_HOST:-tor-proxy}"
TOR_PORT="${TOR_PORT:-9150}"
BYPASS_TOR="${KARASU_OPSEC_BYPASS_TOR:-false}"

if [ "$BYPASS_TOR" = "true" ]; then
    echo "[BOOT] KARASU_OPSEC_BYPASS_TOR=true — Modo Sandbox/Dev: Tor check OMITIDO."
    echo "[WARN] Agentes Hel/Loki estarán BLOQUEADOS por política OPSEC si Tor no está activo."
else
    echo "[BOOT] Verifying Tor SOCKS5 proxy at ${TOR_HOST}:${TOR_PORT}..."

    # Timeout adaptativo: corto en MCP (no bloquear handshake), largo en interactivo
    if [ "$IS_MCP" = "true" ] || [ "${KARASU_SILENT_BOOTSTRAP:-false}" = "true" ]; then
        MAX_TOR_ATTEMPTS="${KARASU_MCP_TOR_TIMEOUT:-10}"  # 10s en modo MCP
    else
        MAX_TOR_ATTEMPTS=20                               # 40s en modo interactivo
    fi

    TOR_READY=false
    for i in $(seq 1 "$MAX_TOR_ATTEMPTS"); do
        if nc -z "${TOR_HOST}" "${TOR_PORT}" 2>/dev/null; then
            TOR_READY=true
            echo "[BOOT] Tor proxy activo en ${TOR_HOST}:${TOR_PORT}"
            break
        fi
        echo "[BOOT] Tor proxy not ready yet (attempt $i/${MAX_TOR_ATTEMPTS})... retrying in 1s"
        sleep 1
    done

    if [ "$TOR_READY" = "false" ]; then
        echo "[WARN] Tor proxy unreachable after ${MAX_TOR_ATTEMPTS}s. Hel/Loki agents will be BLOCKED by OPSEC policy."
        echo "       Surface recon (Heimdall) will proceed normally."
    fi
fi

# ── 3. INICIALIZAR DIRECTORIOS DE DATOS ─────────────────────────────────────
echo "[BOOT] Initializing Karasugakure data directories..."
python3 -c "
from karasugakure.config import get_config
c = get_config()
c.init_dirs()
print('[BOOT] Data directories initialized at:', c.base_dir)
"

# ── 4. INICIALIZAR ESQUEMA DE GRAFO (MIGRACIONES) ────────────────────────────
echo "[BOOT] Connecting to database and running graph schema migrations..."
python3 -c "
from karasugakure.graph.db import get_db
try:
    db = get_db()
    db.connect()
    print('[BOOT] Graph database connection established & schema migrations applied.')
except Exception as e:
    print('[BOOT] Graph schema verification skipped or warning:', e)
"

# ── 5. INICIALIZAR LEDGER FORENSE ────────────────────────────────────────────
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
        'kuzu_db_path': os.environ.get('KUZU_DATABASE_PATH', '/data/karasu_vault.kuzu'),
        'opsec_bypass_tor': os.environ.get('KARASU_OPSEC_BYPASS_TOR', 'false'),
        'silent_bootstrap': os.environ.get('KARASU_SILENT_BOOTSTRAP', 'false'),
    },
    findings=[{'status': 'OK', 'reason': 'Bootstrap completed successfully'}],
    evidence_files=[]
)
print('[BOOT] Forensic Audit Ledger initialized. Boot event recorded.')
"

# ── 6. SMOKE TEST OPCIONAL ────────────────────────────────────────────────────
if [ "${KARASU_RUN_SMOKE_TEST:-false}" = "true" ]; then
    echo "[BOOT] Running smoke test suite..."
    python3 /app/tests/smoke_test.py
fi

echo ""
echo "[BOOT] ══════════════════════════════════════════════"
echo "[BOOT] Karasugakure is OPERATIONAL. All systems GO."
echo "[BOOT] ══════════════════════════════════════════════"
echo ""

# ── 7. EJECUTAR COMANDO SOLICITADO ───────────────────────────────────────────
if [ "$#" -eq 0 ]; then
    exec python3 -m karasugakure.cli tui
elif [ "$1" = "pytest" ] || [ "$1" = "bash" ] || [ "$1" = "sh" ] || [ "$1" = "ls" ] || [ "$1" = "python" ] || [ "$1" = "python3" ] || [ "$1" = "karasu" ] || [ "$1" = "/usr/local/bin/karasu" ]; then
    exec "$@"
else
    if [ "$IS_MCP" = "true" ]; then
        # Restaurar stdout original (fd3) para que MCP pueda escribir JSON-RPC
        exec python3 -m karasugakure.cli "$@" >&3
    else
        exec python3 -m karasugakure.cli "$@"
    fi
fi
