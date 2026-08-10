# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.adapters.l3.bbot
Contexto: CIVIL — Consolidación AmegakureWotan (capa L3, motor externo)

Adaptador honesto para BBOT (Bug Bounty & OSINT CLI).
Doctrina WOTAN-F4:
  • Se invoca el binario REAL 'bbot' si está en el PATH.
  • Si no está => devuelve 'tool_unavailable' explícito y auditable.
  • Sin salida fabricada.
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import logging
import shutil
import subprocess
from typing import Any, Dict, Optional

from amegakurewotan.utils.ratelimit import get_rate_limiter

logger = logging.getLogger("amegakurewotan.adapters.l3.bbot")


def _binary() -> Optional[str]:
    return shutil.which("bbot")


def bbot_scan(target: str, preset: str = "subdomain-enum", timeout: int = 600) -> Dict[str, Any]:
    """
    Ejecuta BBOT contra `target`.
    """
    bin_path = _binary()
    if not bin_path:
        return {
            "status": "tool_unavailable",
            "tool": "bbot",
            "target": target,
            "reason": "Binario 'bbot' no encontrado en PATH; adaptador no ejecutable.",
            "note": "Sin salida fabricada.",
        }

    get_rate_limiter().acquire()

    cmd = [bin_path, "-t", target, "--preset", preset, "-o", "-", "--quiet"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "tool_unavailable",
            "tool": "bbot",
            "target": target,
            "reason": f"Fallo lanzando BBOT: {exc}",
            "note": "Sin salida fabricada.",
        }

    if proc.returncode != 0:
        return {
            "status": "error",
            "tool": "bbot",
            "target": target,
            "reason": f"BBOT exit {proc.returncode}: {proc.stderr[:200]}",
        }

    return {
        "status": "ok",
        "target": target,
        "stdout": proc.stdout,
        "preset": preset,
    }
