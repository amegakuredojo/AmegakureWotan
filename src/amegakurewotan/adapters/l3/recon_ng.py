# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.adapters.l3.recon_ng
Contexto: CIVIL — Consolidación AmegakureWotan (capa L3, motor externo)

Adaptador honesto para Recon-ng (Framework OSINT via recon-cli).
Doctrina WOTAN-F4:
  • Se invoca el binario REAL 'recon-cli' o 'recon-ng' si está en el PATH.
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

logger = logging.getLogger("amegakurewotan.adapters.l3.recon_ng")


def _binary() -> Optional[str]:
    return shutil.which("recon-cli") or shutil.which("recon-ng")


def reconng_run_module(module: str, target: str, timeout: int = 300) -> Dict[str, Any]:
    """
    Ejecuta un módulo Recon-ng en batch mode contra `target`.
    """
    bin_path = _binary()
    if not bin_path:
        return {
            "status": "tool_unavailable",
            "tool": "recon-ng",
            "target": target,
            "reason": "Binario 'recon-cli'/'recon-ng' no encontrado en PATH; adaptador no ejecutable.",
            "note": "Sin salida fabricada.",
        }

    get_rate_limiter().acquire()

    batch = f"modules load {module}\noptions set SOURCE {target}\nrun\n"

    try:
        proc = subprocess.run(
            [bin_path, "-r", "/dev/stdin"],
            input=batch,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "tool_unavailable",
            "tool": "recon-ng",
            "target": target,
            "reason": f"Fallo lanzando Recon-ng: {exc}",
            "note": "Sin salida fabricada.",
        }

    if proc.returncode != 0:
        return {
            "status": "error",
            "tool": "recon-ng",
            "target": target,
            "reason": f"Recon-ng exit {proc.returncode}: {proc.stderr[:200]}",
        }

    return {
        "status": "ok",
        "module": module,
        "target": target,
        "stdout": proc.stdout,
    }
