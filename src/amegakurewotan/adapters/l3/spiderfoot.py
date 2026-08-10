# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.adapters.l3.spiderfoot
Contexto: CIVIL — Consolidación AmegakureWotan (capa L3, motor externo)

Adaptador honesto para SpiderFoot CLI (OSINT automatizado).
Doctrina WOTAN-F4:
  • Se invoca el binario REAL 'sf.py' o 'spiderfoot' si está en el PATH.
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

logger = logging.getLogger("amegakurewotan.adapters.l3.spiderfoot")


def _binary() -> Optional[str]:
    return shutil.which("sf.py") or shutil.which("spiderfoot")


def spiderfoot_scan(target: str, modules: str = "sfp_dnsresolve,sfp_ssl", timeout: int = 300) -> Dict[str, Any]:
    """
    Ejecuta SpiderFoot contra `target`.
    """
    bin_path = _binary()
    if not bin_path:
        return {
            "status": "tool_unavailable",
            "tool": "spiderfoot",
            "target": target,
            "reason": "Binario 'sf.py'/'spiderfoot' no encontrado en PATH; adaptador no ejecutable.",
            "note": "Sin salida fabricada.",
        }

    get_rate_limiter().acquire()

    cmd = [bin_path, "-s", target, "-m", modules, "-q", "-o", "csv"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "tool_unavailable",
            "tool": "spiderfoot",
            "target": target,
            "reason": f"Fallo lanzando SpiderFoot: {exc}",
            "note": "Sin salida fabricada.",
        }

    if proc.returncode != 0:
        return {
            "status": "error",
            "tool": "spiderfoot",
            "target": target,
            "reason": f"SpiderFoot exit {proc.returncode}: {proc.stderr[:200]}",
        }

    return {
        "status": "ok",
        "target": target,
        "stdout": proc.stdout,
        "modules": modules,
    }
