# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.adapters.l3.theharvester
Contexto: CIVIL — Consolidación AmegakureWotan (capa L3, motor externo)

Adaptador honesto para theHarvester (recon pasivo: emails, hosts, subdomi
nios vía fuentes públicas). Invoca el binario REAL si está en el PATH; si no,
devuelve 'tool_unavailable' (sin fabricar salida). Toda ejecución queda
supeditada a la gobernanza GELSI/RoE del gateway que lo invoca.
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import logging
import shutil
import subprocess

from amegakurewotan.utils.ratelimit import get_rate_limiter

logger = logging.getLogger("amegakurewotan.adapters.l3.theharvester")


def _binary() -> str | None:
    return shutil.which("theHarvester")


def theharvester_run(domain: str, sources: str | None = None, limit: int = 100) -> dict:
    """
    Ejecuta theHarvester contra `domain`.

    Returns:
        {"status": "ok", "domain": ..., "stdout": ...} en éxito, o
        {"status": "tool_unavailable", "reason": ...} si el binario falta.
    """
    bin_path = _binary()
    if not bin_path:
        return {
            "status": "tool_unavailable",
            "tool": "theharvester",
            "target": domain,
            "reason": "binario 'theHarvester' no encontrado en PATH; adaptador no ejecutable.",
            "note": "Sin salida fabricada.",
        }

    # Rate-limit DURO (global de 13 req/s, sin ráfagas).
    get_rate_limiter().acquire()

    cmd = [bin_path, "-d", domain, "-l", str(limit), "-f", "-"]
    if sources:
        cmd += ["-b", sources]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "status": "tool_unavailable",
            "tool": "theharvester",
            "target": domain,
            "reason": f"Fallo lanzando theHarvester: {exc}",
            "note": "Sin salida fabricada.",
        }

    if proc.returncode != 0:
        return {
            "status": "error",
            "tool": "theharvester",
            "target": domain,
            "reason": f"theHarvester exit {proc.returncode}: {proc.stderr[:200]}",
        }

    return {"status": "ok", "domain": domain, "stdout": proc.stdout}
