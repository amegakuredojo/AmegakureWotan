# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: karasugakure.dfir.velociraptor
Contexto: CIVIL — Consolidación AmegakureWotan (§6.3, §8.2)

Adaptador Velociraptor para DFIR a gran escala (hunts VQL, colección de artefactos).
Invoca el CLI `velociraptor` si está presente; de lo contrario reporta
'tool_unavailable' sin fabricar resultados.

Referencia de diseño: AmegakureWotan.md §6.3 dfir.velociraptor_hunt / _collect.
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import logging
import shutil
import subprocess
from typing import Any, Dict, Optional

from karasugakure.dfir.runner import tool_unavailable_result

logger = logging.getLogger("karasugakure.dfir.velociraptor")

_VELOCIRAPTOR_BIN = "velociraptor"


def _binary_available() -> bool:
    return shutil.which(_VELOCIRAPTOR_BIN) is not None


def velociraptor_hunt(
    target: str,
    artifact: Optional[str] = None,
    vql: Optional[str] = None,
    config_path: Optional[str] = None,
    timeout: int = 600,
    **_: Any,
) -> Dict[str, Any]:
    """
    Lanza un hunt DFIR contra una etiqueta de clientes o ejecuta VQL.

    Args:
        target:      Etiqueta/label de clientes (p. ej. "windows_workstations") o "server".
        artifact:    Nombre de artefacto Velociraptor a ejecutar (opcional).
        vql:         Query VQL directa (alternativa a artifact).
        config_path: Ruta al api.config.yaml de Velociraptor.
        timeout:     Timeout de ejecución.

    Returns:
        Resultado forense estructurado, o 'tool_unavailable' si el CLI no está.
    """
    if not target or not target.strip():
        return {"status": "error", "tool": "velociraptor", "reason": "target/label vacío"}

    if not _binary_available():
        return tool_unavailable_result(
            "velociraptor",
            "CLI 'velociraptor' no encontrado en PATH; instale el binario para hunts reales.",
            target=target,
        )

    if not vql and not artifact:
        # VQL mínima por defecto: enumerar clientes con la etiqueta objetivo.
        vql = f"SELECT client_id, os_info.hostname FROM clients() WHERE '{target}' IN labels"

    cmd = [_VELOCIRAPTOR_BIN]
    if config_path:
        cmd += ["--config", config_path]
    if vql:
        cmd += ["query", vql]
    else:
        cmd += ["artifacts", "collect", artifact, "--args", f"label={target}"]

    logger.info("Velociraptor exec: %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "tool": "velociraptor", "target": target}
    except (OSError, subprocess.SubprocessError) as exc:
        return tool_unavailable_result("velociraptor", f"fallo de ejecución: {exc}", target=target)

    return {
        "status": "completed" if proc.returncode == 0 else "error",
        "tool": "velociraptor",
        "operation": "hunt" if vql else "collect",
        "target": target,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def velociraptor_collect(target: str, artifact: str, **kwargs: Any) -> Dict[str, Any]:
    """Recolecta un artefacto específico (logs, registros, MFT) de un endpoint/tag."""
    return velociraptor_hunt(target=target, artifact=artifact, **kwargs)
