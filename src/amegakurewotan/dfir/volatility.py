# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.dfir.volatility
Contexto: CIVIL — Consolidación AmegakureWotan (§6.3, §8.2)

Adaptador Volatility 3 para análisis de memoria en contenedor aislado.
Ejecuta el plugin solicitado sobre un dump de memoria montado solo-lectura,
con red desconectada. Reporta 'tool_unavailable' si no hay runtime/imagen.
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import logging
from pathlib import Path
from typing import Any, Dict

from amegakurewotan.dfir.runner import (
    ContainerRunner,
    DfirToolUnavailable,
    tool_unavailable_result,
)
from amegakurewotan.evidence.forensics import sha512_file

logger = logging.getLogger("amegakurewotan.dfir.volatility")

# Imagen por defecto (override vía params["image"]). Volatility 3 empaquetado.
_DEFAULT_IMAGE = "sk4la/volatility3:latest"

# Plugins permitidos (allowlist — evita ejecución arbitraria vía LLM).
_ALLOWED_PLUGINS = frozenset({
    "windows.pslist", "windows.pstree", "windows.psscan",
    "windows.netscan", "windows.netstat", "windows.malfind",
    "windows.dlllist", "windows.handles", "windows.cmdline",
    "linux.pslist", "linux.pstree", "linux.bash", "linux.check_syscall",
    "banners.Banners",
})


def memory_analyze(
    target: str,
    plugin: str = "windows.pslist",
    image: str = _DEFAULT_IMAGE,
    timeout: int = 900,
    **_: Any,
) -> Dict[str, Any]:
    """
    Ejecuta un plugin de Volatility 3 sobre un dump de memoria.

    Args:
        target:  Ruta al dump de memoria en el host (montado :ro en el contenedor).
        plugin:  Plugin Volatility3 (debe estar en el allowlist).
        image:   Imagen del contenedor con Volatility 3.
        timeout: Timeout de ejecución.

    Returns:
        Resultado forense con hash SHA-512 del dump, o 'tool_unavailable'.
    """
    dump = Path(target)
    if not dump.is_file():
        return {"status": "error", "tool": "volatility3", "reason": f"dump no encontrado: {target}"}

    if plugin not in _ALLOWED_PLUGINS:
        return {
            "status": "error", "tool": "volatility3",
            "reason": f"plugin '{plugin}' fuera del allowlist forense",
            "allowed": sorted(_ALLOWED_PLUGINS),
        }

    # Hash del artefacto de entrada para la cadena de custodia (antes de analizar).
    try:
        dump_hash = sha512_file(dump)
    except Exception as exc:  # noqa: BLE001
        dump_hash = f"hash_error:{exc}"

    runner = ContainerRunner(image=image, network="none", read_only_rootfs=True, timeout=timeout)
    if not runner.is_available():
        return tool_unavailable_result(
            "volatility3", "runtime de contenedores no disponible (podman/docker)", target=target
        )

    container_dump = "/evidence/memory.dmp"
    try:
        result = runner.run(
            args=["-f", container_dump, plugin],
            ro_mounts={str(dump.resolve()): container_dump},
        )
    except DfirToolUnavailable as exc:
        return tool_unavailable_result("volatility3", str(exc), target=target)

    result.update({
        "tool": "volatility3",
        "operation": "memory_analyze",
        "plugin": plugin,
        "target": target,
        "dump_sha512": dump_hash,
    })
    return result
