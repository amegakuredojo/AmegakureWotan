# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: karasugakure.dfir.sleuthkit
Contexto: CIVIL — Consolidación AmegakureWotan (§6.3, §8.2)

Adaptador Sleuth Kit para generar timelines de disco (mactime) en contenedor
aislado sobre una imagen forense montada solo-lectura. Reporta 'tool_unavailable'
si el runtime/imagen no está.
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import logging
from pathlib import Path
from typing import Any, Dict

from karasugakure.dfir.runner import (
    ContainerRunner,
    DfirToolUnavailable,
    tool_unavailable_result,
)
from karasugakure.evidence.forensics import sha512_file

logger = logging.getLogger("karasugakure.dfir.sleuthkit")

_DEFAULT_IMAGE = "sleuthkit/sleuthkit:latest"


def disk_timeline(
    target: str,
    image: str = _DEFAULT_IMAGE,
    timeout: int = 900,
    **_: Any,
) -> Dict[str, Any]:
    """
    Genera un body file (fls) de una imagen de disco para timeline forense.

    Args:
        target:  Ruta a la imagen de disco en el host (montada :ro).
        image:   Imagen del contenedor con Sleuth Kit.
        timeout: Timeout de ejecución.

    Returns:
        Resultado forense con hash SHA-512 de la imagen, o 'tool_unavailable'.
    """
    disk = Path(target)
    if not disk.is_file():
        return {"status": "error", "tool": "sleuthkit", "reason": f"imagen no encontrada: {target}"}

    try:
        disk_hash = sha512_file(disk)
    except Exception as exc:  # noqa: BLE001
        disk_hash = f"hash_error:{exc}"

    runner = ContainerRunner(image=image, network="none", read_only_rootfs=True, timeout=timeout)
    if not runner.is_available():
        return tool_unavailable_result(
            "sleuthkit", "runtime de contenedores no disponible (podman/docker)", target=target
        )

    container_disk = "/evidence/disk.img"
    try:
        # fls -r -m / genera un body file recursivo apto para mactime.
        result = runner.run(
            args=["fls", "-r", "-m", "/", container_disk],
            ro_mounts={str(disk.resolve()): container_disk},
        )
    except DfirToolUnavailable as exc:
        return tool_unavailable_result("sleuthkit", str(exc), target=target)

    result.update({
        "tool": "sleuthkit",
        "operation": "disk_timeline",
        "target": target,
        "image_sha512": disk_hash,
    })
    return result
