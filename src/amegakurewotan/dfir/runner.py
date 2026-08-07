# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.dfir.runner
Contexto: CIVIL — Consolidación AmegakureWotan (§6.3, §10.3)

Propósito:
    Ejecutor común para herramientas DFIR pesadas en contenedores AISLADOS.
    Impone (AmegakureWotan.md §6.3):
      - red desconectada por defecto (--network none),
      - volúmenes de entrada de solo lectura (:ro),
      - límites de CPU y memoria,
      - salida redirigida a un directorio de evidencias controlado.

    Detecta el runtime de contenedores (podman preferido, docker fallback). Si no
    hay runtime o la imagen no está disponible, NO fabrica resultados: devuelve un
    veredicto 'tool_unavailable' explícito y auditable (doctrina forense de Lugh).
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("amegakurewotan.dfir.runner")


class DfirToolUnavailable(Exception):
    """La herramienta DFIR o su runtime de contenedor no está disponible."""


def detect_container_runtime() -> Optional[str]:
    """Devuelve la ruta del runtime de contenedores disponible (podman > docker) o None."""
    for candidate in ("podman", "docker"):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def tool_unavailable_result(tool: str, reason: str, target: str = "") -> Dict[str, object]:
    """Resultado forense honesto cuando una herramienta no puede ejecutarse."""
    return {
        "status": "tool_unavailable",
        "tool": tool,
        "target": target,
        "reason": reason,
        "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": "Sin salida fabricada: la herramienta/runtime no está disponible en este host.",
    }


@dataclass
class ContainerRunner:
    """
    Envoltorio de ejecución aislada para una herramienta DFIR.

    Args:
        image:        Imagen del contenedor (p. ej. "sk4la/volatility3:latest").
        cpus:         Límite de CPUs (--cpus).
        memory:       Límite de memoria (--memory, p. ej. "2g").
        network:      Modo de red; "none" por defecto (aislamiento total).
        read_only_rootfs: Monta el rootfs del contenedor como solo lectura.
        timeout:      Timeout de ejecución en segundos.
    """

    image: str
    cpus: str = "1.0"
    memory: str = "2g"
    network: str = "none"
    read_only_rootfs: bool = True
    timeout: int = 600

    def is_available(self) -> bool:
        return detect_container_runtime() is not None

    def build_command(
        self,
        args: List[str],
        ro_mounts: Optional[Dict[str, str]] = None,
        rw_mounts: Optional[Dict[str, str]] = None,
    ) -> List[str]:
        """
        Construye el comando de contenedor endurecido. NO se ejecuta aquí.

        Args:
            args:      Argumentos pasados al entrypoint de la imagen.
            ro_mounts: {host_path: container_path} montados solo-lectura (:ro).
            rw_mounts: {host_path: container_path} montados lectura-escritura (evidencias).
        """
        runtime = detect_container_runtime()
        if not runtime:
            raise DfirToolUnavailable("No hay runtime de contenedores (podman/docker) en el host.")

        cmd: List[str] = [
            runtime, "run", "--rm",
            "--network", self.network,
            "--cpus", self.cpus,
            "--memory", self.memory,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
        ]
        if self.read_only_rootfs:
            cmd += ["--read-only", "--tmpfs", "/tmp"]

        for host, container in (ro_mounts or {}).items():
            cmd += ["-v", f"{host}:{container}:ro"]
        for host, container in (rw_mounts or {}).items():
            Path(host).mkdir(parents=True, exist_ok=True)
            cmd += ["-v", f"{host}:{container}"]

        cmd.append(self.image)
        cmd += args
        return cmd

    def run(
        self,
        args: List[str],
        ro_mounts: Optional[Dict[str, str]] = None,
        rw_mounts: Optional[Dict[str, str]] = None,
    ) -> Dict[str, object]:
        """
        Ejecuta la herramienta en contenedor aislado y captura salida.

        Returns:
            {status, exit_code, stdout, stderr, command} en ejecución real, o
            un resultado 'tool_unavailable' si el runtime/imagen no existe.

        Raises:
            DfirToolUnavailable: si no hay runtime (los handlers lo capturan y
                                 lo convierten en resultado honesto).
        """
        runtime = detect_container_runtime()
        if not runtime:
            raise DfirToolUnavailable("No hay runtime de contenedores (podman/docker) en el host.")

        cmd = self.build_command(args, ro_mounts=ro_mounts, rw_mounts=rw_mounts)
        logger.info("DFIR container exec: %s", " ".join(cmd))
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            return {"status": "timeout", "command": cmd, "reason": f"timeout tras {self.timeout}s"}
        except (OSError, subprocess.SubprocessError) as exc:
            raise DfirToolUnavailable(f"Fallo lanzando contenedor: {exc}") from exc

        # Imagen ausente => exit 125 (podman/docker). No fabricar salida.
        if proc.returncode == 125 or "unable to find image" in (proc.stderr or "").lower():
            return tool_unavailable_result(
                self.image, f"imagen del contenedor no disponible: {proc.stderr.strip()[:200]}"
            )

        return {
            "status": "completed" if proc.returncode == 0 else "error",
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "command": cmd,
        }
