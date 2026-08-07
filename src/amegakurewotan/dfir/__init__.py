# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Paquete: amegakurewotan.dfir
Contexto: CIVIL — Consolidación AmegakureWotan (capa L3/L4 DFIR)

Adaptadores DFIR (Velociraptor, Volatility 3, Sleuth Kit) que ejecutan binarios
en contenedores aislados (§6.3). Principio forense inviolable (doctrina Lugh):
si la herramienta o su runtime NO está disponible, se reporta 'tool_unavailable'
de forma explícita — NUNCA se fabrica salida.
"""
from amegakurewotan.dfir.runner import (
    ContainerRunner,
    DfirToolUnavailable,
    detect_container_runtime,
    tool_unavailable_result,
)

__all__ = [
    "ContainerRunner",
    "DfirToolUnavailable",
    "detect_container_runtime",
    "tool_unavailable_result",
]
