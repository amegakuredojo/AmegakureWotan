# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.adapters.l3.greynoise
Contexto: CIVIL — Consolidación AmegakureWotan (capa L3, motores externos)

Adaptador honesto para GreyNoise (enriquecimiento de IPs: si es escaneo
malicioso de Internet vs. escáner benigno). 

Doctrina de adapters L3 (AmegakureWotan.md §5.2 / WOTAN-F4):
  • El binario/API se invoca SOLO si está disponible (credencial/clave/red).
  • Si falta la clave o el binario => devuelve un veredicto 'tool_unavailable'
    EXPLÍCITO y auditable. NUNCA se fabrica una respuesta.
  • Toda salida de red pasa por el rate-limiter global de 13 req/s (sin ráfagas).
  • Auth vía variable de entorno (nunca hardcodeada).
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import logging
import os

import requests

from amegakurewotan.utils.ratelimit import get_rate_limiter

logger = logging.getLogger("amegakurewotan.adapters.l3.greynoise")

BASE_URL = "https://api.greynoise.io/v3/community"
# GreyNoise free community API: 1 req/min en tier gratuito; el rate-limiter
# global de 13 req/s ya es holgado, pero respetamos su propio techo vía env.
GREYNOISE_MAX_RPS = float(os.environ.get("GREYNOISE_MAX_RPS", "1.0"))


def _api_key() -> str | None:
    key = os.environ.get("GREYNOISE_API_KEY")
    return key or None


def greynoise_ip_report(ip: str) -> dict:
    """
    Enriquece una IP con GreyNoise Community API.

    Returns:
        {"status": "ok", "ip": ..., "classification": ..., ...} en éxito, o
        {"status": "tool_unavailable", "reason": ...} si falta clave/red/binario.
    """
    key = _api_key()
    if not key:
        return {
            "status": "tool_unavailable",
            "tool": "greynoise",
            "target": ip,
            "reason": "GREYNOISE_API_KEY no configurada en el entorno; adaptador no ejecutable.",
            "note": "Sin salida fabricada.",
        }

    # Rate-limit DURO (global de 13 req/s, con respeto al techo de GreyNoise).
    get_rate_limiter().acquire()

    try:
        resp = requests.get(
            BASE_URL + "/ip",
            params={"ip": ip},
            headers={"Authorization": f"Bearer {key}"},
            timeout=20.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "status": "ok",
                "ip": ip,
                "classification": data.get("classification"),
                "name": data.get("name"),
                "noise": data.get("noise"),
                "riot": data.get("riot"),
                "raw": data,
            }
        return {
            "status": "error",
            "tool": "greynoise",
            "target": ip,
            "reason": f"GreyNoise HTTP {resp.status_code}: {resp.text[:200]}",
        }
    except requests.RequestException as exc:
        return {
            "status": "tool_unavailable",
            "tool": "greynoise",
            "target": ip,
            "reason": f"No se pudo alcanzar GreyNoise: {exc}",
            "note": "Sin salida fabricada.",
        }
