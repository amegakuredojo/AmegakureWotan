# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.adapters.l3.shodan
Contexto: CIVIL — Consolidación AmegakureWotan (capa L3, motor externo)

Adaptador honesto para Shodan (búsqueda de servicios/banners en Internet).
Doctrina WOTAN-F4:
  • Se invoca SOLO si SHODAN_API_KEY está configurada en el entorno.
  • Si falta la clave => devuelve 'tool_unavailable' explícito y auditable.
  • Sin salida fabricada.
  • Toda salida de red pasa por el rate-limiter global (13 req/s).
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import logging
import os
from typing import Any, Dict, Optional

import requests

from amegakurewotan.utils.ratelimit import get_rate_limiter

logger = logging.getLogger("amegakurewotan.adapters.l3.shodan")

SHODAN_BASE = "https://api.shodan.io"


def _api_key() -> Optional[str]:
    key = os.environ.get("SHODAN_API_KEY")
    return key or None


def shodan_host_info(ip: str) -> Dict[str, Any]:
    """
    Consulta información de host en Shodan.

    Returns:
        {"status": "ok", "ip": ..., "ports": [...], ...} en éxito, o
        {"status": "tool_unavailable", "reason": ...} si falta clave/red.
    """
    key = _api_key()
    if not key:
        return {
            "status": "tool_unavailable",
            "tool": "shodan",
            "target": ip,
            "reason": "SHODAN_API_KEY no configurada en el entorno; adaptador no ejecutable.",
            "note": "Sin salida fabricada.",
        }

    get_rate_limiter().acquire()

    try:
        resp = requests.get(
            f"{SHODAN_BASE}/shodan/host/{ip}",
            params={"key": key},
            timeout=20.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "status": "ok",
                "ip": ip,
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "org": data.get("org"),
                "country": data.get("country_name"),
                "raw": data,
            }
        return {
            "status": "error",
            "tool": "shodan",
            "target": ip,
            "reason": f"Shodan HTTP {resp.status_code}: {resp.text[:200]}",
        }
    except requests.RequestException as exc:
        return {
            "status": "tool_unavailable",
            "tool": "shodan",
            "target": ip,
            "reason": f"No se pudo alcanzar Shodan: {exc}",
            "note": "Sin salida fabricada.",
        }


def shodan_search(query: str, limit: int = 10) -> Dict[str, Any]:
    """
    Búsqueda de servicios/banners por query en Shodan.
    """
    key = _api_key()
    if not key:
        return {
            "status": "tool_unavailable",
            "tool": "shodan",
            "reason": "SHODAN_API_KEY no configurada en el entorno; adaptador no ejecutable.",
            "note": "Sin salida fabricada.",
        }

    get_rate_limiter().acquire()

    try:
        resp = requests.get(
            f"{SHODAN_BASE}/shodan/host/search",
            params={"key": key, "query": query, "page": 1, "minify": True},
            timeout=20.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            matches = data.get("matches", [])[:limit]
            return {
                "status": "ok",
                "query": query,
                "total": data.get("total", 0),
                "matches": matches,
            }
        return {
            "status": "error",
            "tool": "shodan",
            "reason": f"Shodan HTTP {resp.status_code}: {resp.text[:200]}",
        }
    except requests.RequestException as exc:
        return {
            "status": "tool_unavailable",
            "tool": "shodan",
            "reason": f"No se pudo alcanzar Shodan: {exc}",
            "note": "Sin salida fabricada.",
        }
