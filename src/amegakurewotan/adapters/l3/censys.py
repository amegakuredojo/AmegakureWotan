# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.adapters.l3.censys
Contexto: CIVIL — Consolidación AmegakureWotan (capa L3, motor externo)

Adaptador honesto para Censys (búsqueda de hosts y certificados TLS).
Doctrina WOTAN-F4:
  • Se invoca SOLO si CENSYS_API_ID y CENSYS_API_SECRET están configurados.
  • Si faltan credenciales => devuelve 'tool_unavailable' explícito y auditable.
  • Sin salida fabricada.
  • Toda salida de red pasa por el rate-limiter global (13 req/s).
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import logging
import os
from typing import Any, Dict, Optional, Tuple

import requests

from amegakurewotan.utils.ratelimit import get_rate_limiter

logger = logging.getLogger("amegakurewotan.adapters.l3.censys")

CENSYS_BASE = "https://search.censys.io/api"


def _credentials() -> Optional[Tuple[str, str]]:
    api_id = os.environ.get("CENSYS_API_ID")
    secret = os.environ.get("CENSYS_API_SECRET")
    return (api_id, secret) if (api_id and secret) else None


def censys_host_info(ip: str) -> Dict[str, Any]:
    """
    Consulta información de host en Censys.
    """
    creds = _credentials()
    if not creds:
        return {
            "status": "tool_unavailable",
            "tool": "censys",
            "target": ip,
            "reason": "CENSYS_API_ID y/o CENSYS_API_SECRET no configurados en el entorno; adaptador no ejecutable.",
            "note": "Sin salida fabricada.",
        }

    get_rate_limiter().acquire()

    try:
        resp = requests.get(
            f"{CENSYS_BASE}/v2/hosts/{ip}",
            auth=creds,
            timeout=20.0,
        )
        if resp.status_code == 200:
            data = resp.json().get("result", {})
            return {
                "status": "ok",
                "ip": ip,
                "services": data.get("services", []),
                "labels": data.get("labels", []),
                "raw": data,
            }
        return {
            "status": "error",
            "tool": "censys",
            "target": ip,
            "reason": f"Censys HTTP {resp.status_code}: {resp.text[:200]}",
        }
    except requests.RequestException as exc:
        return {
            "status": "tool_unavailable",
            "tool": "censys",
            "target": ip,
            "reason": f"No se pudo alcanzar Censys: {exc}",
            "note": "Sin salida fabricada.",
        }


def censys_search_hosts(query: str, limit: int = 10) -> Dict[str, Any]:
    """
    Búsqueda de hosts por query en Censys.
    """
    creds = _credentials()
    if not creds:
        return {
            "status": "tool_unavailable",
            "tool": "censys",
            "reason": "CENSYS_API_ID y/o CENSYS_API_SECRET no configurados en el entorno; adaptador no ejecutable.",
            "note": "Sin salida fabricada.",
        }

    get_rate_limiter().acquire()

    try:
        resp = requests.post(
            f"{CENSYS_BASE}/v2/hosts/search",
            auth=creds,
            json={"q": query, "per_page": limit},
            timeout=20.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            hits = data.get("result", {}).get("hits", [])
            return {
                "status": "ok",
                "query": query,
                "hits": hits,
            }
        return {
            "status": "error",
            "tool": "censys",
            "reason": f"Censys HTTP {resp.status_code}: {resp.text[:200]}",
        }
    except requests.RequestException as exc:
        return {
            "status": "tool_unavailable",
            "tool": "censys",
            "reason": f"No se pudo alcanzar Censys: {exc}",
            "note": "Sin salida fabricada.",
        }
