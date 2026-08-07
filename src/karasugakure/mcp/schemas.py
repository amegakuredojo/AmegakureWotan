# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: karasugakure.mcp.schemas
Contexto: CIVIL — Consolidación AmegakureWotan (capa L2, MCP §6.2)

Propósito:
    Esquemas Pydantic tipados para las herramientas del MCP consolidado. Unifican
    recon/intel/graph/darkweb/dfir/forensic/defense con validación de RoE embebida
    en los validadores de campo, tal como especifica AmegakureWotan.md §6.2.

    La validación de scope/acción se delega a policy.roe.ScopeRegistry (deny-by-default),
    y GELSI (policy.gelsi) aplica la decisión final ALLOW/DENY/REQUIRE_HITL en el gateway.
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from karasugakure.policy.roe import (
    ACTION_ACTIVE,
    ACTION_DARKWEB,
    ACTION_DFIR,
    get_scope_registry,
)

# Dominios lógicos del MCP consolidado (AmegakureWotan.md §6.1).
DOMAINS = (
    "recon",
    "intel",
    "graph",
    "darkweb",
    "dfir",
    "forensic",
    "defense",
)


class ReconTarget(BaseModel):
    """Objetivo de reconocimiento tipado (§6.2)."""

    value: str = Field(..., min_length=1, description="dominio, IP, email, org o username")
    type: Literal["domain", "ip", "email", "org", "username"]


class ReconRequest(BaseModel):
    """
    Solicitud de reconocimiento consolidada (§6.2). El validador de scope
    consulta el ScopeRegistry (RoE) y rechaza targets fuera de alcance o
    modos no autorizados por la RoE — deny-by-default.
    """

    target: ReconTarget
    mode: Literal[
        "passive_surface",   # whois, certs, DNS, leaks pasivos
        "active_surface",    # portscan moderado, banner grabbing, Nuclei
        "deep_osint",        # SpiderFoot/Recon-ng/Amass combinados
        "darkweb_profile",   # Tor + búsqueda onion
    ]
    roe_token: str = Field(..., min_length=1)

    @model_validator(mode="after")
    def enforce_roe(self) -> "ReconRequest":
        """
        Validación consolidada con todos los campos ya poblados (Pydantic v2):
        target debe estar en scope de la RoE y el modo debe estar autorizado.
        Deny-by-default vía ScopeRegistry; GELSI repite la comprobación en el gateway.
        """
        registry = get_scope_registry()
        # 1. Scope del target contra la RoE.
        if not registry.is_authorized(self.target.value, self.roe_token):
            raise ValueError(
                f"target '{self.target.value}' fuera de RoE autorizado ('{self.roe_token}')"
            )
        # 2. Cláusula de acción según el modo.
        roe = registry.get(self.roe_token)
        if roe is not None:
            if self.mode == "active_surface" and not roe.allows_active():
                raise ValueError("RoE no autoriza acciones activas (active_surface)")
            if self.mode == "darkweb_profile" and not roe.allows_darkweb():
                raise ValueError("RoE no autoriza operaciones darkweb (darkweb_profile)")
        return self

    def action_category(self) -> str:
        """Mapea el modo recon a la categoría de acción GELSI."""
        return {
            "passive_surface": "passive",
            "active_surface": ACTION_ACTIVE,
            "deep_osint": "passive",
            "darkweb_profile": ACTION_DARKWEB,
        }[self.mode]


class GraphQueryRequest(BaseModel):
    """Consulta de grafo read-only (Kùzu/Neo4j). Allowlist de verbos en el handler."""

    query: str = Field(..., min_length=1, description="Cypher read-only (MATCH/RETURN/WHERE/WITH/LIMIT)")
    roe_token: Optional[str] = None


class DarkwebRequest(BaseModel):
    """Solicitud darkweb — siempre exige RoE que autorice darkweb + doble puerta HITL."""

    query: str = Field(..., min_length=1)
    roe_token: str = Field(..., min_length=1)

    @field_validator("roe_token")
    @classmethod
    def roe_allows_darkweb(cls, v: str, info) -> str:
        roe = get_scope_registry().get(v)
        if roe is not None and not roe.allows_darkweb():
            raise ValueError(f"RoE '{v}' no autoriza operaciones darkweb")
        return v


class DfirRequest(BaseModel):
    """
    Solicitud DFIR (Velociraptor/Volatility/Sleuth Kit). Exige RoE con acción dfir.
    El artefacto/target puede ser un endpoint, un dump de memoria o una imagen de disco.
    """

    operation: Literal[
        "velociraptor_hunt",
        "velociraptor_collect",
        "memory_analyze",
        "disk_timeline",
    ]
    target: str = Field(..., min_length=1, description="endpoint/tag, ruta de dump o imagen de disco")
    roe_token: str = Field(..., min_length=1)
    params: dict = Field(default_factory=dict)

    @field_validator("roe_token")
    @classmethod
    def roe_allows_dfir(cls, v: str, info) -> str:
        roe = get_scope_registry().get(v)
        if roe is not None and not roe.allows_dfir():
            raise ValueError(f"RoE '{v}' no autoriza operaciones DFIR")
        return v


class DefenseRequest(BaseModel):
    """
    Solicitud de ingeniería social DEFENSIVA (detección de phishing, correlación de
    campañas, huella expuesta del personal). NUNCA genera contenido ofensivo.
    """

    operation: Literal[
        "phishing_detect",
        "campaign_correlate",
        "exposed_footprint",
    ]
    subject: str = Field(..., min_length=1, description="dominio/organización/indicador a proteger")
    roe_token: Optional[str] = None


class ForensicAppendRequest(BaseModel):
    """Append a la cadena de custodia consolidada (timeline.jsonl)."""

    collector_id: str = Field(..., min_length=1)
    event_type: str = Field(..., min_length=1)
    payload_hash: str = Field(..., min_length=64, description="SHA-512 hex del artefacto")
    roe_ref: Optional[str] = None
    metadata: dict = Field(default_factory=dict)
