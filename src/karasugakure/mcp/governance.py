# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: karasugakure.mcp.governance
Contexto: CIVIL — Consolidación AmegakureWotan (capa L0, gobernanza MCP F5)

Propósito:
    Funciones de gobernanza Wotan (F5) para el servidor MCP (KarasugakureMCP).
    Cierra el bypass histórico: TODA tool pasa por GELSI antes de ejecutar;
    las acciones dfir/darkweb/evasive o PII sin minimizar levantan un ticket
    HITL (doble puerta) y NO se ejecutan hasta su aprobación; y toda ejecución
    autorizada se sella en la cadena de custodia (timeline.jsonl, HMAC-SHA512).

    Aislado en su propio módulo para que sea importable y testeable sin arrastrar
    el registro de decoradores MCP del SDK (que varía entre versiones). El server
    MCP lo consume vía `from karasugakure.mcp.governance import govern, seal_execution`.
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "lugh — AmegakureDōjō"
__forge_context__ = "CIVIL"

import logging
from typing import Any, Dict, List, Optional, Tuple

from mcp.types import TextContent

logger = logging.getLogger("karasugakure.mcp.governance")

# Categoría de acción GELSI por tool (deny-by-default para las no listadas).
_TOOL_ACTION = {
    "searxng_recon": "passive",
    "heimdall_recon": "passive",
    "huginn_humint": "passive",
    "fenrir_correlate": "passive",
    "kuzu_cypher_query": "passive",
    "kuzu_ingest_entity": "active",
    "export_graph": "passive",
    "audit_verify": "passive",
    "odin_orchestrate": "active",
    "hel_darkweb": "darkweb",
}


def govern(name: str, arguments: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """
    Evalúa la tool contra GELSI (capa L0). Devuelve (decision, payload).

    decision:
      "ALLOW"          → proceder; payload=None.
      "DENY"           → no ejecutar; payload=mensaje de denegación.
      "REQUIRE_HITL"   → ticket creado; payload=ticket_id (pendiente).

    En REQUIRE_HITL se levanta un ticket en el subsistema HITL y se sella en la
    cadena de custodia. El operador resuelve con 'amewotan hitl approve'.
    """
    from karasugakure.evidence.forensics import ChainOfCustody, canonical_json, sha512_bytes
    from karasugakure.policy.gelsi import ActionRequest, Decision, get_gelsi

    action = _TOOL_ACTION.get(name, "active")  # deny-by-default: lo no listado => active (exige RoE)
    target = None
    for key in ("target", "query", "username", "entity_id"):
        if arguments.get(key):
            target = arguments.get(key)
            break
    roe_token = arguments.get("roe_token")

    verdict = get_gelsi().evaluate(
        ActionRequest(
            action_type=action,
            tool=name,
            target=target,
            roe_token=roe_token,
            intent=name,
            collector_id="mcp:KarasugakureMCP",
            metadata={"domain": name.split("_")[0]},
        ),
        seal=True,
    )

    if verdict.decision == Decision.ALLOW:
        return "ALLOW", None

    if verdict.decision == Decision.REQUIRE_HITL:
        try:
            from karasugakure.policy.hitl import get_hitl

            ticket = get_hitl().create_ticket(
                tool=name, action_type=action, target=target,
                roe_ref=verdict.roe_ref, request_args=arguments,
                reasons=verdict.reasons,
            )
            return "REQUIRE_HITL", ticket.ticket_id
        except Exception as exc:  # noqa: BLE001
            logger.error("Fallo al crear ticket HITL para %s: %s", name, exc)
            return "DENY", f"[GELSI] REQUIRE_HITL para '{name}' pero no se pudo crear ticket: {exc}"

    return "DENY", "[GELSI] " + "; ".join(verdict.reasons)


def seal_execution(name: str, arguments: Dict[str, Any], summary_text: str) -> None:
    """Sella el resultado de una ejecución autorizada en timeline.jsonl (HMAC-SHA512)."""
    try:
        from karasugakure.evidence.forensics import (
            ChainOfCustody,
            canonical_json,
            sha512_bytes,
        )

        payload_hash = sha512_bytes(
            canonical_json({"tool": name, "summary": summary_text[:4096]}).encode("utf-8")
        )
        ChainOfCustody().append(
            collector_id=f"mcp:{name}",
            event_type="mcp.exec",
            payload_hash=payload_hash,
            metadata={"tool": name, "args_keys": list(arguments.keys())},
        )
    except Exception as exc:  # noqa: BLE001 — el sellado no debe tumbar la tool.
        logger.error("No se pudo sellar ejecución MCP de '%s': %s", name, exc)


def handle_hitl_tool(name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """Resuelve las tools de control-plane HITL del operador (no pasan por govern)."""
    from karasugakure.policy.hitl import get_hitl

    if name == "wotan_hitl_list":
        pending = get_hitl().list_pending()
        if not pending:
            return [TextContent(type="text", text="[HITL] Sin tickets pendientes.")]
        lines = ["[HITL] Tickets pendientes:"]
        for t in pending:
            lines.append(
                f"  • {t.ticket_id} | tool={t.tool} action={t.action_type} "
                f"target={t.target or '-'} roe={t.roe_ref or '-'}"
            )
        return [TextContent(type="text", text="\n".join(lines))]

    ticket_id = arguments.get("ticket_id", "")
    if name == "wotan_hitl_approve":
        try:
            from karasugakure.mcp.gateway import get_gateway

            res = get_gateway().approve_hitl(
                ticket_id, by=arguments.get("by", "operator"), reason=arguments.get("reason"),
            )
            return [TextContent(
                type="text",
                text=(f"[HITL] Ticket {ticket_id} APPROVED. Re-ejecución vía gateway: "
                      f"decision={res.decision} ok={res.ok} "
                      f"razones={'; '.join(res.reasons)}"),
            )]
        except Exception as exc:  # noqa: BLE001
            return [TextContent(type="text", text=f"[HITL] Error aprobando {ticket_id}: {exc}")]

    if name == "wotan_hitl_deny":
        try:
            from karasugakure.mcp.gateway import get_gateway

            res = get_gateway().deny_hitl(ticket_id, reason=arguments.get("reason"))
            return [TextContent(
                type="text",
                text=f"[HITL] Ticket {ticket_id} DENIED. {res.reasons[0] if res.reasons else ''}",
            )]
        except Exception as exc:  # noqa: BLE001
            return [TextContent(type="text", text=f"[HITL] Error denegando {ticket_id}: {exc}")]

    return [TextContent(type="text", text=f"[HITL] Tool desconocida: {name}")]
