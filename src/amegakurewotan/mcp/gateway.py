# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.mcp.gateway
Contexto: CIVIL — Consolidación AmegakureWotan (capa L2, MCP consolidado)

Propósito:
    Gateway único del MCP consolidado `amegakurewotan.mcp`. Enruta herramientas
    por dominio lógico (recon.* intel.* graph.* darkweb.* dfir.* forensic.* defense.*),
    aplica la capa L0 GELSI ANTES de cualquier ejecución, y sella toda operación
    (autorizada o denegada) en la cadena de custodia (timeline.jsonl).

    Arquitectura (AmegakureWotan.md §10.1 — separación de capas):
        Esquemas Pydantic (mcp.schemas)  →  validación de entrada + RoE
        Handlers de negocio (este módulo) →  deciden qué motor interno invocar
        Adaptadores IO (agents/tools/dfir)→  ejecutan CLI/SDK/contenedores
        Hooks GELSI/ChainOfCustody        →  política + registro probatorio

    Idempotencia (§10.2): cada operación acepta un operation_id; si ya existe un
    evento 'op.completed' con ese id en la cadena, se evita la re-ejecución.

    Los handlers NO deciden autorización: eso es exclusivo de GELSI. Los
    adaptadores NO manejan RoE. Deny-by-default en todo el gateway.
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "lugh — AmegakureDōjō"
__forge_context__ = "CIVIL"

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from amegakurewotan.evidence.forensics import ChainOfCustody, canonical_json, sha512_bytes
from amegakurewotan.policy.gelsi import (
    ActionRequest,
    Decision,
    GelsiMiddleware,
    GelsiVerdict,
    get_gelsi,
)
from amegakurewotan.policy.roe import (
    ACTION_ACTIVE,
    ACTION_DARKWEB,
    ACTION_DFIR,
    ACTION_PASSIVE,
)

logger = logging.getLogger("amegakurewotan.mcp.gateway")

MCP_NAME = "amegakurewotan.mcp"


@dataclass
class GatewayResult:
    """Resultado uniforme de una invocación al gateway consolidado."""

    tool: str
    decision: str
    ok: bool = False
    data: Any = None
    reasons: list = field(default_factory=list)
    roe_ref: Optional[str] = None
    payload_hash: Optional[str] = None
    error: Optional[str] = None
    hitl_ticket_id: Optional[str] = None
    hitl_state: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "decision": self.decision,
            "ok": self.ok,
            "data": self.data,
            "reasons": self.reasons,
            "roe_ref": self.roe_ref,
            "payload_hash": self.payload_hash,
            "error": self.error,
            "hitl_ticket_id": self.hitl_ticket_id,
            "hitl_state": self.hitl_state,
        }


class ConsolidatedGateway:
    """
    Punto de entrada único a las capacidades OSINT/DFIR bajo gobernanza GELSI.

    Uso:
        gw = ConsolidatedGateway()
        res = gw.dispatch("recon.passive_scan",
                          {"target": "target.com", "roe_token": "roe-1"})
        if res.decision == "REQUIRE_HITL": ...   # esperar aprobación humana
        if res.ok: ...                            # resultado disponible en res.data
    """

    def __init__(
        self,
        gelsi: Optional[GelsiMiddleware] = None,
        chain_of_custody: Optional[ChainOfCustody] = None,
    ) -> None:
        self._gelsi = gelsi
        self._coc = chain_of_custody
        self._handlers: Dict[str, Callable[[Dict[str, Any]], Any]] = {}
        self._action_map: Dict[str, str] = {}
        self._register_builtin_handlers()

    # ── Registro de handlers por dominio.tool ─────────────────────────────────
    def register(self, tool: str, action_type: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        """Registra un handler para `dominio.tool` con su categoría de acción GELSI."""
        self._handlers[tool] = handler
        self._action_map[tool] = action_type

    def tools(self) -> list:
        return sorted(self._handlers.keys())

    # ── Dispatch central con gobernanza ───────────────────────────────────────
    def dispatch(self, tool: str, arguments: Dict[str, Any]) -> GatewayResult:
        """
        Enruta una herramienta consolidada. Flujo:
          1. Resolver handler + categoría de acción.
          2. GELSI.evaluate() → ALLOW/DENY/REQUIRE_HITL (sellado en custodia).
          3. Solo si ALLOW: chequear idempotencia y ejecutar el handler (adaptador).
          4. Sellar el resultado en la cadena de custodia.
        """
        if tool not in self._handlers:
            return GatewayResult(tool=tool, decision="DENY", error=f"herramienta desconocida: {tool}")

        arguments = arguments or {}
        # Flag de re-ejecución HITL: viaja a GELSI (metadata) pero NUNCA al handler.
        hitl_bypass = bool(arguments.pop("__hitl_bypass", False))
        action_type = self._action_map.get(tool, ACTION_PASSIVE)
        target = arguments.get("target") or arguments.get("subject") or arguments.get("value")
        roe_token = arguments.get("roe_token")
        intent = str(arguments.get("intent", "")) + " " + tool
        involves_pii = bool(arguments.get("involves_pii", False))

        # ── L0 GELSI: decisión determinista ANTES de ejecutar ─────────────────
        verdict: GelsiVerdict = self._get_gelsi().evaluate(
            ActionRequest(
                action_type=action_type,
                tool=tool,
                target=target,
                roe_token=roe_token,
                intent=intent,
                involves_pii=involves_pii,
                collector_id=arguments.get("collector_id", "mcp-client"),
                metadata={"domain": tool.split(".")[0], "__hitl_bypass": hitl_bypass},
            ),
            seal=True,
        )

        if verdict.decision != Decision.ALLOW:
            # REQUIRE_HITL: levantar ticket pendiente (doble puerta) y NO ejecutar.
            # La decisión queda sellada en la cadena; el operador resuelve vía
            # approve_hitl()/deny_hitl(); solo un ticket APPROVED re-ejecuta.
            hitl_ticket_id = None
            if verdict.decision == Decision.REQUIRE_HITL:
                try:
                    from amegakurewotan.policy.hitl import get_hitl

                    ticket = get_hitl().create_ticket(
                        tool=tool,
                        action_type=action_type,
                        target=target,
                        roe_ref=verdict.roe_ref,
                        request_args=arguments,
                        reasons=verdict.reasons,
                    )
                    hitl_ticket_id = ticket.ticket_id
                except Exception as exc:  # noqa: BLE001
                    logger.error("No se pudo crear ticket HITL para '%s': %s", tool, exc)

            return GatewayResult(
                tool=tool,
                decision=verdict.decision.value,
                ok=False,
                reasons=verdict.reasons,
                roe_ref=verdict.roe_ref,
                hitl_ticket_id=hitl_ticket_id,
                hitl_state="PENDING" if hitl_ticket_id else None,
            )

        # ── Idempotencia (§10.2) ──────────────────────────────────────────────
        operation_id = arguments.get("operation_id")
        if operation_id and self._already_completed(operation_id):
            logger.info("Operación idempotente '%s' ya completada; se omite re-ejecución.", operation_id)
            return GatewayResult(
                tool=tool, decision="ALLOW", ok=True,
                data={"idempotent_skip": True, "operation_id": operation_id},
                roe_ref=verdict.roe_ref,
            )

        # ── Ejecución del adaptador (handler de negocio) ──────────────────────
        try:
            data = self._handlers[tool](arguments)
        except Exception as exc:  # noqa: BLE001 — se sella el fallo y se reporta.
            logger.error("Handler '%s' falló: %s", tool, exc, exc_info=True)
            self._seal_result(tool, verdict.roe_ref, {"error": str(exc)}, event="op.failed",
                              operation_id=operation_id)
            return GatewayResult(tool=tool, decision="ALLOW", ok=False, error=str(exc),
                                 roe_ref=verdict.roe_ref)

        payload_hash = self._seal_result(tool, verdict.roe_ref, data, event="op.completed",
                                         operation_id=operation_id)
        return GatewayResult(
            tool=tool, decision="ALLOW", ok=True, data=data,
            roe_ref=verdict.roe_ref, payload_hash=payload_hash,
        )

    # ── Sellado / idempotencia ────────────────────────────────────────────────
    def _seal_result(self, tool: str, roe_ref: Optional[str], data: Any,
                     event: str, operation_id: Optional[str]) -> str:
        try:
            serialized = canonical_json(data) if isinstance(data, (dict, list)) else str(data)
            payload_hash = sha512_bytes(serialized.encode("utf-8"))
            self._get_coc().append(
                collector_id=f"mcp:{tool}",
                event_type=event,
                payload_hash=payload_hash,
                roe_ref=roe_ref,
                metadata={"tool": tool, "operation_id": operation_id},
            )
            return payload_hash
        except Exception as exc:  # noqa: BLE001
            logger.error("No se pudo sellar el resultado de '%s': %s", tool, exc)
            return ""

    def _already_completed(self, operation_id: str) -> bool:
        for rec in self._get_coc().read_all():
            if rec.get("event_type") == "op.completed" and \
               rec.get("metadata", {}).get("operation_id") == operation_id:
                return True
        return False

    # ── Perezosos ─────────────────────────────────────────────────────────────
    def _get_gelsi(self) -> GelsiMiddleware:
        if self._gelsi is None:
            self._gelsi = get_gelsi()
        return self._gelsi

    def _get_coc(self) -> ChainOfCustody:
        if self._coc is None:
            self._coc = ChainOfCustody()
        return self._coc

    # ── Handlers builtin (adaptadores a los motores existentes) ───────────────
    def _register_builtin_handlers(self) -> None:
        # recon.* — sobre HeimdallAgent / SearXNG existentes.
        self.register("recon.passive_scan", ACTION_PASSIVE, self._h_recon_passive)
        self.register("recon.active_surface", ACTION_ACTIVE, self._h_recon_active)
        self.register("recon.deep_osint", ACTION_PASSIVE, self._h_recon_deep)
        # recon L3 — adapters honestos sobre motores externos (WOTAN-F4).
        self.register("recon.greynoise", ACTION_PASSIVE, self._h_recon_greynoise)
        self.register("recon.theharvester", ACTION_PASSIVE, self._h_recon_theharvester)
        # graph.* — consulta read-only.
        self.register("graph.query", ACTION_PASSIVE, self._h_graph_query)
        # darkweb.* — HelAgent bajo Tor + HITL.
        self.register("darkweb.profile", ACTION_DARKWEB, self._h_darkweb_profile)
        # dfir.* — adaptadores en contenedores aislados (FASE 3).
        self.register("dfir.velociraptor_hunt", ACTION_DFIR, self._h_dfir_velociraptor)
        self.register("dfir.memory_analyze", ACTION_DFIR, self._h_dfir_memory)
        self.register("dfir.disk_timeline", ACTION_DFIR, self._h_dfir_disk)
        # forensic.* — cadena de custodia.
        self.register("forensic.verify", ACTION_PASSIVE, self._h_forensic_verify)
        # defense.* — social-eng defensiva.
        self.register("defense.phishing_detect", ACTION_PASSIVE, self._h_defense_phishing)

    # ── Adaptadores (thin; delegan en motores existentes / FASE 3) ────────────
    def _h_recon_passive(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from amegakurewotan.agents.heimdall import HeimdallAgent
        target = args["target"]
        return {"source": "heimdall", "target": target, "results": HeimdallAgent().execute(target)}

    def _h_recon_active(self, args: Dict[str, Any]) -> Dict[str, Any]:
        # Recon activo: mismo motor Heimdall, marcado como activo (Nuclei/portscan bajo RoE).
        from amegakurewotan.agents.heimdall import HeimdallAgent
        target = args["target"]
        res = HeimdallAgent().execute(target)
        return {"source": "heimdall", "mode": "active_surface", "target": target, "results": res}

    def _h_recon_deep(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from amegakurewotan.agents.heimdall import HeimdallAgent
        target = args["target"]
        return {"source": "heimdall", "mode": "deep_osint", "target": target,
                "results": HeimdallAgent().execute(target)}

    def _h_recon_greynoise(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from amegakurewotan.adapters.l3.greynoise import greynoise_ip_report
        ip = args.get("target") or args.get("ip") or args.get("subject")
        if not ip:
            return {"status": "error", "reason": "recon.greynoise requiere 'target'/'ip'"}
        return greynoise_ip_report(ip)

    def _h_recon_theharvester(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from amegakurewotan.adapters.l3.theharvester import theharvester_run
        domain = args.get("target") or args.get("domain")
        if not domain:
            return {"status": "error", "reason": "recon.theharvester requiere 'target'/'domain'"}
        return theharvester_run(domain, sources=args.get("sources"), limit=int(args.get("limit", 100)))

    def _h_graph_query(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from amegakurewotan.graph.export import export_to_json
        return {"graph": export_to_json()}

    def _h_darkweb_profile(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from amegakurewotan.agents.hel import HelAgent
        return {"source": "hel", "results": HelAgent().execute(args["query"])}

    def _h_dfir_velociraptor(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from amegakurewotan.dfir.velociraptor import velociraptor_hunt
        return velociraptor_hunt(args["target"], **args.get("params", {}))

    def _h_dfir_memory(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from amegakurewotan.dfir.volatility import memory_analyze
        return memory_analyze(args["target"], **args.get("params", {}))

    def _h_dfir_disk(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from amegakurewotan.dfir.sleuthkit import disk_timeline
        return disk_timeline(args["target"], **args.get("params", {}))

    def _h_forensic_verify(self, args: Dict[str, Any]) -> Dict[str, Any]:
        return self._get_coc().verify_chain().to_dict()

    def _h_defense_phishing(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from amegakurewotan.defense.phishing import phishing_detect
        return phishing_detect(args.get("subject", ""), **args.get("params", {}))

    # ── Resolución HITL (doble puerta) ────────────────────────────────────────
    def approve_hitl(self, ticket_id: str, by: str = "operator", reason: Optional[str] = None) -> GatewayResult:
        """
        Resuelve un ticket HITL APPROVED y re-ejecuta la acción SOLO a través
        del gateway (GELSI se re-evalúa sin la puerta HITL, pero se mantienen
        el veto DENY por social-eng ofensiva y la validación de scope/RoE).
        """
        from amegakurewotan.policy.hitl import get_hitl

        ticket = get_hitl().approve(ticket_id, by=by, reason=reason)
        args = dict(ticket.request_args)
        args.pop("__hitl_bypass", None)
        # Re-evaluación GELSI con bypass de la puerta HITL (la RoE sigue obligatoria).
        args["__hitl_bypass"] = True
        res = self.dispatch(ticket.tool, args)
        res.hitl_ticket_id = ticket_id
        res.hitl_state = "APPROVED"
        return res

    def deny_hitl(self, ticket_id: str, by: str = "operator", reason: Optional[str] = None) -> "GatewayResult":
        """Resuelve un ticket HITL DENIED (no ejecuta nada; se sella en la cadena)."""
        from amegakurewotan.policy.hitl import get_hitl

        ticket = get_hitl().deny(ticket_id, by=by, reason=reason)
        return GatewayResult(
            tool=ticket.tool, decision="DENY", ok=False,
            reasons=["HITL denegado por operador: " + (reason or "sin motivo")],
            roe_ref=ticket.roe_ref, hitl_ticket_id=ticket_id, hitl_state="DENIED",
        )


# Singleton perezoso.
_gateway: Optional[ConsolidatedGateway] = None


def get_gateway() -> ConsolidatedGateway:
    global _gateway
    if _gateway is None:
        _gateway = ConsolidatedGateway()
    return _gateway


def reset_gateway() -> None:
    global _gateway
    _gateway = None
