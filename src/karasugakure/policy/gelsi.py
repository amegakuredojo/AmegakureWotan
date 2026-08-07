# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: karasugakure.policy.gelsi
Contexto: CIVIL — Consolidación AmegakureWotan (capa L0)

Propósito:
    GELSI (Governance, Ethics, Legal, Security, Intelligence) — middleware
    OBLIGATORIO entre Hermes/agentes y cualquier herramienta o tarea OSINT/DFIR.
    Es la capa L0 de la arquitectura AmegakureWotan (§4.1).

    Evalúa cada solicitud de acción y emite una decisión determinista:
        ALLOW | DENY | REQUIRE_HITL
    encadenándola en la cadena de custodia (timeline.jsonl) con referencia a
    roe_ref y justificación auditable (§4.1 L0, §7.2).

Reglas deny-by-default (§7.2):
    - Ingeniería social OFENSIVA: DENY absoluto e inapelable (no gateable por RoE).
    - Acción activa/evasiva/darkweb/dfir sin RoE que la autorice: DENY.
    - Target fuera de scope de la RoE: DENY.
    - Acción activa autorizada pero de alto impacto: REQUIRE_HITL.
    - Operación darkweb / dfir intrusiva: REQUIRE_HITL (doble puerta).
    - PII bajo GDPR sin política de minimización: REQUIRE_HITL.

Determinismo: la decisión es función de reglas estáticas + estado de RoE,
NUNCA del LLM (AmegakureWotan.md §9.1).
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "lugh — AmegakureDōjō"
__forge_context__ = "CIVIL"

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from karasugakure.policy.roe import (
    ACTION_ACTIVE,
    ACTION_DARKWEB,
    ACTION_DFIR,
    ACTION_EVASIVE,
    ACTION_PASSIVE,
    RulesOfEngagement,
    ScopeRegistry,
    get_scope_registry,
)

logger = logging.getLogger("karasugakure.policy.gelsi")


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_HITL = "REQUIRE_HITL"


# Acciones que exigen RoE que las autorice explícitamente (no-pasivas).
_ACTIONS_REQUIRING_ROE = frozenset(
    {ACTION_ACTIVE, ACTION_EVASIVE, ACTION_DARKWEB, ACTION_DFIR}
)

# Acciones que, aun autorizadas, cruzan una puerta humana (HITL) por su impacto.
_ACTIONS_REQUIRING_HITL = frozenset({ACTION_EVASIVE, ACTION_DARKWEB, ACTION_DFIR})

# Marcadores de ingeniería social OFENSIVA — DENY inapelable a nivel de plataforma
# (AmegakureWotan.md §1: "elimina explícitamente cualquier capacidad de ingeniería
# social ofensiva: ni pretextos, ni plantillas de phishing, ni contenido persuasivo").
_OFFENSIVE_SOCIAL_PATTERNS = [
    re.compile(r"\bphish(ing|er)?\b", re.IGNORECASE),
    re.compile(r"\bpretext(ing|o)?\b", re.IGNORECASE),
    re.compile(r"\bspear[\s-]?phish", re.IGNORECASE),
    re.compile(r"\bvish(ing)?\b", re.IGNORECASE),
    re.compile(r"\bsmish(ing)?\b", re.IGNORECASE),
    re.compile(r"\b(craft|generate|write|compose)\b.{0,40}\b(lure|bait|persuasi|deceptiv)", re.IGNORECASE),
    re.compile(r"\bimpersonat(e|ion)\b.{0,40}\b(email|message|victim|target)", re.IGNORECASE),
    re.compile(r"\bsocial[\s-]?engineer(ing)?\b.{0,40}\b(attack|campaign|payload|lure)", re.IGNORECASE),
]

# El modo defensivo de ingeniería social SÍ está permitido (detección).
_DEFENSIVE_SOCIAL_HINTS = [
    re.compile(r"\bdetect\b", re.IGNORECASE),
    re.compile(r"\bdefens", re.IGNORECASE),
    re.compile(r"\bawareness\b", re.IGNORECASE),
    re.compile(r"\bcorrelat", re.IGNORECASE),
]


@dataclass
class ActionRequest:
    """
    Solicitud de acción a evaluar por GELSI.

    Args:
        action_type:  Categoría (passive/active/evasive/darkweb/dfir).
        tool:         Herramienta/tarea invocada (p. ej. "recon.passive_scan").
        target:       Objetivo de la acción (dominio, IP, usuario…). Puede ser None.
        roe_token:    ID de la RoE citada. Puede ser None (=> deny en no-pasivas).
        intent:       Texto libre del propósito (se escanea por social-eng ofensiva).
        involves_pii: True si la acción procesa PII de personas físicas.
        collector_id: Agente que solicita (para la cadena de custodia).
        metadata:     Contexto adicional.
    """

    action_type: str
    tool: str
    target: Optional[str] = None
    roe_token: Optional[str] = None
    intent: str = ""
    involves_pii: bool = False
    collector_id: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GelsiVerdict:
    """Veredicto GELSI. `custody_record` se rellena tras encadenar en timeline."""

    decision: Decision
    reasons: List[str] = field(default_factory=list)
    roe_ref: Optional[str] = None
    custody_record: Optional[Dict[str, Any]] = None

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reasons": self.reasons,
            "roe_ref": self.roe_ref,
        }


class GelsiMiddleware:
    """
    Motor de decisión GELSI. Determinista y auditable.

    Cada evaluación se sella en la cadena de custodia como evento
    'gelsi.decision', enlazando la decisión, sus razones y la roe_ref.
    """

    def __init__(
        self,
        scope_registry: Optional[ScopeRegistry] = None,
        chain_of_custody: Optional[Any] = None,
    ) -> None:
        self._scope = scope_registry
        self._coc = chain_of_custody  # ChainOfCustody; perezoso para no forzar I/O en import.

    # ── API pública ──────────────────────────────────────────────────────────
    def evaluate(self, request: ActionRequest, seal: bool = True) -> GelsiVerdict:
        """
        Evalúa una solicitud y devuelve el veredicto. Si `seal=True`, encadena
        la decisión en la cadena de custodia.
        """
        verdict = self._decide(request)
        if seal:
            self._seal(request, verdict)
        self._log(request, verdict)
        return verdict

    # ── Lógica determinista de decisión ──────────────────────────────────────
    def _decide(self, request: ActionRequest) -> GelsiVerdict:
        reasons: List[str] = []

        action = (request.action_type or "").strip().lower()

        # 0. Validación de categoría de acción.
        if action not in {ACTION_PASSIVE, ACTION_ACTIVE, ACTION_EVASIVE, ACTION_DARKWEB, ACTION_DFIR}:
            return GelsiVerdict(
                Decision.DENY,
                reasons=[f"categoría de acción desconocida: '{request.action_type}'"],
                roe_ref=request.roe_token,
            )

        # 1. Ingeniería social OFENSIVA: DENY inapelable (precede a toda RoE).
        if self._is_offensive_social(request.intent) or self._is_offensive_social(request.tool):
            return GelsiVerdict(
                Decision.DENY,
                reasons=[
                    "ingeniería social ofensiva prohibida a nivel de plataforma "
                    "(AmegakureWotan §1) — solo se permite social-eng defensiva"
                ],
                roe_ref=request.roe_token,
            )

        # 2. Acción pasiva: ruta de menor fricción.
        roe: Optional[RulesOfEngagement] = self._get_registry().get(request.roe_token)
        if action == ACTION_PASSIVE:
            # Si hay target y RoE, se valida scope; sin RoE se permite recon pasivo
            # solo cuando no hay target sensible (deny-by-default si target fuera de scope).
            if request.target and roe is not None:
                if not roe.is_target_in_scope(request.target):
                    return GelsiVerdict(
                        Decision.DENY,
                        reasons=[f"target '{request.target}' fuera de scope de RoE '{request.roe_token}'"],
                        roe_ref=request.roe_token,
                    )
            reasons.append("acción pasiva")
            return self._pii_gate(request, Decision.ALLOW, reasons)

        # 3. Acciones no-pasivas: exigen RoE vigente que las autorice.
        if action in _ACTIONS_REQUIRING_ROE:
            if roe is None:
                return GelsiVerdict(
                    Decision.DENY,
                    reasons=[f"acción '{action}' requiere RoE; token '{request.roe_token}' inexistente"],
                    roe_ref=request.roe_token,
                )
            if not roe.is_temporally_valid():
                return GelsiVerdict(
                    Decision.DENY,
                    reasons=[f"RoE '{roe.roe_id}' fuera de ventana temporal"],
                    roe_ref=roe.roe_id,
                )
            if request.target and not roe.is_target_in_scope(request.target):
                return GelsiVerdict(
                    Decision.DENY,
                    reasons=[f"target '{request.target}' fuera de scope de RoE '{roe.roe_id}'"],
                    roe_ref=roe.roe_id,
                )
            if not roe.allows_action(action):
                return GelsiVerdict(
                    Decision.DENY,
                    reasons=[f"RoE '{roe.roe_id}' no autoriza acción '{action}'"],
                    roe_ref=roe.roe_id,
                )

            reasons.append(f"acción '{action}' autorizada por RoE '{roe.roe_id}'")

            # 4. Puerta humana (HITL) para acciones de alto impacto.
            if action in _ACTIONS_REQUIRING_HITL:
                reasons.append(f"acción '{action}' exige aprobación HITL (doble puerta)")
                return GelsiVerdict(Decision.REQUIRE_HITL, reasons=reasons, roe_ref=roe.roe_id)

            # Acción activa autorizada => ALLOW, sujeto a gate de PII.
            return self._pii_gate(request, Decision.ALLOW, reasons, roe_ref=roe.roe_id)

        # Nunca debería alcanzarse.
        return GelsiVerdict(Decision.DENY, reasons=["ruta de decisión no cubierta"], roe_ref=request.roe_token)

    def _pii_gate(
        self,
        request: ActionRequest,
        base_decision: Decision,
        reasons: List[str],
        roe_ref: Optional[str] = None,
    ) -> GelsiVerdict:
        """Endurece la decisión a REQUIRE_HITL si hay PII sin política de minimización."""
        ref = roe_ref or request.roe_token
        if request.involves_pii:
            roe = self._get_registry().get(request.roe_token)
            pii_policy = roe.pii_policy if roe else "unknown"
            if pii_policy != "minimize":
                reasons.append(f"PII bajo GDPR con política '{pii_policy}' (≠ minimize) → HITL")
                return GelsiVerdict(Decision.REQUIRE_HITL, reasons=reasons, roe_ref=ref)
            reasons.append("PII procesada bajo política de minimización GDPR")
        return GelsiVerdict(base_decision, reasons=reasons, roe_ref=ref)

    # ── Detección social-eng ofensiva ────────────────────────────────────────
    @staticmethod
    def _is_offensive_social(text: str) -> bool:
        if not text:
            return False
        # Si el texto es claramente defensivo, no lo marcamos como ofensivo.
        is_defensive = any(p.search(text) for p in _DEFENSIVE_SOCIAL_HINTS)
        for pat in _OFFENSIVE_SOCIAL_PATTERNS:
            if pat.search(text):
                if is_defensive and pat.pattern.startswith(r"\bphish"):
                    # "detect phishing" / "phishing detection" = defensivo permitido.
                    continue
                return True
        return False

    # ── Sellado en cadena de custodia ────────────────────────────────────────
    def _seal(self, request: ActionRequest, verdict: GelsiVerdict) -> None:
        try:
            coc = self._get_coc()
            from karasugakure.evidence.forensics import canonical_json, sha512_bytes

            decision_body = {
                "action_type": request.action_type,
                "tool": request.tool,
                "target": request.target,
                "decision": verdict.decision.value,
                "reasons": verdict.reasons,
            }
            payload_hash = sha512_bytes(canonical_json(decision_body).encode("utf-8"))
            record = coc.append(
                collector_id=f"gelsi:{request.collector_id}",
                event_type="gelsi.decision",
                payload_hash=payload_hash,
                roe_ref=verdict.roe_ref,
                metadata=decision_body,
            )
            verdict.custody_record = record
        except Exception as exc:  # noqa: BLE001 — el sellado no debe tumbar la decisión.
            logger.error("No se pudo sellar la decisión GELSI en la cadena de custodia: %s", exc)

    # ── Perezosos ────────────────────────────────────────────────────────────
    def _get_registry(self) -> ScopeRegistry:
        if self._scope is None:
            self._scope = get_scope_registry()
        return self._scope

    def _get_coc(self) -> Any:
        if self._coc is None:
            from karasugakure.evidence.forensics import ChainOfCustody

            self._coc = ChainOfCustody()
        return self._coc

    @staticmethod
    def _log(request: ActionRequest, verdict: GelsiVerdict) -> None:
        level = logging.INFO if verdict.decision == Decision.ALLOW else logging.WARNING
        logger.log(
            level,
            "GELSI %s | tool=%s action=%s target=%s roe=%s | %s",
            verdict.decision.value,
            request.tool,
            request.action_type,
            request.target,
            verdict.roe_ref,
            "; ".join(verdict.reasons),
        )


# Singleton perezoso.
_gelsi: Optional[GelsiMiddleware] = None


def get_gelsi() -> GelsiMiddleware:
    global _gelsi
    if _gelsi is None:
        _gelsi = GelsiMiddleware()
    return _gelsi


def reset_gelsi() -> None:
    """Resetea el singleton (tests)."""
    global _gelsi
    _gelsi = None
