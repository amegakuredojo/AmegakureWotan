# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: karasugakure.policy.hitl
Contexto: CIVIL — Consolidación AmegakureWotan (capa L0, puerta humana)

Propósito:
    Subsistema Human-In-The-Loop (HITL) para la "doble puerta" de GELSI.
    Cuando GELSI emite REQUIRE_HITL (acciones dfir/darkweb/evasive o PII sin
    minimizar), la ejecución NO se realiza. Se levanta un ticket en una cola
    append-only y sellado en la cadena de custodia como evento 'hitl.pending'.
    Un operador humano (vía CLI 'amewotan hitl approve/deny' o el MCP
    'hitl_approve') resuelve el ticket; la resolución se sella como
    'hitl.approval'/'hitl.denial'. Solo un ticket APPROVED puede ser
    re-ejecutado — y solo a través del gateway gobernado, que preserva el
    veto DENY (social-eng ofensiva) y la validación de scope.

    La persistencia es un log append-only (fsync) en
    <base_dir>/opsec/roe/hitl_queue.jsonl, coherente con el estándar de
    ledgers del Dojo (AmegakureWotan.md §5, forensics.ChainOfCustody).

Determinismo: la resolución HITL es una decisión humana externa; el módulo
solo garantiza que (1) no se ejecuta sin ticket, (2) el ticket es inmutable
una vez resuelto, y (3) toda transición queda sellada.
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "lugh — AmegakureDōjō"
__forge_context__ = "CIVIL"

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("karasugakure.policy.hitl")


class HitlState(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"


@dataclass
class HitlTicket:
    """Ticket de aprobación humana para una acción en REQUIRE_HITL."""

    ticket_id: str
    tool: str
    action_type: str
    target: Optional[str]
    roe_ref: Optional[str]
    request_args: Dict[str, Any]
    reasons: List[str]
    state: HitlState = HitlState.PENDING
    created_ts_utc: str = ""
    resolved_ts_utc: Optional[str] = None
    resolved_by: Optional[str] = None
    resolution_reason: Optional[str] = None
    custody_record: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "tool": self.tool,
            "action_type": self.action_type,
            "target": self.target,
            "roe_ref": self.roe_ref,
            "request_args": self.request_args,
            "reasons": self.reasons,
            "state": self.state.value,
            "created_ts_utc": self.created_ts_utc,
            "resolved_ts_utc": self.resolved_ts_utc,
            "resolved_by": self.resolved_by,
            "resolution_reason": self.resolution_reason,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "HitlTicket":
        return cls(
            ticket_id=d["ticket_id"],
            tool=d["tool"],
            action_type=d["action_type"],
            target=d.get("target"),
            roe_ref=d.get("roe_ref"),
            request_args=d.get("request_args", {}),
            reasons=d.get("reasons", []),
            state=HitlState(d.get("state", "PENDING")),
            created_ts_utc=d.get("created_ts_utc", ""),
            resolved_ts_utc=d.get("resolved_ts_utc"),
            resolved_by=d.get("resolved_by"),
            resolution_reason=d.get("resolution_reason"),
        )


class HitlError(Exception):
    """Error de estado/consistencia del subsistema HITL."""


class HitlManager:
    """
    Gestor de la cola HITL append-only.

    Diseño: cada ticket es una línea JSON en hitl_queue.jsonl. Un ticket
    PENDING puede pasar a APPROVED o DENIED exactamente una vez; la transición
    se persiste como línea nueva (no se sobreescribe) para mantener el ledger
    inmutable y auditable. El estado "vivo" se deriva de la última línea del
    ticket_id (idempotente y resistente a relectura).
    """

    def __init__(self, queue_path: Optional[str | Path] = None) -> None:
        if queue_path is None:
            from karasugakure.config import get_config

            config = get_config()
            queue_path = config.base_dir / "opsec" / "roe" / "hitl_queue.jsonl"
        self.queue_path: Path = Path(queue_path)
        self.queue_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Persistencia append-only ─────────────────────────────────────────────
    def _append(self, record: Dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        try:
            with open(self.queue_path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise HitlError(f"No se pudo persistir ticket HITL: {exc}") from exc

    def _read_all(self) -> List[Dict[str, Any]]:
        if not self.queue_path.exists():
            return []
        out: List[Dict[str, Any]] = []
        try:
            with open(self.queue_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError as exc:
            raise HitlError(f"No se pudo leer la cola HITL: {exc}") from exc
        return out

    # ── Sellado de transición en cadena de custodia ──────────────────────────
    def _seal(self, event_type: str, ticket: HitlTicket) -> Optional[Dict[str, Any]]:
        try:
            from karasugakure.evidence.forensics import (
                ChainOfCustody,
                canonical_json,
                sha512_bytes,
            )

            body = {
                "ticket_id": ticket.ticket_id,
                "tool": ticket.tool,
                "action_type": ticket.action_type,
                "target": ticket.target,
                "roe_ref": ticket.roe_ref,
                "state": ticket.state.value,
                "resolved_by": ticket.resolved_by,
                "resolution_reason": ticket.resolution_reason,
            }
            payload_hash = sha512_bytes(canonical_json(body).encode("utf-8"))
            return ChainOfCustody().append(
                collector_id=f"hitl:{ticket.resolved_by or 'system'}",
                event_type=event_type,
                payload_hash=payload_hash,
                roe_ref=ticket.roe_ref,
                metadata=body,
            )
        except Exception as exc:  # noqa: BLE001 — el sellado no debe tumbar el estado.
            logger.error("No se pudo sellar el evento HITL '%s': %s", event_type, exc)
            return None

    # ── API pública ──────────────────────────────────────────────────────────
    def create_ticket(
        self,
        tool: str,
        action_type: str,
        target: Optional[str],
        roe_ref: Optional[str],
        request_args: Dict[str, Any],
        reasons: List[str],
    ) -> HitlTicket:
        """Levanta un ticket PENDING y lo sella como 'hitl.pending'."""
        ticket = HitlTicket(
            ticket_id=f"hitl-{uuid.uuid4().hex[:12]}",
            tool=tool,
            action_type=action_type,
            target=target,
            roe_ref=roe_ref,
            request_args=request_args,
            reasons=reasons,
            state=HitlState.PENDING,
            created_ts_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )
        self._append(ticket.to_dict())
        cust = self._seal("hitl.pending", ticket)
        ticket.custody_record = cust
        logger.info("HITL ticket creado: %s | tool=%s action=%s", ticket.ticket_id, tool, action_type)
        return ticket

    def _latest_state(self, ticket_id: str) -> Optional[HitlState]:
        state = None
        for rec in self._read_all():
            if rec.get("ticket_id") == ticket_id:
                state = HitlState(rec.get("state", "PENDING"))
        return state

    def get(self, ticket_id: str) -> Optional[HitlTicket]:
        found: Optional[Dict[str, Any]] = None
        for rec in self._read_all():
            if rec.get("ticket_id") == ticket_id:
                found = rec
        if found is None:
            return None
        return HitlTicket.from_dict(found)

    def list_pending(self) -> List[HitlTicket]:
        pending_ids = {
            rec["ticket_id"]
            for rec in self._read_all()
            if rec.get("state") == HitlState.PENDING.value
        }
        tickets: List[HitlTicket] = []
        for tid in sorted(pending_ids):
            t = self.get(tid)
            if t is not None:
                tickets.append(t)
        return tickets

    def approve(self, ticket_id: str, by: str = "operator", reason: Optional[str] = None) -> HitlTicket:
        """Resuelve un ticket PENDING como APPROVED (idempotente: no permite re-resolver)."""
        cur = self._latest_state(ticket_id)
        if cur is None:
            raise HitlError(f"ticket HITL '{ticket_id}' no existe")
        if cur != HitlState.PENDING:
            raise HitlError(f"ticket HITL '{ticket_id}' ya resuelto (estado={cur.value})")
        ticket = self.get(ticket_id)
        if ticket is None:
            raise HitlError(f"ticket HITL '{ticket_id}' inconsistente")
        ticket.state = HitlState.APPROVED
        ticket.resolved_ts_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ticket.resolved_by = by
        ticket.resolution_reason = reason
        self._append(ticket.to_dict())
        ticket.custody_record = self._seal("hitl.approval", ticket)
        logger.info("HITL ticket APPROVED: %s por %s", ticket_id, by)
        return ticket

    def deny(self, ticket_id: str, by: str = "operator", reason: Optional[str] = None) -> HitlTicket:
        """Resuelve un ticket PENDING como DENIED (idempotente)."""
        cur = self._latest_state(ticket_id)
        if cur is None:
            raise HitlError(f"ticket HITL '{ticket_id}' no existe")
        if cur != HitlState.PENDING:
            raise HitlError(f"ticket HITL '{ticket_id}' ya resuelto (estado={cur.value})")
        ticket = self.get(ticket_id)
        if ticket is None:
            raise HitlError(f"ticket HITL '{ticket_id}' inconsistente")
        ticket.state = HitlState.DENIED
        ticket.resolved_ts_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        ticket.resolved_by = by
        ticket.resolution_reason = reason
        self._append(ticket.to_dict())
        ticket.custody_record = self._seal("hitl.denial", ticket)
        logger.info("HITL ticket DENIED: %s por %s", ticket_id, by)
        return ticket


# Singleton perezoso (coherente con get_gelsi/get_gateway).
_hitl: Optional[HitlManager] = None


def get_hitl() -> HitlManager:
    global _hitl
    if _hitl is None:
        _hitl = HitlManager()
    return _hitl


def reset_hitl() -> None:
    """Resetea el singleton (tests)."""
    global _hitl
    _hitl = None
