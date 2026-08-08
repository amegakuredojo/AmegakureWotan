# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.runtime.mission
Contexto: CIVIL — Consolidación AmegakureWotan (capa L1, orquestación de misión)

Propósito:
    Orquestador de MISIÓN end-to-end (WOTAN-F7). Ejecuta un plan OSINT/DFIR
    completo (recon → defensa → superficie activa → grafo → verificación)
    recorriendo EXCLUSIVAMENTE el gateway consolidado gobernado (mcp.gateway).
    Cada paso pasa por la capa L0 GELSI (ALLOW/DENY/REQUIRE_HITL) y queda
    sellado en la cadena de custodia (timeline.jsonl). Al finalizar:

      1. Genera un dossier forense (JSON máquina + Markdown operador).
      2. Sella el dossier en la cadena (evento 'mission.completed').
      3. Firma Ed25519 el estado completo de la cadena (custody_signer).
      4. Verifica el sobre de firma (tamper-evidence).

    Doctrina (deny-by-default, evidencia sobre intuición):
      - La misión NUNCA fuerza una acción: un paso en REQUIRE_HITL se registra
        como ticket PENDIENTE (doble puerta) y NO se ejecuta hasta aprobación
        humana. Un paso DENY se registra con su motivo.
      - La misión NUNCA fabrica salida: cada paso persiste EXACTAMENTE lo que el
        handler real devolvió (incluido 'tool_unavailable' si falta el runtime).
      - Reproducibilidad: mismo plan + misma RoE ⇒ misma secuencia determinista
        de decisiones GELSI (la política es función de reglas + estado de RoE).

Arquitectura (AmegakureWotan.md §4.1 L1, §10):
    MissionOrchestrator.run(plan) → itera PlanStep → gateway.dispatch → sella
    → dossier → firma Ed25519 → verifica. Sin bypass de gobernanza.
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "lugh — AmegakureDōjō"
__forge_context__ = "CIVIL"

import copy
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("amegakurewotan.runtime.mission")

MISSION_SCHEMA_VERSION = "wotan-mission-1.0"

# Marcador de sustitución del objetivo de la misión dentro de los argumentos del plan.
_TARGET_TOKEN = "$TARGET"


# ──────────────────────────────────────────────────────────────────────────────
# Definición de planes de misión (playbooks versionados — AmegakureWotan.md §9.1)
# ──────────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class PlanStep:
    """Un paso de un plan de misión: herramienta consolidada + argumentos base."""

    tool: str
    args: Dict[str, Any] = field(default_factory=dict)
    label: str = ""


# Plan OSINT estándar: pasiva + defensa anti-phishing + superficie activa (gateada
# por RoE) + consulta de grafo + verificación forense. Todos gobernados por GELSI.
PLAN_OSINT_RECON: List[PlanStep] = [
    PlanStep("recon.passive_scan", {"target": _TARGET_TOKEN},
             label="Reconocimiento pasivo de superficie"),
    PlanStep("defense.phishing_detect",
             {"subject": _TARGET_TOKEN, "params": {"protected_brands": [_TARGET_TOKEN]}},
             label="Detección defensiva de phishing / typosquatting"),
    PlanStep("recon.active_surface", {"target": _TARGET_TOKEN},
             label="Superficie activa (gateada por RoE)"),
    PlanStep("graph.query", {},
             label="Consulta del grafo de conocimiento"),
    PlanStep("forensic.verify", {},
             label="Verificación de integridad de la cadena de custodia"),
]

# Plan de triage DFIR: recon pasivo + análisis de memoria + timeline de disco.
# Los pasos DFIR exigen doble puerta HITL (quedan pendientes salvo aprobación).
PLAN_DFIR_TRIAGE: List[PlanStep] = [
    PlanStep("recon.passive_scan", {"target": _TARGET_TOKEN},
             label="Contexto pasivo del host"),
    PlanStep("dfir.memory_analyze", {"target": _TARGET_TOKEN, "params": {}},
             label="Análisis de memoria (Volatility 3) — requiere HITL"),
    PlanStep("dfir.disk_timeline", {"target": _TARGET_TOKEN, "params": {}},
             label="Timeline de disco (Sleuth Kit) — requiere HITL"),
    PlanStep("forensic.verify", {},
             label="Verificación de integridad de la cadena de custodia"),
]

# Plan completo: OSINT + darkweb + DFIR. Ejercita las tres puertas de decisión.
PLAN_FULL: List[PlanStep] = [
    PlanStep("recon.passive_scan", {"target": _TARGET_TOKEN},
             label="Reconocimiento pasivo de superficie"),
    PlanStep("defense.phishing_detect",
             {"subject": _TARGET_TOKEN, "params": {"protected_brands": [_TARGET_TOKEN]}},
             label="Detección defensiva de phishing / typosquatting"),
    PlanStep("recon.active_surface", {"target": _TARGET_TOKEN},
             label="Superficie activa (gateada por RoE)"),
    PlanStep("darkweb.profile", {"query": _TARGET_TOKEN, "target": _TARGET_TOKEN},
             label="Perfilado darkweb (Tor) — requiere HITL"),
    PlanStep("dfir.memory_analyze", {"target": _TARGET_TOKEN, "params": {}},
             label="Análisis de memoria (Volatility 3) — requiere HITL"),
    PlanStep("graph.query", {},
             label="Consulta del grafo de conocimiento"),
    PlanStep("forensic.verify", {},
             label="Verificación de integridad de la cadena de custodia"),
]

PLANS: Dict[str, List[PlanStep]] = {
    "osint_recon": PLAN_OSINT_RECON,
    "dfir_triage": PLAN_DFIR_TRIAGE,
    "full": PLAN_FULL,
}


class MissionError(Exception):
    """Error irrecuperable en la orquestación de una misión."""


# ──────────────────────────────────────────────────────────────────────────────
# Resultados
# ──────────────────────────────────────────────────────────────────────────────
@dataclass
class StepResult:
    """Resultado gobernado de un paso de misión (fiel al veredicto GELSI)."""

    index: int
    tool: str
    label: str
    decision: str
    ok: bool = False
    roe_ref: Optional[str] = None
    payload_hash: Optional[str] = None
    hitl_ticket_id: Optional[str] = None
    hitl_state: Optional[str] = None
    error: Optional[str] = None
    summary: Dict[str, Any] = field(default_factory=dict)
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "tool": self.tool,
            "label": self.label,
            "decision": self.decision,
            "ok": self.ok,
            "roe_ref": self.roe_ref,
            "payload_hash": self.payload_hash,
            "hitl_ticket_id": self.hitl_ticket_id,
            "hitl_state": self.hitl_state,
            "error": self.error,
            "summary": self.summary,
            "reasons": self.reasons,
        }


@dataclass
class MissionResult:
    """Resultado consolidado de una misión end-to-end."""

    mission_id: str
    plan: str
    target: str
    roe_ref: Optional[str]
    operator: str
    started_ts_utc: str
    finished_ts_utc: str
    steps: List[StepResult] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    dossier_json_path: Optional[str] = None
    dossier_md_path: Optional[str] = None
    chain_records: int = 0
    chain_verified: bool = False
    signature: Optional[Dict[str, Any]] = None
    signature_valid: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": MISSION_SCHEMA_VERSION,
            "mission_id": self.mission_id,
            "plan": self.plan,
            "target": self.target,
            "roe_ref": self.roe_ref,
            "operator": self.operator,
            "started_ts_utc": self.started_ts_utc,
            "finished_ts_utc": self.finished_ts_utc,
            "counts": self.counts,
            "steps": [s.to_dict() for s in self.steps],
            "chain": {
                "records": self.chain_records,
                "verified": self.chain_verified,
            },
            "signature": self.signature,
            "signature_valid": self.signature_valid,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Orquestador
# ──────────────────────────────────────────────────────────────────────────────
class MissionOrchestrator:
    """
    Orquesta una misión OSINT/DFIR end-to-end bajo gobernanza total.

    Uso:
        orch = MissionOrchestrator()
        result = orch.run(target="target.com", roe_token="roe-1", plan="osint_recon")

    Los componentes (gateway, cadena de custodia) se inyectan para aislamiento en
    tests; en producción se resuelven a los singletons gobernados por defecto.
    """

    def __init__(
        self,
        gateway: Optional[Any] = None,
        chain_of_custody: Optional[Any] = None,
        reports_dir: Optional[str | Path] = None,
    ) -> None:
        self._gw = gateway
        self._coc = chain_of_custody
        self._reports_dir = Path(reports_dir) if reports_dir else None

    # ── Resolución perezosa ───────────────────────────────────────────────────
    def _gateway(self) -> Any:
        if self._gw is None:
            from amegakurewotan.mcp.gateway import get_gateway

            self._gw = get_gateway()
        return self._gw

    def _coc_ref(self) -> Any:
        if self._coc is None:
            from amegakurewotan.evidence.forensics import ChainOfCustody

            self._coc = ChainOfCustody()
        return self._coc

    def _reports_path(self) -> Path:
        if self._reports_dir is None:
            from amegakurewotan.config import get_config

            self._reports_dir = get_config().base_dir / "reports"
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        return self._reports_dir

    # ── Ejecución de la misión ────────────────────────────────────────────────
    def run(
        self,
        target: str,
        roe_token: Optional[str] = None,
        plan: str = "osint_recon",
        operator: str = "operator",
        sign: bool = True,
    ) -> MissionResult:
        """
        Ejecuta la misión completa. Devuelve MissionResult y persiste el dossier.

        Args:
            target:    Objetivo de la misión (dominio/host/IP).
            roe_token: RoE que autoriza la misión (obligatoria para acción no-pasiva).
            plan:      Nombre del plan ('osint_recon' | 'dfir_triage' | 'full').
            operator:  Identificador del operador (para custodia).
            sign:      Firmar Ed25519 la cadena al finalizar (True en producción).
        """
        if not target or not target.strip():
            raise MissionError("La misión requiere un 'target'.")
        steps_def = PLANS.get(plan)
        if steps_def is None:
            raise MissionError(f"plan desconocido: '{plan}' (opciones: {sorted(PLANS)})")

        target = target.strip()
        mission_id = f"msn-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}-{uuid.uuid4().hex[:8]}"
        started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        gw = self._gateway()
        coc = self._coc_ref()

        # 1. Sello de apertura de misión.
        self._seal_marker(coc, "mission.start", mission_id, target, roe_token, operator, plan)
        logger.info("Misión %s iniciada | plan=%s target=%s roe=%s", mission_id, plan, target, roe_token)

        # 2. Ejecución gobernada de cada paso.
        step_results: List[StepResult] = []
        for idx, pstep in enumerate(steps_def):
            args = self._resolve_args(pstep.args, target)
            if roe_token:
                args.setdefault("roe_token", roe_token)
            args.setdefault("collector_id", f"mission:{operator}")
            args.setdefault("operation_id", f"{mission_id}:{idx}:{pstep.tool}")

            res = gw.dispatch(pstep.tool, args)
            sr = StepResult(
                index=idx,
                tool=pstep.tool,
                label=pstep.label or pstep.tool,
                decision=res.decision,
                ok=bool(res.ok),
                roe_ref=res.roe_ref,
                payload_hash=res.payload_hash,
                hitl_ticket_id=res.hitl_ticket_id,
                hitl_state=res.hitl_state,
                error=res.error,
                reasons=list(res.reasons or []),
                summary=self._summarize(pstep.tool, res.data),
            )
            step_results.append(sr)
            logger.info(
                "Misión %s paso %d/%d [%s] → %s (ok=%s)",
                mission_id, idx + 1, len(steps_def), pstep.tool, res.decision, res.ok,
            )

        finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        counts = self._count_decisions(step_results)

        result = MissionResult(
            mission_id=mission_id,
            plan=plan,
            target=target,
            roe_ref=roe_token,
            operator=operator,
            started_ts_utc=started,
            finished_ts_utc=finished,
            steps=step_results,
            counts=counts,
        )

        # 3. Dossier JSON (máquina) + sello 'mission.completed' con su hash.
        dossier = result.to_dict()
        json_path = self._reports_path() / f"mission_{mission_id}.json"
        self._write_json(json_path, dossier)
        result.dossier_json_path = str(json_path)

        from amegakurewotan.evidence.forensics import canonical_json, sha512_bytes

        dossier_hash = sha512_bytes(canonical_json(dossier).encode("utf-8"))
        self._seal_marker(
            coc, "mission.completed", mission_id, target, roe_token, operator, plan,
            extra={"dossier_sha512": dossier_hash, "counts": counts, "steps": len(step_results)},
        )

        # 4. Verificación de la cadena tras la misión.
        verify = coc.verify_chain()
        result.chain_records = verify.checked_records
        result.chain_verified = verify.is_valid

        # 5. Firma Ed25519 del estado completo de la cadena + verificación del sobre.
        if sign:
            self._sign_and_verify(result)

        # 6. Dossier Markdown (operador) — se genera al final para reflejar la firma.
        md_path = self._reports_path() / f"mission_{mission_id}.md"
        self._write_markdown(md_path, result)
        result.dossier_md_path = str(md_path)

        # Reescribir el JSON con la firma incorporada (dossier completo definitivo).
        self._write_json(json_path, result.to_dict())

        logger.info(
            "Misión %s finalizada | ALLOW=%d DENY=%d HITL=%d ERR=%d | firma_válida=%s",
            mission_id, counts.get("ALLOW", 0), counts.get("DENY", 0),
            counts.get("REQUIRE_HITL", 0), counts.get("ERROR", 0), result.signature_valid,
        )
        return result

    # ── Firma / verificación ──────────────────────────────────────────────────
    def _sign_and_verify(self, result: MissionResult) -> None:
        try:
            from amegakurewotan.evidence.custody_signer import (
                sign_chain,
                verify_chain_signature,
            )

            overlay = sign_chain()
            result.signature = overlay
            verification = verify_chain_signature()
            result.signature_valid = bool(verification.get("valid"))
            if not result.signature_valid:
                logger.error("Sobre de firma NO válido: %s", verification.get("reason"))
        except Exception as exc:  # noqa: BLE001 — la firma no debe tumbar la misión.
            logger.error("No se pudo firmar/verificar la cadena de la misión: %s", exc)
            result.signature = {"error": str(exc)}
            result.signature_valid = False

    # ── Sellado de marcadores de misión ───────────────────────────────────────
    @staticmethod
    def _seal_marker(
        coc: Any,
        event_type: str,
        mission_id: str,
        target: str,
        roe_ref: Optional[str],
        operator: str,
        plan: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            from amegakurewotan.evidence.forensics import canonical_json, sha512_bytes

            body: Dict[str, Any] = {
                "mission_id": mission_id,
                "target": target,
                "plan": plan,
                "operator": operator,
            }
            if extra:
                body.update(extra)
            payload_hash = sha512_bytes(canonical_json(body).encode("utf-8"))
            coc.append(
                collector_id=f"mission:{operator}",
                event_type=event_type,
                payload_hash=payload_hash,
                roe_ref=roe_ref,
                metadata=body,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("No se pudo sellar el marcador '%s': %s", event_type, exc)

    # ── Helpers ────────────────────────────────────────────────────────────────
    @staticmethod
    def _resolve_args(args: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Sustituye recursivamente $TARGET por el objetivo real (copia profunda)."""

        def _sub(value: Any) -> Any:
            if isinstance(value, str):
                return value.replace(_TARGET_TOKEN, target)
            if isinstance(value, dict):
                return {k: _sub(v) for k, v in value.items()}
            if isinstance(value, list):
                return [_sub(v) for v in value]
            return value

        return _sub(copy.deepcopy(args))

    @staticmethod
    def _count_decisions(steps: List[StepResult]) -> Dict[str, int]:
        counts = {"ALLOW": 0, "DENY": 0, "REQUIRE_HITL": 0, "ERROR": 0}
        for s in steps:
            if s.decision == "ALLOW" and not s.ok:
                counts["ERROR"] += 1
            elif s.decision in counts:
                counts[s.decision] += 1
            else:
                counts["ERROR"] += 1
        return counts

    @staticmethod
    def _summarize(tool: str, data: Any) -> Dict[str, Any]:
        """
        Resumen compacto y FIEL del resultado de un handler (no fabrica: si no hay
        datos, el resumen lo refleja). Evita volcar payloads grandes al dossier.
        """
        if data is None:
            return {}
        if not isinstance(data, dict):
            text = str(data)
            return {"value": text[:200] + ("…" if len(text) > 200 else "")}

        # tool_unavailable / error explícitos del adaptador.
        if data.get("status") in ("error", "tool_unavailable") or "tool_unavailable" in data:
            return {
                "status": data.get("status", "tool_unavailable"),
                "reason": data.get("reason") or data.get("tool_unavailable"),
                "tool": data.get("tool"),
            }

        if tool.startswith("recon."):
            results = data.get("results", data)
            return {
                "source": data.get("source"),
                "mode": data.get("mode"),
                "subdomains": len(results.get("subdomains", []) or []) if isinstance(results, dict) else 0,
                "ips": len(results.get("ips", []) or []) if isinstance(results, dict) else 0,
                "ports": results.get("ports", []) if isinstance(results, dict) else [],
            }
        if tool == "defense.phishing_detect":
            return {
                "domain": data.get("domain"),
                "risk_score": data.get("risk_score"),
                "verdict": data.get("verdict"),
                "signals": len(data.get("signals", []) or []),
            }
        if tool == "graph.query":
            graph = data.get("graph", {})
            if isinstance(graph, dict):
                return {
                    "nodes": len(graph.get("nodes", []) or []),
                    "edges": len(graph.get("edges", []) or []),
                }
            return {"graph": "n/a"}
        if tool == "forensic.verify":
            return {
                "is_valid": data.get("is_valid"),
                "checked_records": data.get("checked_records"),
            }
        if tool.startswith("dfir.") or tool.startswith("darkweb."):
            return {
                "status": data.get("status"),
                "tool": data.get("tool") or data.get("source"),
                "operation": data.get("operation"),
            }

        # Fallback genérico: claves de primer nivel.
        return {"keys": sorted(list(data.keys()))[:12]}

    @staticmethod
    def _write_json(path: Path, obj: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())

    @staticmethod
    def _write_markdown(path: Path, result: MissionResult) -> None:
        """
        Dossier de operador en Markdown. Tono clínico, empírico y aséptico
        (Shinobi Nindo DIRECTIVA-ABS-10): reporta input → decisión gobernada →
        resultado, sin lenguaje ofensivo ni relleno.
        """
        c = result.counts
        lines: List[str] = []
        lines.append(f"# Dossier de misión — {result.mission_id}")
        lines.append("")
        lines.append(f"- Objetivo: `{result.target}`")
        lines.append(f"- Plan: `{result.plan}`")
        lines.append(f"- RoE: `{result.roe_ref or 'ninguna (solo pasiva)'}`")
        lines.append(f"- Operador: `{result.operator}`")
        lines.append(f"- Inicio (UTC): {result.started_ts_utc}")
        lines.append(f"- Fin (UTC): {result.finished_ts_utc}")
        lines.append("")
        lines.append("## Resumen de gobernanza")
        lines.append("")
        lines.append(f"- ALLOW: {c.get('ALLOW', 0)}")
        lines.append(f"- DENY: {c.get('DENY', 0)}")
        lines.append(f"- REQUIRE_HITL (pendientes): {c.get('REQUIRE_HITL', 0)}")
        lines.append(f"- ERROR: {c.get('ERROR', 0)}")
        lines.append("")
        lines.append("## Cadena de custodia")
        lines.append("")
        lines.append(f"- Registros verificados: {result.chain_records}")
        lines.append(f"- Integridad de la cadena: {'ÍNTEGRA' if result.chain_verified else 'CORRUPTA'}")
        if result.signature:
            sig = result.signature
            lines.append(f"- Firma Ed25519: {'VÁLIDA' if result.signature_valid else 'NO VÁLIDA'}")
            if isinstance(sig, dict) and sig.get("chain_sha512"):
                lines.append(f"  - chain_sha512: `{sig.get('chain_sha512', '')[:48]}…`")
                lines.append(f"  - pubkey_sha256: `{sig.get('pubkey_sha256', '')[:48]}…`")
                lines.append(f"  - registros firmados: {sig.get('records')}")
                lines.append(f"  - ts_utc: {sig.get('ts_utc')}")
        lines.append("")
        lines.append("## Pasos ejecutados")
        lines.append("")
        lines.append("| # | Herramienta | Decisión | OK | RoE | Resumen |")
        lines.append("|---|-------------|----------|----|-----|---------|")
        for s in result.steps:
            summary_txt = ", ".join(f"{k}={v}" for k, v in s.summary.items()) or "—"
            if len(summary_txt) > 90:
                summary_txt = summary_txt[:87] + "…"
            hitl = f" (HITL {s.hitl_ticket_id})" if s.hitl_ticket_id else ""
            lines.append(
                f"| {s.index} | `{s.tool}`{hitl} | {s.decision} | "
                f"{'sí' if s.ok else 'no'} | {s.roe_ref or '—'} | {summary_txt} |"
            )
        lines.append("")
        lines.append("## Detalle por paso")
        lines.append("")
        for s in result.steps:
            lines.append(f"### {s.index}. {s.label} — `{s.tool}`")
            lines.append("")
            lines.append(f"- Decisión GELSI: **{s.decision}** (ok={s.ok})")
            if s.roe_ref:
                lines.append(f"- RoE: `{s.roe_ref}`")
            if s.payload_hash:
                lines.append(f"- payload_sha512: `{s.payload_hash[:48]}…`")
            if s.hitl_ticket_id:
                lines.append(f"- Ticket HITL: `{s.hitl_ticket_id}` (estado {s.hitl_state})")
            if s.error:
                lines.append(f"- Error: {s.error}")
            if s.reasons:
                lines.append(f"- Motivos: {'; '.join(s.reasons)}")
            if s.summary:
                lines.append(f"- Resultado: {json.dumps(s.summary, ensure_ascii=False)}")
            lines.append("")

        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
            fh.flush()
            os.fsync(fh.fileno())


# ──────────────────────────────────────────────────────────────────────────────
# API funcional + utilidades de estado
# ──────────────────────────────────────────────────────────────────────────────
def run_mission(
    target: str,
    roe_token: Optional[str] = None,
    plan: str = "osint_recon",
    operator: str = "operator",
    sign: bool = True,
) -> MissionResult:
    """Atajo funcional: ejecuta una misión con los singletons gobernados."""
    return MissionOrchestrator().run(
        target=target, roe_token=roe_token, plan=plan, operator=operator, sign=sign
    )


def list_missions(reports_dir: Optional[str | Path] = None) -> List[Dict[str, Any]]:
    """Lista los dossiers de misión persistidos (más recientes primero)."""
    if reports_dir is None:
        from amegakurewotan.config import get_config

        reports_dir = get_config().base_dir / "reports"
    rdir = Path(reports_dir)
    if not rdir.exists():
        return []
    out: List[Dict[str, Any]] = []
    for p in sorted(rdir.glob("mission_*.json"), key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
            out.append({
                "mission_id": d.get("mission_id"),
                "plan": d.get("plan"),
                "target": d.get("target"),
                "roe_ref": d.get("roe_ref"),
                "finished_ts_utc": d.get("finished_ts_utc"),
                "counts": d.get("counts", {}),
                "signature_valid": d.get("signature_valid"),
                "json_path": str(p),
            })
        except (json.JSONDecodeError, OSError):
            continue
    return out


def load_mission(mission_id: str, reports_dir: Optional[str | Path] = None) -> Optional[Dict[str, Any]]:
    """Carga el dossier JSON de una misión por id."""
    if reports_dir is None:
        from amegakurewotan.config import get_config

        reports_dir = get_config().base_dir / "reports"
    p = Path(reports_dir) / f"mission_{mission_id}.json"
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
