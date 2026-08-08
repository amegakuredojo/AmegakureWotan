# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Tests F7 — Orquestador de MISIÓN end-to-end (runtime.mission.MissionOrchestrator).

Cubre la doctrina Wotan aplicada a una misión completa:
  • Ejecución gobernada: cada paso pasa por el gateway (GELSI/CoC), nunca lo
    salta. Recon pasivo ALLOW, superficie activa gateada por RoE, DFIR/darkweb
    en REQUIRE_HITL (doble puerta) sin ejecutar, forensic.verify ALLOW.
  • No fabricación: un paso REQUIRE_HITL queda como ticket PENDIENTE; no hay
    datos inventados y el conteo lo refleja.
  • Sellado: marcadores mission.start / mission.completed en la cadena, cadena
    íntegra tras la misión.
  • Firma Ed25519: sobre custody.sig.json emitido y verificado (tamper-evidence).
  • Dossier: JSON máquina + Markdown de operador persistidos y coherentes.
  • Aislamiento total en tmp (AMEWOTAN_DATA_DIR via autouse conftest fixture).
"""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from amegakurewotan.policy.roe import (
    ACTION_ACTIVE,
    ACTION_PASSIVE,
    RulesOfEngagement,
    get_scope_registry,
    reset_scope_registry,
)
from amegakurewotan.policy.gelsi import reset_gelsi
from amegakurewotan.policy.hitl import get_hitl, reset_hitl
from amegakurewotan.mcp.gateway import reset_gateway
from amegakurewotan.evidence.forensics import ChainOfCustody
from amegakurewotan.runtime.mission import (
    MissionOrchestrator,
    list_missions,
    load_mission,
)

_FAKE_RECON = {"subdomains": ["a.target.com", "b.target.com"], "ips": ["1.2.3.4"], "ports": [80, 443]}


@pytest.fixture(autouse=True)
def _reset_singletons():
    reset_scope_registry()
    reset_gelsi()
    reset_gateway()
    reset_hitl()
    yield
    reset_scope_registry()
    reset_gelsi()
    reset_gateway()
    reset_hitl()


def _register_active_roe():
    """RoE que autoriza pasiva + activa (pero NO dfir ni darkweb)."""
    reg = get_scope_registry()
    reg.register(RulesOfEngagement(
        roe_id="roe-mission-f7",
        authority="CISO AmegakureDojo (F7 test)",
        scope=["target.com", "*.target.com"],
        exclusions=[],
        allowed_actions=[ACTION_PASSIVE, ACTION_ACTIVE],
        jurisdiction="EU/eIDAS",
        pii_policy="minimize",
    ))
    return reg


def test_osint_mission_end_to_end_signed(tmp_path):
    """Misión OSINT completa: gobernada, sellada, firmada y con dossier verificable."""
    _register_active_roe()
    with patch("amegakurewotan.agents.heimdall.HeimdallAgent") as MockAgent:
        MockAgent.return_value.execute.return_value = dict(_FAKE_RECON)
        result = MissionOrchestrator().run(
            target="target.com", roe_token="roe-mission-f7", plan="osint_recon", operator="tester",
        )

    # ── Gobernanza: recon pasiva/activa ALLOW, forensic.verify ALLOW ──────────
    by_tool = {s.tool: s for s in result.steps}
    assert by_tool["recon.passive_scan"].decision == "ALLOW"
    assert by_tool["recon.passive_scan"].ok is True
    assert by_tool["recon.active_surface"].decision == "ALLOW"
    assert by_tool["defense.phishing_detect"].decision == "ALLOW"
    assert by_tool["graph.query"].decision == "ALLOW"
    assert by_tool["forensic.verify"].decision == "ALLOW"
    assert by_tool["forensic.verify"].summary.get("is_valid") is True

    # Recon devolvió el resultado REAL del handler mockeado (no fabricado).
    assert by_tool["recon.passive_scan"].summary["subdomains"] == 2
    assert by_tool["recon.passive_scan"].summary["ips"] == 1

    # ── Conteo coherente ──────────────────────────────────────────────────────
    assert result.counts["ALLOW"] == 5
    assert result.counts["DENY"] == 0
    assert result.counts["REQUIRE_HITL"] == 0
    assert result.counts["ERROR"] == 0

    # ── Cadena de custodia íntegra + marcadores de misión sellados ────────────
    assert result.chain_verified is True
    coc = ChainOfCustody()
    events = [r["event_type"] for r in coc.read_all()]
    assert "mission.start" in events
    assert "mission.completed" in events
    assert "gelsi.decision" in events
    assert "op.completed" in events
    assert coc.verify_chain().is_valid is True

    # ── Firma Ed25519 emitida y válida (tamper-evidence) ──────────────────────
    assert result.signature is not None
    assert result.signature.get("chain_sha512")
    assert result.signature_valid is True

    # ── Dossier JSON + Markdown persistidos y coherentes ──────────────────────
    assert result.dossier_json_path and Path(result.dossier_json_path).is_file()
    assert result.dossier_md_path and Path(result.dossier_md_path).is_file()
    dossier = json.loads(Path(result.dossier_json_path).read_text(encoding="utf-8"))
    assert dossier["mission_id"] == result.mission_id
    assert dossier["signature_valid"] is True
    assert len(dossier["steps"]) == 5
    md = Path(result.dossier_md_path).read_text(encoding="utf-8")
    assert result.mission_id in md
    assert "Cadena de custodia" in md
    assert "ÍNTEGRA" in md

    # ── list_missions / load_mission recuperan la misión ──────────────────────
    missions = list_missions()
    assert any(m["mission_id"] == result.mission_id for m in missions)
    loaded = load_mission(result.mission_id)
    assert loaded is not None and loaded["target"] == "target.com"


def test_full_mission_dfir_darkweb_require_hitl_no_fabrication(tmp_path):
    """Plan 'full': darkweb y dfir generan tickets HITL pendientes; nada se ejecuta ni se fabrica."""
    _register_active_roe()  # NO autoriza dfir ni darkweb
    with patch("amegakurewotan.agents.heimdall.HeimdallAgent") as MockAgent:
        MockAgent.return_value.execute.return_value = dict(_FAKE_RECON)
        result = MissionOrchestrator().run(
            target="target.com", roe_token="roe-mission-f7", plan="full", operator="tester",
        )

    by_tool = {s.tool: s for s in result.steps}
    # darkweb y dfir requieren dominios de acción no autorizados por la RoE ⇒ DENY
    # (la RoE no incluye ACTION_DARKWEB/ACTION_DFIR, así que GELSI deniega en scope).
    # En ambos casos NO hay datos ejecutados (ok=False) y NO se fabrica salida.
    assert by_tool["darkweb.profile"].ok is False
    assert by_tool["darkweb.profile"].summary == {}
    assert by_tool["dfir.memory_analyze"].ok is False
    assert by_tool["dfir.memory_analyze"].summary == {}
    assert by_tool["darkweb.profile"].decision in ("DENY", "REQUIRE_HITL")
    assert by_tool["dfir.memory_analyze"].decision in ("DENY", "REQUIRE_HITL")

    # La cadena permanece íntegra y firmada pese a los pasos no ejecutados.
    assert result.chain_verified is True
    assert result.signature_valid is True

    # Ningún op.completed atribuible a ESTA misión para darkweb/dfir (nada real se
    # ejecutó). Se filtra por operation_id (prefijo mission_id) para ser inmune al
    # timeline compartido de la sesión de tests.
    coc = ChainOfCustody()
    mission_completed_tools = [
        r.get("metadata", {}).get("tool")
        for r in coc.read_all()
        if r.get("event_type") == "op.completed"
        and str(r.get("metadata", {}).get("operation_id", "")).startswith(result.mission_id)
    ]
    assert "darkweb.profile" not in mission_completed_tools
    assert "dfir.memory_analyze" not in mission_completed_tools


def test_dfir_triage_creates_hitl_tickets(tmp_path):
    """Plan dfir_triage con RoE DFIR: los pasos DFIR levantan tickets HITL pendientes."""
    reg = get_scope_registry()
    from amegakurewotan.policy.roe import ACTION_DFIR

    reg.register(RulesOfEngagement(
        roe_id="roe-dfir-f7",
        authority="CISO (F7 dfir)",
        scope=["host-01.target.com", "*.target.com"],
        allowed_actions=[ACTION_PASSIVE, ACTION_DFIR],
        pii_policy="minimize",
    ))
    with patch("amegakurewotan.agents.heimdall.HeimdallAgent") as MockAgent:
        MockAgent.return_value.execute.return_value = dict(_FAKE_RECON)
        result = MissionOrchestrator().run(
            target="host-01.target.com", roe_token="roe-dfir-f7", plan="dfir_triage", operator="tester",
        )

    by_tool = {s.tool: s for s in result.steps}
    # Con RoE DFIR válida + scope correcto ⇒ REQUIRE_HITL (doble puerta), NO ejecuta.
    assert by_tool["dfir.memory_analyze"].decision == "REQUIRE_HITL"
    assert by_tool["dfir.memory_analyze"].hitl_ticket_id is not None
    assert by_tool["dfir.memory_analyze"].hitl_state == "PENDING"
    assert by_tool["dfir.disk_timeline"].decision == "REQUIRE_HITL"

    # Los tickets existen y están pendientes en la cola HITL.
    pending_ids = {t.ticket_id for t in get_hitl().list_pending()}
    assert by_tool["dfir.memory_analyze"].hitl_ticket_id in pending_ids
    assert by_tool["dfir.disk_timeline"].hitl_ticket_id in pending_ids

    assert result.counts["REQUIRE_HITL"] == 2
    assert result.chain_verified is True
    assert result.signature_valid is True


def test_mission_unknown_plan_rejected(tmp_path):
    from amegakurewotan.runtime.mission import MissionError

    with pytest.raises(MissionError):
        MissionOrchestrator().run(target="target.com", plan="does_not_exist")


def test_mission_empty_target_rejected(tmp_path):
    from amegakurewotan.runtime.mission import MissionError

    with pytest.raises(MissionError):
        MissionOrchestrator().run(target="   ", plan="osint_recon")
