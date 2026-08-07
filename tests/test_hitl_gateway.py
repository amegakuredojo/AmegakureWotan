# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Tests F5 — Subsistema HITL (doble puerta GELSI) + gobernanza del MCP server.

Cubre:
  • GELSI REQUIRE_HITL eleva ticket HITL en el gateway (no ejecuta, sella).
  • deny_hitl() resuelve el ticket como DENIED y lo sella en la cadena.
  • approve_hitl() re-ejecuta SOLO vía gateway (GELSI re-evalúa sin puerta HITL
    pero mantiene veto DENY y validación de scope/RoE).
  • El MCP server (AmegakureWotanMCP) gobierna TODA tool: darkweb sin RoE => DENY,
    y una tool en REQUIRE_HITL levanta ticket HITL (cierre del bypass histórico).
  • Idempotencia: un ticket ya resuelto no se puede re-resolver.
"""
import pytest

from amegakurewotan.policy.roe import (
    ACTION_ACTIVE,
    ACTION_DARKWEB,
    ACTION_DFIR,
    ACTION_PASSIVE,
    RulesOfEngagement,
    get_scope_registry,
    reset_scope_registry,
)
from amegakurewotan.policy.gelsi import get_gelsi, reset_gelsi
from amegakurewotan.policy.hitl import get_hitl, reset_hitl
from amegakurewotan.mcp.gateway import get_gateway, reset_gateway
from amegakurewotan.evidence.forensics import ChainOfCustody, canonical_json, sha512_bytes


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


def _register_dfir_roe():
    reg = get_scope_registry()
    reg.register(RulesOfEngagement(
        roe_id="roe-dfir-f5",
        authority="CISO AmegakureDojo (F5 test)",
        scope=["host-01.target.com", "*.target.com"],
        exclusions=[],
        allowed_actions=[ACTION_PASSIVE, ACTION_ACTIVE, ACTION_DARKWEB, ACTION_DFIR],
        jurisdiction="EU/eIDAS",
        pii_policy="minimize",
    ))
    return reg


def test_gateway_dfir_requires_hitl_creates_ticket(tmp_path):
    _register_dfir_roe()
    gw = get_gateway()
    res = gw.dispatch("dfir.memory_analyze", {
        "target": "host-01.target.com",
        "roe_token": "roe-dfir-f5",
        "params": {},
    })
    assert res.decision == "REQUIRE_HITL"
    assert res.ok is False
    assert res.hitl_ticket_id is not None and res.hitl_ticket_id.startswith("hitl-")
    assert res.hitl_state == "PENDING"
    # El ticket existe y está pendiente.
    pending = get_hitl().list_pending()
    assert any(t.ticket_id == res.hitl_ticket_id for t in pending)
    # La decisión GELSI y el ticket HITL quedaron sellados en la cadena.
    coc = ChainOfCustody()
    events = [r["event_type"] for r in coc.read_all()]
    assert "gelsi.decision" in events
    assert "hitl.pending" in events
    assert coc.verify_chain().is_valid


def test_gateway_hitl_deny_seals_and_blocks(tmp_path):
    _register_dfir_roe()
    gw = get_gateway()
    res = gw.dispatch("dfir.memory_analyze", {
        "target": "host-01.target.com", "roe_token": "roe-dfir-f5", "params": {},
    })
    ticket_id = res.hitl_ticket_id
    assert ticket_id is not None
    denied = gw.deny_hitl(ticket_id, by="test-operator", reason="fuera de ventana")
    assert denied.decision == "DENY"
    assert denied.hitl_state == "DENIED"
    # El ticket queda DENIED y nada se ejecutó (no hay op.completed para este ticket).
    from amegakurewotan.policy.hitl import get_hitl

    assert get_hitl().get(ticket_id).state.value == "DENIED"
    # Re-resolver el mismo ticket debe fallar (idempotencia).
    with pytest.raises(Exception):
        gw.deny_hitl(ticket_id, reason="otra vez")


def test_gateway_hitl_scope_enforced_at_first_gate(tmp_path):
    """Target fuera de scope => DENY en la primera puerta GELSI (ni siquiera HITL)."""
    _register_dfir_roe()
    gw = get_gateway()
    res = gw.dispatch("dfir.memory_analyze", {
        "target": "evil-outside.com", "roe_token": "roe-dfir-f5", "params": {},
    })
    assert res.decision == "DENY"
    assert res.hitl_ticket_id is None  # no se levantó ticket: el scope se valida antes de HITL


def test_gateway_hitl_approve_in_scope_runs_handler(tmp_path, monkeypatch):
    _register_dfir_roe()
    gw = get_gateway()

    # Stub del adaptador DFIR para no ejecutar Volatility real. Parchear la
    # entrada registrada en el dict de handlers del gateway.
    captured = {}
    def fake_memory_analyze(args):
        captured["target"] = args.get("target")
        return {"analyzed": args.get("target"), "artifacts": 3}
    gw._handlers["dfir.memory_analyze"] = fake_memory_analyze

    res = gw.dispatch("dfir.memory_analyze", {
        "target": "host-01.target.com", "roe_token": "roe-dfir-f5", "params": {},
    })
    assert res.decision == "REQUIRE_HITL"
    ticket_id = res.hitl_ticket_id
    assert ticket_id is not None
    approved = gw.approve_hitl(ticket_id, by="test-operator")
    assert approved.decision == "ALLOW"
    assert approved.ok is True
    assert captured.get("target") == "host-01.target.com"
    assert approved.data == {"analyzed": "host-01.target.com", "artifacts": 3}
    # El resultado quedó sellado.
    coc = ChainOfCustody()
    assert any(r["event_type"] == "op.completed" and
               r.get("metadata", {}).get("tool") == "dfir.memory_analyze"
               for r in coc.read_all())


def test_mcp_server_govern_denies_darkweb_without_roe(tmp_path):
    # Sin RoE => darkweb debe DENY (cierre del bypass histórico del server).
    from amegakurewotan.mcp import server as mcp_server

    decision, payload = mcp_server._govern("hel_darkweb", {"query": "leak@example.com"})
    assert decision == "DENY"
    assert payload  # mensaje de denegación presente


def test_mcp_server_govern_darkweb_with_roe_creates_hitl(tmp_path):
    _register_dfir_roe()
    from amegakurewotan.mcp import server as mcp_server

    decision, payload = mcp_server._govern(
        "hel_darkweb", {"query": "leak@host-01.target.com", "roe_token": "roe-dfir-f5"},
    )
    assert decision == "REQUIRE_HITL"
    assert isinstance(payload, str) and payload.startswith("hitl-")
    # El ticket HITL quedó sellado.
    coc = ChainOfCustody()
    assert any(r["event_type"] == "hitl.pending" for r in coc.read_all())
    assert coc.verify_chain().is_valid


def test_mcp_server_govern_passive_requires_no_roe(tmp_path):
    from amegakurewotan.mcp import server as mcp_server

    # Recon pasivo sin RoE => ALLOW (recon pasivo no exige RoE según GELSI).
    decision, payload = mcp_server._govern("searxng_recon", {"query": "test"})
    assert decision == "ALLOW"
    assert payload is None
