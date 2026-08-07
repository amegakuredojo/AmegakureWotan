# FORGE_CONTEXT: CIVIL
"""
Tests del gateway MCP consolidado AmegakureWotan (mcp.gateway.ConsolidatedGateway
+ mcp.schemas). Verifica enrutamiento por dominio, gating L0 GELSI, idempotencia
(§10.2) y sellado en cadena de custodia (§6, §10.1).
"""
import pytest
from unittest.mock import patch

from karasugakure.evidence.forensics import ChainOfCustody, sha512_bytes
from karasugakure.policy.roe import (
    ACTION_ACTIVE,
    ACTION_DARKWEB,
    ACTION_DFIR,
    ACTION_PASSIVE,
    RulesOfEngagement,
    ScopeRegistry,
)
from karasugakure.policy.gelsi import GelsiMiddleware
from karasugakure.mcp.gateway import ConsolidatedGateway, GatewayResult
from karasugakure.mcp.schemas import ReconRequest, ReconTarget, DfirRequest


@pytest.fixture
def wired(tmp_path):
    """Gateway cableado con GELSI + RoE + CoC aislados en tmp_path."""
    registry = ScopeRegistry(roe_dir=tmp_path / "roe", pubkey_path=tmp_path / "k.pem")
    coc = ChainOfCustody(timeline_path=tmp_path / "timeline.jsonl", key_path=tmp_path / "k.key")
    gelsi = GelsiMiddleware(scope_registry=registry, chain_of_custody=coc)
    gw = ConsolidatedGateway(gelsi=gelsi, chain_of_custody=coc)
    return gw, registry, coc


def test_unknown_tool_denied(wired):
    gw, _, _ = wired
    res = gw.dispatch("nonexistent.tool", {})
    assert res.decision == "DENY"
    assert "desconocida" in res.error


def test_active_recon_without_roe_denied(wired):
    gw, _, _ = wired
    res = gw.dispatch("recon.active_surface", {"target": "target.com"})
    assert res.decision == "DENY"
    assert res.ok is False


def test_darkweb_requires_hitl(wired):
    gw, registry, _ = wired
    registry.register(RulesOfEngagement(
        roe_id="roe-dw", authority="a", scope=["target.com"],
        allowed_actions=[ACTION_PASSIVE, ACTION_DARKWEB],
    ))
    res = gw.dispatch("darkweb.profile", {"query": "leak", "target": "target.com", "roe_token": "roe-dw"})
    assert res.decision == "REQUIRE_HITL"
    assert res.ok is False  # no ejecuta sin aprobación humana


def test_dfir_requires_hitl(wired):
    gw, registry, _ = wired
    registry.register(RulesOfEngagement(
        roe_id="roe-dfir", authority="a", scope=["host-01"], allowed_actions=[ACTION_DFIR],
    ))
    res = gw.dispatch("dfir.memory_analyze", {"target": "host-01", "roe_token": "roe-dfir"})
    assert res.decision == "REQUIRE_HITL"


def test_forensic_verify_allowed_and_sealed(wired):
    gw, _, coc = wired
    res = gw.dispatch("forensic.verify", {})
    assert res.decision == "ALLOW"
    assert res.ok is True
    assert res.data["is_valid"] is True
    # La invocación debe haberse sellado (gelsi.decision + op.completed).
    events = [r["event_type"] for r in coc.read_all()]
    assert "gelsi.decision" in events
    assert "op.completed" in events


def test_passive_recon_allowed_with_mock(wired):
    gw, _, _ = wired
    with patch("karasugakure.agents.heimdall.HeimdallAgent") as MockAgent:
        MockAgent.return_value.execute.return_value = {"subdomains": ["a.target.com"], "ips": ["1.2.3.4"]}
        res = gw.dispatch("recon.passive_scan", {"target": "target.com"})
    assert res.decision == "ALLOW"
    assert res.ok is True
    assert res.data["source"] == "heimdall"


def test_idempotency_skip(wired):
    gw, _, coc = wired
    with patch("karasugakure.agents.heimdall.HeimdallAgent") as MockAgent:
        MockAgent.return_value.execute.return_value = {"subdomains": []}
        r1 = gw.dispatch("recon.passive_scan", {"target": "target.com", "operation_id": "op-xyz"})
        r2 = gw.dispatch("recon.passive_scan", {"target": "target.com", "operation_id": "op-xyz"})
    assert r1.ok is True
    assert r2.ok is True
    assert r2.data.get("idempotent_skip") is True


def test_offensive_social_denied_at_gateway(wired):
    gw, _, _ = wired
    res = gw.dispatch("recon.passive_scan", {
        "target": "target.com",
        "intent": "generate phishing lure to deceive the victim employee",
    })
    assert res.decision == "DENY"


def test_chain_integrity_after_dispatches(wired):
    gw, _, coc = wired
    gw.dispatch("forensic.verify", {})
    gw.dispatch("recon.active_surface", {"target": "x.com"})  # DENY, sellado
    assert coc.verify_chain().is_valid is True


# ── Esquemas Pydantic (§6.2) ─────────────────────────────────────────────────
def test_recon_request_out_of_scope_rejected(tmp_path):
    from karasugakure.policy.roe import reset_scope_registry
    import karasugakure.mcp.schemas as schemas

    reg = ScopeRegistry(roe_dir=tmp_path / "roe", pubkey_path=tmp_path / "k.pem")
    reg.register(RulesOfEngagement(
        roe_id="roe-1", authority="a", scope=["target.com"], allowed_actions=[ACTION_PASSIVE],
    ))
    with patch.object(schemas, "get_scope_registry", return_value=reg):
        with pytest.raises(ValueError):
            ReconRequest(
                target=ReconTarget(value="evil.com", type="domain"),
                mode="passive_surface",
                roe_token="roe-1",
            )


def test_recon_request_active_needs_roe_clause(tmp_path):
    import karasugakure.mcp.schemas as schemas

    reg = ScopeRegistry(roe_dir=tmp_path / "roe", pubkey_path=tmp_path / "k.pem")
    reg.register(RulesOfEngagement(
        roe_id="roe-passive", authority="a", scope=["target.com"], allowed_actions=[ACTION_PASSIVE],
    ))
    with patch.object(schemas, "get_scope_registry", return_value=reg):
        with pytest.raises(ValueError):
            ReconRequest(
                target=ReconTarget(value="target.com", type="domain"),
                mode="active_surface",  # RoE no permite activo
                roe_token="roe-passive",
            )
