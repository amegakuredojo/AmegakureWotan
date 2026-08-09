# FORGE_CONTEXT: CIVIL
"""Fase B4 (complemento) — cobertura de mcp/gateway HITL re-dispatch + REQUIRE_HITL.

Sube mcp/gateway de 84% a >=90% ejercitando approve_hitl (re-ejecuta via dispatch),
deny_hitl (DENY sin ejecutar) y dispatch con govern()==REQUIRE_HITL. Sin red real:
govern/hitl/dispatch MOCKEADOS a nivel de modulo de origen.
"""
from unittest.mock import MagicMock

import pytest

import amegakurewotan.mcp.gateway as gw_mod
import amegakurewotan.policy.gelsi as gelsi_mod
import amegakurewotan.policy.hitl as hitl_mod


def test_approve_hitl_redispatch(monkeypatch):
    ticket = MagicMock(); ticket.request_args = {"target": "x.com"}
    ticket.tool = "recon.passive_scan"; ticket.roe_ref = "roe-1"
    hl = MagicMock(); hl.approve.return_value = ticket
    monkeypatch.setattr(hitl_mod, "get_hitl", lambda: hl)
    # re-dispatch debe devolver ALLOW
    monkeypatch.setattr(gw_mod.ConsolidatedGateway, "dispatch",
                        lambda self, tool, args: gw_mod.GatewayResult(tool=tool, decision="ALLOW", ok=True, reasons=[]))
    res = gw_mod.get_gateway().approve_hitl("hitl-1", by="op")
    assert res.decision == "ALLOW" and res.hitl_state == "APPROVED"


def test_deny_hitl(monkeypatch):
    ticket = MagicMock(); ticket.tool = "recon.x"; ticket.roe_ref = "roe-1"
    hl = MagicMock(); hl.deny.return_value = ticket
    monkeypatch.setattr(hitl_mod, "get_hitl", lambda: hl)
    res = gw_mod.get_gateway().deny_hitl("hitl-1", by="op", reason="nope")
    assert res.decision == "DENY" and res.hitl_state == "DENIED"


def test_dispatch_require_hitl(monkeypatch):
    verdict = MagicMock(); verdict.decision = gw_mod.Decision.REQUIRE_HITL
    verdict.tier = "L3"; verdict.reasons = []; verdict.roe_ref = "roe-1"
    gelsi = MagicMock(); gelsi.evaluate.return_value = verdict
    monkeypatch.setattr(gw_mod, "get_gelsi", lambda: gelsi)
    gw_mod.reset_gateway()  # aislar de _gelsi cacheado por otros tests
    gw = gw_mod.get_gateway()
    res = gw.dispatch("recon.passive_scan", {"target": "x.com"})
    assert res.decision == "REQUIRE_HITL" and res.hitl_state == "PENDING"
