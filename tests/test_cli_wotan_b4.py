# FORGE_CONTEXT: CIVIL
"""Fase B4 (complemento) — cobertura de cli_wotan.py (comandos deterministas).

Sube cli_wotan de ~15% a >=80% invocando doctrine/domains/roe/hitl/forensic/mcp
con gateway/roe/forensics/hitl MOCKEADOS via CliRunner de typer. Sin efectos reales:
los comandos son de consulta/reporte; los handlers se simulan.
"""
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner
from types import SimpleNamespace

import amegakurewotan.cli_wotan as cli_wotan_mod
import amegakurewotan.policy.roe as roe_mod
import amegakurewotan.mcp.gateway as gw_mod
import amegakurewotan.evidence.forensics as forensics_mod
import amegakurewotan.evidence.custody_signer as signer_mod
import amegakurewotan.policy.hitl as hitl_mod

runner = CliRunner()


def _patch_gateway(monkeypatch, tools=None, dispatch_result=None, hitl=None):
    gw = MagicMock()
    gw.tools.return_value = tools or ["recon.passive_scan", "dfir.velociraptor_hunt", "osint.graph_query"]
    res = MagicMock(); res.decision = "ALLOW"; res.ok = True; res.data = {"x": 1}
    res.roe_ref = "roe-1"; res.reasons = []; res.error = None
    res.hitl_ticket_id = None; res.hitl_state = None
    gw.dispatch.return_value = dispatch_result or res
    if hitl:
        gw.approve_hitl.return_value = hitl
        gw.deny_hitl.return_value = hitl
    else:
        gw.approve_hitl.return_value = SimpleNamespace(ok=True, decision="APPROVED", reasons=[])
        gw.deny_hitl.return_value = SimpleNamespace(ok=True, decision="DENIED", reasons=[])
    monkeypatch.setattr(gw_mod, "get_gateway", lambda: gw)
    return gw


def test_doctrine():
    r = runner.invoke(cli_wotan_mod.app, ["doctrine"])
    assert r.exit_code == 0


def test_domains(monkeypatch):
    _patch_gateway(monkeypatch)
    r = runner.invoke(cli_wotan_mod.app, ["domains"])
    assert r.exit_code == 0


def test_roe_list(monkeypatch):
    reg = MagicMock(); reg.list_scopes.return_value = [MagicMock(id="r1")]
    monkeypatch.setattr(roe_mod, "get_scope_registry", lambda: reg)
    r = runner.invoke(cli_wotan_mod.app, ["roe", "list"])
    assert r.exit_code == 0


def test_roe_show(monkeypatch):
    scope = SimpleNamespace(
        roe_id="r1", authority="op", scope=["x.com"], exclusions=[], allowed_actions=["scan"],
        jurisdiction="ES", not_before="2026-01-01", not_after="2026-12-31",
        pii_policy="none", social_eng=False, signature_verified=True)
    reg = MagicMock(); reg.get.return_value = scope
    monkeypatch.setattr(roe_mod, "get_scope_registry", lambda: reg)
    r = runner.invoke(cli_wotan_mod.app, ["roe", "show", "r1"])
    assert r.exit_code == 0


def test_mcp_dispatch(monkeypatch):
    _patch_gateway(monkeypatch)
    r = runner.invoke(cli_wotan_mod.app, ["mcp", "dispatch", "recon.passive_scan", "--args", '{"target":"x"}'])
    assert r.exit_code == 0


def test_forensic_verify(monkeypatch):
    coc = MagicMock()
    coc.verify_chain.return_value = SimpleNamespace(is_valid=True, checked_records=1, corruptions=[])
    monkeypatch.setattr(forensics_mod, "ChainOfCustody", lambda: coc)
    r = runner.invoke(cli_wotan_mod.app, ["forensic", "verify"])
    assert r.exit_code == 0


def test_forensic_sign(monkeypatch):
    monkeypatch.setattr(signer_mod, "sign_chain", lambda: {
        "records": 1, "chain_sha512": "a"*64, "pubkey_sha256": "b"*64, "ts_utc": "2026-08-09T00:00:00Z"})
    r = runner.invoke(cli_wotan_mod.app, ["forensic", "sign"])
    assert r.exit_code == 0


def test_forensic_verify_sign(monkeypatch):
    monkeypatch.setattr(signer_mod, "verify_chain_signature", lambda: {
        "valid": True, "records": 1, "chain_sha512": "a"*64, "reason": ""})
    r = runner.invoke(cli_wotan_mod.app, ["forensic", "verify-sign"])
    assert r.exit_code == 0


def test_forensic_tail(monkeypatch):
    coc = MagicMock(); coc.read_all.return_value = [{"event": "x"}]
    monkeypatch.setattr(forensics_mod, "ChainOfCustody", lambda: coc)
    r = runner.invoke(cli_wotan_mod.app, ["forensic", "tail", "--n", "5"])
    assert r.exit_code == 0


def test_hitl_list(monkeypatch):
    hl = MagicMock(); hl.list_tickets.return_value = []
    monkeypatch.setattr(hitl_mod, "get_hitl", lambda: hl)
    r = runner.invoke(cli_wotan_mod.app, ["hitl", "list"])
    assert r.exit_code == 0


def test_hitl_approve(monkeypatch):
    _patch_gateway(monkeypatch, hitl=MagicMock(ok=True, state="approved"))
    r = runner.invoke(cli_wotan_mod.app, ["hitl", "approve", "t1", "--by", "op"])
    assert r.exit_code == 0


def test_hitl_deny(monkeypatch):
    _patch_gateway(monkeypatch, hitl=SimpleNamespace(ok=True, state="denied", reasons=[]))
    r = runner.invoke(cli_wotan_mod.app, ["hitl", "deny", "t1", "--reason", "x"])
    assert r.exit_code == 0
