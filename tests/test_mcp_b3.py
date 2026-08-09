# FORGE_CONTEXT: CIVIL
"""Fase B3 — cobertura de mcp/server.py y mcp/governance.py.

Sube mcp/server (18%) y mcp/governance (46%) a >=80% ejercitando las tools MCP
con GELSI/agentes/db MOCKEADOS. Sin salida fabricada: govern() se mockea segun
el caso (ALLOW/DENY/REQUIRE_HITL); kuzu usa DB embebida real en tmp_path.
NOTA: server/governance importan agentes y deps LOCALMENTE dentro de las
funciones, asi que se parchean los modulos de origen (no server_mod/gov_mod).
"""
import asyncio
from unittest.mock import MagicMock, patch

import pytest

import amegakurewotan.mcp.server as server_mod
import amegakurewotan.mcp.governance as gov_mod
import amegakurewotan.agents.heimdall as heimdall_mod
import amegakurewotan.agents.odin as odin_mod
import amegakurewotan.agents.huginn as huginn_mod
import amegakurewotan.agents.hel as hel_mod
import amegakurewotan.agents.fenrir as fenrir_mod
import amegakurewotan.tools.searxng as searxng_mod
import amegakurewotan.graph.export as export_mod
import amegakurewotan.evidence.audit as audit_mod
import amegakurewotan.policy.gelsi as gelsi_mod
import amegakurewotan.policy.hitl as hitl_mod
import amegakurewotan.mcp.gateway as gateway_mod
import amegakurewotan.evidence.forensics as forensics_mod


# ── server: helpers puros ───────────────────────────────────────────────────
def test_forensic_hash():
    h = server_mod._forensic_hash("payload")
    assert len(h) == 128
    assert h != server_mod._forensic_hash("otro")


def test_validate_cypher_allowlist():
    assert server_mod._validate_cypher_allowlist("MATCH (n) RETURN n") is True
    assert server_mod._validate_cypher_allowlist("CREATE (n) RETURN n") is False
    assert server_mod._validate_cypher_allowlist("  ") is False
    assert server_mod._validate_cypher_allowlist("DROP TABLE x") is False


def test_ecs_formatter():
    from amegakurewotan.mcp.server import ECSJSONFormatter
    import logging
    rec = logging.LogRecord("m", logging.INFO, "f.py", 1, "msg", None, None)
    out = ECSJSONFormatter().format(rec)
    assert "message" in out and "forge_context" in out


# ── server: list_tools (cubre todas las definiciones de Tool) ───────────────
def test_list_tools():
    tools = asyncio.run(server_mod.list_tools())
    names = {t.name for t in tools}
    for expected in ("searxng_recon", "heimdall_recon", "odin_orchestrate",
                     "huginn_humint", "hel_darkweb", "fenrir_correlate",
                     "kuzu_ingest_entity", "kuzu_cypher_query", "audit_verify",
                     "export_graph", "wotan_hitl_list", "wotan_hitl_approve",
                     "wotan_hitl_deny"):
        assert expected in names


# ── server: get_kuzu_connection embebido ────────────────────────────────────
def test_get_kuzu_connection(tmp_path, monkeypatch):
    monkeypatch.setenv("KUZU_DATABASE_PATH", str(tmp_path / "vault.kuzu"))
    monkeypatch.setattr(server_mod, "_conn", None)
    monkeypatch.setattr(server_mod, "_db", None)
    conn = server_mod.get_kuzu_connection()
    assert conn is not None
    conn.execute("CREATE NODE TABLE IF NOT EXISTS T (id STRING, PRIMARY KEY(id))")
    conn.execute("MERGE (t:T {id:'x'})")
    res = conn.execute("MATCH (t:T) RETURN t.id")
    assert res.get_next()[0] == "x"


# ── server: call_tool con govern=ALLOW y agentes mock (modulos de origen) ────
def _patch_call_tool(monkeypatch, govern_decision="ALLOW"):
    monkeypatch.setattr(server_mod, "_govern", lambda n, a: (govern_decision, "ticket-x" if govern_decision == "REQUIRE_HITL" else None))
    monkeypatch.setattr(server_mod, "_seal_execution", lambda *a, **k: None)
    heimdall = MagicMock(); heimdall.execute.return_value = {"subdomains": ["a.example.com"], "ips": [], "source": "heimdall"}
    odin = MagicMock(); odin.execute.return_value = {"session_id": "s1", "status": "completed", "findings": [], "correlations": [], "evidence": [], "dossier": {}, "phase": "report"}
    huginn = MagicMock(); huginn.execute.return_value = {"hes": 0.5, "source": "huginn"}
    hel = MagicMock(); hel.execute.return_value = {"onion_sites": [], "leaks_found": [], "source": "hel"}
    fenrir = MagicMock(); fenrir.execute.return_value = [{"from_value": "a", "to_value": "b", "rel_type": "X"}]
    monkeypatch.setattr(heimdall_mod, "HeimdallAgent", lambda: heimdall)
    monkeypatch.setattr(odin_mod, "OdinAgent", lambda: odin)
    monkeypatch.setattr(huginn_mod, "HuginnAgent", lambda: huginn)
    monkeypatch.setattr(hel_mod, "HelAgent", lambda: hel)
    monkeypatch.setattr(fenrir_mod, "FenrirAgent", lambda: fenrir)
    # query_searxng se importa a nivel modulo en server.py (binding fijo),
    # asi que se parchea server_mod directamente.
    monkeypatch.setattr(server_mod, "query_searxng", lambda *a, **k: [{"title": "T", "url": "http://x", "content": "c"}])
    monkeypatch.setattr(export_mod, "export_to_json", lambda *a, **k: {"nodes": [{"id": "n1"}], "edges": []})
    ledger = MagicMock(); ledger.verify_ledger_integrity.return_value = True
    monkeypatch.setattr(audit_mod, "ForensicAuditLedger", lambda: ledger)


def test_call_tool_searxng(monkeypatch):
    _patch_call_tool(monkeypatch)
    out = asyncio.run(server_mod.call_tool("searxng_recon", {"query": "test"}))
    assert out[0].text.startswith("=== SEARXNG RECON")


def test_call_tool_heimdall(monkeypatch):
    _patch_call_tool(monkeypatch)
    out = asyncio.run(server_mod.call_tool("heimdall_recon", {"target": "example.com"}))
    assert "HEIMDALL RECON" in out[0].text


def test_call_tool_odin(monkeypatch):
    _patch_call_tool(monkeypatch)
    out = asyncio.run(server_mod.call_tool("odin_orchestrate", {"target": "example.com"}))
    assert "ODIN ORCHESTRATE" in out[0].text


def test_call_tool_huginn(monkeypatch):
    _patch_call_tool(monkeypatch)
    out = asyncio.run(server_mod.call_tool("huginn_humint", {"username": "john"}))
    assert "HUGINN HUMINT" in out[0].text


def test_call_tool_hel(monkeypatch):
    _patch_call_tool(monkeypatch)
    out = asyncio.run(server_mod.call_tool("hel_darkweb", {"query": "x"}))
    assert "HEL DARKWEB" in out[0].text


def test_call_tool_fenrir(monkeypatch):
    _patch_call_tool(monkeypatch)
    out = asyncio.run(server_mod.call_tool("fenrir_correlate", {}))
    assert "FENRIR CORRELATE" in out[0].text


def test_call_tool_export_graph(monkeypatch):
    _patch_call_tool(monkeypatch)
    out = asyncio.run(server_mod.call_tool("export_graph", {}))
    assert "GRAPH EXPORT" in out[0].text


def test_call_tool_audit_verify(monkeypatch):
    _patch_call_tool(monkeypatch)
    out = asyncio.run(server_mod.call_tool("audit_verify", {}))
    assert "OK" in out[0].text


def test_call_tool_kuzu_ingest(tmp_path, monkeypatch):
    _patch_call_tool(monkeypatch)
    monkeypatch.setenv("KUZU_DATABASE_PATH", str(tmp_path / "vault.kuzu"))
    monkeypatch.setattr(server_mod, "_conn", None)
    monkeypatch.setattr(server_mod, "_db", None)
    out = asyncio.run(server_mod.call_tool("kuzu_ingest_entity", {"entity_id": "x.com", "entity_type": "DOMAIN"}))
    assert "[OK] Entidad ingerida" in out[0].text


def test_call_tool_kuzu_cypher_blocked(monkeypatch):
    _patch_call_tool(monkeypatch)
    out = asyncio.run(server_mod.call_tool("kuzu_cypher_query", {"query": "DROP TABLE x"}))
    assert "OPSEC BLOCKED" in out[0].text


def test_call_tool_kuzu_cypher_ok(tmp_path, monkeypatch):
    _patch_call_tool(monkeypatch)
    monkeypatch.setenv("KUZU_DATABASE_PATH", str(tmp_path / "vault.kuzu"))
    monkeypatch.setattr(server_mod, "_conn", None)
    monkeypatch.setattr(server_mod, "_db", None)
    conn = server_mod.get_kuzu_connection()
    conn.execute("CREATE NODE TABLE IF NOT EXISTS E (id STRING, PRIMARY KEY(id))")
    conn.execute("MERGE (e:E {id:'z'})")
    out = asyncio.run(server_mod.call_tool("kuzu_cypher_query", {"query": "MATCH (e:E) RETURN e.id"}))
    assert "z" in out[0].text


def test_call_tool_unknown(monkeypatch):
    _patch_call_tool(monkeypatch)
    with pytest.raises(ValueError):
        asyncio.run(server_mod.call_tool("no_such_tool", {}))


def test_call_tool_deny(monkeypatch):
    _patch_call_tool(monkeypatch, govern_decision="DENY")
    out = asyncio.run(server_mod.call_tool("odin_orchestrate", {"target": "x"}))
    assert "DENY" in out[0].text


def test_call_tool_require_hitl(monkeypatch):
    _patch_call_tool(monkeypatch, govern_decision="REQUIRE_HITL")
    out = asyncio.run(server_mod.call_tool("hel_darkweb", {"query": "x"}))
    assert "REQUIRE_HITL" in out[0].text


def test_call_tool_hitl_list_direct(monkeypatch):
    _patch_call_tool(monkeypatch)
    hitl = MagicMock(); hitl.list_pending.return_value = []
    monkeypatch.setattr(hitl_mod, "get_hitl", lambda: hitl)
    out = asyncio.run(server_mod.call_tool("wotan_hitl_list", {}))
    assert "Sin tickets" in out[0].text


# ── governance ───────────────────────────────────────────────────────────────
def test_govern_allow(monkeypatch):
    g = MagicMock()
    g.evaluate.return_value = MagicMock(decision="ALLOW", reasons=[], roe_ref=None)
    monkeypatch.setattr(gelsi_mod, "get_gelsi", lambda: g)
    decision, payload = gov_mod.govern("searxng_recon", {"query": "x"})
    assert decision == "ALLOW" and payload is None


def test_govern_deny(monkeypatch):
    g = MagicMock()
    g.evaluate.return_value = MagicMock(decision="DENY", reasons=["no roe"], roe_ref=None)
    monkeypatch.setattr(gelsi_mod, "get_gelsi", lambda: g)
    decision, payload = gov_mod.govern("odin_orchestrate", {"target": "x"})
    assert decision == "DENY" and "GELSI" in payload


def test_govern_require_hitl(monkeypatch):
    g = MagicMock()
    g.evaluate.return_value = MagicMock(decision="REQUIRE_HITL", reasons=["pii"], roe_ref="roe-1")
    hitl = MagicMock()
    ticket = MagicMock(); ticket.ticket_id = "hitl-1"
    hitl.create_ticket.return_value = ticket
    monkeypatch.setattr(gelsi_mod, "get_gelsi", lambda: g)
    monkeypatch.setattr(hitl_mod, "get_hitl", lambda: hitl)
    decision, payload = gov_mod.govern("hel_darkweb", {"query": "x"})
    assert decision == "REQUIRE_HITL" and payload == "hitl-1"


def test_govern_unknown_tool_defaults_active(monkeypatch):
    g = MagicMock()
    g.evaluate.return_value = MagicMock(decision="ALLOW", reasons=[], roe_ref=None)
    monkeypatch.setattr(gelsi_mod, "get_gelsi", lambda: g)
    decision, _ = gov_mod.govern("weird_tool_unknown", {"foo": "bar"})
    assert decision == "ALLOW"


def test_seal_execution_ok(monkeypatch):
    coc = MagicMock()
    monkeypatch.setattr(forensics_mod, "ChainOfCustody", lambda: coc)
    gov_mod.seal_execution("tool_x", {"a": 1}, "summary text")
    assert coc.append.called


def test_seal_execution_error_swallowed(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no fs")
    monkeypatch.setattr(forensics_mod, "ChainOfCustody", boom)
    gov_mod.seal_execution("tool_x", {}, "summary")  # no debe lanzar


def test_handle_hitl_list(monkeypatch):
    hitl = MagicMock(); hitl.list_pending.return_value = []
    monkeypatch.setattr(hitl_mod, "get_hitl", lambda: hitl)
    out = gov_mod.handle_hitl_tool("wotan_hitl_list", {})
    assert "Sin tickets" in out[0].text


def test_handle_hitl_approve(monkeypatch):
    hitl = MagicMock()
    gw = MagicMock()
    gw.approve_hitl.return_value = MagicMock(decision="ALLOW", ok=True, reasons=[])
    monkeypatch.setattr(hitl_mod, "get_hitl", lambda: hitl)
    monkeypatch.setattr(gateway_mod, "get_gateway", lambda: gw)
    out = gov_mod.handle_hitl_tool("wotan_hitl_approve", {"ticket_id": "hitl-1"})
    assert "APPROVED" in out[0].text


def test_handle_hitl_deny(monkeypatch):
    hitl = MagicMock()
    gw = MagicMock()
    gw.deny_hitl.return_value = MagicMock(reasons=["operator denied"])
    monkeypatch.setattr(hitl_mod, "get_hitl", lambda: hitl)
    monkeypatch.setattr(gateway_mod, "get_gateway", lambda: gw)
    out = gov_mod.handle_hitl_tool("wotan_hitl_deny", {"ticket_id": "hitl-1"})
    assert "DENIED" in out[0].text


def test_handle_hitl_unknown(monkeypatch):
    hitl = MagicMock()
    monkeypatch.setattr(hitl_mod, "get_hitl", lambda: hitl)
    out = gov_mod.handle_hitl_tool("wotan_hitl_bogus", {})
    assert "desconocida" in out[0].text
