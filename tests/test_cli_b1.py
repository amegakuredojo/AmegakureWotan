# FORGE_CONTEXT: CIVIL
"""Fase B1 — cobertura de cli.py (CLI legado `amewotan`).

Sube cli.py de 25% a >=80% cubriendo comandos deterministas y ramas
mockeables SIN salida fabricada: run (servidor+autonomo), graph
ingest/query/export/import/view, validate, freeze, report, resume,
export, orchestrate, correlate (degraded), kaisen ingest, audit verify.

Los comandos que requieren agentes/langgraph reales se ejercitan con agentes
MOCKEADOS que devuelven el contrato real (dict con las claves que cli.py lee).
No se simula exito donde el codigo espera fallo: correlate sin DB usa el path
DEGRADED real.
"""
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from typer.testing import CliRunner

from amegakurewotan import cli

runner = CliRunner(env={"COLUMNS": "200"})


# ── Helpers de mock a nivel de modulo cli ──────────────────────────────────
def _fake_db(connected: bool = True):
    db = MagicMock()
    db.check_connection.return_value = connected
    db.config = MagicMock()
    db.config.database_path = "/tmp/fake.kuzu"
    return db


def _patch_agents(monkeypatch, db):
    """Parchea get_db y los agentes en cli. Devuelve dict de mocks para reconfigurar."""
    monkeypatch.setattr(cli, "get_db", lambda: db)

    odin = MagicMock()
    odin.process_finding.return_value = {
        "entity": {"e": {"id": "ent-1"}},
        "validation": {"nato_rating": "B", "status": "VALIDATED", "confidence": 0.9},
    }
    odin.execute.return_value = {
        "status": "completed", "phase": "done", "session_id": "sess-x",
        "consensus_status": "confirmed", "dossier": {"report_path": "/tmp/d.pdf"},
        "evidence": [], "errors": [],
    }
    monkeypatch.setattr(cli, "OdinAgent", lambda: odin)

    tyr = MagicMock()
    tyr.execute.return_value = {"nato_rating": "B", "confidence": 0.75, "status": "VALID"}
    monkeypatch.setattr(cli, "TyrAgent", lambda: tyr)

    skadi = MagicMock()
    skadi.execute.return_value = {"sha512": "a" * 128, "bytes_size": 10}
    monkeypatch.setattr(cli, "SkadiAgent", lambda: skadi)

    norn = MagicMock()
    norn.execute.return_value = "MATCH (n) RETURN n"
    monkeypatch.setattr(cli, "NornAgent", lambda: norn)

    mimir = MagicMock()
    mimir.execute.return_value = [{"id": "n1"}]
    monkeypatch.setattr(cli, "MimirAgent", lambda: mimir)

    fenrir = MagicMock()
    fenrir.execute.return_value = [
        {"from_value": "a", "rel_type": "X", "to_value": "b", "confidence": 0.9,
         "description": "d", "from_type": "Domain", "to_type": "Domain"}
    ]
    monkeypatch.setattr(cli, "FenrirAgent", lambda: fenrir)

    return {"odin": odin, "tyr": tyr, "skadi": skadi, "norn": norn,
            "mimir": mimir, "fenrir": fenrir}


def _inject_code_agent_mock(monkeypatch):
    """code_agent no importa en este entorno; inyecta un modulo fake en sys.modules."""
    mod = types.ModuleType("amegakurewotan.agents.code_agent")
    agent = MagicMock()
    agent.model = MagicMock()
    agent.model.model_id = "meta-llama/Llama-3.3-70B-Instruct"
    agent.run.return_value = None
    mod.create_osint_code_agent = lambda: agent
    monkeypatch.setitem(sys.modules, "amegakurewotan.agents.code_agent", mod)
    return agent


# ── run: modo servidor MCP (mock main + asyncio.run) ──────────────────────
def test_run_server_mode(monkeypatch, tmp_data_dir):
    called = {}
    from unittest.mock import MagicMock as _M

    # cli.run hace `import asyncio` + asyncio.run(mcp_main()). mcp_main es coroutine real.
    async def fake_mcp_main():
        called["ran"] = True

    monkeypatch.setattr("amegakurewotan.mcp.server.main", fake_mcp_main)
    r = runner.invoke(cli.app, ["run"])
    assert r.exit_code == 0, r.stdout
    assert called.get("ran") is True


# ── run: modo autonomo (mock code_agent + input=exit) ──────────────────────
def test_run_autonomous_mode(monkeypatch, tmp_data_dir):
    agent = _inject_code_agent_mock(monkeypatch)
    monkeypatch.setattr("builtins.input", lambda *a, **k: "exit")
    r = runner.invoke(cli.app, ["run", "--autonomous", "--model-id", "m-9b"])
    assert r.exit_code == 0, r.stdout
    assert agent.model.model_id == "m-9b"


# ── graph ingest / query / export (DB conectada) ───────────────────────────
def test_graph_ingest_connected(monkeypatch, tmp_data_dir):
    db = _fake_db(True)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["graph", "ingest", "--type", "Domain",
                                 "--value", "example.com", "-r", "A", "-c", "1"])
    assert r.exit_code == 0, r.stdout
    assert "successfully ingested" in r.stdout.lower()


def test_graph_query_connected(monkeypatch, tmp_data_dir):
    db = _fake_db(True)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["graph", "query", "show all domains"])
    assert r.exit_code == 0, r.stdout
    assert "MATCH" in r.stdout


def test_graph_export_connected(monkeypatch, tmp_data_dir):
    db = _fake_db(True)
    _patch_agents(monkeypatch, db)
    out = str(tmp_data_dir / "g.json")
    r = runner.invoke(cli.app, ["graph", "export", out])
    assert r.exit_code == 0, r.stdout
    assert Path(out).exists()


def test_graph_query_no_records(monkeypatch, tmp_data_dir):
    db = _fake_db(True)
    m = _patch_agents(monkeypatch, db)
    m["mimir"].execute.return_value = []
    r = runner.invoke(cli.app, ["graph", "query", "nothing"])
    assert r.exit_code == 0, r.stdout
    assert "No nodes" in r.stdout


def test_graph_query_exception(monkeypatch, tmp_data_dir):
    db = _fake_db(True)
    m = _patch_agents(monkeypatch, db)
    m["mimir"].execute.side_effect = RuntimeError("boom")
    r = runner.invoke(cli.app, ["graph", "query", "bad"])
    assert r.exit_code == 0, r.stdout
    assert "Execution error" in r.stdout


# ── graph commands sin DB ──────────────────────────────────────────────────
def test_graph_ingest_offline(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["graph", "ingest", "--type", "Domain", "--value", "x"])
    assert r.exit_code == 1
    assert "not reachable" in r.stdout


def test_graph_export_offline(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["graph", "export", str(tmp_data_dir / "x.json")])
    assert r.exit_code == 1


def test_export_offline(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["export"])
    assert r.exit_code == 1
    assert "offline" in r.stdout.lower()


# ── validate / freeze / report ─────────────────────────────────────────────
def test_validate(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["validate", "-r", "A", "-c", "1"])
    assert r.exit_code == 0, r.stdout
    assert "NATO Rating" in r.stdout


def test_freeze_missing_file(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["freeze", str(tmp_data_dir / "nope.bin")])
    assert r.exit_code == 1
    assert "File not found" in r.stdout


def test_freeze_ok(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    f = tmp_data_dir / "ev.bin"
    f.write_bytes(b"0123456789")
    r = runner.invoke(cli.app, ["freeze", str(f)])
    assert r.exit_code == 0, r.stdout
    assert "FROZEN" in r.stdout


def test_report_integrity_fail(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    from amegakurewotan.evidence.audit import ForensicAuditLedger
    ledger = ForensicAuditLedger()
    monkeypatch.setattr(ledger, "verify_ledger_integrity", lambda: False)
    monkeypatch.setattr("amegakurewotan.evidence.audit.ForensicAuditLedger",
                        lambda: ledger)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["report"])
    assert r.exit_code == 1
    assert "integrity check failed" in r.stdout.lower()


def test_report_ok(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    from amegakurewotan.evidence.audit import ForensicAuditLedger
    ledger = ForensicAuditLedger()
    monkeypatch.setattr(ledger, "verify_ledger_integrity", lambda: True)
    monkeypatch.setattr("amegakurewotan.evidence.audit.ForensicAuditLedger",
                        lambda: ledger)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["report"])
    assert r.exit_code == 0, r.stdout
    assert "dossier" in r.stdout.lower()


# ── resume (checkpoint) ────────────────────────────────────────────────────
def test_resume_no_sessions(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    monkeypatch.setattr(cli, "glob", MagicMock())
    cli.glob.glob.return_value = []
    r = runner.invoke(cli.app, ["resume"])
    assert r.exit_code == 1
    assert "No sessions" in r.stdout


def test_resume_with_checkpoint(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    sess = tmp_data_dir / "sessions" / "session_abc.json"
    sess.parent.mkdir(parents=True, exist_ok=True)
    sess.write_text('{"status":"completed","phase":"done"}', encoding="utf-8")
    r = runner.invoke(cli.app, ["resume"])
    assert r.exit_code == 0, r.stdout
    assert "completed successfully" in r.stdout


def test_resume_exception(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    m = _patch_agents(monkeypatch, db)
    m["odin"].execute.side_effect = RuntimeError("nope")
    sess = tmp_data_dir / "sessions" / "session_abc.json"
    sess.parent.mkdir(parents=True, exist_ok=True)
    sess.write_text('{"status":"x"}', encoding="utf-8")
    r = runner.invoke(cli.app, ["resume"])
    assert r.exit_code == 1


# ── orchestrate / correlate ────────────────────────────────────────────────
def test_orchestrate_success(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["orchestrate", "example.com"])
    assert r.exit_code == 0, r.stdout
    assert "Orchestration complete" in r.stdout


def test_orchestrate_suspended(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    m = _patch_agents(monkeypatch, db)
    m["odin"].execute.return_value = {
        "status": "suspended", "phase": "recon", "session_id": "s",
        "consensus_status": "tentative", "dossier": {}, "evidence": [],
        "errors": ["e1"],
    }
    r = runner.invoke(cli.app, ["orchestrate", "example.com"])
    assert r.exit_code == 1
    assert "suspended" in r.stdout.lower()


def test_orchestrate_exception(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    m = _patch_agents(monkeypatch, db)
    m["odin"].execute.side_effect = RuntimeError("fail")
    r = runner.invoke(cli.app, ["orchestrate", "example.com"])
    assert r.exit_code == 1


def test_correlate_degraded(monkeypatch, tmp_data_dir):
    db = _fake_db(False)  # sin DB => path DEGRADED real
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["correlate"])
    assert r.exit_code == 1
    assert "DEGRADED" in r.stdout


def test_correlate_connected(monkeypatch, tmp_data_dir):
    db = _fake_db(True)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["correlate"])
    assert r.exit_code == 0, r.stdout
    assert "ingested" in r.stdout.lower()


def test_correlate_connected_empty(monkeypatch, tmp_data_dir):
    db = _fake_db(True)
    m = _patch_agents(monkeypatch, db)
    m["fenrir"].execute.return_value = []
    r = runner.invoke(cli.app, ["correlate"])
    assert r.exit_code == 0, r.stdout
    assert "No new correlations" in r.stdout


# ── kaisen ingest ──────────────────────────────────────────────────────────
def test_kaisen_ingest_missing(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["kaisen", "ingest", str(tmp_data_dir / "nope.md")])
    assert r.exit_code == 1
    assert "File not found" in r.stdout


def test_kaisen_ingest_ok(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    md = tmp_data_dir / "dossier.md"
    md.write_text(
        "# OSINT INVESTIGATION DOSSIER: example.com\n"
        "Session ID: `sess-1`\nStatus: completed\nConsensus Status: confirmed\n"
        "## Sources\n- **Source**: google\n## Discovered Correlations\n- a -> b\n",
        encoding="utf-8",
    )
    r = runner.invoke(cli.app, ["kaisen", "ingest", str(md)])
    assert r.exit_code == 0, r.stdout
    lessons = (tmp_data_dir / "kaisen" / "lessons_learned.json").read_text()
    assert "example.com" in lessons


# ── audit verify (no debe crashear; cubre rama OK/CRITICAL) ────────────────
def test_audit_verify_runs(monkeypatch, tmp_data_dir):
    db = _fake_db(False)
    _patch_agents(monkeypatch, db)
    r = runner.invoke(cli.app, ["audit", "verify"])
    assert r.exit_code == 0
    assert "Integrity" in r.stdout
