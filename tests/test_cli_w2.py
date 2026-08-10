# FORGE_CONTEXT: CIVIL
"""Sprint W2 — Cobertura cli.py: comandos recon/humint/darkweb/entity/archive/
resume/orchestrate/correlate-live/kaisen-list-playbooks-promote.
Sube cli.py de 62% a >=80%. Todos los agentes MOCKEADOS sin salida fabricada.
"""
import json
import time
from unittest.mock import MagicMock

from typer.testing import CliRunner

from amegakurewotan import cli

runner = CliRunner(env={"COLUMNS": "200"})


# ── Helpers (reusan patrón test_cli_b1) ────────────────────────
def _fake_db_connected():
    db = MagicMock()
    db.check_connection.return_value = True
    db.config = MagicMock()
    db.config.database_path = "/tmp/fake.kuzu"
    return db


def _fake_db_offline():
    db = MagicMock()
    db.check_connection.return_value = False
    return db


def _patch_all_agents(monkeypatch, db):
    monkeypatch.setattr(cli, "get_db", lambda: db)
    # Heimdall
    heimdall = MagicMock()
    heimdall.execute.return_value = {
        "subdomains": ["a.t.com"],
        "ips": ["1.1.1.1"],
        "ports": [80],
    }
    monkeypatch.setattr(cli, "HeimdallAgent", lambda: heimdall)
    # Loki
    loki = MagicMock()
    loki.execute.return_value = {
        "profiles": [{"platform": "github", "url": "https://github.com/x"}],
        "emails": ["x@ex.com"],
    }
    monkeypatch.setattr(cli, "LokiAgent", lambda: loki)
    # Hel
    hel = MagicMock()
    hel.execute.return_value = {
        "onion_sites": [{"onion": "abc.onion", "title": "T"}],
        "leaks_found": [],
    }
    monkeypatch.setattr(cli, "HelAgent", lambda: hel)
    # Huginn
    huginn = MagicMock()
    huginn.execute.return_value = {
        "target": "corp.com",
        "entity_type": "Domain",
        "certainty": 90,
        "status": "CONFIRMED",
        "hes": 30.0,
        "hypothesis": {"title": "H", "context": "C", "vulnerability": "V"},
    }
    monkeypatch.setattr(cli, "HuginnAgent", lambda: huginn)
    # OdinAgent (process_finding + process_connection + execute)
    odin = MagicMock()
    odin.process_finding.return_value = {
        "entity": {"e": {"id": "ent-1"}},
        "validation": {"nato_rating": "B", "status": "VALIDATED", "confidence": 0.9},
    }
    odin.process_connection.return_value = True
    odin.execute.return_value = {
        "status": "completed",
        "phase": "done",
        "session_id": "sess-y",
        "consensus_status": "confirmed",
        "dossier": {"report_path": "/tmp/d.pdf"},
        "evidence": [],
        "errors": [],
    }
    monkeypatch.setattr(cli, "OdinAgent", lambda: odin)
    # Fenrir
    fenrir = MagicMock()
    fenrir.execute.return_value = [
        {
            "from_value": "a.com",
            "rel_type": "CORRELATED_WITH",
            "to_value": "b.com",
            "confidence": 0.9,
            "description": "match",
            "from_type": "Domain",
            "to_type": "Domain",
        }
    ]
    monkeypatch.setattr(cli, "FenrirAgent", lambda: fenrir)
    # Audit ledger
    ledger = MagicMock()
    ledger.verify_ledger_integrity.return_value = True
    ledger.log_execution.return_value = None
    monkeypatch.setattr(cli, "audit_ledger", ledger)
    # export helpers
    monkeypatch.setattr(
        cli,
        "export_to_json",
        lambda: {
            "nodes": [{"properties": {"value": "x"}, "labels": ["Domain"]}],
            "edges": [],
        },
    )
    monkeypatch.setattr(cli, "export_all_nodes", lambda: [])
    return {
        "heimdall": heimdall,
        "loki": loki,
        "hel": hel,
        "huginn": huginn,
        "odin": odin,
        "fenrir": fenrir,
    }


# ── recon ────────────────────────────────────────────────────────
def test_cli_recon(monkeypatch):
    mocks = _patch_all_agents(monkeypatch, _fake_db_connected())
    result = runner.invoke(cli.app, ["recon", "example.com"])
    assert result.exit_code == 0
    mocks["heimdall"].execute.assert_called_once_with("example.com")


def test_cli_recon_offline(monkeypatch):
    mocks = _patch_all_agents(monkeypatch, _fake_db_offline())
    result = runner.invoke(cli.app, ["recon", "example.com"])
    assert result.exit_code == 0  # no error; just no db ingest


# ── humint ───────────────────────────────────────────────────────
def test_cli_humint(monkeypatch):
    mocks = _patch_all_agents(monkeypatch, _fake_db_connected())
    result = runner.invoke(cli.app, ["humint", "johndoe"])
    assert result.exit_code == 0
    mocks["loki"].execute.assert_called_once_with("johndoe")


# ── darkweb ──────────────────────────────────────────────────────
def test_cli_darkweb(monkeypatch):
    mocks = _patch_all_agents(monkeypatch, _fake_db_offline())
    result = runner.invoke(cli.app, ["darkweb", "leaked credentials"])
    assert result.exit_code == 0
    mocks["hel"].execute.assert_called_once()


# ── entity ───────────────────────────────────────────────────────
def test_cli_entity(monkeypatch):
    mocks = _patch_all_agents(monkeypatch, _fake_db_offline())
    result = runner.invoke(cli.app, ["entity", "corp.com", "--type", "Persona jurídica"])
    assert result.exit_code == 0
    mocks["huginn"].execute.assert_called_once()


# ── archive ──────────────────────────────────────────────────────
def test_cli_archive(monkeypatch):
    _patch_all_agents(monkeypatch, _fake_db_offline())
    result = runner.invoke(cli.app, ["archive", "http://example.com"])
    assert result.exit_code == 0


# ── resume ───────────────────────────────────────────────────────
def test_cli_resume_no_sessions(monkeypatch, tmp_path):
    _patch_all_agents(monkeypatch, _fake_db_offline())
    monkeypatch.setattr(cli, "get_config", lambda: MagicMock(base_dir=tmp_path))
    result = runner.invoke(cli.app, ["resume"])
    assert result.exit_code != 0  # sin sesiones: Exit(1)


def test_cli_resume_with_session(monkeypatch, tmp_path):
    mocks = _patch_all_agents(monkeypatch, _fake_db_offline())
    cfg = MagicMock()
    cfg.base_dir = tmp_path
    (tmp_path / "sessions").mkdir()
    sess_file = tmp_path / "sessions" / "session_testsess.json"
    sess_file.write_text("{}")
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    result = runner.invoke(cli.app, ["resume", "testsess"])
    assert result.exit_code == 0


# ── orchestrate ──────────────────────────────────────────────────
def test_cli_orchestrate_success(monkeypatch):
    mocks = _patch_all_agents(monkeypatch, _fake_db_offline())
    result = runner.invoke(cli.app, ["orchestrate", "target.com"])
    assert result.exit_code == 0
    mocks["odin"].execute.assert_called_with(task="target.com")


def test_cli_orchestrate_failed(monkeypatch):
    mocks = _patch_all_agents(monkeypatch, _fake_db_offline())
    mocks["odin"].execute.return_value = {
        "status": "failed",
        "phase": "recon",
        "session_id": "s1",
        "consensus_status": "tentative",
        "dossier": {},
        "evidence": [],
        "errors": ["err"],
    }
    result = runner.invoke(cli.app, ["orchestrate", "fail.com"])
    assert result.exit_code != 0


# ── correlate (DB live path) ─────────────────────────────────────
def test_cli_correlate_with_db(monkeypatch):
    mocks = _patch_all_agents(monkeypatch, _fake_db_connected())
    result = runner.invoke(cli.app, ["correlate"])
    assert result.exit_code == 0
    mocks["fenrir"].execute.assert_called_once()


def test_cli_correlate_empty(monkeypatch):
    mocks = _patch_all_agents(monkeypatch, _fake_db_connected())
    mocks["fenrir"].execute.return_value = []
    result = runner.invoke(cli.app, ["correlate"])
    assert result.exit_code == 0


# ── kaisen list / playbooks / promote ───────────────────────────
def test_cli_kaisen_list_empty(monkeypatch, tmp_path):
    _patch_all_agents(monkeypatch, _fake_db_offline())
    monkeypatch.setattr(cli, "get_config", lambda: MagicMock(base_dir=tmp_path))
    result = runner.invoke(cli.app, ["kaisen", "list"])
    assert result.exit_code == 0
    assert "No lessons" in result.output


def test_cli_kaisen_list_with_data(monkeypatch, tmp_path):
    _patch_all_agents(monkeypatch, _fake_db_offline())
    cfg = MagicMock()
    cfg.base_dir = tmp_path
    (tmp_path / "kaisen").mkdir()
    lessons = [
        {
            "target": "corp.com",
            "target_type": "Domain",
            "session_id": "s1",
            "status": "ok",
            "consensus_status": "confirmed",
            "timestamp": time.time(),
            "sources_involved": [],
            "wins": [],
            "failed_hypotheses": [],
            "playbooks": [],
            "filepath": "x.md",
        }
    ]
    (tmp_path / "kaisen" / "lessons_learned.json").write_text(json.dumps(lessons))
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    result = runner.invoke(cli.app, ["kaisen", "list"])
    assert result.exit_code == 0
    assert "corp.com" in result.output


def test_cli_kaisen_playbooks_empty(monkeypatch, tmp_path):
    _patch_all_agents(monkeypatch, _fake_db_offline())
    monkeypatch.setattr(cli, "get_config", lambda: MagicMock(base_dir=tmp_path))
    result = runner.invoke(cli.app, ["kaisen", "playbooks"])
    assert result.exit_code == 0


def test_cli_kaisen_promote_no_data(monkeypatch, tmp_path):
    _patch_all_agents(monkeypatch, _fake_db_offline())
    monkeypatch.setattr(cli.ForensicAuditLedger, "__init__", lambda s: None)
    monkeypatch.setattr(cli.ForensicAuditLedger, "verify_ledger_integrity", lambda s: True)
    monkeypatch.setattr(cli, "get_config", lambda: MagicMock(base_dir=tmp_path))
    result = runner.invoke(cli.app, ["kaisen", "promote"])
    assert result.exit_code == 0


def test_cli_graph_import(monkeypatch, tmp_path):
    _patch_all_agents(monkeypatch, _fake_db_connected())
    graph_file = tmp_path / "graph.json"
    graph_file.write_text(json.dumps({"nodes": [], "edges": []}))
    result = runner.invoke(cli.app, ["graph", "import", str(graph_file)])
    assert result.exit_code == 0

def test_cli_graph_import_not_found(monkeypatch):
    _patch_all_agents(monkeypatch, _fake_db_connected())
    result = runner.invoke(cli.app, ["graph", "import", "/tmp/nonexistent_graph_file.json"])
    assert result.exit_code != 0

def test_cli_graph_view(monkeypatch):
    _patch_all_agents(monkeypatch, _fake_db_connected())
    result = runner.invoke(cli.app, ["graph", "view"])
    assert result.exit_code == 0

def test_cli_kaisen_playbooks_with_data(monkeypatch, tmp_path):
    _patch_all_agents(monkeypatch, _fake_db_offline())
    cfg = MagicMock(); cfg.base_dir = tmp_path
    (tmp_path / "kaisen").mkdir()
    lessons = [{"session_id": "s1", "playbooks": ["pattern1"]}]
    (tmp_path / "kaisen" / "lessons_learned.json").write_text(json.dumps(lessons))
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    result = runner.invoke(cli.app, ["kaisen", "playbooks"])
    assert result.exit_code == 0 and "pattern1" in result.output

def test_cli_kaisen_promote_with_data(monkeypatch, tmp_path):
    _patch_all_agents(monkeypatch, _fake_db_offline())
    monkeypatch.setattr(cli.ForensicAuditLedger, "__init__", lambda s: None)
    monkeypatch.setattr(cli.ForensicAuditLedger, "verify_ledger_integrity", lambda s: True)
    cfg = MagicMock(); cfg.base_dir = tmp_path
    (tmp_path / "kaisen").mkdir()
    lessons = [{"wins": ["w1", "w2", "w3", "w4", "w5", "w6"], "failed_hypotheses": ["f1"]}]
    (tmp_path / "kaisen" / "lessons_learned.json").write_text(json.dumps(lessons))
    monkeypatch.setattr(cli, "get_config", lambda: cfg)
    result = runner.invoke(cli.app, ["kaisen", "promote"])
    assert result.exit_code == 0 and "PROMOTION PLAN" in result.output

