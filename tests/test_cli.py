# FORGE_CONTEXT: CIVIL
"""Tests de cli.py (CLI principal `amewotan`, harness histórico).

Solo comandos PUROS/deterministas que NO invocan agentes en vivo ni DB:
  • init  (crea dirs + ledger, check_connection puede ser False en tests)
  • audit verify (integridad del ForensicAuditLedger en tmp)
  • kaisen list / playbooks (leen lessons_learned.json del data dir)

Los comandos recon/humint/darkweb/entity/graph.* requieren agentes o Kùzu vivo
y se documentan en el ADR de cobertura como "requieren harness integración".
No se mockean para fingir cobertura: la doctrina prohíbe salida fabricada.
"""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from amegakurewotan.cli import app

runner = CliRunner(env={"COLUMNS": "200"})


def test_init_creates_dirs(tmp_data_dir):
    # tmp_data_dir autouse ya existe; init() re-crea y reporta OK.
    r = runner.invoke(app, ["init"])
    assert r.exit_code == 0, r.stdout
    # init() garantiza que los subdirectorios esperados existan tras la llamada.
    for sub in ("bin", "evidence", "opsec/roe", "reports", "sessions"):
        assert (tmp_data_dir / sub).is_dir(), f"falta dir: {sub}"


def test_audit_verify_reports_status(tmp_data_dir):
    # Sin ledger => verify debe reportar sin crashear (maneja archivo ausente).
    r = runner.invoke(app, ["audit", "verify"])
    assert r.exit_code == 0
    assert "Integrity" in r.stdout


def test_kaisen_list_empty(tmp_data_dir):
    r = runner.invoke(app, ["kaisen", "list"])
    assert r.exit_code == 0
    assert "No lessons" in r.stdout


def test_kaisen_playbooks_empty(tmp_data_dir):
    r = runner.invoke(app, ["kaisen", "playbooks"])
    assert r.exit_code == 0
    assert "No playbooks" in r.stdout


def test_kaisen_list_with_lessons(tmp_data_dir):
    lessons = [{
        "timestamp": 1700000000.0, "target": "example.com", "target_type": "Domain",
        "session_id": "sess-1", "status": "completed", "consensus_status": "confirmed",
        "playbooks": ["linkedin -> breach"],
    }]
    (tmp_data_dir / "kaisen").mkdir(exist_ok=True)
    (tmp_data_dir / "kaisen" / "lessons_learned.json").write_text(
        json.dumps(lessons), encoding="utf-8",
    )
    rl = runner.invoke(app, ["kaisen", "list"])
    assert rl.exit_code == 0
    assert "example.com" in rl.stdout
    rp = runner.invoke(app, ["kaisen", "playbooks"])
    assert rp.exit_code == 0
    assert "linkedin -> breach" in rp.stdout
