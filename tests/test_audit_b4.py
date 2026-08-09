# FORGE_CONTEXT: CIVIL
"""Fase B4 (complemento) — cobertura de evidence/audit.py (ForensicAuditLedger).

Sube evidence/audit de 22% a >=80% con fs real en tmp (config.base_dir redirigido
por fixture tmp_data_dir). Sin fabricar: el ledger real escribe/verifica hash-chain
y HMAC con la master key generada en tmp.
"""
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import amegakurewotan.evidence.audit as audit_mod
from amegakurewotan.config import get_config
import amegakurewotan.config as config_mod


def test_ledger_init_creates_key(tmp_data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None)
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    assert ledger.key_path.exists()
    assert ledger.ledger_path.parent.exists()


def test_log_execution_writes_record(tmp_data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None)
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    rec = ledger.log_execution(
        agent_name="heimdall",
        action="recon",
        parameters={"target": "example.com"},
        findings=[{"confidence": 0.9, "value": "1.2.3.4"}],
        evidence_files=[{"path": "/ev/x.png"}]
    )
    assert "record_hash" in rec and "signature" in rec
    # hash-chain link escrito en archivo
    lines = ledger.ledger_path.read_text().strip().splitlines()
    assert len(lines) == 1


def test_log_execution_no_findings(tmp_data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None)
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    rec = ledger.log_execution("odin", "correlate", {}, [], [])
    assert rec["payload"]["confidence_summary"]["average_confidence"] == 0.0


def test_pgp_sign_unavailable(tmp_data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None)
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    # gpg no disponible en entorno headless => devuelve None
    assert ledger._try_pgp_sign("payload") is None


def test_key_rotation_new_key(tmp_data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None)
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    # forzar antiguedad de la key > 30 dias
    old = ledger.key_path.stat().st_mtime - (40 * 86400)
    import os
    os.utime(ledger.key_path, (old, old))
    monkeypatch.setenv("AMEWOTAN_KEY_ROTATION_DAYS", "30")
    ledger._check_key_rotation()
    # la key vieja se archiva y se crea una nueva
    assert ledger.key_path.exists()
    assert list(ledger.keys_dir.glob("audit_master_*.key.bak"))


def _force_db_offline(monkeypatch):
    import amegakurewotan.graph.db as db_mod
    monkeypatch.setattr(db_mod, "_db_instance", None)
    monkeypatch.setattr(db_mod.GraphDB, "check_connection", lambda self: False)


def test_verify_empty_ledger(tmp_data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None)
    _force_db_offline(monkeypatch)
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    assert ledger.verify_ledger_integrity() is True


def test_verify_valid_ledger(tmp_data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None)
    _force_db_offline(monkeypatch)
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger.log_execution("heimdall", "recon", {"target": "a.com"},
                        [{"confidence": 0.8}], [])
    ledger.log_execution("odin", "correlate", {}, [{"confidence": 0.9}], [])
    assert ledger.verify_ledger_integrity() is True


def test_verify_corrupt_ledger(tmp_data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None)
    _force_db_offline(monkeypatch)
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger.ledger_path.write_text('{"payload": {}, "signature": "x", "record_hash": "y"}\n')
    assert ledger.verify_ledger_integrity() is False


def test_run_self_test(tmp_data_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None)
    _force_db_offline(monkeypatch)
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    assert ledger.run_self_test() is True
