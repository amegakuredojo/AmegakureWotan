# FORGE_CONTEXT: CIVIL
"""Fase B4 (complemento) — cobertura de evidence/audit (log branches) y
evidence/forensics (append/read/verify) con fs tmp aislado y db offline.

Sube evidence/audit (22%->~70%) y evidence/forensics (84%->~95%) ejercitando
log_execution con parametros/evidence variados, verify_ledger_integrity con
records reales, ChainOfCustody.append/read_all/verify_chain con timeline aislado.
Sin salida fabricada: fs tmp real, db forzada offline.
"""
import json
from unittest.mock import MagicMock

import pytest

import amegakurewotan.config as config_mod
import amegakurewotan.evidence.audit as audit_mod
import amegakurewotan.evidence.forensics as forensics_mod
import amegakurewotan.graph.db as db_mod


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(config_mod, "_config", None)
    monkeypatch.setattr(db_mod, "_db_instance", None)
    monkeypatch.setattr(db_mod.GraphDB, "check_connection", lambda self: False)
    yield tmp_path


def test_audit_log_metadata(isolated):
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger.log_execution(
        agent_name="odin", action="correlate",
        parameters={"target": "x.com", "operator": "lugh"},
        findings=[{"confidence": 0.9, "type": "email"}],
        evidence_files=[{"path": "ev-1", "hash_sha512": "deadbeef"}],
        operator_id="lugh", target_id="x.com",
    )
    lines = ledger.ledger_path.read_text().strip().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["payload"]["agent"] == "odin"


def test_audit_verify_with_records(isolated):
    ledger = audit_mod.ForensicAuditLedger()
    ledger.ledger_path.parent.mkdir(parents=True, exist_ok=True)
    ledger.log_execution("heimdall", "recon", {"target": "a.com"}, [{"confidence": 0.8}], [])
    ledger.log_execution("odin", "correlate", {}, [{"confidence": 0.9}], [])
    assert ledger.verify_ledger_integrity() is True


def test_forensics_append_read_verify(isolated):
    coc = forensics_mod.ChainOfCustody()
    h = forensics_mod.sha512_bytes(b"x.com")
    coc.append(collector_id="lugh", event_type="op.start", payload_hash=h,
               roe_ref="roe-1", metadata={"tool": "recon.passive_scan"})
    coc.append(collector_id="lugh", event_type="op.completed", payload_hash=h,
               roe_ref="roe-1", metadata={"tool": "recon.passive_scan"})
    all_records = coc.read_all()
    assert len(all_records) == 2
    result = coc.verify_chain()
    assert result.is_valid is True
    assert result.checked_records == 2
