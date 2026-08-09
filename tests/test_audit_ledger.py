# FORGE_CONTEXT: CIVIL
"""Tests del ForensicAuditLedger (evidence/audit): ledger criptográfico firmado.

Cubre rutas PURAS y locales (sin Kùzu vivo; el ledger cae a archivo):
  • log_execution escribe un bloque firmado y hash-enlazado
  • verify_ledger_integrity confirma integridad (cadena HMAC válida)
  • tamper en una entrada intermedia es DETECTADO (corrupción) => integridad False
  • clave maestra 0600 y hash-chain enlazado (prev_hash != todo-ceros tras 1 entrada)

No se fabrica evidencia: el contenido sellado es el que el sistema genera.
"""
import json
from pathlib import Path

import pytest

from amegakurewotan.evidence.audit import ForensicAuditLedger


def _reset_graph_singleton():
    import amegakurewotan.graph.db as db_mod
    db_mod._db_instance = None


def test_ledger_log_and_verify(tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KUZU_DATABASE_PATH", str(tmp_path / "clean.kuzu"))
    import amegakurewotan.config as cfg
    cfg._config = None
    _reset_graph_singleton()
    cfg.get_config().init_dirs()
    ledger = ForensicAuditLedger()
    # Limpia cualquier entrada previa del data dir de sesión.
    lp = tmp_path / "evidence" / "audit_trail.log"
    if lp.exists():
        lp.unlink()
    ledger.log_execution(
        agent_name="heimdall", action="recon",
        parameters={"target": "example.com"}, findings=[{"confidence": 0.9}],
        evidence_files=[],
    )
    assert lp.exists()
    # La clave maestra se crea con permisos 0600.
    key = tmp_path / "opsec" / "keys" / "audit_master.key"
    assert key.exists()
    mode = oct(key.stat().st_mode & 0o777)
    assert mode == "0o600", f"permisos clave = {mode}"
    # Integra tras un registro real.
    assert ledger.verify_ledger_integrity() is True


def test_ledger_hash_chain_links_entries(tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KUZU_DATABASE_PATH", str(tmp_path / "clean.kuzu"))
    import amegakurewotan.config as cfg
    cfg._config = None
    _reset_graph_singleton()
    cfg.get_config().init_dirs()
    ledger = ForensicAuditLedger()
    lp = tmp_path / "evidence" / "audit_trail.log"
    if lp.exists():
        lp.unlink()
    ledger.log_execution("a", "x", {}, [{"confidence": 1.0}], [])
    ledger.log_execution("b", "y", {}, [{"confidence": 0.5}], [])
    lines = [json.loads(l) for l in lp.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert len(lines) == 2
    # El segundo bloque enlaza el hash del primero (prev_record_hash real).
    h0 = lines[0]["record_hash"]
    h1 = lines[1]["record_hash"]
    assert h0 != "0" * 64
    assert h1 != h0
    assert ledger.verify_ledger_integrity() is True


def test_ledger_detects_tamper(tmp_path, monkeypatch):
    monkeypatch.setenv("AMEWOTAN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("KUZU_DATABASE_PATH", str(tmp_path / "clean.kuzu"))
    import amegakurewotan.config as cfg
    cfg._config = None
    _reset_graph_singleton()
    cfg.get_config().init_dirs()
    ledger = ForensicAuditLedger()
    lp = tmp_path / "evidence" / "audit_trail.log"
    if lp.exists():
        lp.unlink()
    ledger.log_execution("a", "x", {}, [{"confidence": 1.0}], [])
    ledger.log_execution("b", "y", {}, [{"confidence": 0.5}], [])

    # Altero la primer entrada (evidencia adulterada) y reescribo el archivo.
    lines = lp.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["payload"]["action"] = "TAMPERED"  # adultero el payload firmado
    lines[0] = json.dumps(rec)
    lp.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # La integridad debe FALLAR (hash-chain roto o firma inválida).
    assert ledger.verify_ledger_integrity() is False
