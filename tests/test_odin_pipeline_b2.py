# FORGE_CONTEXT: CIVIL
"""Fase B2 (complemento) — cobertura del pipeline langgraph de OdinAgent.

Sube odin.py de 21% a >=80% ejecutando OdinAgent().execute() con TODOS los
sub-agentes y dependencias (db/ledger/export) MOCKEADAS. Sin salida fabricada:
db.check_connection()=False fuerza las ramas mock del pipeline (correlate usa
correlaciones mock, freeze/report generan archivos reales en tmp). El ledger se
mockea para no tocar Kuzu/fs forense real.
"""
from unittest.mock import MagicMock

import pytest

from amegakurewotan.agents import odin as odin_mod


def _patch_odin_pipeline(monkeypatch):
    # db offline => ramas mock del pipeline (sin Kuzu)
    fake_db = MagicMock()
    fake_db.check_connection.return_value = False
    monkeypatch.setattr(odin_mod, "get_db", lambda: fake_db)

    # ledger mock (sin fs forense real)
    ledger = MagicMock()
    ledger.verify_ledger_integrity.return_value = True
    monkeypatch.setattr(odin_mod, "ForensicAuditLedger", lambda: ledger)

    # ledger gate siempre pasa
    monkeypatch.setattr(odin_mod, "check_ledger_gate", lambda state, name: True)

    # agentes subordinados mock con contratos realistas
    heimdall = MagicMock()
    heimdall.execute.return_value = {"subdomains": ["api.example.com"], "ips": ["1.2.3.4"], "source": "heimdall"}
    loki = MagicMock()
    loki.execute.return_value = {"profiles": [{"platform": "github", "url": "https://github.com/x"}],
                                  "emails": ["x@proton.me"], "source": "loki"}
    hel = MagicMock()
    hel.execute.return_value = {"onion_sites": [{"onion": "leaks.onion", "title": "LD"}],
                                 "leaks_found": [], "source": "hel"}
    huginn = MagicMock()
    huginn.execute.return_value = {"hes": 0.5, "certainty": 60, "status": "HYPOTHESIS", "source": "huginn"}
    mimir = MagicMock()
    mimir.execute.return_value = {"ok": True}
    tyr = MagicMock()
    tyr.execute.return_value = {"is_trusted": True, "conflicting": False, "consensus_score": 0.9}
    skadi = MagicMock()
    skadi.execute.return_value = {"filename": "ev.json", "sha512": "abc", "bytes_size": 10}

    for name, inst in [("HeimdallAgent", heimdall), ("LokiAgent", loki), ("HelAgent", hel),
                       ("MimirAgent", mimir), ("TyrAgent", tyr), ("SkadiAgent", skadi)]:
        monkeypatch.setattr(odin_mod, name, lambda i=inst: i)

    # HuginnAgent se importa localmente dentro de correlate_node
    import amegakurewotan.agents.huginn as huginn_mod
    monkeypatch.setattr(huginn_mod, "HuginnAgent", lambda: huginn)

    # Nota: export_to_json se importa localmente en correlate_node y solo se usa
    # si db.check_connection()=True. Con db offline no se invoca, no hay que parchearlo.


def test_odin_pipeline_success(monkeypatch, tmp_data_dir):
    _patch_odin_pipeline(monkeypatch)
    agent = odin_mod.OdinAgent()
    state = agent.execute("example.com")
    assert state["status"] == "completed"
    assert state["dossier"]["report_path"]


def test_odin_pipeline_resume(monkeypatch, tmp_data_dir):
    _patch_odin_pipeline(monkeypatch)
    agent = odin_mod.OdinAgent()
    # crear checkpoint previo
    odin_mod.save_checkpoint({"session_id": "resume-s", "target": "x.com", "phase": "recon",
                              "findings": [], "correlations": [], "evidence": [], "dossier": {},
                              "status": "active", "errors": [], "retry_count": {}, "consensus_status": "trusted"})
    state = agent.execute("", session_id="resume-s")
    assert state["session_id"] == "resume-s"


def test_odin_pipeline_resume_not_found(monkeypatch, tmp_data_dir):
    _patch_odin_pipeline(monkeypatch)
    agent = odin_mod.OdinAgent()
    with pytest.raises(ValueError):
        agent.execute("", session_id="no-existe-xyz")


def test_odin_validate_blocked(monkeypatch, tmp_data_dir):
    # tyr devuelve conflicting => pipeline bloqueado
    _patch_odin_pipeline(monkeypatch)
    tyr = MagicMock()
    tyr.execute.return_value = {"is_trusted": False, "conflicting": True, "consensus_score": 0.2}
    monkeypatch.setattr(odin_mod, "TyrAgent", lambda: tyr)
    agent = odin_mod.OdinAgent()
    state = agent.execute("example.com")
    assert state["status"] == "failed"
    assert state["consensus_status"] == "blocked"
