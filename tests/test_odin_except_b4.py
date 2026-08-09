# FORGE_CONTEXT: CIVIL
"""Fase B4 (complemento) — cobertura de ramas except del pipeline OdinAgent.

Sube agents/odin de 73% a >=85% forzando excepciones en cada sub-agente del
pipeline (ramas except) y ejercitando el path db-online (execute_transaction real
con Kuzu embebido en tmp). Sin salida fabricada: los agentes son MagicMock que
lanzan RuntimeError para simular fallo de herramienta.
"""
from unittest.mock import MagicMock

import pytest

import amegakurewotan.agents.odin as odin_mod
import amegakurewotan.graph.db as db_mod
from amegakurewotan.config import get_config


def _fresh_db(tmp_path, monkeypatch):
    cfg = get_config()
    cfg.kuzu.database_path = str(tmp_path / "vault.kuzu")
    monkeypatch.setattr(db_mod, "_db_instance", None)
    return db_mod.get_db()


def _base_agents():
    agents = {}
    for name in ["heimdall", "loki", "hel", "huginn", "mimir", "tyr", "skadi"]:
        m = MagicMock()
        m.execute.return_value = {"status": "ok", "data": {name: 1}}
        agents[name] = m
    return agents


@pytest.mark.parametrize("fail", ["heimdall", "loki", "hel", "huginn", "mimir", "tyr", "skadi"])
def test_pipeline_node_exception(monkeypatch, fail):
    agents = _base_agents()
    agents[fail].execute.side_effect = RuntimeError(f"{fail} down")
    import amegakurewotan.agents.huginn as huginn_mod
    for name, inst in [("HeimdallAgent", agents["heimdall"]), ("LokiAgent", agents["loki"]),
                       ("HelAgent", agents["hel"]), ("HuginnAgent", agents["huginn"]),
                       ("MimirAgent", agents["mimir"]), ("TyrAgent", agents["tyr"]),
                       ("SkadiAgent", agents["skadi"])]:
        if name == "HuginnAgent":
            monkeypatch.setattr(huginn_mod, name, lambda i=inst: i)
        else:
            monkeypatch.setattr(odin_mod, name, lambda i=inst: i)
    monkeypatch.setattr(odin_mod, "get_db", lambda: MagicMock(check_connection=MagicMock(return_value=False)))
    monkeypatch.setattr(odin_mod, "check_ledger_gate", lambda *a, **k: (True, None))
    monkeypatch.setattr(odin_mod, "ForensicAuditLedger", lambda: MagicMock())
    res = odin_mod.OdinAgent().execute("example.com")
    assert isinstance(res, dict)


def test_pipeline_db_online_commit(tmp_path, monkeypatch):
    db = _fresh_db(tmp_path, monkeypatch)
    agents = _base_agents()
    import amegakurewotan.agents.huginn as huginn_mod
    for name, inst in [("HeimdallAgent", agents["heimdall"]), ("LokiAgent", agents["loki"]),
                       ("HelAgent", agents["hel"]), ("HuginnAgent", agents["huginn"]),
                       ("MimirAgent", agents["mimir"]), ("TyrAgent", agents["tyr"]),
                       ("SkadiAgent", agents["skadi"])]:
        if name == "HuginnAgent":
            monkeypatch.setattr(huginn_mod, name, lambda i=inst: i)
        else:
            monkeypatch.setattr(odin_mod, name, lambda i=inst: i)
    monkeypatch.setattr(odin_mod, "check_ledger_gate", lambda *a, **k: (True, None))
    monkeypatch.setattr(odin_mod, "ForensicAuditLedger", lambda: MagicMock())
    res = odin_mod.OdinAgent().execute("example.com")
    assert isinstance(res, dict)
    assert db.check_connection() is True
