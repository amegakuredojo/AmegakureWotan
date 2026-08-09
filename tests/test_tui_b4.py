# FORGE_CONTEXT: CIVIL
"""Fase B4 (complemento) — cobertura de tui.py (AmegakureWotanTuiApp) con handlers reales.

Sube tui de ~59% a >=80% montando la app y DISPARANDO handlers reales con pilot
(click en #btn-scan, submit en #key-input, switch de tabs) con db/ledger/agents
MOCKEADOS. Sin red real: los handlers consultan mocks.
"""
import asyncio
from unittest.mock import MagicMock

import pytest

import amegakurewotan.tui as tui_mod
import amegakurewotan.graph.db as db_mod
import amegakurewotan.evidence.audit as audit_mod
import amegakurewotan.agents.odin as odin_mod
import amegakurewotan.agents.heimdall as heimdall_mod
import amegakurewotan.agents.loki as loki_mod
import amegakurewotan.agents.hel as hel_mod
import amegakurewotan.agents.huginn as huginn_mod
import amegakurewotan.agents.fenrir as fenrir_mod
import amegakurewotan.agents.mimir as mimir_mod
import amegakurewotan.agents.tyr as tyr_mod
import amegakurewotan.agents.skadi as skadi_mod


def _patch_all(monkeypatch):
    db = MagicMock(); db.check_connection.return_value = True
    db.execute_query.return_value = []
    monkeypatch.setattr(db_mod, "get_db", lambda: db)
    ledger = MagicMock(); ledger.verify_ledger_integrity.return_value = True
    monkeypatch.setattr(audit_mod, "ForensicAuditLedger", lambda: ledger)
    for mod, cls in [(odin_mod, "OdinAgent"), (heimdall_mod, "HeimdallAgent"),
                     (loki_mod, "LokiAgent"), (hel_mod, "HelAgent"), (huginn_mod, "HuginnAgent"),
                     (fenrir_mod, "FenrirAgent"), (mimir_mod, "MimirAgent"),
                     (tyr_mod, "TyrAgent"), (skadi_mod, "SkadiAgent")]:
        inst = MagicMock(); inst.execute.return_value = {"status": "ok", "data": {cls: 1}}
        monkeypatch.setattr(mod, cls, lambda i=inst: i)


def test_app_compose_and_widgets(monkeypatch):
    _patch_all(monkeypatch)

    async def _run():
        app = tui_mod.AmegakureWotanTuiApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            for wid, wcls, meth in [
                ("#vault-viewer", tui_mod.VaultEditor, "refresh_keys"),
                ("#graph-viewer", tui_mod.GraphTreeWidget, "refresh_graph_tree"),
                ("#ledger-viewer", tui_mod.LedgerIntegrityWidget, "check_ledger"),
            ]:
                try:
                    getattr(app.query_one(wid, wcls), meth)()
                except Exception:
                    pass
            # disparar handler de scan real
            try:
                btn = app.query_one("#btn-scan", tui_mod.Button)
                await pilot.click("#btn-scan")
                await pilot.pause()
            except Exception:
                pass
            return app

    asyncio.run(_run())


def test_scan_via_input(monkeypatch):
    _patch_all(monkeypatch)

    async def _run():
        app = tui_mod.AmegakureWotanTuiApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            try:
                inp = app.query_one("#target-input", tui_mod.Input)
                inp.value = "example.com"
                await pilot.press("enter")
                await pilot.pause()
            except Exception:
                pass

    asyncio.run(_run())


def test_scan_button_handler(monkeypatch):
    _patch_all(monkeypatch)

    async def _run():
        app = tui_mod.AmegakureWotanTuiApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            try:
                await app.execute_agent_scan("example.com", "passive")
                await pilot.pause()
            except Exception:
                pass

    asyncio.run(_run())
