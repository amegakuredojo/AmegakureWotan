# FORGE_CONTEXT: CIVIL
"""Fase B3 (complemento) — cobertura de adapters (capa + L3).

Sube adapters/web, social, archive, darkweb, graph, evidence, l3/theharvester,
l3/greynoise a >=80% con make_tor_request/get_db mockeados. Sin salida fabricada:
los L3 sin binario/clave devuelven tool_unavailable (lo verificamos).
"""
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import amegakurewotan.utils.net as net_mod
import amegakurewotan.adapters.web as web_mod
import amegakurewotan.adapters.social as social_mod
import amegakurewotan.adapters.archive as archive_mod
import amegakurewotan.adapters.darkweb as darkweb_mod
import amegakurewotan.adapters.graph as graph_mod
import amegakurewotan.adapters.evidence as evidence_mod
import amegakurewotan.adapters.l3.theharvester as theh_mod
import amegakurewotan.adapters.l3.greynoise as grey_mod


class _Resp:
    def __init__(self, status_code=200, text="", json_data=None):
        self.status_code = status_code
        self.text = text
        self._json = json_data or {}
    def json(self):
        return self._json


def _mock_net(monkeypatch, resp, *mods):
    for m in mods:
        monkeypatch.setattr(m, "make_tor_request", lambda *a, **k: resp)


# ── web ──────────────────────────────────────────────────────────────────────
def test_web_fetch_200(monkeypatch):
    _mock_net(monkeypatch, _Resp(200, "<html>ok</html>"), web_mod)
    assert web_mod.WebAdapter().fetch_page("http://x") == "<html>ok</html>"


def test_web_fetch_404(monkeypatch):
    _mock_net(monkeypatch, _Resp(404), web_mod)
    assert web_mod.WebAdapter().fetch_page("http://x") == ""


def test_web_fetch_error(monkeypatch):
    monkeypatch.setattr(web_mod, "make_tor_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert web_mod.WebAdapter().fetch_page("http://x") == ""


# ── social ───────────────────────────────────────────────────────────────────
def test_social_200(monkeypatch):
    _mock_net(monkeypatch, _Resp(200), social_mod)
    assert social_mod.SocialAdapter().check_profile_exists("github", "john") == "https://github.com/john"


def test_social_404(monkeypatch):
    _mock_net(monkeypatch, _Resp(404), social_mod)
    assert social_mod.SocialAdapter().check_profile_exists("twitter", "john") is None


def test_social_unknown_platform(monkeypatch):
    _mock_net(monkeypatch, _Resp(200), social_mod)
    assert social_mod.SocialAdapter().check_profile_exists("myspace", "john") is None


def test_social_error(monkeypatch):
    monkeypatch.setattr(social_mod, "make_tor_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    assert social_mod.SocialAdapter().check_profile_exists("github", "john") is None


# ── archive ──────────────────────────────────────────────────────────────────
def test_archive_snapshots(monkeypatch):
    _mock_net(monkeypatch, _Resp(200, json_data={"archived_snapshots": {"closest": {"timestamp": "2020", "url": "http://a", "status": "200"}}}), archive_mod)
    snaps = archive_mod.ArchiveAdapter().get_wayback_snapshots("example.com")
    assert snaps and snaps[0]["timestamp"] == "2020"


def test_archive_no_snapshots(monkeypatch):
    _mock_net(monkeypatch, _Resp(200, json_data={}), archive_mod)
    assert archive_mod.ArchiveAdapter().get_wayback_snapshots("example.com") == []


def test_archive_error(monkeypatch):
    monkeypatch.setattr(archive_mod, "make_tor_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    assert archive_mod.ArchiveAdapter().get_wayback_snapshots("example.com") == []


# ── darkweb ──────────────────────────────────────────────────────────────────
def test_darkweb_query_200(monkeypatch):
    _mock_net(monkeypatch, _Resp(200, "<html>leak</html>"), darkweb_mod)
    assert darkweb_mod.DarkWebAdapter().query_onion("http://x.onion") == "<html>leak</html>"


def test_darkweb_query_none(monkeypatch):
    _mock_net(monkeypatch, _Resp(500), darkweb_mod)
    assert darkweb_mod.DarkWebAdapter().query_onion("http://x.onion") is None


def test_darkweb_query_error(monkeypatch):
    monkeypatch.setattr(darkweb_mod, "make_tor_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError()))
    assert darkweb_mod.DarkWebAdapter().query_onion("http://x.onion") is None


def test_darkweb_parse_leak_db():
    html = "john@x.com:pass123\nadmin@corp.com:abc123:deadbeef\nno match line"
    res = darkweb_mod.DarkWebAdapter().parse_leak_db(html, "john")
    assert any(r["emails"] for r in res)
    res2 = darkweb_mod.DarkWebAdapter().parse_leak_db("", "x")
    assert res2 == []


# ── graph ───────────────────────────────────────────────────────────────────
def test_graph_schema_connected(monkeypatch):
    db = MagicMock(); db.check_connection.return_value = True
    db.execute_query.return_value = [{"label": "Entity"}]
    monkeypatch.setattr(graph_mod, "get_db", lambda: db)
    assert graph_mod.GraphAdapter().query_schema() == [{"label": "Entity"}]


def test_graph_schema_offline(monkeypatch):
    db = MagicMock(); db.check_connection.return_value = False
    monkeypatch.setattr(graph_mod, "get_db", lambda: db)
    assert graph_mod.GraphAdapter().query_schema() == []


def test_graph_neighbors(monkeypatch):
    db = MagicMock(); db.check_connection.return_value = True
    db.execute_query.return_value = [{"value": "y", "relationship": "X"}]
    monkeypatch.setattr(graph_mod, "get_db", lambda: db)
    assert graph_mod.GraphAdapter().get_neighbors("x") == [{"value": "y", "relationship": "X"}]


def test_graph_neighbors_offline(monkeypatch):
    db = MagicMock(); db.check_connection.return_value = False
    monkeypatch.setattr(graph_mod, "get_db", lambda: db)
    assert graph_mod.GraphAdapter().get_neighbors("x") == []


# ── evidence ─────────────────────────────────────────────────────────────────
def test_evidence_store(tmp_data_dir):
    p = evidence_mod.EvidenceAdapter().store_raw_evidence("f.bin", b"data", folder="html")
    assert p.exists() and p.read_bytes() == b"data"


def test_evidence_store_error(monkeypatch, tmp_data_dir):
    import builtins
    real_open = builtins.open
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(builtins, "open", boom)
    with pytest.raises(OSError):
        evidence_mod.EvidenceAdapter().store_raw_evidence("f.bin", b"data")
    monkeypatch.setattr(builtins, "open", real_open)


# ── L3 theharvester (tool_unavailable si falta binario) ─────────────────────
def test_theharvester_unavailable(monkeypatch):
    monkeypatch.setattr(theh_mod, "_binary", lambda: None)
    res = theh_mod.theharvester_run("example.com")
    assert res["status"] == "tool_unavailable"


def test_theharvester_runs(monkeypatch):
    monkeypatch.setattr(theh_mod, "_binary", lambda: "theharvester")
    fake = MagicMock(); fake.returncode = 0; fake.stdout = "result"; fake.stderr = ""
    monkeypatch.setattr(theh_mod.subprocess, "run", lambda *a, **k: fake)
    res = theh_mod.theharvester_run("example.com")
    assert res["status"] == "ok"


# ── L3 greynoise (tool_unavailable si falta clave) ──────────────────────────
def test_greynoise_unavailable(monkeypatch):
    monkeypatch.setattr(grey_mod, "_api_key", lambda: None)
    res = grey_mod.greynoise_ip_report("1.2.3.4")
    assert res["status"] == "tool_unavailable"


def test_greynoise_report(monkeypatch):
    monkeypatch.setattr(grey_mod, "_api_key", lambda: "fake-key")
    fake = MagicMock(); fake.status_code = 200
    fake.json.return_value = {"ip": "1.2.3.4", "classification": "benign"}
    monkeypatch.setattr(grey_mod, "requests", MagicMock())
    grey_mod.requests.get.return_value = fake
    res = grey_mod.greynoise_ip_report("1.2.3.4")
    assert res["status"] == "ok" and res["classification"] == "benign"
