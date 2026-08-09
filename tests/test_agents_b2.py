# FORGE_CONTEXT: CIVIL
"""Fase B2 — cobertura de agentes (odin/norn/fenrir/hel/loki/huginn/heimdall).

Sube los agentes de 3-75% a >=80% ejercitando contratos reales con
dependencias (red/tor/skills/multiprocessing) MOCKEADAS:
- norn/fenrir/odin: deterministas o con get_db mock.
- hel/loki/huginn: parcheamos opsec.run_isolated_process para ejecutar la
  funcion inline (sin multiprocessing real) y enforce_opsec_policy a no-op,
  y mockeamos los adapters (DarkWebAdapter/SocialAdapter) y los sub-agentes
  internos de huginn. NO fabricamos salida: los adapters mockeados devuelven
  estructuras vacias/realistas segun el codigo.
"""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from amegakurewotan.agents import odin as odin_mod
from amegakurewotan.agents import norn as norn_mod
from amegakurewotan.agents import fenrir as fenrir_mod
from amegakurewotan.agents import hel as hel_mod
from amegakurewotan.agents import loki as loki_mod
from amegakurewotan.agents import huginn as huginn_mod
from amegakurewotan.agents import heimdall as heimdall_mod
from amegakurewotan.policy import opsec


# ── Helper: ejecutar inline (sin multiprocessing) para hel/loki/huginn ─────
# Parcheamos a nivel de modulo del agente porque importan los nombres
# directamente desde opsec (from ... import run_isolated_process).
def _inline_isolation(monkeypatch):
    for mod in (opsec, hel_mod, loki_mod, huginn_mod):
        monkeypatch.setattr(mod, "run_isolated_process", lambda f, *a, **k: f(), raising=False)
        monkeypatch.setattr(mod, "enforce_opsec_policy", lambda *a, **k: None, raising=False)
        monkeypatch.setattr(mod, "check_tor_socks_proxy", lambda *a, **k: True, raising=False)


# ── norn (determinista, 100% cubrible) ───────────────────────────────────────
def test_norn_normalize_value():
    n = norn_mod.NornAgent()
    assert n.normalize_value("1.2.3.4") == ("1.2.3.4", "IP")
    assert n.normalize_value("a@b.com") == ("a@b.com", "Email")
    assert n.normalize_value("x.onion") == ("x.onion", "Domain")
    assert n.normalize_value("example.com") == ("example.com", "Domain")
    assert n.normalize_value("john") == ("john", "Alias")


def test_norn_vague_query():
    n = norn_mod.NornAgent()
    with pytest.raises(ValueError):
        n.execute("hello")


def test_norn_ambiguous_query():
    n = norn_mod.NornAgent()
    with pytest.raises(ValueError):
        n.execute("how do I find things")


def test_norn_traverse():
    n = norn_mod.NornAgent()
    out = n.execute("traverse from example.com depth 2")
    assert "MATCH p" in out and "example.com" in out


def test_norn_traverse_with_filters():
    n = norn_mod.NornAgent()
    out = n.execute("traverse from example.com depth 2 filter edge RESOLVES_TO source heimdall time 2026-06-11")
    assert "resolves_to" in out and "heimdall" in out


def test_norn_reverse_pivot():
    n = norn_mod.NornAgent()
    out = n.execute("reverse pivot to identity from x.onion")
    assert "m:Alias" in out or "Alias" in out


def test_norn_common_neighbors():
    n = norn_mod.NornAgent()
    out = n.execute("common neighbors of a.com and b.com")
    assert "common" in out.lower() or "MATCH" in out


def test_norn_shared_identifiers():
    n = norn_mod.NornAgent()
    out = n.execute("shared identifiers of a.com and b.com")
    assert "MATCH" in out


def test_norn_path_intersection():
    n = norn_mod.NornAgent()
    out = n.execute("path intersection between a.com and b.com")
    assert "MATCH" in out


def test_norn_temporal():
    n = norn_mod.NornAgent()
    out = n.execute("list nodes created after 2026-06-11")
    assert "created_at" in out


def test_norn_pivot():
    n = norn_mod.NornAgent()
    out = n.execute("pivot from example.com to Domain")
    assert "Domain" in out


def test_norn_multihop():
    n = norn_mod.NornAgent()
    out = n.execute("find paths of 3 hops from example.com")
    assert "[*..3]" in out


def test_norn_path_hops():
    n = norn_mod.NornAgent()
    out = n.execute("path between a.com and b.com up to 4 hops")
    assert "[*..4]" in out


def test_norn_path_default():
    n = norn_mod.NornAgent()
    out = n.execute("path between a.com and b.com")
    assert "shortestPath" in out


def test_norn_connected_to():
    n = norn_mod.NornAgent()
    out = n.execute("show connections to example.com")
    assert "MATCH" in out


def test_norn_list_type():
    n = norn_mod.NornAgent()
    out = n.execute("list domains")
    assert "MATCH (n:Domain)" in out


def test_norn_fallback():
    n = norn_mod.NornAgent()
    out = n.execute("weirdquerything")
    assert "CONTAINS" in out


# ── fenrir (puro, escribe subgraph) ─────────────────────────────────────────
def test_fenrir_temporal_correlation(tmp_data_dir):
    f = fenrir_mod.FenrirAgent()
    data = {
        "nodes": [
            {"properties": {"value": "a.com", "created_at": 1000}, "labels": ["Domain"]},
            {"properties": {"value": "b.com", "created_at": 110000}, "labels": ["Domain"]},
        ],
        "edges": [],
    }
    out = f.execute(data, session_id="b2")
    assert isinstance(out, list)


def test_fenrir_multihop_correlation(tmp_data_dir):
    f = fenrir_mod.FenrirAgent()
    data = {
        "nodes": [
            {"properties": {"value": "john", "created_at": 1}, "labels": ["Alias"]},
            {"properties": {"value": "john@x.com", "created_at": 2}, "labels": ["Email"]},
            {"properties": {"value": "x.com", "created_at": 3}, "labels": ["Domain"]},
        ],
        "edges": [
            {"source_value": "john", "target_value": "john@x.com", "relationship": "HAS_EMAIL",
             "properties": {"source": "loki"}},
            {"source_value": "john@x.com", "target_value": "x.com", "relationship": "RESOLVES_TO",
             "properties": {"source": "heimdall"}},
        ],
    }
    out = f.execute(data, session_id="b2b")
    assert any(c["rel_type"] == "CORRELATED_WITH" for c in out)


def test_fenrir_subdomain_suffix(tmp_data_dir):
    f = fenrir_mod.FenrirAgent()
    data = {
        "nodes": [
            {"properties": {"value": "example.com"}, "labels": ["Domain"]},
            {"properties": {"value": "sub.example.com"}, "labels": ["Domain"]},
        ],
        "edges": [],
    }
    out = f.execute(data, session_id="b2c")
    assert any(c["rel_type"] == "HAS_SUBDOMAIN" for c in out)


def test_fenrir_no_correlations(tmp_data_dir):
    f = fenrir_mod.FenrirAgent()
    data = {"nodes": [{"properties": {"value": "x.com"}, "labels": ["Domain"]}], "edges": []}
    out = f.execute(data, session_id="b2d")
    assert out == []


# ── odin (save/load checkpoint + process_finding/connection con db mock) ────
def test_odin_save_load_checkpoint(monkeypatch, tmp_data_dir):
    state = {"session_id": "odin-s1", "target": "example.com", "phase": "recon",
             "findings": [], "correlations": [], "evidence": [], "dossier": {},
             "status": "running", "errors": [], "retry_count": {}, "consensus_status": "pending"}
    odin_mod.save_checkpoint(state)
    loaded = odin_mod.load_checkpoint("odin-s1")
    assert loaded is not None
    assert loaded["session_id"] == "odin-s1"


def test_odin_load_checkpoint_missing():
    assert odin_mod.load_checkpoint("does-not-exist-xyz") is None


def test_odin_process_finding(monkeypatch):
    tyr = MagicMock()
    tyr.execute.return_value = {"nato_rating": "B", "confidence": 0.9, "status": "VALID"}
    mimir = MagicMock()
    mimir.execute.return_value = {"entity": {"e": {"id": "x"}}}
    monkeypatch.setattr(odin_mod, "TyrAgent", lambda: tyr)
    monkeypatch.setattr(odin_mod, "MimirAgent", lambda: mimir)
    agent = odin_mod.OdinAgent()
    res = agent.process_finding("Domain", "example.com", "heimdall", "A", "1")
    assert "entity" in res and "validation" in res


def test_odin_process_connection(monkeypatch):
    mimir = MagicMock()
    mimir.execute.return_value = {"edge": {"id": "e1"}}
    monkeypatch.setattr(odin_mod, "MimirAgent", lambda: mimir)
    agent = odin_mod.OdinAgent()
    res = agent.process_connection("Domain", "a.com", "Domain", "b.com",
                                   "HAS_SUBDOMAIN", "x", "heimdall")
    assert res is not None


# ── hel (darkweb, inline isolation + DarkWebAdapter mock) ───────────────────
def test_hel_execute(monkeypatch, tmp_data_dir):
    _inline_isolation(monkeypatch)
    adapter = MagicMock()
    adapter.query_onion.return_value = "<html><title>LeakDB</title>leak row</html>"
    adapter.parse_leak_db.return_value = [{"leak": "cred: admin:pass"}]
    monkeypatch.setattr(hel_mod, "DarkWebAdapter", lambda: adapter)
    agent = hel_mod.HelAgent()
    res = agent.execute("admin@corp.com")
    assert res["source"] == "hel"
    assert "onion_sites" in res


# ── loki (humint, inline isolation + SocialAdapter mock) ───────────────────
def test_loki_execute(monkeypatch, tmp_data_dir):
    _inline_isolation(monkeypatch)
    adapter = MagicMock()
    adapter.check_profile_exists.return_value = "https://github.com/johndoe"
    monkeypatch.setattr(loki_mod, "SocialAdapter", lambda: adapter)
    agent = loki_mod.LokiAgent()
    res = agent.execute("johndoe")
    assert res["source"] == "loki"
    assert any("github" in p["platform"] for p in res["profiles"])


def test_loki_collision(monkeypatch, tmp_data_dir):
    _inline_isolation(monkeypatch)
    adapter = MagicMock()
    adapter.check_profile_exists.return_value = None
    monkeypatch.setattr(loki_mod, "SocialAdapter", lambda: adapter)
    agent = loki_mod.LokiAgent()
    res = agent.execute("admin")  # alias de colision
    assert res["collision_detected"] is True


# ── huginn (Domain 7, inline isolation + sub-agentes mock) ─────────────────
def test_huginn_calculate_hes_physical():
    a = huginn_mod.HuginnAgent()
    score = a.calculate_hes(10, 20, 30, 40, 50, 60, "Persona física")
    assert 0 <= score <= 100


def test_huginn_calculate_hes_legal():
    a = huginn_mod.HuginnAgent()
    score = a.calculate_hes(10, 20, 30, 40, 50, 60, "Persona jurídica")
    assert 0 <= score <= 100


def test_huginn_evaluate_certainty():
    a = huginn_mod.HuginnAgent()
    assert a.evaluate_certainty(95) == "ACTIONABLE"
    assert a.evaluate_certainty(90) == "HUMAN_REVIEW_REQUIRED"
    assert a.evaluate_certainty(50) == "HYPOTHESIS"


def test_huginn_execute_physical(monkeypatch, tmp_data_dir):
    _inline_isolation(monkeypatch)

    # Loki interno devuelve perfiles; Heimdall interno devuelve subdomains
    class FakeLoki:
        def execute(self, target, **kw):
            return {"profiles": [{"platform": "github", "url": "https://github.com/x"}],
                    "emails": ["x@proton.me"], "source": "loki"}
    class FakeHeimdall:
        def execute(self, target, **kw):
            return {"subdomains": ["api.example.com"], "source": "heimdall"}
    monkeypatch.setattr(huginn_mod, "LokiAgent", FakeLoki)
    monkeypatch.setattr(huginn_mod, "HeimdallAgent", FakeHeimdall)
    # ProvenanceRouter.route devuelve un id
    fake_router = MagicMock()
    fake_router.route.return_value = "run-123"
    monkeypatch.setattr(huginn_mod, "ProvenanceRouter", lambda: fake_router)

    agent = huginn_mod.HuginnAgent()
    res = agent.execute("john doe", entity_type="Persona física")
    assert res["source"] == "huginn"
    assert res["hes"] >= 0


def test_huginn_execute_legal(monkeypatch, tmp_data_dir):
    _inline_isolation(monkeypatch)

    class FakeLoki:
        def execute(self, target, **kw):
            return {"profiles": [], "emails": [], "source": "loki"}
    class FakeHeimdall:
        def execute(self, target, **kw):
            return {"subdomains": ["api.corp.com", "mail.corp.com"], "source": "heimdall"}
    monkeypatch.setattr(huginn_mod, "LokiAgent", FakeLoki)
    monkeypatch.setattr(huginn_mod, "HeimdallAgent", FakeHeimdall)
    fake_router = MagicMock()
    fake_router.route.return_value = "run-456"
    monkeypatch.setattr(huginn_mod, "ProvenanceRouter", lambda: fake_router)

    agent = huginn_mod.HuginnAgent()
    res = agent.execute("Corp S.A.", entity_type="Persona jurídica")
    assert res["source"] == "huginn"


# Nota: heimdall (75% hoy) queda fuera de B2; su execute usa Tor SOCKS via
# utils.net (no httpx directo) y requiere aislamiento mas complejo. Se declara
# en el sello como cubierto parcialmente (>=75%).

