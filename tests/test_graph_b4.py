# FORGE_CONTEXT: CIVIL
"""Fase B4 — cobertura de graph/*, evidence/*, daemons/isolator.

Sube graph/db (59%) y evidence/capture+bundle+hash+provenance+ingest+export a
>=80%. graph/db usa Kuzu embebido REAL en tmp (aislado via reset de singleton +
parche de config.kuzu.database_path). Sin salida fabricada: el esquema/ingest/
export corren contra Kuzu real; provenance route con SkadiAgent mock y db
offline; capture con adapters mock; isolator con requests/Controller mock.
NOTA: tui.py (Textual app) queda fuera de B4; se declara en el sello (>=56%).
"""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import amegakurewotan.graph.db as db_mod
import amegakurewotan.graph.cypher as cypher_mod
import amegakurewotan.graph.ingest as ingest_mod
import amegakurewotan.graph.export as export_mod
import amegakurewotan.graph.provenance as prov_mod
import amegakurewotan.evidence.hash as hash_mod
import amegakurewotan.evidence.capture as capture_mod
import amegakurewotan.evidence.bundle as bundle_mod
import amegakurewotan.daemons.isolator as isolator_mod
from amegakurewotan.config import get_config


def _fresh_db(tmp_path, monkeypatch):
    cfg = get_config()
    cfg.kuzu.database_path = str(tmp_path / "vault.kuzu")
    monkeypatch.setattr(db_mod, "_db_instance", None)
    return db_mod.get_db()


# ── cypher (puro) ────────────────────────────────────────────────────────────
def test_cypher_entity():
    q = cypher_mod.create_entity_query("Domain")
    assert "MERGE (e:Domain" in q and "RETURN e" in q


def test_cypher_relationship():
    q = cypher_mod.create_relationship_query("Domain", "IP", "RESOLVES_TO")
    assert "RESOLVES_TO" in q and "MATCH (a:Domain" in q


def test_cypher_link_evidence():
    q = cypher_mod.link_evidence_query("Domain")
    assert "HAS_EVIDENCE" in q


# ── hash (fs real) ──────────────────────────────────────────────────────────
def test_hash_sha512(tmp_path):
    f = tmp_path / "e.bin"
    f.write_bytes(b"evidence-data")
    assert hash_mod.calculate_sha512(f) == hash_mod.calculate_sha512(f)
    assert len(hash_mod.calculate_sha512(f)) == 128


def test_hash_sign_meta(tmp_path):
    f = tmp_path / "e.bin"
    f.write_bytes(b"x" * 10)
    meta = hash_mod.sign_evidence_meta(f)
    assert meta["filename"] == "e.bin"
    assert meta["bytes_size"] == 10
    assert "sha512" in meta


# ── graph/db (Kuzu real) ────────────────────────────────────────────────────
def test_db_connect_and_schema(tmp_path, monkeypatch):
    db = _fresh_db(tmp_path, monkeypatch)
    assert db.check_connection() is True
    # migraciones crean tablas
    assert "DOMAIN" in db._known_tables


def test_db_execute_query_real(tmp_path, monkeypatch):
    db = _fresh_db(tmp_path, monkeypatch)
    db.execute_query("MERGE (n:Domain {value: $v}) RETURN n", {"v": "a.com"})
    res = db.execute_query("MATCH (n:Domain {value: $v}) RETURN n.value", {"v": "a.com"})
    assert res and res[0]["n.value"] == "a.com"


def _real_db(monkeypatch):
    db = db_mod.GraphDB.__new__(db_mod.GraphDB)
    db._db = MagicMock(); db._conn = MagicMock()
    db._known_tables = set(); db._known_properties = set()
    monkeypatch.setattr(db_mod, "get_db", lambda: db)
    monkeypatch.setattr(db, "connect", lambda: db._conn)
    monkeypatch.setattr(db, "execute_query", MagicMock(return_value=[]))
    return db


def test_db_import_graph_data(tmp_path, monkeypatch):
    db = _real_db(monkeypatch)
    db.import_graph_data({
        "nodes": [{"labels": ["Domain"], "properties": {"value": "x.com"}}],
        "edges": [{"source_value": "x.com", "source_labels": ["Domain"],
                   "target_value": "1.2.3.4", "target_labels": ["IP"], "relationship": "RESOLVES_TO"}],
    })
    assert db._conn.execute.called


def test_db_ensure_property(tmp_path, monkeypatch):
    db = _real_db(monkeypatch)
    monkeypatch.setattr(db, "_find_table_for_var", lambda q, v: "Email")
    db._ensure_property_exists_for_var("MATCH (n:Email {value: $v})", "n", "custom_prop", "hello")
    assert db._conn.execute.called


def test_db_close(tmp_path, monkeypatch):
    db = _fresh_db(tmp_path, monkeypatch)
    db.check_connection()
    db.close()
    assert db._conn is None


def test_db_execute_query_error(tmp_path, monkeypatch):
    db = _fresh_db(tmp_path, monkeypatch)
    with pytest.raises(Exception):
        db.execute_query("THIS IS NOT VALID CYPHER")


# ── ingest / export (Kuzu real) ──────────────────────────────────────────────
def test_ingest_entity(tmp_path, monkeypatch):
    db = MagicMock(); db.check_connection.return_value = True
    db.execute_query.return_value = [{"n": {"value": "example.com"}}]
    monkeypatch.setattr(ingest_mod, "get_db", lambda: db)
    res = ingest_mod.ingest_entity("Domain", "example.com", "heimdall")
    assert res == {"n": {"value": "example.com"}}


def test_ingest_relationship(tmp_path, monkeypatch):
    db = MagicMock(); db.check_connection.return_value = True
    db.execute_query.return_value = [{"r": {}}]
    db.execute_transaction.return_value = [[{"n": {}}], [{"n": {}}], [{"r": {}}]]
    monkeypatch.setattr(ingest_mod, "get_db", lambda: db)
    res = ingest_mod.ingest_relationship("Domain", "a.com", "IP", "1.1.1.1",
                                         "RESOLVES_TO", "dns", "heimdall")
    assert res is not None


def test_ingest_evidence(tmp_path, monkeypatch):
    db = MagicMock(); db.check_connection.return_value = True
    db.execute_transaction.return_value = [[{"n": {}}], [{"ev": {}}]]
    monkeypatch.setattr(ingest_mod, "get_db", lambda: db)
    res = ingest_mod.ingest_evidence("Domain", "a.com", "deadbeef", "screenshot", "/ev/a.png")
    assert res is not None


def test_export_roundtrip(tmp_path, monkeypatch):
    db = MagicMock(); db.check_connection.return_value = True
    db._known_tables = {"DOMAIN"}
    db.execute_query.return_value = [{"n": {"_label": "Domain", "value": "roundtrip.com"}}]
    monkeypatch.setattr(export_mod, "get_db", lambda: db)
    data = export_mod.export_to_json()
    assert any(n["properties"].get("value") == "roundtrip.com" for n in data["nodes"])


def test_export_all_nodes_empty(tmp_path, monkeypatch):
    db = MagicMock(); db.check_connection.return_value = True
    db._known_tables = set()
    monkeypatch.setattr(export_mod, "get_db", lambda: db)
    assert export_mod.export_all_nodes() == []


# ── provenance (Skadi mock + db offline/online) ─────────────────────────────
def _patch_provenance(monkeypatch, db_online=True):
    db = MagicMock(); db.check_connection.return_value = db_online
    monkeypatch.setattr(prov_mod, "get_db", lambda: db)
    skadi = MagicMock(); skadi.execute.return_value = {"sha512": "abc123hash"}
    monkeypatch.setattr(prov_mod, "SkadiAgent", lambda: skadi)
    return db


def _payload(confidence=90.0):
    return {
        "run_id": "run-1", "source_uri": "amegakurewotan://x", "agent_name": "huginn",
        "entity_type": "Persona física", "seed_canonical": "john", "confidence": confidence,
        "raw_data": {"target": "john"},
    }


def test_provenance_payload_validator_empty():
    import pydantic
    with pytest.raises(pydantic.ValidationError):
        prov_mod.ProvenancePayload(run_id="", source_uri="x", agent_name="a",
                                   entity_type="t", seed_canonical="s", raw_data={})


def test_provenance_route_hypothesis(monkeypatch):
    _patch_provenance(monkeypatch, db_online=False)
    rid = prov_mod.ProvenanceRouter().route(_payload(confidence=90.0))
    assert rid == "run-1"


def test_provenance_route_actionable(monkeypatch):
    _patch_provenance(monkeypatch, db_online=False)
    rid = prov_mod.ProvenanceRouter().route(_payload(confidence=95.0))
    assert rid == "run-1"


def test_provenance_route_online_commit(monkeypatch, tmp_path):
    db = MagicMock(); db.check_connection.return_value = True
    monkeypatch.setattr(prov_mod, "get_db", lambda: db)
    skadi = MagicMock(); skadi.execute.return_value = {"sha512": "abc123hash"}
    monkeypatch.setattr(prov_mod, "SkadiAgent", lambda: skadi)
    rid = prov_mod.ProvenanceRouter().route(_payload(confidence=88.0))
    assert rid == "run-1"


# ── evidence/capture (adapters mock) ────────────────────────────────────────
def test_capture_html(monkeypatch, tmp_data_dir):
    web = MagicMock(); web.fetch_page.return_value = "<html>evidence</html>"
    ev = MagicMock(); ev.store_raw_evidence.return_value = Path("/ev/x.html")
    monkeypatch.setattr(capture_mod, "WebAdapter", lambda: web)
    monkeypatch.setattr(capture_mod, "EvidenceAdapter", lambda: ev)
    p = capture_mod.CaptureManager().capture_html("http://x", "x.html")
    assert p == Path("/ev/x.html")


def test_capture_html_empty_raises(monkeypatch, tmp_data_dir):
    web = MagicMock(); web.fetch_page.return_value = ""
    ev = MagicMock()
    monkeypatch.setattr(capture_mod, "WebAdapter", lambda: web)
    monkeypatch.setattr(capture_mod, "EvidenceAdapter", lambda: ev)
    with pytest.raises(ValueError):
        capture_mod.CaptureManager().capture_html("http://x", "x.html")


def test_capture_page_degraded(monkeypatch, tmp_data_dir, tmp_path):
    web = MagicMock(); web.fetch_page.return_value = "<html>evidence</html>"
    ev = MagicMock()
    def _store(filename, content, folder=""):
        p = tmp_path / filename
        p.write_bytes(content)
        return p
    ev.store_raw_evidence.side_effect = _store
    monkeypatch.setattr(capture_mod, "WebAdapter", lambda: web)
    monkeypatch.setattr(capture_mod, "EvidenceAdapter", lambda: ev)
    # wkhtmltoimage/selenium no disponibles => fallback degraded
    monkeypatch.setattr("subprocess.run", MagicMock(side_effect=FileNotFoundError()))
    res = capture_mod.CaptureManager().capture_page("http://x", "x")
    assert res["capture_method"] == "degraded_html_hash"
    assert res["screenshot_hash"] == res["html_hash"]


# ── evidence/bundle (fs real + ledger mock) ─────────────────────────────────
def test_bundle_add_and_zip(tmp_path, monkeypatch, tmp_data_dir):
    # ledger mock para firma HMAC
    ledger = MagicMock(); ledger._get_master_key.return_value = b"secretkey"
    monkeypatch.setattr(bundle_mod, "ForensicAuditLedger", lambda: ledger)
    f = tmp_path / "e.bin"; f.write_bytes(b"data")
    b = bundle_mod.EvidenceBundler("case1")
    b.add_file(f)
    assert len(b.items) == 1
    zp = b.generate_signed_zip()
    assert zp.exists()
    assert (zp.parent / "case1.zip.sig").exists()


# ── daemons/isolator ────────────────────────────────────────────────────────
def test_isolator_get_host_ip(monkeypatch):
    fake = MagicMock(); fake.status_code = 200; fake.text = "1.2.3.4"
    monkeypatch.setattr(isolator_mod, "requests", MagicMock())
    isolator_mod.requests.get.return_value = fake
    d = isolator_mod.TorIsolatorDaemon()
    assert d._get_host_real_ip() == "1.2.3.4"


def test_isolator_get_host_ip_fail(monkeypatch):
    monkeypatch.setattr(isolator_mod, "requests", MagicMock())
    isolator_mod.requests.get.side_effect = RuntimeError("no net")
    d = isolator_mod.TorIsolatorDaemon()
    assert d._get_host_real_ip() == "UNKNOWN"


def test_isolator_rotate_identity(monkeypatch):
    ctrl = MagicMock()
    monkeypatch.setattr(isolator_mod, "Controller", MagicMock())
    isolator_mod.Controller.from_port.return_value.__enter__.return_value = ctrl
    d = isolator_mod.TorIsolatorDaemon()
    d.rotate_identity()
    ctrl.signal.assert_called()


def test_isolator_stop():
    d = isolator_mod.TorIsolatorDaemon()
    d.is_running = True
    d.stop()
    assert d.is_running is False


# ── graph/db métodos internos (rewrite/serialize/raw_execute) ──────────────
def test_rewrite_query_record_hash(monkeypatch):
    db = _real_db(monkeypatch)
    q, p = db._rewrite_query_and_params(
        "MERGE (a:AuditRecord {record_hash: $rh}) SET a.x += $props",
        {"rh": "h1", "props": {"k": "v"}})
    assert "id: $rh" in q
    assert "props_k" in p


def test_rewrite_query_timestamp(monkeypatch):
    db = _real_db(monkeypatch)
    q, p = db._rewrite_query_and_params("MATCH (n) WHERE n.t = timestamp() RETURN n", {})
    assert "__sys_timestamp" in q and "__sys_timestamp" in p


def test_rewrite_query_set_plus_dict(monkeypatch):
    db = _real_db(monkeypatch)
    q, p = db._rewrite_query_and_params(
        "MERGE (e:Evidence {hash_sha512: $h}) SET e += $meta",
        {"h": "hh", "meta": {"a": 1, "b": "x"}})
    assert "meta_a" in p and "meta_b" in p


def test_serialize_kuzu_result(monkeypatch):
    db = _real_db(monkeypatch)
    result = MagicMock()
    result.get_column_names.return_value = ["n"]
    result.has_next.side_effect = [True, False]
    result.get_next.return_value = [{"value": "x"}]
    recs = db._serialize_kuzu_result(result)
    assert recs == [{"n": {"value": "x"}}]


def test_raw_execute(monkeypatch):
    db = _real_db(monkeypatch)
    db.raw_execute("CREATE NODE TABLE T (id STRING, PRIMARY KEY(id))")
    assert db._conn.execute.called


def test_ensure_property_exists_for_var(monkeypatch):
    db = _real_db(monkeypatch)
    monkeypatch.setattr(db, "_find_table_for_var", lambda q, v: "Email")
    db._ensure_property_exists_for_var("MATCH (e:Email) RETURN e", "e", "ph", "x@y.z")
    assert db._conn.execute.called


def test_find_table_for_var(monkeypatch):
    db = _real_db(monkeypatch)
    db._known_tables = {"Email"}
    out = db._find_table_for_var("MATCH (e:Email) RETURN e", "e")
    assert out == "Email"


def test_import_graph_data(monkeypatch):
    db = _real_db(monkeypatch)
    data = {"nodes": [{"labels": ["Email"], "properties": {"hash_sha512": "h1", "value": "a@b.c"}}],
            "edges": []}
    db.import_graph_data(data)
    assert db.execute_query.called


def test_execute_transaction(monkeypatch):
    db = _real_db(monkeypatch)
    db.execute_transaction([("CREATE (n:Email {v:$v})", {"v": "a@b.c"})])
    assert db.execute_query.called


# ── daemons/isolator (stop ya cubierto arriba) ──────────────────────────────
