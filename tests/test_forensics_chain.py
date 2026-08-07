# FORGE_CONTEXT: CIVIL
"""
Tests de la cadena de custodia consolidada AmegakureWotan (forensics.ChainOfCustody).
Verifica append encadenado, integridad HMAC-SHA512, y detección de manipulación
por cambio de un solo bit en payload/prev_hash/orden (AmegakureWotan.md §5.1, §10.3).
"""
import json

import pytest

from karasugakure.evidence.forensics import (
    ChainOfCustody,
    GENESIS_HASH,
    canonical_json,
    sha512_bytes,
    sha512_file,
)


@pytest.fixture
def coc(tmp_path):
    """ChainOfCustody aislado en tmp_path (timeline + clave HMAC efímeros)."""
    return ChainOfCustody(
        timeline_path=tmp_path / "timeline.jsonl",
        key_path=tmp_path / "custody_hmac.key",
    )


def test_key_created_with_0600(coc):
    import stat

    mode = coc.key_path.stat().st_mode
    assert stat.S_IMODE(mode) == 0o600, "La clave HMAC debe tener permisos 0600."
    assert len(coc.key_path.read_bytes()) == 64


def test_append_and_chain_link(coc):
    r0 = coc.append("heimdall", "recon.passive_scan", sha512_bytes(b"raw-0"), roe_ref="roe-1")
    r1 = coc.append("loki", "recon.humint", sha512_bytes(b"raw-1"), roe_ref="roe-1")

    assert r0["seq"] == 0
    assert r0["prev_hash"] == GENESIS_HASH
    assert r1["seq"] == 1
    assert r1["prev_hash"] == r0["chain_hash"], "El registro N debe enlazar al chain_hash de N-1."
    assert len(r0["chain_hash"]) == 128  # HMAC-SHA512 hex


def test_verify_chain_valid(coc):
    for i in range(5):
        coc.append("heimdall", "recon.passive_scan", sha512_bytes(f"raw-{i}".encode()), roe_ref="roe-1")
    result = coc.verify_chain()
    assert result.is_valid is True
    assert result.checked_records == 5
    assert result.corruptions == []


def test_empty_chain_is_valid(coc):
    result = coc.verify_chain()
    assert result.is_valid is True
    assert result.checked_records == 0


def test_tamper_payload_single_bit(coc):
    """Alterar un byte del payload_hash de un registro debe invalidar la cadena."""
    coc.append("heimdall", "recon.passive_scan", sha512_bytes(b"raw-0"), roe_ref="roe-1")
    coc.append("loki", "recon.humint", sha512_bytes(b"raw-1"), roe_ref="roe-1")

    lines = coc.timeline_path.read_text().splitlines()
    rec = json.loads(lines[0])
    # Flip de un carácter del payload_hash (contenido probatorio).
    ph = list(rec["payload_hash"])
    ph[0] = "0" if ph[0] != "0" else "1"
    rec["payload_hash"] = "".join(ph)
    lines[0] = json.dumps(rec, ensure_ascii=False)
    coc.timeline_path.write_text("\n".join(lines) + "\n")

    result = coc.verify_chain()
    assert result.is_valid is False
    assert any("HMAC no coincide" in c["reason"] for c in result.corruptions)


def test_tamper_reorder_records(coc):
    """Reordenar registros rompe la secuencia y el enlace de cadena."""
    coc.append("a", "recon.passive_scan", sha512_bytes(b"0"), roe_ref="roe-1")
    coc.append("b", "recon.passive_scan", sha512_bytes(b"1"), roe_ref="roe-1")
    coc.append("c", "recon.passive_scan", sha512_bytes(b"2"), roe_ref="roe-1")

    lines = coc.timeline_path.read_text().splitlines()
    lines[1], lines[2] = lines[2], lines[1]  # swap
    coc.timeline_path.write_text("\n".join(lines) + "\n")

    result = coc.verify_chain()
    assert result.is_valid is False


def test_tamper_delete_record(coc):
    """Borrar un registro intermedio rompe el enlace de cadena."""
    coc.append("a", "recon.passive_scan", sha512_bytes(b"0"), roe_ref="roe-1")
    coc.append("b", "recon.passive_scan", sha512_bytes(b"1"), roe_ref="roe-1")
    coc.append("c", "recon.passive_scan", sha512_bytes(b"2"), roe_ref="roe-1")

    lines = coc.timeline_path.read_text().splitlines()
    del lines[1]
    coc.timeline_path.write_text("\n".join(lines) + "\n")

    result = coc.verify_chain()
    assert result.is_valid is False


def test_wrong_key_fails_verification(coc, tmp_path):
    """Verificar con otra clave HMAC debe fallar (posesión de clave obligatoria)."""
    coc.append("a", "recon.passive_scan", sha512_bytes(b"0"), roe_ref="roe-1")
    coc.append("b", "recon.passive_scan", sha512_bytes(b"1"), roe_ref="roe-1")

    other = ChainOfCustody(
        timeline_path=coc.timeline_path,
        key_path=tmp_path / "other.key",  # clave distinta
    )
    result = other.verify_chain()
    assert result.is_valid is False


def test_canonical_json_deterministic():
    a = {"b": 1, "a": 2, "c": [3, 2, 1]}
    b = {"c": [3, 2, 1], "a": 2, "b": 1}
    assert canonical_json(a) == canonical_json(b)


def test_sha512_file(tmp_path):
    p = tmp_path / "artifact.bin"
    p.write_bytes(b"forensic-artifact")
    assert sha512_file(p) == sha512_bytes(b"forensic-artifact")
    assert len(sha512_file(p)) == 128
