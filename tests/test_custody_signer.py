# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Tests F6 — Sello no-repudiable Ed25519 sobre la cadena de custodia consolidada.

Cubre:
  • Generación de clave Ed25519 (permisos 0600) bajo opsec/keys.
  • sign_chain() produce un sobre custody.sig.json con chain_sha512 + firma.
  • verify_chain_signature() == valid sobre la cadena íntegra.
  • Tamper-evidence: mutar UN byte de un registro invalida la firma.
  • Idempotencia: re-firmar con la misma clave re-emite sobre consistente.
Requiere openssl con soporte Ed25519 (OpenSSL >= 1.1.1).
"""
import json
import os

import pytest

from amegakurewotan.evidence.custody_signer import (
    sign_chain,
    verify_chain_signature,
)
from amegakurewotan.evidence.forensics import ChainOfCustody


pytestmark = pytest.mark.skipif(
    __import__("shutil").which("openssl") is None,
    reason="openssl no disponible en el host",
)


@pytest.fixture
def seeded_chain(tmp_path):
    """Cadena de custodia con algunos registros reales (appends sellados)."""
    coc = ChainOfCustody(
        timeline_path=tmp_path / "evidence" / "timeline.jsonl",
        key_path=tmp_path / "opsec" / "keys" / "custody_hmac.key",
    )
    coc.append(collector_id="gelsi:test", event_type="gelsi.decision",
               payload_hash="a" * 128, roe_ref="roe-1", metadata={"x": 1})
    coc.append(collector_id="mcp:tool", event_type="op.completed",
               payload_hash="b" * 128, roe_ref="roe-1", metadata={"tool": "recon.passive_scan"})
    coc.append(collector_id="hitl:op", event_type="hitl.approval",
               payload_hash="c" * 128, roe_ref="roe-1", metadata={"ticket": "hitl-1"})
    return coc


def test_sign_creates_overlay_and_verifies(seeded_chain, tmp_path):
    overlay = sign_chain(seeded_chain.timeline_path)
    assert overlay["alg"] == "Ed25519"
    assert overlay["chain_sha512"] and len(overlay["chain_sha512"]) == 128
    assert overlay["signature_hex"] and len(overlay["signature_hex"]) == 128  # 64 bytes hex
    # El sobre se escribió aparte (no dentro del timeline).
    sig_path = seeded_chain.timeline_path.parent / "custody.sig.json"
    assert sig_path.exists()
    # El timeline NO contiene el campo de firma.
    raw = seeded_chain.timeline_path.read_text(encoding="utf-8")
    assert "signature_hex" not in raw

    res = verify_chain_signature(seeded_chain.timeline_path)
    assert res["valid"] is True
    assert res["records"] == 3
    assert res["chain_sha512"] == overlay["chain_sha512"]


def test_sign_key_permissions_0600(seeded_chain, tmp_path):
    sign_chain(seeded_chain.timeline_path)
    from amegakurewotan.config import get_config
    key_path = get_config().base_dir / "opsec" / "keys" / "custody_ed25519.pem"
    assert key_path.exists()
    mode = os.stat(key_path).st_mode & 0o777
    assert mode == 0o600, f"clave con permisos inesperados: {oct(mode)}"


def test_tamper_invalidates_signature(seeded_chain, tmp_path):
    sign_chain(seeded_chain.timeline_path)
    assert verify_chain_signature(seeded_chain.timeline_path)["valid"] is True

    # Mutar un byte de un registro existente (append-only violado -> tamper).
    tl = seeded_chain.timeline_path
    lines = tl.read_text(encoding="utf-8").splitlines()
    assert lines
    # Cambio determinista: reemplaza el primer 'a' por 'A' en la línea 1.
    lines[0] = lines[0].replace("a", "A", 1)
    tl.write_text("\n".join(lines) + "\n", encoding="utf-8")

    res = verify_chain_signature(seeded_chain.timeline_path)
    assert res["valid"] is False
    assert "alterada" in res["reason"] or "NO verificada" in res["reason"]


def test_resign_idempotent_same_digest(seeded_chain, tmp_path):
    o1 = sign_chain(seeded_chain.timeline_path)
    o2 = sign_chain(seeded_chain.timeline_path)
    # Misma cadena => mismo digest y misma firma (determinista).
    assert o1["chain_sha512"] == o2["chain_sha512"]
    assert o1["signature_hex"] == o2["signature_hex"]


def test_verify_without_overlay_is_invalid(seeded_chain, tmp_path):
    res = verify_chain_signature(seeded_chain.timeline_path)
    assert res["valid"] is False
    assert "ausente" in res["reason"]
