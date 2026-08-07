# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.evidence.custody_signer
Contexto: CIVIL — Consolidación AmegakureWotan (capa forense L5, F6)

Propósito:
    Capa de sellado NO-REPUDIABLE sobre la cadena de custodia consolidada
    (timeline.jsonl). El hash-chain HMAC-SHA512 de forensics.ChainOfCustody es
    simétrico: quien posea la clave HMAC puede re-firmar. La doctrina Odin/Wotan
    exige atribución criptográfica Ed25519 vía openssl (AmegakureWotan.md §5,
    compliance.signature = "Ed25519 vía openssl; firma fuera del archivo sellado").

    Este módulo calcula el digest SHA-512 de TODA la cadena (registros ordenados
    canónicamente) y lo firma Ed25519. El sobre de firma vive APARTE
    (custody.sig.json), NUNCA dentro del timeline, coherente con el patrón de
    ledgers append-only del Dojo. La verificación re-deriva el digest y comprueba
    la firma contra la clave pública.

    Determinismo: firma del estado completo de la cadena en el instante t. Cualquier
    bit alterado en cualquier registro invalida la firma (tamper-evidence).
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "lugh — AmegakureDōjō"
__forge_context__ = "CIVIL"

import hashlib
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("amegakurewotan.evidence.custody_signer")

SIG_ALG = "Ed25519"
SIG_OVERLAY_NAME = "custody.sig.json"


class CustodySignerError(Exception):
    """Error de generación/verificación de la firma Ed25519 de la cadena."""


def _resolve_paths(timeline_path: Optional[str | Path] = None) -> "tuple[Path, Path, Path]":
    """Resuelve (timeline, sig_overlay, privkey) contra la config global."""
    from amegakurewotan.config import get_config

    config = get_config()
    base = config.base_dir
    if timeline_path is None:
        timeline_path = base / "evidence" / "timeline.jsonl"
    else:
        timeline_path = Path(timeline_path)
    sig_path = timeline_path.parent / SIG_OVERLAY_NAME
    key_path = base / "opsec" / "keys" / "custody_ed25519.pem"
    return timeline_path, sig_path, key_path


def _derive_chain_digest(timeline_path: Path) -> str:
    """
    Digest SHA-512 determinista de TODA la cadena. Los registros se leen en orden
    de aparición y se serializan canónicamente (sort_keys, sin espacios) ANTES de
    hashear, de modo que el digest no depende de formato de escritura.
    """
    h = hashlib.sha512()
    if not timeline_path.exists():
        raise CustodySignerError(f"timeline.jsonl no existe: {timeline_path}")
    count = 0
    with open(timeline_path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CustodySignerError(f"Registro corrupto en cadena: {exc}") from exc
            # canonical_json propio (sin import circular con forensics).
            serialized = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            h.update(serialized.encode("utf-8"))
            count += 1
    if count == 0:
        raise CustodySignerError("Cadena vacía: nada que firmar.")
    return h.hexdigest()


def _ensure_keypair(key_path: Path) -> Path:
    """Genera el par Ed25519 (permisos 600) si no existe. Devuelve ruta privada."""
    if key_path.exists():
        return key_path
    key_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key_path)],
            check=True, capture_output=True, timeout=30,
        )
        os.chmod(key_path, 0o600)
    except (subprocess.SubprocessError, OSError) as exc:
        raise CustodySignerError(f"No se pudo generar la clave Ed25519: {exc}") from exc
    logger.info("Clave Ed25519 de custodia generada (0600) en %s", key_path)
    return key_path


def _pubkey_pem(key_path: Path) -> str:
    proc = subprocess.run(
        ["openssl", "pkey", "-in", str(key_path), "-pubout"],
        check=True, capture_output=True, text=True, timeout=30,
    )
    return proc.stdout


def _pubkey_sha256(key_path: Path) -> str:
    return hashlib.sha256(_pubkey_pem(key_path).encode("utf-8")).hexdigest()


def _openssl_sign(key_path: Path, digest_hex: str) -> str:
    """Firma Ed25519 (rawin) de los bytes crudos del digest SHA-512.

    EdDSA no admite digest explícito; pkeyutl -rawin firma el mensaje crudo (los
    64 bytes del SHA-512). Portable en OpenSSL >=3.0.
    """
    import tempfile
    digest_bytes = bytes.fromhex(digest_hex)
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(digest_bytes)
        datafile = tf.name
    try:
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key_path), "-in", datafile],
            capture_output=True, timeout=30,
        )
    finally:
        try:
            os.unlink(datafile)
        except OSError:
            pass
    if proc.returncode != 0:
        raise CustodySignerError(f"openssl sign falló: {proc.stderr.decode().strip()}")
    return proc.stdout.hex()


def _openssl_verify(key_path: Path, digest_hex: str, sig_hex: str) -> bool:
    import tempfile
    digest_bytes = bytes.fromhex(digest_hex)
    with tempfile.NamedTemporaryFile(delete=False) as df:
        df.write(digest_bytes)
        datafile = df.name
    with tempfile.NamedTemporaryFile(delete=False) as sf:
        sf.write(bytes.fromhex(sig_hex))
        sigfile = sf.name
    # Verificar contra la clave PUBLICA (no la privada).
    pub_proc = subprocess.run(
        ["openssl", "pkey", "-in", str(key_path), "-pubout"],
        capture_output=True, timeout=30,
    )
    ok = False
    if pub_proc.returncode == 0:
        with tempfile.NamedTemporaryFile(delete=False) as pf:
            pf.write(pub_proc.stdout)
            pubfile = pf.name
        try:
            proc = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", pubfile,
                 "-in", datafile, "-sigfile", sigfile],
                capture_output=True, text=True, timeout=30,
            )
            ok = proc.returncode == 0 and "Success" in (proc.stdout + proc.stderr)
        finally:
            try:
                os.unlink(pubfile)
            except OSError:
                pass
    for f in (datafile, sigfile):
        try:
            os.unlink(f)
        except OSError:
            pass
    return ok


def sign_chain(timeline_path: Optional[str | Path] = None) -> Dict[str, Any]:
    """
    Firma Ed25519 el estado completo de la cadena de custodia.

    Returns:
        Sobre de firma (dict) también persistido en custody.sig.json:
        {alg, pubkey_sha256, chain_sha512, signature_hex, ts_utc, records, signer}.
    Raises:
        CustodySignerError: si la cadena está vacía/corrupta o openssl falla.
    """
    tl_path, sig_path, key_path = _resolve_paths(timeline_path)
    key_path = _ensure_keypair(key_path)
    chain_digest = _derive_chain_digest(tl_path)

    # Contar registros para el sobre (evidencia cuantitativa).
    record_count = 0
    with open(tl_path, "r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                record_count += 1

    signature_hex = _openssl_sign(key_path, chain_digest)
    overlay = {
        "alg": SIG_ALG,
        "pubkey_sha256": _pubkey_sha256(key_path),
        "chain_sha512": chain_digest,
        "signature_hex": signature_hex,
        "records": record_count,
        "signer": "amegakurewotan.custody.ed25519",
        "ts_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(sig_path, "w", encoding="utf-8") as fh:
        json.dump(overlay, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    logger.info("Cadena de custodia firmada Ed25519: %d registros | chain_sha512=%s…",
                record_count, chain_digest[:16])
    return overlay


def verify_chain_signature(timeline_path: Optional[str | Path] = None) -> Dict[str, Any]:
    """
    Verifica la firma Ed25519 del estado de la cadena contra el sobre persistido.

    Returns:
        {valid, chain_sha512, overlay_sha512, records, reason}
        valid=True solo si la firma Ed25519 verifica y el digest derivado
        coincide con el del sobre (tamper-evidence total).
    """
    tl_path, sig_path, key_path = _resolve_paths(timeline_path)
    result: Dict[str, Any] = {
        "valid": False, "chain_sha512": None, "overlay_sha512": None,
        "records": 0, "reason": "",
    }
    if not sig_path.exists():
        result["reason"] = "sobre de firma ausente (custody.sig.json)"
        return result
    try:
        overlay = json.loads(sig_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        result["reason"] = f"sobre ilegible: {exc}"
        return result

    if not key_path.exists():
        result["reason"] = "clave pública/privada de custodia ausente"
        return result

    try:
        current_digest = _derive_chain_digest(tl_path)
    except CustodySignerError as exc:
        result["reason"] = str(exc)
        return result

    result["chain_sha512"] = current_digest
    result["records"] = overlay.get("records", 0)

    if current_digest != overlay.get("chain_sha512"):
        result["reason"] = "el digest de la cadena NO coincide con el firmado (cadena alterada)"
        return result

    ok = _openssl_verify(key_path, current_digest, overlay.get("signature_hex", ""))
    if not ok:
        result["reason"] = "firma Ed25519 NO verificada"
        return result

    result["valid"] = True
    result["reason"] = "firma Ed25519 válida y cadena íntegra"
    return result
