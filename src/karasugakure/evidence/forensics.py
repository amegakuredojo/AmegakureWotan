# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: karasugakure.evidence.forensics
Contexto: CIVIL — Consolidación AmegakureWotan (Karasugakure + SENTINEL-OSINT)

Propósito:
    Cadena de custodia criptográfica encadenada compartida (`ChainOfCustody`).
    Es el registro probatorio OFICIAL de toda operación OSINT/DFIR del ecosistema
    AmegakureWotan, materializado como `timeline.jsonl` (append-only, HMAC-SHA512
    encadenado). Cada evento forense (captura, escaneo, ejecución de herramienta
    externa, decisión GELSI, aprobación HITL, resultado VQL/Volatility/Sleuth Kit)
    se serializa de forma canónica y se enlaza al anterior mediante hash-chain.

    El "Forensic Audit Ledger" de Karasugakure (evidence/audit.py) se conserva como
    frontend histórico; este módulo provee el estándar consolidado exigido por la
    arquitectura AmegakureWotan §5 (SENTINEL ChainOfCustody como estándar global).

Modelo de registro (AmegakureWotan.md §5.1):
    {
      "seq":          <int>,
      "ts_utc":       "2026-08-07T10:00:00Z",
      "collector_id": "<agente o herramienta>",
      "event_type":   "<tipo de evento>",
      "payload_hash": "<sha512 del artefacto crudo>",
      "roe_ref":      "<id de RoE o null>",
      "prev_hash":    "<chain_hash anterior>",
      "chain_hash":   "<HMAC-SHA512(key, prev_hash || canonical_json(body))>"
    }

Garantías:
    - Append-only con fsync síncrono tras cada escritura.
    - Verificación completa sin sistema vivo (solo timeline.jsonl + clave).
    - Cualquier mutación de un bit en payload/prev_hash invalida la cadena.
    - Clave HMAC de 64 bytes, permisos 0600, generada con os.urandom.

Estándar forense (doctrina Lugh): SHA512 mínimo. NUNCA SHA256.
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "lugh — AmegakureDōjō"
__forge_context__ = "CIVIL"

import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("karasugakure.evidence.forensics")

# Hash-chain genesis anchor (no hay registro previo al primero).
GENESIS_HASH: str = "0" * 128  # SHA-512/HMAC-SHA512 hex digest = 128 chars

# Versión del esquema de la cadena de custodia consolidada.
CUSTODY_SCHEMA_VERSION: str = "cc-1.0"


class ChainOfCustodyError(Exception):
    """Error irrecuperable en la cadena de custodia (I/O, clave, o corrupción crítica)."""


@dataclass
class ChainVerificationResult:
    """Resultado estructurado de ChainOfCustody.verify_chain()."""

    is_valid: bool = True
    checked_records: int = 0
    corruptions: List[Dict[str, Any]] = field(default_factory=list)

    def add_corruption(self, seq: Optional[int], line: int, reason: str, **extra: Any) -> None:
        self.is_valid = False
        entry: Dict[str, Any] = {"seq": seq, "line": line, "reason": reason}
        entry.update(extra)
        self.corruptions.append(entry)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "checked_records": self.checked_records,
            "corruptions": self.corruptions,
        }


def sha512_bytes(data: bytes) -> str:
    """SHA-512 hex digest de un buffer en memoria."""
    return hashlib.sha512(data).hexdigest()


def sha512_file(path: str | Path, chunk_size: int = 1 << 20) -> str:
    """
    SHA-512 hex digest de un artefacto en disco, leído por chunks para no
    cargar archivos grandes (dumps de memoria, PCAP) en RAM.

    Raises:
        ChainOfCustodyError: Si el artefacto no existe o no es legible.
    """
    p = Path(path)
    if not p.is_file():
        raise ChainOfCustodyError(f"Artefacto no encontrado para hashing: {p}")
    h = hashlib.sha512()
    try:
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(chunk_size), b""):
                h.update(chunk)
    except OSError as exc:
        raise ChainOfCustodyError(f"Fallo leyendo artefacto {p}: {exc}") from exc
    return h.hexdigest()


def canonical_json(body: Dict[str, Any]) -> str:
    """
    Serialización canónica determinista: claves ordenadas, sin espacios
    superfluos, UTF-8, NaN prohibido. Es la ÚNICA representación usada para
    calcular el chain_hash — cualquier desviación rompe la verificación.
    """
    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


class ChainOfCustody:
    """
    Cadena de custodia consolidada AmegakureWotan.

    El registro probatorio oficial es `timeline.jsonl`. La clave HMAC vive fuera
    del archivo (permisos 0600) para que la verificación exija posesión de la
    clave y el archivo no pueda re-firmarse sin ella.

    Uso típico:
        coc = ChainOfCustody()
        rec = coc.append(
            collector_id="heimdall",
            event_type="recon.passive_scan",
            payload_hash=sha512_bytes(raw_output),
            roe_ref="roe-2026-001",
        )
        result = coc.verify_chain()
        assert result.is_valid
    """

    def __init__(
        self,
        timeline_path: Optional[str | Path] = None,
        key_path: Optional[str | Path] = None,
    ) -> None:
        if timeline_path is None or key_path is None:
            # Resolución perezosa contra la config global (permite override en tests).
            from karasugakure.config import get_config

            config = get_config()
            base = config.base_dir
            if timeline_path is None:
                timeline_path = base / "evidence" / "timeline.jsonl"
            if key_path is None:
                key_path = base / "opsec" / "keys" / "custody_hmac.key"

        self.timeline_path: Path = Path(timeline_path)
        self.key_path: Path = Path(key_path)
        self.timeline_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._key: bytes = self._load_or_create_key()

    # ── Gestión de clave HMAC ────────────────────────────────────────────────
    def _load_or_create_key(self) -> bytes:
        """Carga la clave HMAC de 64 bytes; la genera (0600) si no existe."""
        if self.key_path.exists():
            try:
                with open(self.key_path, "rb") as fh:
                    key = fh.read()
                if len(key) < 32:
                    raise ChainOfCustodyError(
                        f"Clave de custodia demasiado corta ({len(key)} bytes) en {self.key_path}"
                    )
                return key
            except OSError as exc:
                raise ChainOfCustodyError(f"No se pudo leer la clave de custodia: {exc}") from exc

        secret = os.urandom(64)
        try:
            fd = os.open(self.key_path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(secret)
                fh.flush()
                os.fsync(fh.fileno())
        except FileExistsError:
            # Carrera: otro proceso la creó primero. Reintentar lectura.
            return self._load_or_create_key()
        except OSError as exc:
            raise ChainOfCustodyError(f"No se pudo crear la clave de custodia: {exc}") from exc
        logger.info("Clave HMAC de cadena de custodia generada (0600) en %s", self.key_path)
        return secret

    # ── Cálculo de hash-chain ────────────────────────────────────────────────
    def _compute_chain_hash(self, prev_hash: str, body: Dict[str, Any]) -> str:
        """chain_hash = HMAC-SHA512(key, prev_hash || canonical_json(body))."""
        message = (prev_hash + canonical_json(body)).encode("utf-8")
        return hmac.new(self._key, message, hashlib.sha512).hexdigest()

    def _last_chain_hash(self) -> str:
        """Recupera el chain_hash del último registro; GENESIS_HASH si vacío."""
        if not self.timeline_path.exists() or self.timeline_path.stat().st_size == 0:
            return GENESIS_HASH
        last_valid = GENESIS_HASH
        try:
            with open(self.timeline_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                        ch = record.get("chain_hash")
                        if isinstance(ch, str) and ch:
                            last_valid = ch
                    except json.JSONDecodeError:
                        # Línea corrupta: no debe avanzar el ancla. verify_chain lo reportará.
                        continue
        except OSError as exc:
            raise ChainOfCustodyError(f"No se pudo leer timeline.jsonl: {exc}") from exc
        return last_valid

    def _next_seq(self) -> int:
        """Siguiente número de secuencia (recuento de registros existentes)."""
        if not self.timeline_path.exists():
            return 0
        count = 0
        try:
            with open(self.timeline_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    if line.strip():
                        count += 1
        except OSError as exc:
            raise ChainOfCustodyError(f"No se pudo contar registros en timeline.jsonl: {exc}") from exc
        return count

    # ── Append forense ───────────────────────────────────────────────────────
    def append(
        self,
        collector_id: str,
        event_type: str,
        payload_hash: str,
        roe_ref: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Encadena un nuevo evento forense y lo persiste en timeline.jsonl con fsync.

        Args:
            collector_id: Agente o herramienta que produjo el evento (p. ej. "heimdall").
            event_type:   Tipo de evento (p. ej. "recon.passive_scan", "gelsi.decision").
            payload_hash: SHA-512 del artefacto crudo asociado (usar sha512_bytes/sha512_file).
            roe_ref:      ID de la RoE que autoriza la acción, o None.
            metadata:     Campos auxiliares NO probatorios (contexto, decisión, etc.).
                          Se incluyen en el cuerpo firmado, por lo que quedan sellados.

        Returns:
            El registro completo persistido (incluye seq, ts_utc, chain_hash).

        Raises:
            ChainOfCustodyError: Ante fallo de I/O o campos inválidos.
        """
        if not collector_id or not collector_id.strip():
            raise ChainOfCustodyError("collector_id es obligatorio.")
        if not event_type or not event_type.strip():
            raise ChainOfCustodyError("event_type es obligatorio.")
        if not payload_hash or not isinstance(payload_hash, str):
            raise ChainOfCustodyError("payload_hash (SHA-512) es obligatorio.")

        prev_hash = self._last_chain_hash()
        seq = self._next_seq()
        ts_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Cuerpo firmado: TODO lo que no sea el propio chain_hash entra aquí.
        body: Dict[str, Any] = {
            "schema": CUSTODY_SCHEMA_VERSION,
            "seq": seq,
            "ts_utc": ts_utc,
            "collector_id": collector_id,
            "event_type": event_type,
            "payload_hash": payload_hash,
            "roe_ref": roe_ref,
            "prev_hash": prev_hash,
            "metadata": metadata or {},
        }
        chain_hash = self._compute_chain_hash(prev_hash, body)

        record = dict(body)
        record["chain_hash"] = chain_hash

        try:
            with open(self.timeline_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise ChainOfCustodyError(f"Fallo al escribir en timeline.jsonl: {exc}") from exc

        logger.info(
            "CoC append seq=%d collector=%s event=%s chain=%s…",
            seq, collector_id, event_type, chain_hash[:16],
        )
        return record

    # ── Verificación ─────────────────────────────────────────────────────────
    def verify_chain(self) -> ChainVerificationResult:
        """
        Verifica la integridad completa de timeline.jsonl:
          1. Secuencia monótona (seq == índice).
          2. Enlace hash-chain (prev_hash == chain_hash anterior).
          3. Reconstrucción del chain_hash con la clave HMAC (detecta mutación de body).

        Returns:
            ChainVerificationResult con is_valid y lista detallada de corrupciones.
        """
        result = ChainVerificationResult()

        if not self.timeline_path.exists() or self.timeline_path.stat().st_size == 0:
            return result  # Cadena vacía es íntegra por definición.

        expected_prev = GENESIS_HASH
        expected_seq = 0
        line_num = 0

        try:
            with open(self.timeline_path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    line_num += 1

                    try:
                        record = json.loads(raw)
                    except json.JSONDecodeError as exc:
                        result.add_corruption(None, line_num, f"JSON inválido: {exc}")
                        continue

                    seq = record.get("seq")
                    chain_hash = record.get("chain_hash")

                    if chain_hash is None or "chain_hash" not in record:
                        result.add_corruption(seq, line_num, "chain_hash ausente")
                        continue

                    # 1. Secuencia monótona
                    if seq != expected_seq:
                        result.add_corruption(
                            seq, line_num, "secuencia rota (posible inserción/borrado)",
                            expected_seq=expected_seq, actual_seq=seq,
                        )

                    # 2. Enlace de cadena
                    actual_prev = record.get("prev_hash")
                    if actual_prev != expected_prev:
                        result.add_corruption(
                            seq, line_num, "enlace hash-chain roto",
                            expected_prev=expected_prev, actual_prev=actual_prev,
                        )

                    # 3. Reconstrucción HMAC del body (detecta cualquier mutación)
                    body = {k: v for k, v in record.items() if k != "chain_hash"}
                    recomputed = self._compute_chain_hash(body.get("prev_hash", ""), body)
                    if not hmac.compare_digest(recomputed, str(chain_hash)):
                        result.add_corruption(
                            seq, line_num, "chain_hash HMAC no coincide (contenido alterado)",
                            expected_hash=recomputed, actual_hash=chain_hash,
                        )

                    expected_prev = chain_hash
                    expected_seq += 1
                    result.checked_records += 1
        except OSError as exc:
            raise ChainOfCustodyError(f"No se pudo leer timeline.jsonl para verificación: {exc}") from exc

        if result.is_valid:
            logger.info("Cadena de custodia verificada: %d registros íntegros.", result.checked_records)
        else:
            logger.error(
                "Cadena de custodia CORRUPTA: %d corrupciones detectadas.",
                len(result.corruptions),
            )
        return result

    def read_all(self) -> List[Dict[str, Any]]:
        """Devuelve todos los registros de la cadena (para auditoría/exportación)."""
        records: List[Dict[str, Any]] = []
        if not self.timeline_path.exists():
            return records
        with open(self.timeline_path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records
