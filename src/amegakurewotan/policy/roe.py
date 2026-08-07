# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.policy.roe
Contexto: CIVIL — Consolidación AmegakureWotan

Propósito:
    Registro de Reglas de Empeño (RoE) firmadas. Una RoE es un documento YAML
    firmado digitalmente por la autoridad que autoriza una misión OSINT/DFIR.
    Define alcance (targets en scope), acciones permitidas (pasiva/activa/
    evasiva/darkweb/dfir), jurisdicción, ventana temporal y política PII.

    Toda acción del ecosistema se cita contra una RoE mediante `roe_ref`,
    incluidas las denegaciones GELSI (AmegakureWotan.md §5.3, §7.2).

Interfaz consumida por el MCP consolidado (§6.2):
    scope_registry.is_authorized(value, roe_token) -> bool
    scope_registry.get(roe_token)                   -> RulesOfEngagement
    roe.allows_active()                             -> bool
    roe.allows_darkweb()                            -> bool

Firma:
    Ed25519 vía openssl (preferencia forense de Lugh). La firma se calcula sobre
    el estado canónico del documento y se almacena APARTE (no dentro del YAML),
    coherente con el patrón de ledgers append-only del Dojo. Verificación
    best-effort: si no hay clave pública configurada, la RoE se marca
    `signature_verified=False` pero sigue siendo utilizable en modo dev/sandbox.
"""
from __future__ import annotations

__version__ = "1.0.0"
__author__ = "lugh — AmegakureDōjō"
__forge_context__ = "CIVIL"

import fnmatch
import logging
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("amegakurewotan.policy.roe")

# Categorías de acción reconocidas por GELSI (AmegakureWotan.md §4.1 L0).
ACTION_PASSIVE: str = "passive"
ACTION_ACTIVE: str = "active"
ACTION_EVASIVE: str = "evasive"
ACTION_DARKWEB: str = "darkweb"
ACTION_DFIR: str = "dfir"

VALID_ACTIONS = frozenset(
    {ACTION_PASSIVE, ACTION_ACTIVE, ACTION_EVASIVE, ACTION_DARKWEB, ACTION_DFIR}
)


class RoEError(Exception):
    """Error de carga, parseo o validación de una Regla de Empeño."""


@dataclass
class RulesOfEngagement:
    """
    Regla de Empeño firmada para una misión OSINT/DFIR autorizada.

    Campos:
        roe_id:            Identificador único (citado en roe_ref de la cadena de custodia).
        authority:         Autoridad que autoriza la misión.
        scope:             Patrones de targets autorizados (glob: "*.target.com", "1.2.3.0/24").
        exclusions:        Patrones explícitamente fuera de scope (OOS) — tienen prioridad.
        allowed_actions:   Subconjunto de VALID_ACTIONS permitido.
        jurisdiction:      Marco legal aplicable (p. ej. "EU/eIDAS", "GDPR").
        not_before/after:  Ventana temporal ISO-8601 UTC (o None).
        pii_policy:        Política de PII ("minimize" por defecto, GDPR).
        social_eng:        SIEMPRE defensivo. La ingeniería social ofensiva está prohibida
                           a nivel de plataforma; este flag solo habilita detección defensiva.
        signature_verified: True si la firma Ed25519 se validó contra la clave pública.
    """

    roe_id: str
    authority: str
    scope: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    allowed_actions: List[str] = field(default_factory=lambda: [ACTION_PASSIVE])
    jurisdiction: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    pii_policy: str = "minimize"
    social_eng: str = "defensive_only"
    signature_verified: bool = False
    source_path: Optional[str] = None

    # ── Consultas de política ────────────────────────────────────────────────
    def allows_action(self, action: str) -> bool:
        return action in self.allowed_actions

    def allows_active(self) -> bool:
        return ACTION_ACTIVE in self.allowed_actions

    def allows_evasive(self) -> bool:
        return ACTION_EVASIVE in self.allowed_actions

    def allows_darkweb(self) -> bool:
        return ACTION_DARKWEB in self.allowed_actions

    def allows_dfir(self) -> bool:
        return ACTION_DFIR in self.allowed_actions

    def is_temporally_valid(self, now_utc: Optional[float] = None) -> bool:
        """Verifica que la RoE esté dentro de su ventana temporal."""
        now_utc = now_utc if now_utc is not None else time.time()
        if self.not_before and self._iso_to_epoch(self.not_before) > now_utc:
            return False
        if self.not_after and self._iso_to_epoch(self.not_after) < now_utc:
            return False
        return True

    def is_target_in_scope(self, target: str) -> bool:
        """
        True si `target` cae dentro del scope y NO está en exclusiones.
        Las exclusiones (OOS) tienen prioridad absoluta sobre el scope.
        """
        if not target:
            return False
        target = target.strip().lower()

        for excl in self.exclusions:
            if self._match(target, excl):
                return False

        if not self.scope:
            # RoE sin scope explícito: deny-by-default (no autoriza nada).
            return False

        return any(self._match(target, pat) for pat in self.scope)

    # ── Helpers ──────────────────────────────────────────────────────────────
    @staticmethod
    def _match(target: str, pattern: str) -> bool:
        pattern = pattern.strip().lower()
        if not pattern:
            return False
        # Coincidencia exacta, glob, o sufijo de dominio.
        if fnmatch.fnmatch(target, pattern):
            return True
        if pattern.startswith("*.") and target.endswith(pattern[1:]):
            return True
        if target == pattern:
            return True
        # Dominio y subdominios: pattern "target.com" cubre "sub.target.com".
        if not any(c in pattern for c in "*?[") and (
            target == pattern or target.endswith("." + pattern)
        ):
            return True
        return False

    @staticmethod
    def _iso_to_epoch(iso_ts: str) -> float:
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                return time.mktime(time.strptime(iso_ts, fmt))
            except (ValueError, TypeError):
                continue
        raise RoEError(f"Timestamp ISO-8601 inválido en RoE: {iso_ts}")

    @classmethod
    def from_dict(cls, data: Dict[str, Any], source_path: Optional[str] = None) -> "RulesOfEngagement":
        roe_id = data.get("roe_id") or data.get("id")
        if not roe_id:
            raise RoEError("RoE sin 'roe_id'.")
        authority = data.get("authority") or data.get("authorized_by")
        if not authority:
            raise RoEError(f"RoE '{roe_id}' sin 'authority'.")

        allowed = data.get("allowed_actions") or [ACTION_PASSIVE]
        invalid = set(allowed) - VALID_ACTIONS
        if invalid:
            raise RoEError(f"RoE '{roe_id}' con acciones inválidas: {invalid}")

        # Blindaje de plataforma: la ingeniería social ofensiva NUNCA se acepta.
        social = str(data.get("social_eng", "defensive_only")).lower()
        if social not in ("defensive_only", "none", "disabled"):
            logger.warning(
                "RoE '%s' intentó habilitar social_eng='%s'; forzado a 'defensive_only' "
                "(la ingeniería social ofensiva está prohibida a nivel de plataforma).",
                roe_id, social,
            )
            social = "defensive_only"

        return cls(
            roe_id=str(roe_id),
            authority=str(authority),
            scope=list(data.get("scope", []) or []),
            exclusions=list(data.get("exclusions", []) or []),
            allowed_actions=list(allowed),
            jurisdiction=data.get("jurisdiction"),
            not_before=data.get("not_before"),
            not_after=data.get("not_after"),
            pii_policy=str(data.get("pii_policy", "minimize")),
            social_eng=social,
            source_path=source_path,
        )


class ScopeRegistry:
    """
    Registro de RoE cargadas desde YAML firmado.

    Deny-by-default: si no hay RoE que autorice explícitamente un target+acción,
    la operación se rechaza. El registro es consultado por GELSI y por los
    validadores Pydantic del MCP consolidado.

    Directorio por defecto: <base_dir>/opsec/roe/*.yaml
    Firmas Ed25519:         <archivo>.sig  +  clave pública en opsec/keys/roe_pub.pem
    """

    def __init__(self, roe_dir: Optional[str | Path] = None, pubkey_path: Optional[str | Path] = None):
        if roe_dir is None or pubkey_path is None:
            from amegakurewotan.config import get_config

            config = get_config()
            if roe_dir is None:
                roe_dir = config.base_dir / "opsec" / "roe"
            if pubkey_path is None:
                pubkey_path = config.base_dir / "opsec" / "keys" / "roe_pub.pem"

        self.roe_dir: Path = Path(roe_dir)
        self.pubkey_path: Path = Path(pubkey_path)
        self.roe_dir.mkdir(parents=True, exist_ok=True)
        self._registry: Dict[str, RulesOfEngagement] = {}
        self.load_all()

    # ── Carga ────────────────────────────────────────────────────────────────
    def load_all(self) -> None:
        """(Re)carga todas las RoE del directorio. Best-effort por archivo."""
        self._registry.clear()
        for yaml_path in sorted(self.roe_dir.glob("*.y*ml")):
            try:
                roe = self._load_file(yaml_path)
                self._registry[roe.roe_id] = roe
                logger.info(
                    "RoE cargada: %s (firma_verificada=%s, acciones=%s)",
                    roe.roe_id, roe.signature_verified, roe.allowed_actions,
                )
            except Exception as exc:  # noqa: BLE001 — carga tolerante, se reporta y continúa
                logger.error("Fallo cargando RoE %s: %s", yaml_path.name, exc)

    def _load_file(self, path: Path) -> RulesOfEngagement:
        import yaml  # PyYAML (dependencia transitiva ya presente en el entorno)

        try:
            raw = path.read_text(encoding="utf-8")
            data = yaml.safe_load(raw) or {}
        except Exception as exc:  # noqa: BLE001
            raise RoEError(f"No se pudo parsear YAML {path}: {exc}") from exc

        roe = RulesOfEngagement.from_dict(data, source_path=str(path))
        roe.signature_verified = self._verify_signature(path)
        return roe

    def _verify_signature(self, path: Path) -> bool:
        """
        Verifica firma Ed25519 (<archivo>.sig) contra la clave pública via openssl.
        Devuelve False (no lanza) si falta firma/clave — modo dev/sandbox permitido.
        """
        sig_path = Path(str(path) + ".sig")
        if not sig_path.exists() or not self.pubkey_path.exists():
            return False
        try:
            proc = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify",
                    "-pubin", "-inkey", str(self.pubkey_path),
                    "-rawin", "-in", str(path),
                    "-sigfile", str(sig_path),
                ],
                capture_output=True, text=True, timeout=15,
            )
            verified = proc.returncode == 0 and "Success" in (proc.stdout + proc.stderr)
            if not verified:
                logger.warning("Firma RoE NO verificada para %s: %s", path.name, proc.stderr.strip())
            return verified
        except (subprocess.SubprocessError, OSError) as exc:
            logger.warning("openssl no disponible para verificar RoE %s: %s", path.name, exc)
            return False

    # ── Registro programático (tests / ingesta dinámica) ─────────────────────
    def register(self, roe: RulesOfEngagement) -> None:
        self._registry[roe.roe_id] = roe

    # ── Consultas (interfaz MCP) ─────────────────────────────────────────────
    def get(self, roe_token: Optional[str]) -> Optional[RulesOfEngagement]:
        if not roe_token:
            return None
        return self._registry.get(roe_token)

    def is_authorized(self, value: str, roe_token: Optional[str]) -> bool:
        """
        True si `value` (target) está autorizado por la RoE `roe_token` y esta
        está temporalmente vigente. Deny-by-default ante RoE inexistente.
        """
        roe = self.get(roe_token)
        if roe is None:
            logger.warning("RoE '%s' no encontrada — deny-by-default para target '%s'.", roe_token, value)
            return False
        if not roe.is_temporally_valid():
            logger.warning("RoE '%s' fuera de ventana temporal.", roe_token)
            return False
        return roe.is_target_in_scope(value)

    def list_roe(self) -> List[str]:
        return list(self._registry.keys())


# Singleton perezoso (patrón coherente con config.get_config()).
_scope_registry: Optional[ScopeRegistry] = None


def get_scope_registry() -> ScopeRegistry:
    global _scope_registry
    if _scope_registry is None:
        _scope_registry = ScopeRegistry()
    return _scope_registry


def reset_scope_registry() -> None:
    """Resetea el singleton (usado en tests para aislar estado)."""
    global _scope_registry
    _scope_registry = None
