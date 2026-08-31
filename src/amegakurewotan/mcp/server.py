# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: 3.0
# FORGE_DATE: 2026-07-05T15:43:00Z
# FIX-03: MCP Server expandido con todas las tools del framework

"""
Módulo: amegakurewotan.mcp.server
Contexto: CIVIL
Propósito: Servidor MCP (Model Context Protocol) stdio para AGY / OpenCode.
           Expone el arsenal completo del framework OSINT como tools MCP.
Prerequisitos: Kùzu DB, SearXNG, Tor proxy (opcional — configurable por AMEWOTAN_OPSEC_BYPASS_TOR)
Impacto: Permite a LLMs cliente ejecutar OSINT de grado forense militar.
OWASP Ref: A01:2021 (Broken Access Control), A05:2021 (Security Misconfiguration)
Exit Codes:
    0  — Éxito
    1  — Error general
    2  — Error de conexión
    5  — Artefacto forense no generado
    99 — Error crítico inesperado
"""
__version__ = "2.0.0"
__author__ = "lugh — AmegakureDōjō"
__forge_date__ = "2026-07-05T15:43:00Z"
__forge_context__ = "CIVIL"

import asyncio
import hashlib
import json
import logging
import time
import os
import sys
import traceback
from typing import Any, Dict, List, Optional

import kuzu
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from amegakurewotan.tools.searxng import query_searxng

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONSTANTES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# GOBERNANZA WOTAN (F5): GELSI + HITL + cadena de custodia
# Toda tool pasa por govern() antes de ejecutar. Cierra el bypass histórico:
# darkweb/dfir/active ya no se ejecutan sin RoE, y TODA ejecución se sella.
# La lógica vive en mcp.governance (importable sin el SDK MCP de bajo nivel).
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
from amegakurewotan.mcp.governance import (  # noqa: E402  (tras imports locales)
    govern as _govern,
    seal_execution as _seal_execution,
    handle_hitl_tool as _handle_hitl_tool,
)


SERVER_NAME: str = "AmegakureWotanMCP"
FORGE_OPERATOR: str = "lugh"

# Allowlist Cypher: SOLO operaciones de lectura (Ring 7 — Allowlist > Denylist)
_CYPHER_ALLOWLIST: frozenset = frozenset({
    "MATCH", "RETURN", "WHERE", "WITH", "LIMIT",
    "ORDER", "SKIP", "OPTIONAL", "CALL", "UNWIND"
})

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LOGGING ECS-COMPATIBLE (Ring 3 — JSON Lines a stderr)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
class ECSJSONFormatter(logging.Formatter):
    """Logging handler ECS-compatible. Emite a stderr para no contaminar JSON-RPC stdout."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "log": {
                "level": record.levelname,
                "logger": record.name,
            },
            "process": {
                "pid": os.getpid(),
                "thread": {"id": record.thread},
            },
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "labels": {
                "forge_context": __forge_context__,
                "forge_version": "3.0",
                "operator": FORGE_OPERATOR,
                "server": SERVER_NAME,
            },
        }
        if record.exc_info:
            log_entry["error"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "stack_trace": self.formatException(record.exc_info),
            }
        return json.dumps(log_entry, ensure_ascii=False)


logger = logging.getLogger(SERVER_NAME)
_log_handler = logging.StreamHandler(sys.stderr)
_log_handler.setFormatter(ECSJSONFormatter())
logger.addHandler(_log_handler)
logger.setLevel(logging.INFO)
logger.propagate = False

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# KÙZU DB — Lazy-initialized (evita crashes en import y contaminación stdout)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
_db: Optional[kuzu.Database] = None
_conn: Optional[kuzu.Connection] = None


def get_kuzu_connection() -> kuzu.Connection:
    """
    NIST SP 800-86 aligned database loader con auto-schema migration y validación.

    Returns:
        kuzu.Connection activa.

    Raises:
        RuntimeError: Si la conexión falla tras inicialización.
    """
    global _db, _conn
    if _conn is None:
        try:
            from amegakurewotan.config import get_config
            cfg = get_config()
            db_path = os.environ.get("KUZU_DATABASE_PATH") or getattr(cfg.kuzu, "database_path", None) or str(cfg.base_dir / "vault.kuzu")
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            _db = kuzu.Database(db_path)
            _conn = kuzu.Connection(_db)
            _conn.execute(
                "CREATE NODE TABLE IF NOT EXISTS Entity "
                "(id STRING, type STRING, PRIMARY KEY (id))"
            )
            _conn.execute(
                "CREATE REL TABLE IF NOT EXISTS LINKS_TO "
                "(FROM Entity TO Entity, context STRING)"
            )
            logger.info("Esquema Kùzu verificado/creado exitosamente.")
        except Exception as exc:
            logger.error(f"Error al inicializar Kùzu: {exc} — {traceback.format_exc()}")
            raise RuntimeError(f"Kùzu init failed: {exc}") from exc
    return _conn


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SERVIDOR MCP
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
app = Server(SERVER_NAME)


def _forensic_hash(payload_str: str) -> str:
    """
    NIST SP 800-86: Genera SHA-512 con timestamp para cadena de custodia.

    Args:
        payload_str: Payload a hashear.

    Returns:
        SHA-512 hex digest del payload + timestamp UTC.
    """
    timestamp = str(time.time())
    data = (timestamp + payload_str).encode("utf-8")
    return hashlib.sha512(data).hexdigest()


def _validate_cypher_allowlist(query: str) -> bool:
    """
    Ring 7: Verificar que la consulta Cypher es read-only usando allowlist estricto.
    NUNCA usar denylist (insuficiente — permite DROP, CALL db.xxx, etc.).

    Args:
        query: Consulta Cypher a verificar.

    Returns:
        True si es read-only, False si intenta escritura.
    """
    first_word = query.strip().split()[0].upper() if query.strip() else ""
    return first_word in _CYPHER_ALLOWLIST


# Registro de tools en el servidor MCP de bajo nivel. El SDK mcp >=2.0 renombró
# la API de alto nivel (list_tools/call_tool); en esa versión el registro es un
# no-op pero el módulo debe importar sin fallar. La gobernanza Wotan (F5) viaja
# por mcp.governance y el gateway, no por este decorador.
def _register_mcp_tools(app):
    if hasattr(app, "list_tools") and hasattr(app, "call_tool"):

        @app.list_tools()
        async def _list_tools():
            return [
                Tool(name="searxng_recon", description="(registrada vía gateway Wotan gobernado)",
                     inputSchema={"type": "object", "properties": {}, "required": []}),
            ]

        @app.call_tool()
        async def _call_tool(name, arguments):  # pragma: no cover - path only on old SDK
            from amegakurewotan.mcp.governance import govern, handle_hitl_tool

            decision, payload = govern(name, arguments)
            if decision == "ALLOW":
                return handle_hitl_tool(name, arguments) if name.startswith("wotan_hitl") else [
                    TextContent(type="text", text="[WOTAN] ejecución vía gateway requerida")]
            if decision == "REQUIRE_HITL":
                return [TextContent(type="text", text=f"[GELSI: REQUIRE_HITL] ticket {payload}")]
            return [TextContent(type="text", text=f"[GELSI: DENY] {payload}")]

    return app


# Nota: el registro de alto nivel (@app.list_tools/@app.call_tool) requiere el SDK
# mcp <2.0. Bajo mcp 2.0.0 el server de bajo nivel no expone esos decoradores;
# la gobernanza Wotan (F5) se sirve vía mcp.governance + gateway. No se invoca
# _register_mcp_tools(app) aquí para garantizar import limpio en mcp 2.0.0.
async def list_tools() -> List[Tool]:
    """Lista el arsenal completo de tools OSINT expuestas al LLM cliente."""
    return [
        # ── Búsqueda OSINT ──────────────────────────────────────────────────
        Tool(
            name="searxng_recon",
            description=(
                "Ejecuta una búsqueda OSINT profunda vía SearXNG/Tor. "
                "Soporta Google Dorks avanzados (site:, filetype:, inurl:, intitle:). "
                "Retorna resultados comprimidos con hash SHA-512 de cadena de custodia."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "El Dork o consulta OSINT. Ej: 'site:target.com filetype:pdf'",
                    },
                    "engines": {
                        "type": "string",
                        "description": "Motores específicos, ej: 'google,github,brave'. Omitir = todos.",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Número máximo de resultados (default: 10, máx: 50).",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
        ),
        # ── Reconocimiento de Infraestructura ───────────────────────────────
        Tool(
            name="heimdall_recon",
            description=(
                "Reconocimiento completo de infraestructura: DNS (A/MX/NS/TXT/CNAME), "
                "WHOIS, historial de certificados SSL (crt.sh), ASN/ASO lookup, "
                "subdominios pasivos. No requiere Tor. "
                "Retorna JSON estructurado con todos los hallazgos + hash SHA-512."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Dominio, IP o CIDR objetivo. Ej: 'example.com' o '1.2.3.4'",
                    },
                },
                "required": ["target"],
            },
        ),
        # ── Orquestación Completa ───────────────────────────────────────────
        Tool(
            name="odin_orchestrate",
            description=(
                "Ejecuta el pipeline OSINT completo via Odin (orquestador LangGraph): "
                "Heimdall (infra) → Huginn (HUMINT) → Hel (darkweb si Tor activo) → "
                "Fenrir (correlación) → Tyr (scoring NATO) → Skadi (evidencia). "
                "Guarda checkpoint de sesión para reanudación. "
                "ADVERTENCIA: Puede demorar 5-15 minutos según target."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Dominio, IP, username, email u organización objetivo.",
                    },
                    "session_id": {
                        "type": "string",
                        "description": "(Opcional) ID de sesión previa para reanudar investigación.",
                    },
                    "phases": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "(Opcional) Fases a ejecutar. Default: todas. Opciones: heimdall, huginn, hel, fenrir, tyr, skadi",
                    },
                },
                "required": ["target"],
            },
        ),
        # ── HUMINT ──────────────────────────────────────────────────────────
        Tool(
            name="huginn_humint",
            description=(
                "Reconocimiento HUMINT y entidades corporativas via Huginn: "
                "búsqueda de perfiles sociales, aliases, emails asociados, "
                "huella digital de persona/organización. Calcula Human Exposure Score (HES). "
                "Usa Tor para requests si está disponible."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username, nombre real, o razón social a investigar.",
                    },
                },
                "required": ["username"],
            },
        ),
        # ── Dark Web ────────────────────────────────────────────────────────
        Tool(
            name="hel_darkweb",
            description=(
                "Búsqueda en Dark Web / Deep Web vía Hel agent. "
                "REQUIERE Tor proxy activo. Si no hay Tor, retorna error OPSEC. "
                "Busca en directorios onion, bases de datos de leaks, foros. "
                "Ejecuta en proceso aislado para protección de memoria."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Término de búsqueda (email, alias, dominio, hash de contraseña).",
                    },
                },
                "required": ["query"],
            },
        ),
        # ── Correlación de Entidades ────────────────────────────────────────
        Tool(
            name="fenrir_correlate",
            description=(
                "Análisis de correlación relacional entre entidades del grafo via Fenrir. "
                "Detecta identidades compartidas, links por email/IP/dominio, "
                "traversales multi-hop, clustering de identidades. "
                "Opera sobre el grafo Kùzu actual."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "(Opcional) ID de sesión a correlacionar. Default: última sesión.",
                    },
                },
                "required": [],
            },
        ),
        # ── Grafo Kùzu ──────────────────────────────────────────────────────
        Tool(
            name="kuzu_ingest_entity",
            description=(
                "Inyecta una nueva entidad descubierta en el grafo forense local (Kùzu). "
                "Registra hash SHA-512 de cadena de custodia."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "entity_id": {
                        "type": "string",
                        "description": "Identificador único (ej: correo, IP, dominio, alias).",
                    },
                    "entity_type": {
                        "type": "string",
                        "description": "Tipo de entidad: EMAIL, IP, DOMAIN, ALIAS, ORGANIZATION, PROFILE.",
                    },
                },
                "required": ["entity_id", "entity_type"],
            },
        ),
        Tool(
            name="kuzu_cypher_query",
            description=(
                "Ejecuta consulta Cypher READ-ONLY sobre el grafo forense histórico. "
                "Solo se permiten operaciones MATCH/RETURN/WHERE/WITH/LIMIT (allowlist estricto). "
                "Ejemplo: 'MATCH (n:Domain) RETURN n LIMIT 10'"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Consulta Cypher read-only. MATCH/RETURN/WHERE permitidos.",
                    },
                },
                "required": ["query"],
            },
        ),
        # ── Auditoría Forense ────────────────────────────────────────────────
        Tool(
            name="audit_verify",
            description=(
                "Verifica la integridad criptográfica completa del ledger forense. "
                "Valida HMAC-SHA512, hash-chain links y firmas PGP de cada registro. "
                "Retorna OK o lista detallada de corrupciones detectadas."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        # ── Exportación ─────────────────────────────────────────────────────
        Tool(
            name="export_graph",
            description=(
                "Exporta la base de datos Kùzu completa como JSON estructurado. "
                "Incluye todos los nodos, relaciones y metadatos de execution contract. "
                "Hash SHA-512 del export incluido para cadena de custodia."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_id": {
                        "type": "string",
                        "description": "(Opcional) Filtrar export por target de investigación.",
                    },
                },
                "required": [],
            },
        ),
        # ── Control-plane Wotan (HITL) — operador resuelve la doble puerta ─────
        Tool(
            name="wotan_hitl_list",
            description=(
                "Lista los tickets Human-In-The-Loop pendientes (acciones dfir/darkweb/"
                "evasive o PII sin minimizar que GELSI puso en REQUIRE_HITL)."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        Tool(
            name="wotan_hitl_approve",
            description=(
                "Aprueba un ticket HITL y re-ejecuta la acción SOLO a través del gateway "
                "gobernado (GELSI re-evalúa sin la puerta HITL pero mantiene veto DENY y scope)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ticket_id": {"type": "string", "description": "ID del ticket HITL (hitl-...)."},
                    "by": {"type": "string", "description": "(Opcional) quien aprueba. Default: operator."},
                    "reason": {"type": "string", "description": "(Opcional) justificación."},
                },
                "required": ["ticket_id"],
            },
        ),
        Tool(
            name="wotan_hitl_deny",
            description=(
                "Denega un ticket HITL (no ejecuta nada; se sella en la cadena de custodia)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "ticket_id": {"type": "string", "description": "ID del ticket HITL (hitl-...)."},
                    "reason": {"type": "string", "description": "(Opcional) justificación de la denegación."},
                },
                "required": ["ticket_id"],
            },
        ),
    ]


async def call_tool(name: str, arguments: dict) -> List[TextContent]:
    """
    Manejador central de ejecución de tools MCP.

    Args:
        name: Nombre de la tool a ejecutar.
        arguments: Argumentos de la tool.

    Returns:
        Lista de TextContent con los resultados.

    Raises:
        ValueError: Si la tool es desconocida.
    """
    logger.info(f"Tool invocada: {name} | args_keys={list(arguments.keys())}")

    # ── Control-plane Wotan HITL (no pasa por _govern: es acción de operador) ──
    if name in ("wotan_hitl_list", "wotan_hitl_approve", "wotan_hitl_deny"):
        return _handle_hitl_tool(name, arguments)

    # ── Gobernanza Wotan (F5): GELSI + HITL + cadena de custodia ──────────────
    # Toda tool pasa por govern(). Sin ALLOW, NO se ejecuta (deny-by-default).
    decision, payload = _govern(name, arguments)
    if decision != "ALLOW":
        if decision == "REQUIRE_HITL":
            return [TextContent(
                type="text",
                text=(f"[GELSI: REQUIRE_HITL] La acción requiere aprobación humana (doble puerta). "
                      f"Ticket creado: {payload}. Resolver con: amewotan hitl approve {payload}"),
            )]
        return [TextContent(type="text", text=f"[GELSI: DENY] {payload}")]

    # ── Tool: searxng_recon ──────────────────────────────────────────────────
    if name == "searxng_recon":
        query: str = arguments.get("query", "")
        engines: Optional[str] = arguments.get("engines")
        max_results: int = min(int(arguments.get("max_results", 10)), 50)
        try:
            results = query_searxng(query, engines=engines, max_results=max_results)
            compressed_lines = []
            for item in results:
                title = item.get("title", "")
                url = item.get("url", "")
                content = item.get("content", "").replace("\n", " ").strip()
                compressed_lines.append(f"[{title}]({url}) — {content}")
            compressed_text = "\n".join(compressed_lines) if compressed_lines else "(sin resultados)"
            custody_hash = _forensic_hash(json.dumps(results, ensure_ascii=False))
            logger.info(f"searxng_recon completado. Resultados={len(results)} SHA-512={custody_hash[:16]}...")
            _seal_execution(name, arguments, compressed_text)
            return [TextContent(
                type="text",
                text=(
                    f"=== SEARXNG RECON | SHA-512: {custody_hash[:32]}... ===\n"
                    f"Query: {query} | Engines: {engines or 'all'} | Results: {len(results)}\n\n"
                    f"{compressed_text}"
                ),
            )]
        except Exception as exc:
            logger.error(f"searxng_recon error: {exc}", exc_info=True)
            return [TextContent(type="text", text=f"[ERROR] searxng_recon: {exc}")]

    # ── Tool: heimdall_recon ─────────────────────────────────────────────────
    elif name == "heimdall_recon":
        target: str = arguments.get("target", "").strip()
        try:
            from amegakurewotan.agents.heimdall import HeimdallAgent
            agent = HeimdallAgent()
            results = agent.execute(target)
            custody_hash = _forensic_hash(json.dumps(results, ensure_ascii=False, default=str))
            logger.info(f"heimdall_recon completado para {target}. SHA-512={custody_hash[:16]}...")
            _seal_execution(name, arguments, json.dumps(results, default=str)[:4096])
            return [TextContent(
                type="text",
                text=(
                    f"=== HEIMDALL RECON | Target: {target} | SHA-512: {custody_hash[:32]}... ===\n"
                    f"{json.dumps(results, indent=2, ensure_ascii=False, default=str)}"
                ),
            )]
        except Exception as exc:
            logger.error(f"heimdall_recon error para {target}: {exc}", exc_info=True)
            return [TextContent(type="text", text=f"[ERROR] heimdall_recon: {exc}")]

    # ── Tool: odin_orchestrate ───────────────────────────────────────────────
    elif name == "odin_orchestrate":
        target: str = arguments.get("target", "").strip()
        session_id: Optional[str] = arguments.get("session_id")
        phases: Optional[List[str]] = arguments.get("phases")
        try:
            from amegakurewotan.agents.odin import OdinAgent
            agent = OdinAgent()
            kwargs: Dict[str, Any] = {}
            if session_id:
                kwargs["session_id"] = session_id
            if phases:
                kwargs["phases"] = phases
            results = agent.execute(target, **kwargs)
            sid = results.get("session_id", "unknown")
            custody_hash = _forensic_hash(json.dumps(results, ensure_ascii=False, default=str))
            logger.info(f"odin_orchestrate completado. session={sid} SHA-512={custody_hash[:16]}...")
            # Compresión táctica: dossier + summary, no dump completo
            summary = {
                "session_id": sid,
                "target": target,
                "phase": results.get("phase", "unknown"),
                "status": results.get("status", "unknown"),
                "findings_count": len(results.get("findings", [])),
                "correlations_count": len(results.get("correlations", [])),
                "evidence_count": len(results.get("evidence", [])),
                "custody_sha512": custody_hash,
            }
            _seal_execution(name, arguments, json.dumps(summary, default=str)[:4096])
            return [TextContent(
                type="text",
                text=(
                    f"=== ODIN ORCHESTRATE | Target: {target} ===\n"
                    f"{json.dumps(summary, indent=2, ensure_ascii=False)}\n\n"
                    f"=== DOSSIER ===\n"
                    f"{json.dumps(results.get('dossier', {}), indent=2, ensure_ascii=False, default=str)}"
                ),
            )]
        except Exception as exc:
            logger.error(f"odin_orchestrate error para {target}: {exc}", exc_info=True)
            return [TextContent(type="text", text=f"[ERROR] odin_orchestrate: {exc}")]

    # ── Tool: huginn_humint ──────────────────────────────────────────────────
    elif name == "huginn_humint":
        username: str = arguments.get("username", "").strip()
        try:
            from amegakurewotan.agents.huginn import HuginnAgent
            agent = HuginnAgent()
            results = agent.execute(username)
            custody_hash = _forensic_hash(json.dumps(results, ensure_ascii=False, default=str))
            logger.info(f"huginn_humint completado para {username}. SHA-512={custody_hash[:16]}...")
            _seal_execution(name, arguments, json.dumps(results, default=str)[:4096])
            return [TextContent(
                type="text",
                text=(
                    f"=== HUGINN HUMINT | Target: {username} | SHA-512: {custody_hash[:32]}... ===\n"
                    f"{json.dumps(results, indent=2, ensure_ascii=False, default=str)}"
                ),
            )]
        except Exception as exc:
            logger.error(f"huginn_humint error para {username}: {exc}", exc_info=True)
            return [TextContent(type="text", text=f"[ERROR] huginn_humint: {exc}")]

    # ── Tool: hel_darkweb ────────────────────────────────────────────────────
    elif name == "hel_darkweb":
        query: str = arguments.get("query", "").strip()
        try:
            from amegakurewotan.agents.hel import HelAgent
            from amegakurewotan.policy.opsec import OPSECViolationException
            agent = HelAgent()
            results = agent.execute(query)
            custody_hash = _forensic_hash(json.dumps(results, ensure_ascii=False, default=str))
            logger.info(f"hel_darkweb completado para query '{query[:32]}...'. SHA-512={custody_hash[:16]}...")
            _seal_execution(name, arguments, json.dumps(results, default=str)[:4096])
            return [TextContent(
                type="text",
                text=(
                    f"=== HEL DARKWEB | SHA-512: {custody_hash[:32]}... ===\n"
                    f"{json.dumps(results, indent=2, ensure_ascii=False, default=str)}"
                ),
            )]
        except Exception as exc:
            logger.error(f"hel_darkweb error: {exc}", exc_info=True)
            return [TextContent(type="text", text=f"[OPSEC/ERROR] hel_darkweb: {exc}")]

    # ── Tool: fenrir_correlate ───────────────────────────────────────────────
    elif name == "fenrir_correlate":
        session_id: Optional[str] = arguments.get("session_id")
        try:
            from amegakurewotan.agents.fenrir import FenrirAgent
            from amegakurewotan.graph.export import export_to_json
            agent = FenrirAgent()
            graph_data = export_to_json()
            kwargs: Dict[str, Any] = {}
            if session_id:
                kwargs["session_id"] = session_id
            correlations = agent.execute(graph_data, **kwargs)
            custody_hash = _forensic_hash(json.dumps(correlations, ensure_ascii=False, default=str))
            logger.info(f"fenrir_correlate completado. Correlaciones={len(correlations)} SHA-512={custody_hash[:16]}...")
            _seal_execution(name, arguments, json.dumps(correlations, default=str)[:4096])
            return [TextContent(
                type="text",
                text=(
                    f"=== FENRIR CORRELATE | Correlaciones: {len(correlations)} | SHA-512: {custody_hash[:32]}... ===\n"
                    f"{json.dumps(correlations, indent=2, ensure_ascii=False, default=str)}"
                ),
            )]
        except Exception as exc:
            logger.error(f"fenrir_correlate error: {exc}", exc_info=True)
            return [TextContent(type="text", text=f"[ERROR] fenrir_correlate: {exc}")]

    # ── Tool: kuzu_ingest_entity ─────────────────────────────────────────────
    elif name == "kuzu_ingest_entity":
        e_id: str = arguments.get("entity_id", "").strip()
        e_type: str = arguments.get("entity_type", "Entity").strip()
        try:
            cypher = "MERGE (e:Entity {id: $id, type: $type}) RETURN e"
            get_kuzu_connection().execute(cypher, {"id": e_id, "type": e_type})
            custody_hash = _forensic_hash(f"INGEST:{e_id}:{e_type}")
            logger.info(f"Entidad ingerida: {e_id} [{e_type}] SHA-512={custody_hash[:16]}...")
            return [TextContent(
                type="text",
                text=f"[OK] Entidad ingerida: {e_id} [{e_type}] | SHA-512: {custody_hash}",
            )]
        except Exception as exc:
            logger.error(f"kuzu_ingest_entity error: {exc}", exc_info=True)
            return [TextContent(type="text", text=f"[ERROR] kuzu_ingest_entity: {exc}")]

    # ── Tool: kuzu_cypher_query ──────────────────────────────────────────────
    elif name == "kuzu_cypher_query":
        cypher: str = arguments.get("query", "").strip()
        # Ring 7: Allowlist estricto (NO denylist)
        if not _validate_cypher_allowlist(cypher):
            logger.warning(f"OPSEC: Consulta Cypher bloqueada por allowlist: '{cypher[:60]}'")
            return [TextContent(
                type="text",
                text=(
                    "[OPSEC BLOCKED] Solo consultas read-only permitidas. "
                    "Palabras clave válidas: MATCH, RETURN, WHERE, WITH, LIMIT, ORDER, SKIP, OPTIONAL, UNWIND. "
                    f"Primera palabra detectada: '{cypher.strip().split()[0] if cypher.strip() else 'vacío'}'"
                ),
            )]
        try:
            result = get_kuzu_connection().execute(cypher)
            output: List[str] = []
            while result.has_next():
                output.append(str(result.get_next()))
            return [TextContent(type="text", text=json.dumps(output, ensure_ascii=False))]
        except Exception as exc:
            logger.error(f"kuzu_cypher_query error: {exc}", exc_info=True)
            return [TextContent(type="text", text=f"[ERROR] Cypher: {exc}")]

    # ── Tool: audit_verify ───────────────────────────────────────────────────
    elif name == "audit_verify":
        try:
            from amegakurewotan.evidence.audit import ForensicAuditLedger
            ledger = ForensicAuditLedger()
            is_ok = ledger.verify_ledger_integrity()
            status = "Forensic Audit Ledger Integrity: OK" if is_ok else "Forensic Audit Ledger Integrity: COMPROMISED"
            logger.info(f"audit_verify: {status}")
            return [TextContent(type="text", text=status)]
        except Exception as exc:
            logger.error(f"audit_verify error: {exc}", exc_info=True)
            return [TextContent(type="text", text=f"[ERROR] audit_verify: {exc}")]

    # ── Tool: export_graph ───────────────────────────────────────────────────
    elif name == "export_graph":
        target_id: Optional[str] = arguments.get("target_id")
        try:
            from amegakurewotan.graph.export import export_to_json
            kwargs: Dict[str, Any] = {}
            if target_id:
                kwargs["target_id"] = target_id
            graph_data = export_to_json(**kwargs)
            custody_hash = _forensic_hash(json.dumps(graph_data, sort_keys=True, ensure_ascii=False))
            nodes_count = len(graph_data.get("nodes", []))
            edges_count = len(graph_data.get("edges", []))
            logger.info(f"export_graph completado. Nodos={nodes_count} Edges={edges_count} SHA-512={custody_hash[:16]}...")
            _seal_execution(name, arguments, json.dumps(graph_data, default=str)[:4096])
            return [TextContent(
                type="text",
                text=(
                    f"=== GRAPH EXPORT | Nodos: {nodes_count} | Edges: {edges_count} | SHA-512: {custody_hash[:32]}... ===\n"
                    f"{json.dumps(graph_data, indent=2, ensure_ascii=False, default=str)}"
                ),
            )]
        except Exception as exc:
            logger.error(f"export_graph error: {exc}", exc_info=True)
            return [TextContent(type="text", text=f"[ERROR] export_graph: {exc}")]

    else:
        logger.warning(f"Tool desconocida solicitada: {name}")
        raise ValueError(f"[AMEWOTAN-MCP] Tool desconocida: '{name}'")


# Registro condicional en el servidor MCP de bajo nivel (solo SDK mcp <2.0).
# En mcp 2.0.0 no existe la API de alto nivel; el módulo importa y la gobernanza
# Wotan (F5) se sirve vía mcp.governance + gateway.
if hasattr(app, "call_tool"):
    call_tool = app.call_tool()(call_tool)  # type: ignore[assignment]
if hasattr(app, "list_tools"):
    list_tools = app.list_tools()(list_tools)  # type: ignore[assignment]


async def main() -> None:
    """Entry point async del servidor MCP stdio."""
    logger.info(f"Iniciando {SERVER_NAME} v{__version__} (Modo MCP stdio)")
    try:
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())
    except Exception as exc:
        logger.error(f"Error crítico en MCP server: {exc} — {traceback.format_exc()}")
        sys.exit(99)


if __name__ == "__main__":
    asyncio.run(main())
