import asyncio
import hashlib
import json
import logging
import time
from typing import Any, Dict, List

import kuzu
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from karasugakure.tools.searxng import query_searxng

# Inicialización de logger forense
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - [%(name)s] - %(message)s")
logger = logging.getLogger("KarasuMCP")

# Inicialización de base de grafos empotrada (Kùzu)
# Zero standing footprint: Se creará el archivo en el volumen persistente montado.
db = kuzu.Database("/data/karasu_vault.kuzu")
conn = kuzu.Connection(db)

# Creación del esquema inicial (si no existe)
try:
    conn.execute("CREATE NODE TABLE IF NOT EXISTS Entity (id STRING, type STRING, PRIMARY KEY (id))")
    conn.execute("CREATE REL TABLE IF NOT EXISTS LINKS_TO (FROM Entity TO Entity, context STRING)")
    logger.info("Esquema de KùzuDB verificado/creado.")
except Exception as e:
    logger.error(f"Error al inicializar esquema Kùzu: {e}")

# Instancia del servidor MCP
app = Server("KarasugakureMCP")

def generar_hash_forense(payload_str: str) -> str:
    """NIST SP 800-86: Genera SHA-512 del payload para cadena de custodia."""
    timestamp = str(time.time())
    data_to_hash = (timestamp + payload_str).encode('utf-8')
    return hashlib.sha512(data_to_hash).hexdigest()

@app.list_tools()
async def list_tools() -> list[Tool]:
    """Lista las armas/herramientas expuestas al LLM cliente."""
    return [
        Tool(
            name="searxng_recon",
            description="Ejecuta una búsqueda OSINT profunda vía SearXNG/Tor. Permite Dorks.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "El Dork o consulta a buscar."},
                    "engines": {"type": "string", "description": "Motores específicos, ej: 'google,github'."}
                },
                "required": ["query"]
            }
        ),
        Tool(
            name="kuzu_ingest_entity",
            description="Inyecta una nueva entidad descubierta en el grafo local.",
            inputSchema={
                "type": "object",
                "properties": {
                    "entity_id": {"type": "string", "description": "Identificador único (ej. correo, IP)."},
                    "entity_type": {"type": "string", "description": "Tipo (ej. EMAIL, IP, DOMAIN, ALIAS)."}
                },
                "required": ["entity_id", "entity_type"]
            }
        ),
        Tool(
            name="kuzu_cypher_query",
            description="Ejecuta una consulta Cypher de solo lectura sobre el grafo histórico.",
            inputSchema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Consulta en lenguaje Cypher."}
                },
                "required": ["query"]
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Manejador de ejecución de herramientas MCP."""
    
    # ── Tool: searxng_recon ──
    if name == "searxng_recon":
        query = arguments.get("query")
        engines = arguments.get("engines")
        logger.info(f"Iniciando Reconocimiento: {query}")
        try:
            # Ejecución de red
            results = query_searxng(query, engines=engines)
            # Compresión Táctica de Tokens (Ahorro de ~90% de ventana de contexto)
            compressed_lines = []
            for item in results:
                title = item.get("title", "")
                url = item.get("url", "")
                content = item.get("content", "").replace("\n", " ").strip()
                compressed_lines.append(f"[{title}]({url}) - Snippet: {content}")
            
            compressed_text = "\n".join(compressed_lines)
            
            # Cadena de custodia (SHA-512) usando el payload crudo para integridad
            crypto_hash = generar_hash_forense(json.dumps(results, ensure_ascii=False))
            logger.info(f"Reconocimiento completado. Hash SHA-512: {crypto_hash}")
            
            return [TextContent(
                type="text",
                text=f"=== RECON RESULTS (SHA-512: {crypto_hash}) ===\n{compressed_text}"
            )]
        except Exception as e:
            return [TextContent(type="text", text=f"Error en Reconocimiento: {str(e)}")]

    # ── Tool: kuzu_ingest_entity ──
    elif name == "kuzu_ingest_entity":
        e_id = arguments.get("entity_id")
        e_type = arguments.get("entity_type")
        try:
            # Upsert básico en Cypher usando MERGE equivalente en Kuzu.
            # Nota: Kuzu usa MERGE igual que Neo4j
            cypher = "MERGE (e:Entity {id: $id, type: $type}) RETURN e"
            # Kuzu parameters
            conn.execute(cypher, {"id": e_id, "type": e_type})
            
            crypto_hash = generar_hash_forense(f"INGEST:{e_id}:{e_type}")
            logger.info(f"Entidad Ingerida: {e_id} [{e_type}] - Hash: {crypto_hash}")
            return [TextContent(type="text", text=f"Entidad ingerida con éxito. Hash: {crypto_hash}")]
        except Exception as e:
            return [TextContent(type="text", text=f"Error en ingesta: {str(e)}")]

    # ── Tool: kuzu_cypher_query ──
    elif name == "kuzu_cypher_query":
        cypher = arguments.get("query")
        # Prevenir escritura en esta tool por OpSec
        if "CREATE" in cypher.upper() or "MERGE" in cypher.upper() or "DELETE" in cypher.upper() or "SET" in cypher.upper():
            return [TextContent(type="text", text="Error: Violación OpSec. Solo consultas READ-ONLY (MATCH) están permitidas aquí.")]
        
        try:
            result = conn.execute(cypher)
            
            # Formatear salida
            output = []
            while result.has_next():
                output.append(str(result.get_next()))
                
            return [TextContent(type="text", text=json.dumps(output))]
        except Exception as e:
            return [TextContent(type="text", text=f"Error Cypher: {str(e)}")]
            
    else:
        raise ValueError(f"Herramienta desconocida: {name}")

async def main():
    logger.info("Iniciando servidor MCP Karasugakure (Modo Asimétrico)")
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
