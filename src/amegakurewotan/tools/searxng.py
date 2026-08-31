#!/usr/bin/env python3
"""
Cliente CLI + LangChain Tool para el nodo SearXNG self-hosted.
Consume el endpoint JSON local — no hace scraping directo
de terceros, así que no hereda la fragilidad de DuckDuckGoSearchRun.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import os
import logging
import httpx

logger = logging.getLogger("amegakurewotan.tools.searxng")

# Usa la URL interna de la red de Docker (SEARXNG_URL por variable de entorno)
SEARXNG_URL = os.getenv("SEARXNG_URL", "http://127.0.0.1:8080/search")
MAX_RETRIES = 2
BACKOFF_BASE = 0.5

def query_searxng(
    q: str,
    engines: Optional[str] = None,
    categories: Optional[str] = None,
    max_results: int = 10,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"q": q, "format": "json"}
    if engines:
        params["engines"] = engines
    if categories:
        params["categories"] = categories

    last_exc: Exception | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with httpx.Client(timeout=timeout) as client:
                r = client.get(SEARXNG_URL, params=params)
                r.raise_for_status()
                data = r.json()
                return data.get("results", [])[:max_results]
        except Exception as exc:
            last_exc = exc
            if attempt < MAX_RETRIES:
                time.sleep(BACKOFF_BASE * attempt)
    
    raise RuntimeError(f"SearXNG query falló tras {MAX_RETRIES} reintentos: {last_exc}")



try:
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel, Field

    class SearxNGInput(BaseModel):
        query: str = Field(description="Consulta o dork (site:, filetype:, inurl:...)")
        engines: Optional[str] = Field(default=None, description="ej. 'google,github'")

    class SearxNGSearchTool(BaseTool):
        name: str = "searxng_search"
        description: str = (
            "Metabuscador self-hosted (Google/Bing/Brave/GitHub simultáneo, "
            "vía Tor). Soporta dorks avanzados. Devuelve JSON estructurado."
        )
        args_schema: type[BaseModel] = SearxNGInput

        def _run(self, query: str, engines: Optional[str] = None) -> str:
            results = query_searxng(query, engines=engines)
            return json.dumps(results, ensure_ascii=False, indent=2)

        async def _arun(self, query: str, engines: Optional[str] = None) -> str:
            return self._run(query, engines)

except ImportError:
    SearxNGSearchTool = None  # LangChain no instalado

def main() -> None:
    parser = argparse.ArgumentParser(description="Cliente CLI del nodo SearXNG")
    parser.add_argument("query", help="consulta o dork")
    parser.add_argument("--engines", default=None, help="ej. google,github,brave")
    parser.add_argument("--categories", default=None)
    parser.add_argument("--max", type=int, default=10)
    args = parser.parse_args()

    try:
        results = query_searxng(
            args.query, engines=args.engines, categories=args.categories, max_results=args.max
        )
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(results, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    main()
