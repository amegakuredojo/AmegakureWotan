# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: 3.0
# FORGE_DATE: 2026-08-31T06:00:00Z
"""
Módulo: amegakurewotan.tools.searxng
Contexto: CIVIL — Motor de búsqueda OSINT multi-nivel sin dependencias de Docker.

Propósito:
    Motor de búsqueda OSINT resiliente con arquitectura de dos niveles:
        Tier 1 — SearXNG local (si SEARXNG_URL responde dentro del probe timeout).
        Tier 2 — DuckDuckGo HTML nativo (httpx + BeautifulSoup4).
                 Cero dependencias adicionales: httpx y bs4 ya están en pyproject.toml.

    Nunca lanza RuntimeError por ausencia de SearXNG o Docker.
    Salida siempre normalizada: [{"title": str, "url": str, "content": str}].

Prerequisitos:
    httpx >= 0.27 (en pyproject.toml)
    beautifulsoup4 >= 4.12 (en pyproject.toml)
    lxml >= 5.2 (en pyproject.toml — parser de bs4)

Impacto: Permite a searxng_recon operar en cualquier máquina sin servicios externos.
OWASP Ref: A05:2021 (Security Misconfiguration — no depender de servicio no disponible)

Exit Codes (CLI):
    0 — Éxito
    1 — Error (todos los tiers fallaron, lista vacía retornada de todos modos)
"""
from __future__ import annotations

__version__ = "2.0.0"
__author__ = "lugh — AmegakureDōjō"
__forge_context__ = "CIVIL"
__forge_date__ = "2026-08-31T06:00:00Z"

import argparse
import json
import logging
import os
import random
import sys
import time
from typing import Any, Optional

import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger("amegakurewotan.tools.searxng")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONSTANTES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SEARXNG_URL: str = os.getenv("SEARXNG_URL", "http://127.0.0.1:8080/search")
SEARXNG_PROBE_TIMEOUT: float = 2.0      # timeout rápido — detecta si SearXNG está activo
NATIVE_CONNECT_TIMEOUT: float = 5.0
NATIVE_READ_TIMEOUT: float = 15.0
MAX_RETRIES: int = 2
BACKOFF_BASE: float = 0.5

DDG_LITE_URL: str = "https://lite.duckduckgo.com/lite/"
DDG_HTML_URL: str = "https://html.duckduckgo.com/html/"

# Pool de User-Agents reales 2024-2025 (≥20 entradas — Ring 8: UA rotation)
_USER_AGENTS: list[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.130 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HELPERS INTERNOS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _pick_headers() -> dict[str, str]:
    """
    Genera headers HTTP con UA aleatorio del pool 2024-2025.

    Returns:
        dict con User-Agent rotado y headers estándar de navegador.
    """
    return {
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }


def _parse_ddg_lite(html: str, max_results: int) -> list[dict[str, str]]:
    """
    Parsea la tabla de resultados de DDG Lite (https://lite.duckduckgo.com/lite/).

    Args:
        html: HTML crudo de la respuesta DDG Lite.
        max_results: Límite de resultados a retornar.

    Returns:
        Lista de dicts normalizados {"title", "url", "content"}.
    """
    if not isinstance(html, str):
        return []
    soup = BeautifulSoup(html, "lxml")
    results: list[dict[str, str]] = []
    links = soup.select("a.result-link")
    snippets = soup.select("td.result-snippet")
    for i, link in enumerate(links):
        if not link.get("href"):
            continue
        content = snippets[i].get_text(strip=True) if i < len(snippets) else ""
        results.append({
            "title": link.get_text(strip=True),
            "url": str(link["href"]),
            "content": content,
        })
        if len(results) >= max_results:
            break
    return results


def _parse_ddg_html(html: str, max_results: int) -> list[dict[str, str]]:
    """
    Parsea la página HTML clásica de DuckDuckGo (https://html.duckduckgo.com/html/).

    Args:
        html: HTML crudo de la respuesta DDG HTML.
        max_results: Límite de resultados a retornar.

    Returns:
        Lista de dicts normalizados {"title", "url", "content"}.
    """
    if not isinstance(html, str):
        return []
    soup = BeautifulSoup(html, "lxml")
    results: list[dict[str, str]] = []
    for div in soup.select(".result"):
        title_el = div.select_one(".result__title a")
        snippet_el = div.select_one(".result__snippet")
        if title_el and title_el.get("href"):
            results.append({
                "title": title_el.get_text(strip=True),
                "url": str(title_el["href"]),
                "content": snippet_el.get_text(strip=True) if snippet_el else "",
            })
        if len(results) >= max_results:
            break
    return results


def _native_ddg_search(
    q: str,
    max_results: int = 10,
    connect_timeout: float = NATIVE_CONNECT_TIMEOUT,
    read_timeout: float = NATIVE_READ_TIMEOUT,
) -> list[dict[str, str]]:
    """
    Motor de búsqueda nativo DuckDuckGo HTML Lite (Tier 2).

    Intenta DDG Lite primero; si retorna vacío hace fallback a DDG HTML clásico.
    No requiere Docker ni servicios externos. Si todos los intentos fallan,
    retorna lista vacía (nunca lanza excepción).

    Args:
        q: Consulta o dork de búsqueda.
        max_results: Límite de resultados a retornar.
        connect_timeout: Timeout de conexión TCP en segundos.
        read_timeout: Timeout de lectura de respuesta en segundos.

    Returns:
        Lista de dicts normalizados {"title", "url", "content"}.

    Side effects:
        Logging INFO/WARNING de cada intento y resultado.
    """
    timeout = httpx.Timeout(
        connect=connect_timeout,
        read=read_timeout,
        write=5.0,
        pool=5.0,
    )

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with httpx.Client(
                timeout=timeout,
                headers=_pick_headers(),
                follow_redirects=True,
            ) as client:
                # Intento DDG Lite (más ligero, estable, sin JS)
                resp = client.post(DDG_LITE_URL, data={"q": q, "kl": "us-en"})
                resp.raise_for_status()
                text = resp.text if isinstance(resp.text, str) else ""
                results = _parse_ddg_lite(text, max_results)
                if results:
                    logger.info(
                        "native_ddg: Tier-2 DDG Lite OK — %d resultados (intento %d)",
                        len(results), attempt,
                    )
                    return results

                # DDG Lite retornó vacío — fallback a DDG HTML clásico
                logger.info("native_ddg: DDG Lite vacío — probando DDG HTML clásico")
                resp2 = client.get(DDG_HTML_URL, params={"q": q, "kl": "us-en"})
                resp2.raise_for_status()
                text2 = resp2.text if isinstance(resp2.text, str) else ""
                results2 = _parse_ddg_html(text2, max_results)
                logger.info(
                    "native_ddg: Tier-2 DDG HTML — %d resultados (intento %d)",
                    len(results2), attempt,
                )
                return results2

        except Exception as exc:
            logger.warning("native_ddg: intento %d/%d falló: %s", attempt, MAX_RETRIES, exc)
            if attempt < MAX_RETRIES:
                backoff = BACKOFF_BASE * (2 ** (attempt - 1))
                time.sleep(backoff)

    logger.error(
        "native_ddg: todos los intentos fallaron — retornando lista vacía (no RuntimeError)"
    )
    return []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# API PÚBLICA
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def query_searxng(
    q: str,
    engines: Optional[str] = None,
    categories: Optional[str] = None,
    max_results: int = 10,
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """
    Motor de búsqueda OSINT multi-nivel.

    Tier 1: SearXNG local (si SEARXNG_URL responde en SEARXNG_PROBE_TIMEOUT segundos).
    Tier 2: DuckDuckGo HTML nativo (httpx + BeautifulSoup4 — sin deps adicionales).

    Nunca lanza RuntimeError por ausencia de SearXNG o Docker.
    Si todos los tiers fallan, retorna lista vacía.

    Args:
        q: Consulta o dork OSINT. Ej: "site:target.com filetype:pdf".
        engines: (Opcional) motores SearXNG específicos. Ej: "google,github".
        categories: (Opcional) categorías SearXNG. Ej: "it,social media".
        max_results: Límite de resultados (default: 10).
        timeout: Timeout para llamadas (no afecta el probe de Tier 1).

    Returns:
        Lista de dicts normalizados [{"title": str, "url": str, "content": str}].

    Side effects:
        Logging INFO de qué tier se usó y cuántos resultados se obtuvieron.
    """
    # ── Tier 1: SearXNG local ──────────────────────────────────────────────────
    params: dict[str, Any] = {"q": q, "format": "json"}
    if engines:
        params["engines"] = engines
    if categories:
        params["categories"] = categories

    try:
        with httpx.Client(timeout=SEARXNG_PROBE_TIMEOUT) as client:
            r = client.get(SEARXNG_URL, params=params)
            r.raise_for_status()
            data = r.json()
            results = data.get("results", [])[:max_results]
            logger.info(
                "query_searxng: Tier-1 SearXNG OK — %d resultados (url=%s)",
                len(results), SEARXNG_URL,
            )
            return results
    except Exception as exc:
        logger.info(
            "query_searxng: SearXNG no disponible (%s) — activando Tier-2 motor nativo",
            type(exc).__name__,
        )

    # ── Tier 2: Motor nativo DuckDuckGo ───────────────────────────────────────
    return _native_ddg_search(q, max_results=max_results)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LANGCHAIN TOOL (opcional — solo si langchain_core está instalado)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

try:
    from langchain_core.tools import BaseTool
    from pydantic import BaseModel, Field

    class SearxNGInput(BaseModel):
        """Schema de entrada para SearxNGSearchTool (LangChain)."""
        query: str = Field(description="Consulta o dork (site:, filetype:, inurl:...)")
        engines: Optional[str] = Field(
            default=None,
            description="Motores específicos. Ej: 'google,github,brave'",
        )

    class SearxNGSearchTool(BaseTool):
        """
        LangChain Tool para búsqueda OSINT multi-nivel.
        Usa Tier-1 SearXNG si disponible, Tier-2 DDG nativo en caso contrario.
        """
        name: str = "searxng_search"
        description: str = (
            "Motor OSINT multi-nivel: SearXNG local (si disponible) o DuckDuckGo HTML nativo. "
            "Soporta dorks avanzados (site:, filetype:, inurl:, intitle:). "
            "Devuelve JSON estructurado."
        )
        args_schema: type[BaseModel] = SearxNGInput

        def _run(self, query: str, engines: Optional[str] = None) -> str:
            """
            Ejecuta búsqueda OSINT.

            Args:
                query: Consulta o dork OSINT.
                engines: (Opcional) motores SearXNG específicos.

            Returns:
                JSON string con lista de resultados normalizados.
            """
            results = query_searxng(query, engines=engines)
            return json.dumps(results, ensure_ascii=False, indent=2)

        async def _arun(self, query: str, engines: Optional[str] = None) -> str:
            """Wrapper async (delega a _run — httpx es síncrono)."""
            return self._run(query, engines)

except ImportError:
    SearxNGSearchTool = None  # LangChain no instalado — degradación elegante


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main() -> None:
    """Punto de entrada CLI del motor de búsqueda OSINT."""
    parser = argparse.ArgumentParser(
        description="Motor OSINT multi-nivel: SearXNG local + DuckDuckGo nativo"
    )
    parser.add_argument("query", help="Consulta o dork OSINT")
    parser.add_argument("--engines", default=None, help="Motores SearXNG. Ej: google,github,brave")
    parser.add_argument("--categories", default=None, help="Categorías SearXNG")
    parser.add_argument("--max", type=int, default=10, help="Número máximo de resultados")
    args = parser.parse_args()

    try:
        results = query_searxng(
            args.query,
            engines=args.engines,
            categories=args.categories,
            max_results=args.max,
        )
    except Exception as exc:
        logger.error("Error inesperado en CLI: %s", exc, exc_info=True)
        print(f"[!] Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(results, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
