# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Módulo: amegakurewotan.defense.phishing
Contexto: CIVIL — Consolidación AmegakureWotan (§6.1 defense.*, §7.1)

Detección DEFENSIVA de phishing. Analiza indicadores (dominio, cabeceras, URLs,
texto recibido) y produce un score de riesgo con señales explicables. Es de sólo
lectura/análisis: NUNCA genera contenido persuasivo ni plantillas de ataque.

Heurísticas defensivas:
    - Homoglifos / typosquatting sobre una marca protegida.
    - TLDs de bajo coste frecuentes en abuso.
    - Presencia de IP cruda en la URL.
    - Palabras gatillo de urgencia/credenciales.
    - Discrepancia entre dominio mostrado y dominio real.
"""
from __future__ import annotations

__version__ = "1.0.0"
__forge_context__ = "CIVIL"

import re
from typing import Any, Dict, List, Optional

# TLDs frecuentemente abusados en campañas de phishing (señal, no veredicto).
_SUSPICIOUS_TLDS = frozenset({
    "zip", "mov", "top", "xyz", "gq", "ml", "cf", "tk", "work", "click", "link", "country",
})

# Palabras gatillo típicas de ingeniería social (para DETECCIÓN, no generación).
_URGENCY_TRIGGERS = [
    re.compile(r"\b(verify|confirm|update)\b.{0,30}\b(account|password|credential)", re.IGNORECASE),
    re.compile(r"\b(suspend|lock|disabl|deactivat)", re.IGNORECASE),
    re.compile(r"\b(urgent|immediately|within 24 hours|act now)\b", re.IGNORECASE),
    re.compile(r"\b(wire transfer|invoice|payment overdue|gift card)\b", re.IGNORECASE),
]

_IP_URL = re.compile(r"https?://(\d{1,3}\.){3}\d{1,3}")
_URL = re.compile(r"https?://([^/\s]+)")

# Confusiones de homoglifos comunes para typosquatting.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})


def _domain_of(url_or_domain: str) -> str:
    m = _URL.search(url_or_domain)
    host = m.group(1) if m else url_or_domain
    return host.strip().lower().split(":")[0]


def _looks_typosquat(candidate: str, brand: str) -> bool:
    """
    Heurística de typosquatting/homoglifos. candidate ya es != brand (crudo).
    Señal fuerte: tras normalizar homoglifos, candidate == brand (se ven iguales)
    o quedan a distancia de edición <= 2 sobre el label principal.
    """
    if candidate == brand:
        return False
    c = candidate.translate(_HOMOGLYPHS)
    b = brand.translate(_HOMOGLYPHS)
    # 1. Homoglifos: idénticos tras normalizar => typosquat claro (paypa1 -> paypal).
    if c == b:
        return True
    # 2. Marca embebida como label o distancia de edición pequeña.
    c_label = c.split(".")[0]
    b_label = b.split(".")[0]
    if b_label in c_label and c_label != b_label:
        return True
    return _levenshtein(c_label, b_label) <= 2


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def phishing_detect(
    subject: str,
    protected_brands: Optional[List[str]] = None,
    body: str = "",
    **_: Any,
) -> Dict[str, Any]:
    """
    Evalúa un indicador (URL/dominio/texto) contra heurísticas de phishing defensivo.

    Args:
        subject:          URL, dominio o remitente sospechoso a analizar.
        protected_brands: Marcas/dominios de la organización a proteger (para typosquat).
        body:             Cuerpo del mensaje recibido (opcional) para triggers de urgencia.

    Returns:
        {risk_score: 0..100, verdict, signals: [...], domain}. Sólo análisis defensivo.
    """
    signals: List[str] = []
    score = 0
    domain = _domain_of(subject) if subject else ""
    protected_brands = [b.strip().lower() for b in (protected_brands or []) if b.strip()]

    if not subject:
        return {"risk_score": 0, "verdict": "no_input", "signals": [], "domain": ""}

    # 1. IP cruda en URL.
    if _IP_URL.search(subject):
        score += 30
        signals.append("URL con dirección IP cruda (evita reputación de dominio)")

    # 2. TLD sospechoso.
    if domain and domain.rsplit(".", 1)[-1] in _SUSPICIOUS_TLDS:
        score += 20
        signals.append(f"TLD frecuentemente abusado: .{domain.rsplit('.', 1)[-1]}")

    # 3. Typosquatting sobre marca protegida.
    for brand in protected_brands:
        if domain and domain != brand and _looks_typosquat(domain, brand):
            score += 35
            signals.append(f"posible typosquatting de la marca protegida '{brand}' → '{domain}'")
            break

    # 4. Triggers de urgencia/credenciales en el cuerpo.
    haystack = f"{subject}\n{body}"
    trig_hits = [p.pattern for p in _URGENCY_TRIGGERS if p.search(haystack)]
    if trig_hits:
        score += min(10 * len(trig_hits), 30)
        signals.append(f"lenguaje de urgencia/credenciales detectado ({len(trig_hits)} patrón/es)")

    # 5. Subdominio excesivo (marca embebida como subdominio de otro dominio).
    if domain.count(".") >= 3:
        score += 10
        signals.append("cadena de subdominios inusualmente larga")

    score = min(score, 100)
    verdict = "high" if score >= 60 else "medium" if score >= 30 else "low"

    return {
        "tool": "defense.phishing_detect",
        "domain": domain,
        "risk_score": score,
        "verdict": verdict,
        "signals": signals,
        "mode": "defensive_only",
    }
