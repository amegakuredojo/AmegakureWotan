# PROTOCOLO: AMEGAKURE_FORGE | DESARROLLO
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: AmegakureWotan-1.0
"""
Paquete: karasugakure.defense
Contexto: CIVIL — Consolidación AmegakureWotan (§6.1 defense.*, §7.1)

Ingeniería social DEFENSIVA exclusivamente: detección de phishing, correlación de
campañas contra la organización, huella digital expuesta del personal. NUNCA
genera pretextos, plantillas de phishing ni contenido persuasivo (§1).
"""
from karasugakure.defense.phishing import phishing_detect

__all__ = ["phishing_detect"]
