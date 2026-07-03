from typing import Any, Dict
from smolagents import CodeAgent, HfApiModel
from karasugakure.tools.searxng import SearxNGSearchTool

def create_osint_code_agent() -> CodeAgent:
    """
    Instancia el CodeAgent táctico para OSINT.
    Utiliza un LLM (por defecto HuggingFace, pero se puede sobreescribir)
    y se arma con la herramienta SearXNG.
    """
    # En un entorno real de despliegue, el modelo puede ser local (Ollama)
    # o una API externa con alta ventana de contexto.
    model = HfApiModel(model_id="meta-llama/Llama-3.3-70B-Instruct")
    
    # Armamento del agente
    tools = [SearxNGSearchTool()]
    
    # System Prompt Militar / OSINT
    system_prompt = """
    ERES KARASU, UN CODE-AGENT DE INTELIGENCIA (OSINT).
    Tu objetivo es recolectar, procesar y estructurar información de inteligencia.
    
    REGLAS DE ENFRENTAMIENTO:
    1. Utiliza la herramienta `searxng_search` para buscar en la web profunda y superficial.
    2. Utiliza Dorks avanzados si es necesario (site:, inurl:, filetype:).
    3. Escribe código Python en el sandbox para analizar los resultados JSON devueltos por la herramienta.
    4. Usa expresiones regulares en Python para extraer correos electrónicos, dominios, IPs y nombres.
    5. Nunca inventes datos (cero alucinaciones). Si no encuentras el objetivo, repórtalo como "TARGET_NOT_FOUND".
    """
    
    agent = CodeAgent(
        tools=tools,
        model=model,
        system_prompt=system_prompt,
        add_base_tools=True, # Proporciona herramientas base de smolagents
    )
    
    return agent

if __name__ == "__main__":
    # Smoke test rápido
    agent = create_osint_code_agent()
    print("[+] CodeAgent instanciado con SearXNG local.")
