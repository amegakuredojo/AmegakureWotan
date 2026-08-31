#!/usr/bin/env bash
# FORGE_CONTEXT: CIVIL
# FORGE_VERSION: 3.0
# ==============================================================================
# AmegakureWotan — Zero-Config Native Installer (pipx / pip)
# ==============================================================================
# Installs AmegakureWotan CLI and MCP Server natively on any Linux/Unix/macOS host
# without Docker, Tor or root requirements.
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          🦅 AMEGAKURE WOTAN — ZERO-CONFIG MCP INSTALLER          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 1. Python Environment Checks
echo -e "${YELLOW}[*] Comprobando entorno de Python en el host...${NC}"
PYTHON_BIN=""
for cmd in python3 python; do
    if command -v "$cmd" &> /dev/null; then
        PY_VER=$("$cmd" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$("$cmd" -c 'import sys; print(sys.version_info.major)')
        PY_MINOR=$("$cmd" -c 'import sys; print(sys.version_info.minor)')
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 10 ]; then
            PYTHON_BIN="$cmd"
            echo -e "${GREEN}[✔] Python $PY_VER detectado ($cmd).${NC}"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}[!] Se requiere Python >= 3.10 para ejecutar AmegakureWotan.${NC}"
    exit 1
fi

INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"
CURRENT_DIR=$(pwd)

# 2. Instalación vía pipx o venv nativo
echo -e "\n${YELLOW}[*] Instalando paquete y binarios CLI / MCP...${NC}"

if command -v pipx &> /dev/null; then
    echo -e "${CYAN}[i] pipx detectado. Instalando paquete en entorno aislado...${NC}"
    pipx uninstall amegakurewotan &> /dev/null || true
    pipx install --editable .
    echo -e "${GREEN}[✔] Instalado exitosamente vía pipx.${NC}"

else
    echo -e "${CYAN}[i] Configurando entorno virtual nativo (.venv)...${NC}"
    if [ ! -d ".venv" ]; then
        "$PYTHON_BIN" -m venv .venv
    fi
    ./.venv/bin/pip install --upgrade pip -q
    ./.venv/bin/pip install -e . -q
    
    # Enlazar binarios en ~/.local/bin
    ln -sf "$CURRENT_DIR/.venv/bin/amewotan" "$INSTALL_DIR/amewotan"
    ln -sf "$CURRENT_DIR/.venv/bin/amewotan-cli" "$INSTALL_DIR/amewotan-cli"
    ln -sf "$CURRENT_DIR/.venv/bin/amewotan-mcp" "$INSTALL_DIR/amewotan-mcp"
    echo -e "${GREEN}[✔] Binarios enlazados en $INSTALL_DIR.${NC}"
fi

# 3. Inicialización de directorios de usuario
echo -e "\n${YELLOW}[*] Inicializando bóveda local (~/.amegakurewotan)...${NC}"
"$INSTALL_DIR/amewotan-cli" init
echo -e "${GREEN}[✔] Bóveda de inteligencia y grafo inicializados.${NC}"



# 4. Resumen e instrucciones
echo -e "\n${BLUE}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}¡AmegakureWotan está 100% operativo y listo para usarse!${NC}"
echo -e ""
echo -e "Comandos disponibles:"
echo -e "  • ${YELLOW}amewotan orchestrate <target>${NC} : Reconocimiento OSINT multi-agente"
echo -e "  • ${YELLOW}amewotan-mcp${NC}                  : Servidor MCP stdio para LLMs"
echo -e "  • ${YELLOW}amewotan audit verify${NC}         : Verificación forense HMAC-SHA512"
echo -e ""
echo -e "Configuración MCP stdio para Antigravity / Claude Desktop:"
echo -e "${CYAN}  {"
echo -e "    \"mcpServers\": {"
echo -e "      \"amegakurewotan\": {"
echo -e "        \"type\": \"stdio\","
echo -e "        \"command\": \"amewotan-mcp\""
echo -e "      }"
echo -e "    }"
echo -e "  }${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════${NC}"

if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "\n${YELLOW}[!] Asegúrate de que $INSTALL_DIR esté en tu PATH.${NC}"
    echo -e "Añade a tu ~/.bashrc o ~/.zshrc:"
    echo -e "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

