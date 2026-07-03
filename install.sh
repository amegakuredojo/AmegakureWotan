#!/usr/bin/env bash
# ==============================================================================
# Karasugakure - Installation & Bootstrap Script
# ==============================================================================
# This script initializes the project environment and creates a global CLI wrapper
# for seamless execution without needing to prefix with `make` or `docker compose`.
# ==============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║            KARASUGAKURE — OSINT BOOTSTRAP INSTALLER              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# 1. Dependency Checks
echo -e "${YELLOW}[*] Checking prerequisites...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[!] Docker is not installed. Please install Docker and try again.${NC}"
    exit 1
fi

if ! command -v docker compose &> /dev/null && ! docker-compose --version &> /dev/null; then
    echo -e "${RED}[!] Docker Compose is not installed. Please install it and try again.${NC}"
    exit 1
fi
echo -e "${GREEN}[✔] Docker and Docker Compose found.${NC}"

# 2. Build Docker Environment
echo -e "\n${YELLOW}[*] Building Karasugakure secure containers (this may take a few minutes)...${NC}"
make build

# 3. Create Global Wrapper
echo -e "\n${YELLOW}[*] Setting up global CLI wrapper...${NC}"
INSTALL_DIR="$HOME/.local/bin"
mkdir -p "$INSTALL_DIR"

WRAPPER_PATH="$INSTALL_DIR/karasu"
CURRENT_DIR=$(pwd)

cat > "$WRAPPER_PATH" << 'EOF'
#!/usr/bin/env bash
# Karasugakure Global Wrapper
PROJECT_DIR="CURRENT_DIR_PLACEHOLDER"
cd "$PROJECT_DIR" || exit 1
if [ "$1" == "recon" ] || [ "$1" == "shell" ] || [ "$1" == "test" ]; then
    make "$@"
else
    docker compose run --rm -v "$PROJECT_DIR/src:/app/src:z" karasu "$@"
fi
EOF

# Replace placeholder with absolute path
sed -i "s|CURRENT_DIR_PLACEHOLDER|$CURRENT_DIR|g" "$WRAPPER_PATH"
chmod +x "$WRAPPER_PATH"

echo -e "${GREEN}[✔] Wrapper installed at $WRAPPER_PATH${NC}"

# 4. Final Instructions
echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${GREEN}Karasugakure is now fully operational!${NC}"
echo -e "You can now run the tool from ANYWHERE in your terminal using:"
echo -e "  ${YELLOW}karasu --help${NC}"
echo -e ""
echo -e "Examples:"
echo -e "  karasu recon scanme.nmap.org"
echo -e "  karasu graph view"
echo -e "  karasu shell"
echo -e "${BLUE}======================================================================${NC}"

# Remind to add to PATH if not there
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo -e "${RED}Note: $INSTALL_DIR is not in your PATH.${NC}"
    echo -e "Add this line to your ~/.bashrc or ~/.zshrc:"
    echo -e "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
