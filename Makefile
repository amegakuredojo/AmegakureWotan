# Makefile — AmegakureWotan Native Development & Operation Interface

.PHONY: setup install test cov mcp recon verify-ledger clean

VENV_PY := .venv/bin/python3
VENV_PIP := .venv/bin/pip

# ── SETUP & INSTALLATION ──────────────────────────────────────────────────────
setup:
	@echo "[SETUP] Creando entorno virtual e instalando dependencias en modo editable..."
	@test -d .venv || python3 -m venv .venv
	@$(VENV_PIP) install --upgrade pip -q
	@$(VENV_PIP) install -e ".[dev]" -q
	@echo "[SETUP] Listo. Para activar: source .venv/bin/activate"

install:
	@bash ./install.sh

# ── TESTING & QUALITY ─────────────────────────────────────────────────────────
test:
	@$(VENV_PY) -m pytest tests/ -v --tb=short

cov:
	@$(VENV_PY) -m pytest tests/ -q --no-header -p no:cacheprovider \
	  --cov=src/amegakurewotan --cov-report=term-missing --cov-fail-under=80

# ── OPERACIONES NATIVAS ───────────────────────────────────────────────────────
mcp:
	@$(VENV_PY) -m amegakurewotan.mcp.server

recon:
	@$(VENV_PY) -m amegakurewotan.cli_wotan orchestrate $(TARGET)

verify-ledger:
	@$(VENV_PY) -m amegakurewotan.cli_wotan audit verify

# ── CLEANUP ───────────────────────────────────────────────────────────────────
clean:
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@rm -rf .pytest_cache .coverage htmlcov dist build *.egg-info

