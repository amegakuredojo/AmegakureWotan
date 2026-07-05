# Makefile — Karasugakure Operation Interface

.PHONY: build up down shell recon humint darkweb correlate report test clean verify-ledger

# Genera hash reproducible del build context para el ledger forense
BUILD_HASH := $(shell find src/ skills/ pyproject.toml Dockerfile -type f \
               -exec sha512sum {} \; | sha512sum | cut -d' ' -f1 | head -c 16)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── LIFECYCLE ─────────────────────────────────────────────────────────────────
build:
	@echo "[BUILD] Building Karasugakure image (build hash: $(BUILD_HASH))..."
	@docker compose build \
	  --build-arg IMAGE_BUILD_HASH=$(BUILD_HASH) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  --no-cache
	@echo "[QA] Running Trivy SAST vulnerability scan..."
	@docker image save karasugakure/karasu:latest -o /tmp/karasu-latest.tar
	@chmod 644 /tmp/karasu-latest.tar
	@docker run --rm -v /tmp/karasu-latest.tar:/tmp/karasu-latest.tar:z aquasec/trivy image --input /tmp/karasu-latest.tar --severity CRITICAL
	@rm /tmp/karasu-latest.tar

	@echo "[BUILD] Image built. Updating .env with build hash..."
	@sed -i "s/^KARASU_IMAGE_HASH=.*/KARASU_IMAGE_HASH=$(BUILD_HASH)/" .env || \
	  echo "KARASU_IMAGE_HASH=$(BUILD_HASH)" >> .env
	@sed -i "s/^BUILD_DATE=.*/BUILD_DATE=$(BUILD_DATE)/" .env || \
	  echo "BUILD_DATE=$(BUILD_DATE)" >> .env

up:
	@echo "[UP] Starting all services (+ Tor + Karasu bootstrap)..."
	@docker compose up -d tor-proxy
	@echo "[UP] Waiting for infrastructure..."
	@sleep 5
	@docker compose run --rm karasu --help

down:
	@docker compose down

# ── COMANDOS OPERACIONALES ────────────────────────────────────────────────────
shell:
	@docker compose run --rm -it -v $(PWD)/src:/app/src:z karasu bash

recon:
	@docker compose run --rm -v $(PWD)/src:/app/src:z karasu recon $(TARGET)

humint:
	@docker compose run --rm -v $(PWD)/src:/app/src:z karasu humint $(USERNAME)

darkweb:
	@docker compose run --rm -v $(PWD)/src:/app/src:z karasu darkweb "$(QUERY)"

correlate:
	@docker compose run --rm -v $(PWD)/src:/app/src:z karasu correlate

report:
	@docker compose run --rm -v $(PWD)/src:/app/src:z karasu report

# ── TESTING ───────────────────────────────────────────────────────────────────
test:
	@docker compose run --rm \
	  -e KARASU_RUN_SMOKE_TEST=true \
	  -e KARASU_DATA_DIR=/tmp/karasu_data \
	  -e KUZU_DATABASE_PATH=/tmp/karasu_data/karasu_vault.kuzu \
	  -v $(PWD)/src:/app/src:z \
	  -v $(PWD)/tests:/app/tests:z \
	  karasu pytest /app/tests/ -v --tb=short

# ── FORENSIC VERIFICATION ─────────────────────────────────────────────────────
verify-ledger:
	@docker compose run --rm karasu audit verify

# ── CLEANUP ───────────────────────────────────────────────────────────────────
clean:
	@docker compose down -v --remove-orphans
	@docker image rm karasugakure/karasu:latest 2>/dev/null || true
