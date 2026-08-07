# Makefile — AmegakureWotan Operation Interface

.PHONY: build up down shell recon humint darkweb correlate report test clean verify-ledger

# Genera hash reproducible del build context para el ledger forense
BUILD_HASH := $(shell find src/ skills/ pyproject.toml Dockerfile -type f \
               -exec sha512sum {} \; | sha512sum | cut -d' ' -f1 | head -c 16)
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# ── LIFECYCLE ─────────────────────────────────────────────────────────────────
build:
	@echo "[BUILD] Building AmegakureWotan image (build hash: $(BUILD_HASH))..."
	@docker compose build \
	  --build-arg IMAGE_BUILD_HASH=$(BUILD_HASH) \
	  --build-arg BUILD_DATE=$(BUILD_DATE) \
	  --no-cache
	@echo "[QA] Running Trivy SAST vulnerability scan..."
	@docker image save amegakurewotan/amewotan:latest -o /tmp/amewotan-latest.tar
	@chmod 644 /tmp/amewotan-latest.tar
	@docker run --rm -v /tmp/amewotan-latest.tar:/tmp/amewotan-latest.tar:z aquasec/trivy image --input /tmp/amewotan-latest.tar --severity CRITICAL
	@rm /tmp/amewotan-latest.tar

	@echo "[BUILD] Image built. Updating .env with build hash..."
	@sed -i "s/^AMEWOTAN_IMAGE_HASH=.*/AMEWOTAN_IMAGE_HASH=$(BUILD_HASH)/" .env || \
	  echo "AMEWOTAN_IMAGE_HASH=$(BUILD_HASH)" >> .env
	@sed -i "s/^BUILD_DATE=.*/BUILD_DATE=$(BUILD_DATE)/" .env || \
	  echo "BUILD_DATE=$(BUILD_DATE)" >> .env

up:
	@echo "[UP] Starting all services (+ Tor + Karasu bootstrap)..."
	@docker compose up -d tor-proxy
	@echo "[UP] Waiting for infrastructure..."
	@sleep 5
	@docker compose run --rm amegakurewotan --help

down:
	@docker compose down

# ── COMANDOS OPERACIONALES ────────────────────────────────────────────────────
shell:
	@docker compose run --rm -it -v $(PWD)/src:/app/src:z amegakurewotan bash

recon:
	@docker compose run --rm -v $(PWD)/src:/app/src:z amegakurewotan recon $(TARGET)

humint:
	@docker compose run --rm -v $(PWD)/src:/app/src:z amegakurewotan humint $(USERNAME)

darkweb:
	@docker compose run --rm -v $(PWD)/src:/app/src:z amegakurewotan darkweb "$(QUERY)"

correlate:
	@docker compose run --rm -v $(PWD)/src:/app/src:z amegakurewotan correlate

report:
	@docker compose run --rm -v $(PWD)/src:/app/src:z amegakurewotan report

# ── TESTING ───────────────────────────────────────────────────────────────────
test:
	@docker compose run --rm \
	  -e AMEWOTAN_RUN_SMOKE_TEST=true \
	  -e AMEWOTAN_DATA_DIR=/tmp/amegakurewotan_data \
	  -e KUZU_DATABASE_PATH=/tmp/amegakurewotan_data/amegakurewotan_vault.kuzu \
	  -v $(PWD)/src:/app/src:z \
	  -v $(PWD)/tests:/app/tests:z \
	  amegakurewotan pytest /app/tests/ -v --tb=short

# ── FORENSIC VERIFICATION ─────────────────────────────────────────────────────
verify-ledger:
	@docker compose run --rm amegakurewotan audit verify

# ── CLEANUP ───────────────────────────────────────────────────────────────────
clean:
	@docker compose down -v --remove-orphans
	@docker image rm amegakurewotan/amewotan:latest 2>/dev/null || true
