# ─── STAGE 1: BUILDER ───────────────────────────────────────────────────────
# FORGE_CONTEXT: CIVIL | FORGE_VERSION: 3.0 | FORGE_DATE: 2026-07-05T15:43:00Z
FROM python:3.13-slim-bookworm AS builder

# Instalar dependencias del sistema necesarias para compilar wheels + amass (Go)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt-dev \
    git \
    golang-go \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Clonar repositorios de herramientas OSINT para compilar sus dependencias C
RUN git clone --branch v5.1.2 --depth 1 https://github.com/lanmaster53/recon-ng.git /opt/recon-ng \
    && git clone --branch 4.4.0 --depth 1 https://github.com/laramies/theHarvester.git /opt/theHarvester \
    && sed -i 's/aiohttp==3.8.5/aiohttp>=3.9.0/g' /opt/theHarvester/requirements/base.txt \
    && sed -i 's/uvloop==0.17.0/uvloop>=0.19.0/g' /opt/theHarvester/requirements/base.txt \
    && sed -i 's/lxml==4.9.3/lxml>=5.2.0/g' /opt/theHarvester/requirements/base.txt

# Compilar amass (Go binary) en el stage builder — FIX-04: WAS en runtime stage
# Esto evita instalar golang-go en runtime (+500MB) y hace el build reproducible
ENV GOPATH=/root/go
ENV PATH=$GOPATH/bin:$PATH
RUN go install github.com/owasp-amass/amass/v4/...@v4.2.0 2>/dev/null || true

# Copiar manifests del proyecto
COPY pyproject.toml requirements-pinned.txt ./
COPY src/ ./src/

# Instalar todas las dependencias (proyecto + dev + herramientas OSINT) en el directorio aislado /install
RUN pip install --upgrade pip --no-cache-dir \
    && pip install --prefix=/install --no-cache-dir --require-hashes -r requirements-pinned.txt \
    && pip install --prefix=/install --no-cache-dir build \
    && pip install --prefix=/install --no-cache-dir sherlock-project>=0.14.3 \
    && pip install --prefix=/install --no-cache-dir -r /opt/recon-ng/REQUIREMENTS \
    && pip install --prefix=/install --no-cache-dir -r /opt/theHarvester/requirements/base.txt \
    && pip install --prefix=/install --no-cache-dir --upgrade websockets

# ─── STAGE 2: RUNTIME ───────────────────────────────────────────────────────
FROM python:3.13-slim-bookworm AS runtime

# Metadatos de imagen — el IMAGE_BUILD_HASH se inyecta en build time
# para que el ForensicAuditLedger lo registre en el primer bloque
ARG IMAGE_BUILD_HASH="unset"
ARG BUILD_DATE="unset"
ENV KARASU_IMAGE_HASH=${IMAGE_BUILD_HASH}
ENV KARASU_BUILD_DATE=${BUILD_DATE}

# Instalar herramientas OSINT del sistema y dependencias runtime (sin gcc ni compiladores)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network OSINT tools
    nmap \
    whois \
    dnsutils \
    netcat-openbsd \
    curl \
    wget \
    # Web capture para Skadi/bundle (headless)
    wkhtmltopdf \
    # Chromium para Selenium headless (fallback de wkhtmltopdf)
    chromium \
    chromium-driver \
    # Cryptographic tools
    gnupg \
    gpg \
    # Proxychains para wrapping de subprocesos legacy
    proxychains4 \
    # Git (requerido para gitleaks hook y tool version hash)
    git \
    # Timezone data (necesario para correcta serialización de timestamps)
    tzdata \
    # SSL certs actualizados
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copiar las instalaciones de python compiladas desde el builder
COPY --from=builder /install /usr/local

# Copiar los repositorios OSINT ya clonados desde el builder
COPY --from=builder /opt/recon-ng /opt/recon-ng
COPY --from=builder /opt/theHarvester /opt/theHarvester

# FIX-04: Copiar amass binary ya compilado desde builder (sin re-instalar Go en runtime)
COPY --from=builder /root/go/bin/amass /usr/local/bin/amass

# Crear enlaces simbólicos para los scripts OSINT
RUN ln -s /opt/recon-ng/recon-ng /usr/local/bin/recon-ng \
    && ln -s /opt/theHarvester/theHarvester.py /usr/local/bin/theharvester

# Crear usuario no-root con UID fijo para aislamiento
RUN groupadd -g 1001 karasu \
    && useradd -u 1001 -g karasu -m -s /bin/bash -d /home/karasu karasu

# Copiar código fuente y assets del proyecto
COPY --chown=karasu:karasu src/ /app/src/
COPY --chown=karasu:karasu skills/ /app/skills/
COPY --chown=karasu:karasu templates/ /app/templates/
COPY --chown=karasu:karasu prompts/ /app/prompts/
COPY --chown=karasu:karasu opsec/ /app/opsec/
COPY --chown=karasu:karasu tests/ /app/tests/
COPY --chown=karasu:karasu docker/karasu/entrypoint.sh /entrypoint.sh

# Copiar proxychains config al lugar que el sistema espera
COPY opsec/proxychains4.conf /etc/proxychains4.conf

# Permisos
RUN chmod +x /entrypoint.sh \
    && chmod 600 /app/opsec/torrc \
    && chown -R karasu:karasu /app

# Directorio de trabajo y datos del operador
WORKDIR /app
RUN mkdir -p /data/evidence /data/sessions /data/reports /data/graph \
    && chown -R karasu:karasu /data

USER karasu

# Variables de entorno del contenedor
ENV PYTHONPATH=/app/src
ENV KARASU_DATA_DIR=/data
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
# OPSEC: Tor bypass para modo Sandbox/Dev (false = kill switch activo)
ENV KARASU_OPSEC_BYPASS_TOR=false
# Sandbox: permite override de path de Kùzu via env var
ENV KUZU_DATABASE_PATH=/data/karasu_vault.kuzu

ENTRYPOINT ["/entrypoint.sh"]
CMD []
