# Karasugakure — CLI-only OSINT Orchestration Harness

Karasugakure is a structured, CLI-only OSINT framework built for tactical intelligence collection and relational link analysis. It operates on a graph-based persistence layer using Neo4j/Memgraph.

## Pantheon of Agents

- **Odin**: Strategic orchestrator and threat modeler.
- **Heimdall**: Infrastructure and surface reconnaissance.
- **Loki**: HUMINT, digital footprints, and profile scans.
- **Hel**: Deep/darkweb onion searches (Strictly routed via Tor SOCKS5).
- **Mimir**: Relational graph database memory repository.
- **Tyr**: Intelligence validation scoring engine using the NATO evaluation matrix.
- **Skadi**: Evidence preservation vault signing.
- **Fenrir**: Graph link correlation engine.
- **Norn**: Natural language search intent compiler to Cypher queries.

## Getting Started

1. **Launch Database and Tor Proxy**:
   ```bash
   docker compose up -d
   ```

2. **Initialize Environment**:
   ```bash
   .venv/bin/karasu init
   ```

3. **Run Scanning Tasks**:
   * Surface Recon:
     ```bash
     .venv/bin/karasu recon target.com
     ```
   * Digital Footprint:
     ```bash
     .venv/bin/karasu humint username
     ```
   * Darkweb Lookup:
     ```bash
     .venv/bin/karasu darkweb "leak_db_query"
     ```

4. **Run Relational Correlation (Fenrir)**:
   ```bash
   .venv/bin/karasu correlate
   ```

5. **Generate Dossier Report**:
   ```bash
   .venv/bin/karasu report
   ```

## Pi Agent Integration

This project includes a Pi extension located in `.pi/extensions/karasugakure.ts`. When you run Pi in this directory, the Karasugakure tools will be injected into Pi's runtime, enabling the agent to execute recon, humint, and graph query command-line tools natively!
