# Karasugakure — Runbook

## Getting Started

1. Start container services (Neo4j & Tor Proxy):
   ```bash
   docker compose up -d
   ```

2. Initialize the Karasugakure environment:
   ```bash
   karasu init
   ```

3. Run a recon task on a domain:
   ```bash
   karasu recon target.com
   ```

4. Run a HUMINT alias lookup:
   ```bash
   karasu humint username
   ```

5. Search deep web leak databases:
   ```bash
   karasu darkweb "keyword"
   ```

6. Query the graph using natural language:
   ```bash
   karasu graph query "find connections to target.com"
   ```

7. Generate dossier report:
   ```bash
   karasu report
   ```
