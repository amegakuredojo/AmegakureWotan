# Karasugakure — Architecture Design

Karasugakure is a modular, CLI-only OSINT orchestration system.

## Pantheon of Agents

- **Odin**: Coordinates tasks, checks guardrails, processes findings and connections.
- **Heimdall**: Infrastructure/surface recon (amass, shodan).
- **Loki**: HUMINT scan (sherlock, profile check).
- **Hel**: Deep/darkweb onion searches (Tor routed).
- **Mimir**: Historical rel DB (Neo4j/Memgraph).
- **Tyr**: Intelligence scorer (NATO matrix verification).
- **Skadi**: Cryptographic signing and evidence vault manager.
- **Fenrir**: Target correlations.
- **Norn**: Translates natural language queries into Cypher statements.

## Networking & OPSEC

Adapters perform HTTP requests via Tor proxies. The system does not alter host-wide network configurations (such as Parrot OS's AnonSurf) to prevent DNS leaks and firewall conflicts on openSUSE. Instead, it uses application-level SOCKS5 proxying (`socks5h://127.0.0.1:9050`) containerized via Docker.
