# 🦅 AmegakureWotan (烏隠れ) — Advanced OSINT Forensic Graph Harness

![License](https://img.shields.io/badge/License-Proprietary-red.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-green.svg)
![Python](https://img.shields.io/badge/Python-3.13+-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)
![Database](https://img.shields.io/badge/GraphDB-K%C3%B9zu-yellow.svg)

AmegakureWotan is a highly-secure, modular, and containerized **Open Source Intelligence (OSINT)** framework built for the shadows of the Amegakure Dojo. It executes stealthy automated intelligence gathering, correlates complex cyber-entities using an embedded **Kùzu Graph Database**, and maintains absolute cryptographic integrity of all findings through its **Forensic Audit Ledger**.

Designed with paramount **OPSEC** in mind, it routes all external reconnaissance through a self-healing **Tor SOCKS5 Proxy Network**, ensuring operator anonymity while investigating hostile targets, dark web assets, and corporate infrastructure.

---

## 🕷️ Architecture & OPSEC

- **Isolated Docker Runtime:** The entire pipeline executes inside a locked-down, network-restricted `docker-compose` topology.
- **Strict OPSEC Networking:** The reconnaissance container is disconnected from the clearnet. It bridges EXCLUSIVELY to a Tor proxy sidecar container. A "Kill Switch" guarantees no traffic escapes unanonymized.
- **Embedded Graph DB (Kùzu):** Intelligence nodes (Domains, IPs, Emails, Personas) are structured locally using Kùzu, allowing lightning-fast relational queries entirely offline.
- **Forensic Audit Ledger:** Every agent action and DB mutation is cryptographically hashed (HMAC-SHA512) into a tamper-proof audit trail for legally verifiable chain-of-custody reporting.
- **Agent Mesh Topology:**
  - `Heimdall`: Digital Reconnaissance & Perimeter Mapping.
  - `Huginn`: Corporate Entity & HUMINT mapping.
  - `Tyr`: Information verification & NATO intelligence scoring.
  - `Hel`: Dark Web / Deep Web intel indexing.
  - `Odin`: Workflow orchestrator and central brain.
  - `Mimir`: Memory retrieval and contextual search.

---

## ⚡ Installation (Zero to OSINT in 60s)

AmegakureWotan includes a seamless bootstrap installer that builds the secure Docker architecture and injects a global command wrapper into your system.

### Prerequisites:
- `git`
- `docker`
- `docker compose`

### Setup:
```bash
git clone https://github.com/amegakuredojo/AmegakureWotan.git
cd AmegakureWotan
./install.sh
```

> **Note:** The `install.sh` script will build the hardened containers and create a global wrapper at `~/.local/bin/karasu`. Ensure `~/.local/bin` is in your `$PATH`.

---

## ⚔️ Usage & Commands

Once installed, AmegakureWotan acts as a native CLI tool. You do not need to be in the project folder to run it.

### Core Orchestration
Launch a full automated reconnaissance cycle against a target (Domain, IP, Persona):
```bash
karasu orchestrate target.com
```

### Graph Visualization
View the correlated OSINT footprint in a beautiful ASCII tree format directly in your terminal (No web ports exposed for strict OPSEC):
```bash
karasu graph view
```

### Forensic Operations
Verify the cryptographic integrity of your case ledger:
```bash
karasu audit verify
```

Export a sanitized JSON intelligence dossier:
```bash
karasu export
```

Generate a Markdown dossier report:
```bash
karasu report --format markdown
```

### Dark Web Ops
Search indexed onion endpoints safely through the internal Tor proxy:
```bash
karasu darkweb "search_query"
```

### Interactive Dashboard (TUI)
Launch the Textual User Interface for immersive investigation directly in the terminal:
```bash
karasu tui
```

---

## ⚔️ Consolidated Governed Layer (`amewotan`)

Beyond the historical `karasu` OSINT harness, AmegakureWotan ships a **consolidated,
governed operator layer** exposed through the `amewotan` CLI. Every capability
(recon / defense / active surface / darkweb / DFIR / forensic) is routed through a
single MCP gateway under the **GELSI** policy engine (deny-by-default), the
**HITL** double-gate for high-risk actions, and the **HMAC-SHA512 chain of
custody**. Nothing bypasses governance, and missing tooling yields
`tool_unavailable` — never fabricated output.

### End-to-end governed mission (WOTAN-F7)
Run a full OSINT mission whose every step is policy-evaluated, sealed in the
custody timeline, and cryptographically signed (Ed25519 via openssl):
```bash
amewotan mission plans                                  # list available playbooks
amewotan mission run target.com --plan osint_recon --roe roe-1
amewotan mission list                                   # persisted mission dossiers
amewotan mission status  msn-YYYYMMDDHHMMSS-xxxxxxxx    # governance + chain + signature
amewotan mission report  msn-YYYYMMDDHHMMSS-xxxxxxxx    # forensic dossier (md|json)
```
Each mission emits a machine dossier (`mission_<id>.json`) and an operator dossier
(`mission_<id>.md`) under `<data_dir>/reports/`, and seals `mission.start` /
`mission.completed` markers into the chain.

Plans: `osint_recon` (passive + phishing defense + active surface + graph + verify),
`dfir_triage` (passive + memory/disk DFIR under HITL + verify), `full` (all gates).

### Forensic chain: verify & non-repudiable signature
```bash
amewotan forensic verify         # HMAC-SHA512 hash-chain integrity
amewotan forensic sign           # Ed25519 signature over the full chain digest
amewotan forensic verify-sign    # tamper-evidence: any altered byte invalidates it
```

### Governance & HITL
```bash
amewotan doctrine                # active Odin/Wotan doctrine
amewotan domains                 # consolidated MCP tools by domain
amewotan roe list                # loaded signed Rules of Engagement
amewotan hitl list               # pending human-in-the-loop tickets
amewotan hitl approve <ticket>   # approve → re-executes ONLY via governed gateway
amewotan hitl deny <ticket>      # deny (sealed, executes nothing)
```

---

## 🧪 Testing & CI

AmegakureWotan features a robust test suite that validates OPSEC fail-safes, graph database consistency, NATO scoring algorithms, and audit tamper-detection.

To run the full suite (Smoke Tests + Pytest):
```bash
karasu test
# or if running from source:
make test
```

---

## 🛡️ License & Disclaimer

Copyright (c) 2026 AmegakureDojo - Shakujo Forge V3. All rights reserved.

**PROPRIETARY AND CONFIDENTIAL.**

No permission is granted to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of this software without explicit written authorization from AmegakureDojo command.

This software contains military-grade OSINT and forensic mechanisms. Any unauthorized execution or deployment outside of isolated authorized sandboxes constitutes a breach of security protocols.

Operators are solely responsible for compliance with their local legislation and international laws.

*Property of Amegakure Dojo.*
