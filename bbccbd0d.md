# Karasugakure — Project Tree

```text
karasugakure/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/
│   └── karasugakure/
│       ├── __init__.py
│       ├── cli.py
│       ├── config.py
│       ├── runtime/
│       │   ├── __init__.py
│       │   ├── harness.py
│       │   ├── session.py
│       │   └── router.py
│       ├── policy/
│       │   ├── __init__.py
│       │   ├── scope.py
│       │   ├── opsec.py
│       │   └── guardrails.py
│       ├── agents/
│       │   ├── __init__.py
│       │   ├── odin.py
│       │   ├── heimdall.py
│       │   ├── loki.py
│       │   ├── hel.py
│       │   ├── mimir.py
│       │   ├── tyr.py
│       │   ├── skadi.py
│       │   ├── fenrir.py
│       │   └── norn.py
│       ├── adapters/
│       │   ├── __init__.py
│       │   ├── web.py
│       │   ├── social.py
│       │   ├── darkweb.py
│       │   ├── archive.py
│       │   ├── graph.py
│       │   └── evidence.py
│       ├── graph/
│       │   ├── __init__.py
│       │   ├── db.py
│       │   ├── cypher.py
│       │   ├── ingest.py
│       │   └── export.py
│       ├── evidence/
│       │   ├── __init__.py
│       │   ├── capture.py
│       │   ├── hash.py
│       │   └── bundle.py
│       ├── reports/
│       │   ├── __init__.py
│       │   ├── findings.py
│       │   └── dossier.py
│       └── utils/
│           ├── __init__.py
│           ├── logging.py
│           ├── fs.py
│           └── net.py
├── prompts/
│   ├── system.md
│   ├── odin.md
│   ├── norn.md
│   └── tyr.md
├── skills/
│   ├── recon/
│   ├── humint/
│   ├── archive/
│   ├── darkweb/
│   └── report/
├── templates/
│   ├── dossier.md
│   ├── evidence.md
│   └── graph_seed.cypher
├── opsec/
│   ├── proxychains4.conf
│   ├── torrc
│   ├── ua_rotation.json
│   └── tls_fingerprint_policy.json
├── sessions/
├── evidence/
│   ├── screenshots/
│   ├── html/
│   ├── transcripts/
│   ├── hashes/
│   └── video/
├── graph_db/
│   ├── neo4j/
│   └── memgraph/
└── docs/
    ├── architecture.md
    ├── threat_model.md
    └── runbook.md
```
