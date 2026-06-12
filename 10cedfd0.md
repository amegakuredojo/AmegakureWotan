# Karasugakure — Agent Action Matrix

| Priority | Agent | Task | Dependency | Exit Criteria |
|---|---|---|---|---|
| P0 | Odin | Deterministic phase control, checkpoint, resume, rollback | Session state, ledger | No phase advance without checkpoint; resume exactness verified |
| P0 | Tyr | Hard validation gate and contradiction handling | Source metadata, confidence scores | Any score below threshold blocks pipeline with recorded reason |
| P0 | Audit Ledger | Hash-chained logging and integrity verification | Master key, evidence hashes | Tamper test fails closed; audit verify passes on clean log |
| P1 | Norn | Multi-hop NL to Cypher translation | Graph schema, Mimir | Deterministic Cypher for normal and temporal queries |
| P1 | Mimir | Persistent graph storage, provenance, deduplication | Graph backend | Nodes, edges, lineage and snapshots persist across restarts |
| P1 | Fenrir | Correlation engine and duplicate suppression | Mimir graph data | No duplicate edges, no cyclic correlation loops |
| P2 | Heimdall | Infrastructure recon normalization | Tor/proxy policy | DNS, ASN, ports, certs mapped with provenance |
| P2 | Loki | Identity and alias resolution | Process isolation, UA rotation | Profile/email/alias pivots logged and deduped |
| P2 | Hel | Tor-only deep web retrieval | Tor availability | No clear-web leakage; bounded-source retrieval only |
| P2 | Skadi | Evidence freezing and signing | Evidence vault, hash tools | Every artifact hash-linked and signed |
| P3 | OPSEC Policy | Routing enforcement and isolation | Tor, proxychains, subprocess sandbox | Any route failure blocks action |
| P4 | Kaisen Base | Knowledge capture and heuristic promotion | Finished engagements, report artifacts | Lessons stored and reusable patterns promoted |

## Validation Gates

1. Session checkpoint before every major action.
2. Audit verify after every ledger mutation.
3. Graph query round-trip after every ingest.
4. Correlation dedup test after every Fenrir run.
5. Tor failure test must block Loki and Hel.
6. Resume test must reconstruct the latest session.
7. Controlled contradiction test must trigger Tyr block.
8. Evidence freeze must preserve hashes and signature validity.
9. Final report must compile from frozen artifacts only.

## Execution Sequence

1. Harden Odin, Tyr, and Ledger.
2. Expand Mimir, Norn, and Fenrir.
3. Harden Heimdall, Loki, Hel, and Skadi.
4. Enforce OPSEC runtime rules.
5. Institutionalize Kaisen.
6. Run full validation gates again.
