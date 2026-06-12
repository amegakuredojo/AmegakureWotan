# Karasugakure — Threat Model

## Assets
- Operator Identity (IP Address, location, metadata).
- Investigation Context (targets, connections, stored evidence).

## Threats
1. **Accidental Network Leakage**: Requesting a target domain or server directly without routing through proxies, revealing the operator's IP address.
2. **DNS Leakage**: Requesting resolution of target domains via local DNS servers instead of remote/Tor DNS resolving.
3. **Database Compromise**: Relational evidence leaks.

## Mitigations
- **Selective application-level proxying**: Explicitly route darkweb/recon queries via Tor SOCKS5.
- **NATO Evaluation Matrix**: Eliminate false positives and low-quality findings through Tyr scoring.
- **Signed Evidence Vault**: Ensure integrity of evidence files with Skadi's SHA-256 signatures.
