# Verificación Forense Externa — AmegakureWotan

Cómo un tercero (auditor, cliente, tribunal) verifica la cadena de custodia
**sin instalar el paquete** `amegakurewotan`, usando SOLO tres artefactos:

- `timeline.jsonl` — registro probatorio (append-only, HMAC-SHA512 encadenado).
- `custody.sig.json` — sobre de firma Ed25519 (fuera del timeline).
- `<pubkey>.pem` — clave **pública** Ed25519 del firmante.

Opcional: `custody_hmac.key` (clave HMAC, operator-local) para re-verificar el
hash-chain sin depender solo de la firma.

## Algoritmo (replicado en `scripts/verify_external.sh`)

1. **Digest de la cadena.** Se recorre `timeline.jsonl` en orden; cada registro
   se serializa canónicamente (`json.dumps(sort_keys=True, separators=(",",":"))`),
   se hashea SHA-512 y se acumula. Resultado: `chain_sha512` (64 bytes).
   Es idéntico a `evidence/custody_signer._derive_chain_digest`.
2. **Firma Ed25519.** El firmante calculó `signature_hex = openssl pkeyutl -sign
   -rawin` sobre los 64 bytes del digest. El tercero verifica con la clave
   pública: `openssl pkeyutl -verify -rawin -pubin -inkey <pub>`. "Success" ⇒
   la cadena no fue alterada tras la firma.
3. **Hash-chain HMAC (opcional).** Si se entrega `custody_hmac.key`, el script
   reconstruye cada `chain_hash = HMAC-SHA512(key, prev_hash || canonical(body))`
   y compara con el persistido, detectando mutación de cualquier bit del body
   o rotura del enlace (ver `evidence/forensics.py:verify_chain`).

## Ejecución

```bash
# Desde un entorno LIMPIO (solo openssl + python3 stdlib)
bash scripts/verify_external.sh /ruta/evidence opsec/keys/roe_pub.pem
# → FIRMA ED25519 VÁLIDA
# → HASH-CHAIN: omitido (no se proveyó custody_hmac.key; ...)
# → CADENA ÍNTEGRA + FIRMA VÁLIDA

# Con clave HMAC para verificación de enlace completa:
bash scripts/verify_external.sh /ruta/evidence opsec/keys/roe_pub.pem opsec/keys/custody_hmac.key
```

## Tamper-evidence (prueba de falsificación)

```bash
cp -r /ruta/evidence /tmp/tamper
# alterar 1 byte de cualquier registro en /tmp/tamper/timeline.jsonl
bash scripts/verify_external.sh /tmp/tamper opsec/keys/roe_pub.pem
# → FIRMA ED25519 INVÁLIDA — cadena manipulada   (exit 1)
```

La firma Ed25519 es sobre el digest de TODA la cadena; un solo byte alterado
invalida el sobre. Esto cumple el requisito TRL-9 de verificación desde un
entorno externo limpio, no desde el propio repo.

## Notas de despliegue

- La clave **privada** Ed25519 (`custody_ed25519.pem` / `roe_priv.pem`) NUNCA se
  comparte. Solo la pública va al bundle de verificación.
- `custody_hmac.key` es operator-local (`.gitignore`); si se entrega a un auditor,
  se hace por canal aparte, fuera del repo.
- La verificación no requiere red, Tor, podman ni el grafo Kùzu.
