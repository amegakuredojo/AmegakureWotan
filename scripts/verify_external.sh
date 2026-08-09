#!/usr/bin/env bash
# verify_external.sh — Verificación forense EXTERNA de AmegakureWotan
#
# Un tercero valida la cadena de custodia con SOLO:
#   - timeline.jsonl              (registro probatorio)
#   - custody.sig.json            (sobre de firma Ed25519)
#   - <pubkey>.pem                (clave PUBLICA Ed25519)
#   - [opcional] custody_hmac.key (clave HMAC para re-verificar el hash-chain)
#
# NO importa el paquete amegakurewotan. Replica el algoritmo de:
#   evidence/forensics.py  (HMAC-SHA512 hash-chain)
#   evidence/custody_signer.py (firma Ed25519 sobre SHA-512 del timeline)
#
# Uso:
#   bash scripts/verify_external.sh <dir_evidence> <pubkey_ed25519.pem> [hmac_key]
#
# Salida: "CADENA ÍNTEGRA + FIRMA VÁLIDA" o falla (tamper-evidence).
set -euo pipefail

EVIDENCE_DIR="${1:-}"
PUBKEY="${2:-}"
HMAC_KEY="${3:-}"

if [[ -z "$EVIDENCE_DIR" || -z "$PUBKEY" ]]; then
  echo "Uso: verify_external.sh <dir_evidence> <pubkey_ed25519.pem> [hmac_key]" >&2
  exit 2
fi

TIMELINE="$EVIDENCE_DIR/timeline.jsonl"
SIG="$EVIDENCE_DIR/custody.sig.json"

if [[ ! -f "$TIMELINE" ]]; then echo "ERROR: falta $TIMELINE" >&2; exit 1; fi
if [[ ! -f "$SIG" ]]; then echo "ERROR: falta $SIG (sobre de firma)" >&2; exit 1; fi
if [[ ! -f "$PUBKEY" ]]; then echo "ERROR: falta $PUBKEY" >&2; exit 1; fi

# ── 1. Reconstruir el digest SHA-512 canónico de TODA la cadena ──────────────
# Igual que _derive_chain_digest(): cada registro se serializa canónicamente
# (sort_keys, separators ",:"), se hashea en orden de aparición.
CHAIN_DIGEST=$(python3 - "$TIMELINE" <<'PY'
import hashlib, json, sys
h = hashlib.sha512()
count = 0
with open(sys.argv[1], "r", encoding="utf-8") as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)
        serialized = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        h.update(serialized.encode("utf-8"))
        count += 1
if count == 0:
    sys.exit("ERROR: timeline vacío")
print(h.hexdigest())
PY
) || { echo "ERROR: reconstruyendo digest: $CHAIN_DIGEST" >&2; exit 1; }

# ── 2. Verificar firma Ed25519 del sobre contra la clave PÚBLICA ─────────────
# custody_signer firma (pkeyutl -sign -rawin) los 64 bytes del SHA-512.
SIGNATURE_HEX=$(python3 - "$SIG" <<'PY'
import json, sys
overlay = json.load(open(sys.argv[1]))
print(overlay["signature_hex"])
PY
)

SIG_FILE=$(mktemp); DIGEST_FILE=$(mktemp); PUB_FILE=$(mktemp)
trap 'rm -f "$SIG_FILE" "$DIGEST_FILE" "$PUB_FILE"' EXIT

# Extraer clave pública PEM del archivo dado (ya es PEM o la derivamos)
if grep -q "BEGIN PUBLIC KEY" "$PUBKEY"; then
  cp "$PUBKEY" "$PUB_FILE"
else
  # Si es la privada, derivamos la pública (no se usa para firmar)
  openssl pkey -in "$PUBKEY" -pubout -out "$PUB_FILE" 2>/dev/null
fi

python3 - "$SIGNATURE_HEX" "$CHAIN_DIGEST" <<PY
import sys
sig = bytes.fromhex(sys.argv[1])
dig = bytes.fromhex(sys.argv[2])
open("$SIG_FILE","wb").write(sig)
open("$DIGEST_FILE","wb").write(dig)
PY

if openssl pkeyutl -verify -rawin -pubin -inkey "$PUB_FILE" \
  -in "$DIGEST_FILE" -sigfile "$SIG_FILE" 2>/dev/null | grep -q "Success"; then
  echo "FIRMA ED25519 VÁLIDA (sobre custody.sig.json)"
else
  echo "FIRMA ED25519 INVÁLIDA — cadena manipulada" >&2
  exit 1
fi

# ── 3. Re-verificar el hash-chain HMAC-SHA512 (si se proveyó la clave) ───────
if [[ -n "$HMAC_KEY" && -f "$HMAC_KEY" ]]; then
  python3 - "$TIMELINE" "$HMAC_KEY" <<'PY'
import hashlib, hmac, json, sys
timeline, keyfile = sys.argv[1], sys.argv[2]
key = open(keyfile,"rb").read()
if len(key) < 32:
    sys.exit("ERROR: clave HMAC corta")
GENESIS = "0"*128
expected_prev = GENESIS
expected_seq = 0
line_num = 0
with open(timeline, "r", encoding="utf-8") as fh:
    for raw in fh:
        raw = raw.strip()
        if not raw:
            continue
        line_num += 1
        rec = json.loads(raw)
        seq = rec.get("seq")
        chain_hash = rec.get("chain_hash")
        if chain_hash is None:
            sys.exit(f"ERROR: chain_hash ausente en línea {line_num}")
        if seq != expected_seq:
            sys.exit(f"ERROR: secuencia rota línea {line_num}")
        if rec.get("prev_hash") != expected_prev:
            sys.exit(f"ERROR: enlace hash-chain roto línea {line_num}")
        body = {k:v for k,v in rec.items() if k != "chain_hash"}
        msg = (rec.get("prev_hash","") + json.dumps(body, sort_keys=True, separators=(",",":"), ensure_ascii=False)).encode("utf-8")
        recomputed = hmac.new(key, msg, hashlib.sha512).hexdigest()
        if not hmac.compare_digest(recomputed, str(chain_hash)):
            sys.exit(f"ERROR: chain_hash HMAC no coincide línea {line_num}")
        expected_prev = chain_hash
        expected_seq += 1
print(f"HASH-CHAIN ÍNTEGRO ({line_num} registros)")
PY
  CHAIN_RC=$?
  if [[ $CHAIN_RC -ne 0 ]]; then exit 1; fi
else
  echo "HASH-CHAIN: omitido (no se proveyó custody_hmac.key; la firma Ed25519 ya atestigua la cadena)"
fi

echo "───"
echo "CADENA ÍNTEGRA + FIRMA VÁLIDA"
