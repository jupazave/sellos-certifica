#!/usr/bin/env bash
# Regenera el par sintetico usado en tests (NO es material del SAT).
# Imita el cifrado legacy del SAT: PKCS#8 con PBE-SHA1-3DES, en DER.
#
# Confirmado compatible con:
#   - LibreSSL 3.3.6 (openssl del sistema en macOS)
#   - OpenSSL 3.6.3 (brew install openssl@3)
# Si tu OpenSSL/LibreSSL rechaza "-v1 PBE-SHA1-3DES", sustituye esa linea por
# "-v2 des3" y documenta el cambio en tests/fixtures/README.md.
set -euo pipefail
cd "$(dirname "$0")"

PASS="sintetica123"
PLAIN="$(mktemp "${TMPDIR:-/tmp}/sintetica-plain.XXXXXX")"
trap 'rm -f "$PLAIN"' EXIT

openssl genrsa -out "$PLAIN" 2048
openssl req -new -x509 -key "$PLAIN" -days 3650 \
  -subj "/CN=PRUEBA SINTETICA/x500UniqueIdentifier=XAXX010101000" \
  -outform DER -out sintetica.cer
openssl pkcs8 -topk8 -inform PEM -in "$PLAIN" \
  -outform DER -out sintetica.key -v1 PBE-SHA1-3DES -passout "pass:${PASS}"

echo "OK: sintetica.cer / sintetica.key (contrasena: ${PASS})"
