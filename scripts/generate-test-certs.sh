#!/usr/bin/env bash
# generate-test-certs.sh — Create TLS certificates for the kmip-go mTLS tests.
#
# Outputs (written to testdata/certs/ relative to this script's parent directory):
#   ca.crt / ca.key     — root CA (self-signed, 10y)
#   kms.crt / kms.key   — KMS TLS server cert
#                         SANs: cosmian-kms, localhost, host.docker.internal, 127.0.0.1
#   client.crt / key    — mTLS client cert (presented by the Go test client)
#
# Usage:
#   bash scripts/generate-test-certs.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${REPO_ROOT}/testdata/certs"
mkdir -p "${DIR}"

# ── Root CA ──────────────────────────────────────────────────────────────────
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
  -keyout "${DIR}/ca.key" -out "${DIR}/ca.crt" \
  -days 3650 -nodes \
  -subj "/CN=Cosmian Test CA/O=Cosmian/C=FR"

# ── Helper: issue a leaf cert ─────────────────────────────────────────────────
issue_cert() {
  local name="$1" usage="$2"
  shift 2
  local san_parts=()
  for h in "$@"; do
    if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      san_parts+=("IP:${h}")
    else
      san_parts+=("DNS:${h}")
    fi
  done
  local san_string; san_string=$(IFS=,; echo "${san_parts[*]}")

  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-384 \
    -keyout "${DIR}/${name}.key" -out "${DIR}/${name}.csr" \
    -nodes -subj "/CN=${name}/O=Cosmian/C=FR"
  openssl x509 -req \
    -in "${DIR}/${name}.csr" \
    -CA "${DIR}/ca.crt" -CAkey "${DIR}/ca.key" -CAcreateserial \
    -out "${DIR}/${name}.crt" -days 3650 \
    -extfile <(printf "subjectAltName=%s\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%s" \
               "${san_string}" "${usage}")
  rm -f "${DIR}/${name}.csr"
  echo "issued: ${name}.crt"
}

issue_cert "kms"    "serverAuth" "cosmian-kms" "localhost" "host.docker.internal" "127.0.0.1"
issue_cert "client" "clientAuth" "localhost" "127.0.0.1"

echo "Certificates written to ${DIR}"
