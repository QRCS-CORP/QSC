#!/usr/bin/env bash
# QSC Stage 6 software-token test runner; not a physical-HSM qualification.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS="${1:?usage: qualify_stage6_nss.sh OUTPUT_DIRECTORY}"
CC="${CC:-gcc}"
NSS_MODULE="${QSC_STAGE6_NSS_MODULE:-/usr/lib/x86_64-linux-gnu/libsoftokn3.so}"

if [[ ! -f "$NSS_MODULE" ]]; then
    echo "BLOCKED: NSS PKCS11 software-token module not installed: $NSS_MODULE" >&2
    exit 2
fi

for prog in certutil openssl python3 "$CC" ar timeout xargs; do
    if ! command -v "$prog" >/dev/null 2>&1; then
        echo "BLOCKED: missing test dependency $prog" >&2
        exit 2
    fi
done

mkdir -p "$RESULTS"
RESULTS="$(cd "$RESULTS" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/qsc-hsm-stage6-XXXXXXXX")"
SERVER_PID=""

cleanup()
{
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi

    rm -rf -- "$TMP"
}
trap cleanup EXIT

mkdir -p "$TMP/libobj" "$TMP/nssdb"
printf 'QSC Stage 6, compiler %s\n' "$($CC --version | head -1)" | tee "$RESULTS/toolchain.txt"

# Compile the pinned general-purpose QSC implementation without any hardware providers.
# Hardware sources are linked only into the test executable. No existing source is edited.
find "$ROOT/QSC" -maxdepth 1 -name '*.c' \
    ! -name hwprovider.c ! -name hwpkcs11tls.c \
    ! -name p11loader.c ! -name p11session.c ! -name p11keys.c \
    ! -name p11sign.c ! -name p11agree.c -print0 | \
    xargs -0 -P 8 -I '{}' bash -c '
        name="$(basename "$2" .c)"
        "$1" -std=c11 -O2 -w -I "$3" -c "$2" -o "$4/${name}.o"
    ' _ "$CC" '{}' "$ROOT/QSC" "$TMP/libobj" \
    >"$RESULTS/compile_stdout.log" 2>"$RESULTS/compile.log"
ar rcs "$TMP/libqsc.a" "$TMP"/libobj/*.o

"$CC" -std=c11 -O2 -Wall -Wextra -Werror \
    -DQSC_HARDWARE_ENABLED -DQSC_HARDWARE_PKCS11_ENABLED \
    -I "$ROOT/QSC" -I/usr/include/p11-kit-1 \
    "$ROOT/QSCTest/HW/hwpkcs11_stage6_test.c" \
    "$ROOT/QSC/p11loader.c" "$ROOT/QSC/p11session.c" \
    "$ROOT/QSC/p11keys.c" "$ROOT/QSC/p11sign.c" \
    "$ROOT/QSC/p11agree.c" "$ROOT/QSC/hwpkcs11tls.c" \
    "$TMP/libqsc.a" -ldl -lpthread -lm -o "$TMP/qsc_stage6" \
    >"$RESULTS/stage6_compile.log" 2>&1

certutil -N --empty-password -d "sql:$TMP/nssdb" >"$RESULTS/nss_init.log" 2>&1
"$TMP/qsc_stage6" "$NSS_MODULE" "$TMP/nssdb" "$RESULTS" \
    >"$RESULTS/nss_stage6.log" 2>&1

python3 - "$RESULTS" <<'PY'
from pathlib import Path
import sys
folder = Path(sys.argv[1])
point = (folder / 'nss_p256_public.sec1').read_bytes()
assert len(point) == 65 and point[0] == 4
spki_p256 = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')
(folder / 'nss_p256_public.der').write_bytes(spki_p256 + point)
PY

openssl pkey -pubin -inform DER -in "$RESULTS/nss_p256_public.der" \
    -out "$RESULTS/nss_p256_public.pem" >"$RESULTS/openssl_pubkey.log" 2>&1
openssl dgst -sha256 -verify "$RESULTS/nss_p256_public.pem" \
    -signature "$RESULTS/nss_tls_signature.der" "$RESULTS/nss_tls_message.bin" \
    >"$RESULTS/openssl_signature_verify.log" 2>&1
openssl req -inform DER -in "$RESULTS/nss_p256_request.der" -verify -noout -subject \
    >"$RESULTS/openssl_csr_verify.log" 2>&1

# The CA private key is deliberately confined to the disposable temporary directory.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -noenc \
    -keyout "$TMP/ca.key" -out "$RESULTS/test_ca.pem" -days 1 \
    -subj '/CN=QSC Stage6 Local Test CA' >"$RESULTS/ca_create.log" 2>&1
printf '%s\n' 'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature' \
    'extendedKeyUsage=serverAuth,clientAuth' \
    'subjectAltName=DNS:qsc-stage6-nss.example' > "$TMP/ext.cnf"
openssl x509 -req -inform DER -in "$RESULTS/nss_p256_request.der" \
    -CA "$RESULTS/test_ca.pem" -CAkey "$TMP/ca.key" -CAcreateserial \
    -out "$RESULTS/nss_p256_leaf.pem" -days 1 -sha256 -extfile "$TMP/ext.cnf" \
    >"$RESULTS/issuance.log" 2>&1
openssl x509 -in "$RESULTS/nss_p256_leaf.pem" -outform DER \
    -out "$RESULTS/nss_p256_leaf.der" >"$RESULTS/leaf_convert.log" 2>&1
openssl verify -CAfile "$RESULTS/test_ca.pem" "$RESULTS/nss_p256_leaf.pem" \
    >"$RESULTS/openssl_chain_verify.log" 2>&1

PORT="${QSC_STAGE6_PORT:-$(python3 - <<'PY'
import socket
s=socket.socket()
s.bind(('127.0.0.1', 0))
print(s.getsockname()[1])
s.close()
PY
)}"

"$TMP/qsc_stage6" "$NSS_MODULE" "$TMP/nssdb" "$RESULTS" \
    "$RESULTS/nss_p256_leaf.der" "$PORT" \
    >"$RESULTS/qsc_tls_server.log" 2>&1 &
SERVER_PID="$!"

ready=0
for i in {1..100}; do
    if grep -q 'loopback TLS server READY' "$RESULTS/qsc_tls_server.log"; then
        ready=1
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if [[ "$ready" -ne 1 ]]; then
    echo 'FAIL: QSC test TLS server did not start' >&2
    exit 1
fi

timeout 20 openssl s_client -connect "127.0.0.1:$PORT" -tls1_3 \
    -servername qsc-stage6-nss.example \
    -CAfile "$RESULTS/test_ca.pem" -verify_hostname qsc-stage6-nss.example \
    -verify_return_error -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 \
    -brief </dev/null >"$RESULTS/openssl_tls_client.log" 2>&1
wait "$SERVER_PID"
SERVER_PID=""

grep -q 'Verification: OK' "$RESULTS/openssl_tls_client.log"
grep -q 'Signature type: ecdsa_secp256r1_sha256' "$RESULTS/openssl_tls_client.log"
grep -q 'PASS: Stage6 QSC PKCS11 TLS 1.3 vs OpenSSL independent peer' "$RESULTS/qsc_tls_server.log"

echo "PASS: QSC Stage6 NSS software-token independent OpenSSL verification ($CC)" | tee "$RESULTS/summary.txt"
echo 'NOT QUALIFIED: No physical HSM, no physical token attestation, no actual hardware disconnect/PIN lockout, no production FIPS claims.' | tee -a "$RESULTS/summary.txt"
