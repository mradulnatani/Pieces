#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./build/pieces}"
if [[ ! -x "$BIN" ]]; then
    echo "Error: $BIN not found or not executable. Build first with: cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Run this host integration script with sudo: sudo $0 $BIN"
    exit 1
fi

TMP_CTX="$(mktemp -d)"
OCI_BUNDLE="$(mktemp -d)"
trap 'rm -rf "$TMP_CTX" "$OCI_BUNDLE"' EXIT

cat > "$TMP_CTX/hello.txt" <<'EOF'
hello from pieces host test
EOF

cat > "$TMP_CTX/Piecefile" <<'EOF'
FROM alpine:3.18
ENV VERIFY_ENV=ok
WORKDIR /app
COPY hello.txt /app/hello.txt
RUN cat /app/hello.txt > /app/built.txt
CMD ["/bin/sh", "-c", "while true; do cat /app/built.txt; sleep 1; done"]
EOF

echo "[1/8] Building test image with build-time RUN..."
"$BIN" build "$TMP_CTX" --tag verify-img

echo "[2/8] Testing --read-only, non-root --user, and allowlist seccomp blocking unshare..."
"$BIN" run --rm --read-only --user 1000:1000 --run-as-non-root --net none verify-img \
    /bin/sh -c 'test "$(id -u)" = "1000" && ! touch /ro-test 2>/dev/null && ! unshare -U id 2>/dev/null'

echo "[3/8] Starting detached container with limits & port mapping..."
CID=$("$BIN" run -d --name verify-c1 -p 18080:8080 --memory 128m --cpus 0.5 --pids-max 64 verify-img)
echo "Started container: $CID"

sleep 2
echo "[4/8] Checking ps, stats, and logs..."
"$BIN" ps
"$BIN" stats verify-c1
"$BIN" logs -n 5 verify-c1

echo "[5/8] Running exec inside running container..."
"$BIN" exec verify-c1 /bin/sh -c 'echo "ENV=$VERIFY_ENV PWD=$(pwd)" && test -f /app/built.txt'

echo "[6/8] Stopping and removing native container..."
"$BIN" stop -t 2 verify-c1
"$BIN" rm verify-c1

echo "[7/8] Testing OCI Runtime Spec lifecycle (spec -> create -> state -> start -> kill -> delete)..."
cp -a .pieces/images/verify-img "$OCI_BUNDLE/rootfs"
(cd "$OCI_BUNDLE" && "$OLDPWD/$BIN" spec)
"$BIN" create --bundle "$OCI_BUNDLE" verify-oci-1
"$BIN" state verify-oci-1
"$BIN" start verify-oci-1
sleep 1
"$BIN" kill verify-oci-1 SIGKILL || true
sleep 1
"$BIN" delete -f verify-oci-1

echo "[8/8] Cleaning up image..."
"$BIN" rmi verify-img

echo "Host verification (native + hardened + OCI runtime) passed!"
