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
trap 'rm -rf "$TMP_CTX"' EXIT

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

echo "[1/6] Building test image with build-time RUN..."
"$BIN" build "$TMP_CTX" --tag verify-img

echo "[2/6] Starting detached container with limits & port mapping..."
CID=$("$BIN" run -d --name verify-c1 -p 18080:8080 --memory 128m --cpus 0.5 --pids-max 64 verify-img)
echo "Started container: $CID"

sleep 2
echo "[3/6] Checking ps and logs..."
"$BIN" ps
"$BIN" logs -n 5 verify-c1

echo "[4/6] Running exec inside running container..."
"$BIN" exec verify-c1 /bin/sh -c 'echo "UID=$(id -u) ENV=$VERIFY_ENV PWD=$(pwd)" && test -f /app/built.txt'

echo "[5/6] Stopping and removing container + image..."
"$BIN" stop -t 2 verify-c1
"$BIN" rm verify-c1
"$BIN" rmi verify-img

echo "[6/6] Host verification passed!"
