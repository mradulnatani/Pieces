# Pieces Tutorial: Production-Oriented Guide & Integration

This tutorial explains how to compile, secure, operate, and integrate **Pieces** (C++20) into your projects without relying on Docker Hub.

---

## 1. Prerequisites & Build

Verify host dependencies:

```bash
g++ --version              # C++20 compiler
cmake --version            # CMake 3.20+
pkg-config --modversion libcurl libarchive openssl libcap
which ip nsenter iptables  # iproute2, util-linux, iptables
ls /sys/fs/cgroup/cgroup.controllers  # cgroups v2 check
```

Compile and run unit tests:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

---

## 2. Image Sources (Without Docker Hub)

Docker Hub (`docker.io` / `registry-1.docker.io`) is intentionally blocked. You have three supported image sources:

1. **Built-in official distro rootfs tarballs:** `alpine:3.18`, `fedora:38`, `ubuntu:22.04`
2. **Any tarball URL (`FROM_URL`) with optional checksum (`SHA256`)**
3. **Any non-Docker-Hub OCI registry (`ghcr.io`, `quay.io`, `registry.fedoraproject.org`, or private `localhost:5000`)**

```bash
# Pull from a non-Docker-Hub OCI registry (all blobs verified via SHA-256)
./build/pieces pull ghcr.io/your-org/base-runtime:1.0 -t base-rt
./build/pieces images
```

---

## 3. Building Project Images (`Piecefile`)

Instructions (`ENV`, `WORKDIR`, `COPY`, `RUN`) execute **in declaration order**:

```dockerfile
FROM alpine:3.18
# Optional integrity pin when using FROM_URL:
# FROM_URL https://example.com/rootfs.tar.gz
# SHA256 0123456789abcdef...

ENV APP_ENV=production PORT=8000
WORKDIR /app

COPY ./requirements.txt /app/requirements.txt
RUN apk add --no-cache python3 py3-pip && pip install --no-cache-dir -r /app/requirements.txt

COPY . /app
CMD ["python3", "app.py"]
```

Build the image (uses `.pieces/cache` automatically; pass `--no-cache` to bypass):

```bash
sudo ./build/pieces build . --tag my-service
```

---

## 4. Running Production-Style Services

### Detached Service with Port Forwarding, Restart Policy, Log Rotation & Limits

```bash
sudo ./build/pieces run -d \
  --name web \
  -p 8080:8000 \
  --restart unless-stopped \
  --log-max-size 10m \
  --log-max-files 3 \
  --memory 256m \
  --cpus 0.5 \
  --pids-max 64 \
  my-service
```

### Interactive TTY Shell (`-it`)

```bash
sudo ./build/pieces run --rm -it alpine-3.18 /bin/sh
```

### Inspect, Logs, Exec, Stop & Prune

```bash
./build/pieces ps -a
./build/pieces logs -n 50 -f web
sudo ./build/pieces exec -it web /bin/sh
sudo ./build/pieces stop -t 10 web
./build/pieces rm web
./build/pieces prune
```

---

## 5. Security Hardening & Rootless Mode

- **Default container hardening:** Drops dangerous Linux capabilities (`CAP_SYS_ADMIN`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN`, etc.), applies a `seccomp-bpf` filter (`PR_SET_NO_NEW_PRIVS`) blocking high-risk syscalls (`kexec_load`, `init_module`, `bpf`, `ptrace`, `mount`, `reboot`, etc.), mounts `/sys` and `/proc/sys` read-only, and masks `/proc/kcore`, `/proc/keys`, `/sys/firmware`, etc.
- **Custom capabilities / privileged escape hatch:** Use `--cap-add`, `--cap-drop`, or `--privileged` when strictly required.
- **Rootless mode (`CLONE_NEWUSER`):** Automatically used when invoked without `sudo` (or with `--rootless`). Uses `/etc/subuid` + `/etc/subgid` via `newuidmap`/`newgidmap` when configured, or falls back to single-UID mapping (`0 -> host_uid`).

---

## 6. Live Host Verification

On a real Linux host (with `sudo` or unprivileged user namespaces enabled), run:

```bash
sudo ./scripts/verify_host.sh
```
