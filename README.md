# Pieces

**Pieces** is a lightweight, hardened, **OCI Runtime Spec–compatible** and **Docker-parity** Linux container runtime written in **C++20**.

It executes containers directly using Linux kernel primitives—namespaces (`unshare`, `setns`), `pivot_root`, in-namespace OverlayFS with a fast hybrid `tmpfs` fallback, direct `NETLINK_ROUTE` networking, default-deny allowlist `seccomp-bpf`, `libcap` capability dropping, AppArmor/SELinux MAC labels, `/proc` & `/sys` masking, rootless `CLONE_NEWUSER` (`/etc/subuid`, `/etc/subgid`, `pasta`/`slirp4netns`), and cgroups v2—while supporting `Dockerfile` multi-stage builds with layer caching, named volumes, custom networks + embedded DNS, `compose`, an opt-in Docker Unix socket REST API (`serve`), and the `runc`/`crun`-style **OCI Runtime Specification** CLI (`spec`, `create`, `start`, `state`, `kill`, `delete`).

For the full book-length engineering manual documenting every C++ module, kernel syscall, CLI option, security layer, Netlink packet flow, Compose engine, REST shim, and OCI/Kubernetes workflow, read **[TUTORIAL.md](TUTORIAL.md)**.

---

## Highlights

- **Sub-10 ms startup engineering:** Zero-copy `--read-only` rootfs, in-namespace OverlayFS (or `< 1 ms` hybrid `tmpfs` + read-only bind-mount fallback), `/dev/shm/.pieces-run/` RAM scratch for `--rm`, zero-subprocess `NETLINK_ROUTE` `veth`/bridge setup, `flock`-locked `O(active)` IPAM, pre-built BPF filters, and skipped `userns` sync pipes when running as root.
- **Docker-parity build & image workflow:** Supports both `Piecefile` and `Dockerfile` (`-f/--file` override), multi-stage `FROM ... AS <stage>` + `COPY --from=<stage>` + `--chown=`, content-addressed layer cache (`.pieces/cache/layers/`), `.piecesignore` / `.dockerignore`, local `FROM <image>`, `ARG`/`--build-arg`, `USER`, `ADD`, `EXPOSE`, `VOLUME`, `LABEL`, `$VAR` expansion, `tag`, and `inspect`.
- **Hardened by default:** Default-deny **allowlist `seccomp-bpf`** (`AUDIT_ARCH` checked + `PR_SET_NO_NEW_PRIVS`, blocking `unshare`, `setns`, `chroot`, `mount`, `bpf`, `ptrace`, etc.), custom OCI `seccomp` JSON profiles (`--seccomp-profile`), `libcap` dropping (`--cap-drop`/`--cap-add`), `--read-only` rootfs, `--user` / `--run-as-non-root`, AppArmor/SELinux `--security-opt`, and default lateral/host bridge firewall isolation (`--no-isolate-net` to opt out).
- **Supply-chain verified registries (no Docker Hub):** Pulls from built-in upstream Linux CDNs (`alpine:3.18`, `fedora:38`, `ubuntu:22.04`), direct tarballs (`FROM_URL` + `SHA256`), or explicit non-Docker-Hub OCI v2 registries (`ghcr.io/...`, `quay.io/...`, `registry.fedoraproject.org/...`, `localhost:5000/...`) with OpenSSL `EVP_sha256()` verification, OCI whiteout extraction, and `pieces login` / `~/.docker/config.json` auth. Docker Hub is intentionally disabled.
- **Full runtime, volumes, networks, Compose & REST API:** `--net host|bridge|none|<custom_net>`, `--entrypoint`, `--env-file`, `--tmpfs`, `--add-host`, `--dns`, `cp`, `volume create|ls|inspect|rm`, `network create|ls|inspect|rm` with embedded UDP DNS responder, rootless `pasta`/`slirp4netns` networking, `compose up|down|ps|logs`, optional `serve` Docker REST Unix socket (`/_ping`, `/version`, `/info`, `/containers/...`, `/images/json`, `/volumes`, `/networks`), and OCI `create`/`start`/`state`/`kill`/`delete`.

---

## Architecture

```text
CMakeLists.txt             CMake build (C++20, libcurl, libarchive, OpenSSL::Crypto, libcap, util, pthread)
include/pieces/*.hpp       Public C++ module headers
src/
├── main.cpp               CLI entry point (20 native commands + 6 OCI commands)
├── cli.cpp                Subcommand, `--flag=val`, short-flag, and global `--root` parser
├── parser.cpp             Piecefile/Dockerfile parser (multi-stage FROM..AS, ARG, USER, ADD, EXPOSE, VOLUME, LABEL)
├── json.cpp               Self-contained JsonValue recursive-descent parser & serializer
├── registry.cpp           Non-Docker-Hub OCI v2 pull client (Bearer + Basic auth, `~/.docker/config.json`, EVP SHA-256)
├── filesystem.cpp         Cached downloads, safe tar + whiteouts, layer cache, `.dockerignore`, multi-stage build, volumes, tag
├── security.cpp           Default-deny allowlist seccomp-bpf, OCI seccomp JSON, libcap, AppArmor/SELinux, UID/GID
├── namespaces.cpp         unshare, setns, in-ns OverlayFS / hybrid tmpfs, pivot_root, tmpfs mounts, masked /proc,/sys
├── network.cpp            NETLINK_ROUTE bridge/veth/IP/route, custom networks, EmbeddedDnsServer, flock IPAM, pasta/slirp4netns
├── cgroup.cpp             Cgroup v2 memory.max, cpu.max, pids.max, custom cgroupsPath, telemetry reader
├── container.cpp          Supervisor, PTY relay, rotating logs, restart backoff, --timing, inspect, cp, env-file, hosts/dns
├── compose.cpp            Compose YAML parser, depends_on topological sort, compose up/down/ps/logs
├── daemon.cpp             Optional AF_UNIX HTTP/1.1 Docker REST API shim (`pieces serve`)
└── oci_runtime.cpp        OCI Runtime Spec engine (spec, create, start, state, kill, delete, exec.fifo, hooks)
tests/
└── test_pieces.cpp        6 C++ unit test suites (runs unprivileged via ctest)
scripts/
└── verify_host.sh         8-step live Linux kernel host verification script (requires sudo)
```

---

## Requirements

- **Operating System:** Linux (`x86_64`, `aarch64`, `armv7l`, `i386`/`i686`, `riscv64`; kernel 5.11+ recommended for rootless `userxattr` OverlayFS and cgroups v2).
- **Build Toolchain:** CMake `3.20+`, C++20 compiler (`g++` 13+ or `clang++`), `pkg-config`.
- **Libraries (`-dev` packages):** `libcurl`, `libarchive`, `openssl` (`libcrypto`), `libcap`.
- **Runtime Privileges & Host Utilities:**
  - `sudo` / `root` (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`) for bridge networking, `-p` port forwarding, and cgroup v2 limits; unprivileged users can run rootless (`CLONE_NEWUSER`) with optional `newuidmap`/`newgidmap` (`/etc/subuid` & `/etc/subgid`), optional `fuse-overlayfs`, and optional `pasta` / `slirp4netns` for rootless networking.
  - `iptables` (optional, for NAT `MASQUERADE`, bridge isolation, and `-p` DNAT rules) and `ip` / `nsenter` (fallback only when `NETLINK_ROUTE` fails).

---

## Quick Start

### 1. Build & Run Unit Tests

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### 2. Multi-Stage Builds, Hardened Runs, Volumes & Compose

Build from a `Piecefile` or `Dockerfile`:

```dockerfile
ARG BASE=alpine:3.18
FROM $BASE AS builder
WORKDIR /src
COPY ./app /src
RUN chmod +x /src/start.sh

FROM alpine:3.18
USER 1000:1000
EXPOSE 8080/tcp
VOLUME ["/data"]
WORKDIR /app
COPY --from=builder /src/start.sh /app/start.sh
CMD ["/app/start.sh"]
```

Run containers, named volumes, custom networks, and Compose stacks:

```bash
# Build with automatic layer caching (-f to specify alternate Dockerfile path)
sudo ./build/pieces build . --tag my-service

# Ephemeral, read-only, non-root run with tmpfs, env-file, and startup timing
sudo ./build/pieces run --rm --read-only --run-as-non-root --tmpfs /tmp:size=32m --env-file .env --timing my-service

# Custom network + named volume + detached service
sudo ./build/pieces volume create app-data
sudo ./build/pieces network create app-net
sudo ./build/pieces run -d --name api --net app-net -v app-data:/data -p 8080:8080 my-service

# Inspect, copy files, view telemetry/logs, enter namespaces, stop, and clean up
sudo ./build/pieces inspect api
sudo ./build/pieces cp api:/app/start.sh ./start.sh.bak
sudo ./build/pieces stats api
sudo ./build/pieces exec -it api /bin/sh
sudo ./build/pieces stop api && sudo ./build/pieces rm api

# Multi-container Compose workflow & optional Docker REST Unix socket
sudo ./build/pieces compose up -d
sudo ./build/pieces compose ps
sudo ./build/pieces compose down
sudo ./build/pieces serve --socket /run/pieces/docker.sock
```

---

## Performance & Startup Timing

Pieces avoids interpreter startup, full-tree copies, and network helper subprocesses:

| Optimization Area | Mechanism Used by Pieces | Eliminated Overhead |
| --- | --- | --- |
| **CLI & Dispatch** | Native compiled C++20 binary (`-O3` in Release) | ~141 ms Python interpreter boot |
| **`--read-only` Rootfs** | `readonly-bind`: pivots directly onto the immutable image dir (`MS_RDONLY`) | Zero directory creation, zero file copies |
| **Writable Rootfs (`!readonly_rootfs`)** | `in-ns-overlay`: creates empty `upper`/`work`/`rootfs` (in `/dev/shm/.pieces-run/` RAM `tmpfs` for `--rm`) and mounts kernel `overlay` / `userxattr` / `fuse-overlayfs` inside `pid2`, or fast hybrid `tmpfs` + RO bind-mounts (`--full-copy` optional) | Eliminates ~543 ms full-image copy and ~304 ms recursive cleanup |
| **Build Layer Cache** | Content-addressed `.pieces/cache/layers/<chain_hash>` snapshots | Skips re-running unchanged `COPY`/`RUN` stages on rebuild |
| **Networking & IPAM** | Direct `NETLINK_ROUTE` sockets for bridge/`veth`/IP/route; sysfs + `/run/pieces/.net_ready_*` fast skip; `flock`-locked per-network IPAM (`O(active)`) | Eliminates `ip` / `nsenter` subprocess spawns and exited-container directory scans |
| **Security & Pipes** | Seccomp BPF & target `cap_value_t` computed once before `fork()`; rootful runs skip `userns_done_pipe` | Removes per-spawn compilation and extra parent/child pipe round-trips |

### Measured Timings (Observed in Sandbox Pre-Docker-Parity Benchmark Run)

| Command / Benchmark | Observed Timing | Breakdown / Notes |
| --- | --- | --- |
| `./build/pieces --help` | **5.92 ms** | Down from **147.3 ms** in the earlier Python CLI |
| `./build/pieces images` | **6.55 ms** | Direct C++ directory + `.pieces_meta.json` scan |
| `./build/pieces ps -a` | **5.56 ms** | Direct C++ container metadata scan + PID reconciliation |
| `./build/pieces run --rm --read-only --timing --net none ubuntu-22.04 /bin/true` *(pre-`unshare`)* | **1.01 ms** internal (**7.19 ms** wall-clock) | `config+seccomp+caps`: **0.48 ms**, `rootfs (readonly-bind)`: **0.01 ms**, `unshare`: **0.52 ms** *(aborted at sandbox `ENOSYS`)*; `cleanup`: **0.13 ms** |
| `./build/pieces run --rm --timing --net none ubuntu-22.04 /bin/true` *(writable, pre-`unshare`)* | **1.00 ms** internal (**7.38 ms** wall-clock) | `config+seccomp+caps`: **0.33 ms**, `rootfs (in-ns-overlay)`: **0.13 ms** *(down from 543.31 ms copy)*, `unshare`: **0.53 ms** *(aborted at sandbox `ENOSYS`)*, `cleanup`: **0.32 ms** *(down from 304.18 ms)* |

> [!NOTE]
> Inside this sandbox environment, the `unshare` syscall is blocked (`ENOSYS: Function not implemented`), so kernel-side post-`unshare` phases (`mount_in_namespace_rootfs`, `pivot_root`, `veth` creation, and `execvpe`) could not run here. Measure full end-to-end startup latency on a standard Linux host with:
> ```bash
> sudo ./build/pieces run --rm --timing ubuntu-22.04 /bin/true
> ```

---

## Kubernetes & `containerd` (OCI Runtime Spec)

Pieces implements the low-level **OCI Runtime Spec CLI** (`create`/`start`/`state`/`kill`/`delete`) used by `containerd` (`io.containerd.runc.v2` shim) under Kubernetes:

```bash
./build/pieces spec [--rootless]
sudo ./build/pieces --root /run/pieces create --bundle /path/to/bundle --pid-file /tmp/c1.pid c1
sudo ./build/pieces --root /run/pieces state c1
sudo ./build/pieces --root /run/pieces start c1
sudo ./build/pieces stats c1
sudo ./build/pieces --root /run/pieces kill c1 SIGTERM
sudo ./build/pieces --root /run/pieces delete [-f] c1
```

Supported `config.json` features include `linux.namespaces` path joining (`setns` for Pod Sandbox `network`/`ipc`/`uts` sharing), `linux.cgroupsPath` (`kubepods.slice` placement), `linux.resources` (`memory.limit`, `cpu.quota`/`period`, `pids.limit`), `linux.seccomp` JSON profiles, `linux.maskedPaths` / `linux.readonlyPaths`, `root.readonly`, `process.apparmorProfile` / `selinuxLabel`, `uidMappings` / `gidMappings`, `annotations`, and all 6 OCI lifecycle `hooks`.

> [!NOTE]
> Pieces is an OCI low-level runtime binary, not a standalone CRI gRPC daemon. `kubelet` integrates with Pieces through `containerd` (or `CRI-O`), which handles CRI RPCs, image pulls, Pod Sandboxes, and CNI networking. See [Chapter 14](TUTORIAL.md#chapter-14-wiring-pieces-into-containerd--kubernetes) for details.

---

## Image Sources (No Docker Hub)

Docker Hub (`docker.io`, `registry-1.docker.io`, `index.docker.io`, `registry.hub.docker.com`) is disabled by design. Use:
1. **Built-in upstream Linux distro rootfs CDNs:** `alpine:3.18`, `fedora:38`, `ubuntu:22.04`
2. **Direct tarballs (`FROM_URL` + optional `SHA256`):** Any `http://` or `https://` `.tar`, `.tar.gz`, `.tgz`, `.tar.xz`, or `.tar.bz2`
3. **Explicit non-Docker-Hub OCI registries:** `ghcr.io/...`, `quay.io/...`, `registry.fedoraproject.org/...`, `localhost:5000/...` (`pieces login` + `pieces pull <ref>`)

---

## Host Verification

After building on a Linux host with namespaces and `sudo` available, run the full 8-step live kernel integration suite:

```bash
sudo ./scripts/verify_host.sh ./build/pieces
```

---

## Complete Documentation

See **[TUTORIAL.md](TUTORIAL.md)** for **The Pieces Book: Complete Architecture, Kernel Internals & Operations Guide**—covering every C++ file, syscall, `Piecefile`/`Dockerfile` rule, multi-stage layer cache, Netlink message, custom network & DNS, Compose orchestration, REST Unix socket API, seccomp BPF instruction, OCI state transition, benchmark methodology, CLI flag, JSON schema, and integration recipe.
