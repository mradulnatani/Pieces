# Pieces

**Pieces** is a lightweight, hardened, **OCI Runtime Spec–compatible** Linux container runtime written in **C++20**.

It executes containers directly using Linux kernel primitives—namespaces (`unshare`, `setns`), `pivot_root`, in-namespace OverlayFS with a fast hybrid `tmpfs` fallback, direct `NETLINK_ROUTE` networking, default-deny allowlist `seccomp-bpf`, `libcap` capability dropping, AppArmor/SELinux MAC labels, `/proc` & `/sys` masking, rootless `CLONE_NEWUSER` (`/etc/subuid` & `/etc/subgid`), and cgroups v2—while also implementing the `runc`/`crun`-style **OCI Runtime Specification** CLI (`spec`, `create`, `start`, `state`, `kill`, `delete`).

For the full book-length engineering manual documenting every C++ module, kernel syscall, CLI option, security layer, Netlink packet flow, and OCI/Kubernetes workflow, read **[TUTORIAL.md](TUTORIAL.md)**.

---

## Highlights

- **Sub-10 ms startup engineering:** Zero-copy `--read-only` rootfs, in-namespace OverlayFS (or `< 1 ms` hybrid `tmpfs` + read-only bind-mount fallback), `/dev/shm/.pieces-run/` RAM scratch for `--rm`, zero-subprocess `NETLINK_ROUTE` `veth`/bridge setup, `flock`-locked `O(active)` IPAM, pre-built BPF filters, and skipped `userns` sync pipes when running as root.
- **Hardened by default:** Default-deny **allowlist `seccomp-bpf`** (`AUDIT_ARCH` checked + `PR_SET_NO_NEW_PRIVS`, blocking `unshare`, `setns`, `chroot`, `mount`, `bpf`, `ptrace`, etc.), custom OCI `seccomp` JSON profiles (`--seccomp-profile`), `libcap` dropping (`--cap-drop`/`--cap-add`), `--read-only` rootfs, `--user` / `--run-as-non-root`, AppArmor/SELinux `--security-opt`, and default lateral/host bridge firewall isolation (`--no-isolate-net` to opt out).
- **Supply-chain verified images (no Docker Hub):** Pulls from built-in upstream Linux CDNs (`alpine:3.18`, `fedora:38`, `ubuntu:22.04`), direct tarballs (`FROM_URL` + `SHA256`), or explicit non-Docker-Hub OCI v2 registries (`ghcr.io/...`, `quay.io/...`, `registry.fedoraproject.org/...`, `localhost:5000/...`) with OpenSSL `EVP_sha256()` verification and OCI whiteout extraction. Docker Hub (`docker.io`, `registry-1.docker.io`, etc.) is intentionally disabled.
- **Full native & OCI lifecycle:** `Piecefile` builds with ordered `COPY`/`RUN`/`ENV`/`WORKDIR`, detached services (`-d`, `stop`, rotating `logs`, `--restart` backoff, `exec`, `stats`, `prune`), interactive PTY (`-it`), and OCI `create`/`start`/`state`/`kill`/`delete` + Pod Sandbox namespace joining.

---

## Architecture

```text
CMakeLists.txt             CMake build (C++20, libcurl, libarchive, OpenSSL::Crypto, libcap, util)
include/pieces/*.hpp       Public C++ module headers
src/
├── main.cpp               CLI entry point (12 native commands + 6 OCI commands)
├── cli.cpp                Subcommand, flag, and global `--root` argument parser
├── parser.cpp             Piecefile parser (FROM, FROM_URL, SHA256, COPY, RUN, ENV, WORKDIR, CMD, ENTRYPOINT)
├── json.cpp               Self-contained JsonValue recursive-descent parser & serializer
├── registry.cpp           Non-Docker-Hub OCI v2 pull client (Bearer auth, multi-arch index, EVP SHA-256)
├── filesystem.cpp         Cached libcurl downloads, safe libarchive + OCI whiteouts, build RUN, rootfs prep
├── security.cpp           Default-deny allowlist seccomp-bpf, OCI seccomp JSON, libcap, AppArmor/SELinux, UID/GID
├── namespaces.cpp         unshare, setns, in-ns OverlayFS / hybrid tmpfs, pivot_root, /dev & masked /proc,/sys
├── network.cpp            Direct NETLINK_ROUTE bridge/veth/IP/route, bridge isolation firewall, flock IPAM, NAT/DNAT
├── cgroup.cpp             Cgroup v2 memory.max, cpu.max, pids.max, custom cgroupsPath, telemetry reader
├── container.cpp          Supervisor, PTY relay, rotating logs, restart backoff, --timing profiler, orphan cleanup
└── oci_runtime.cpp        OCI Runtime Spec engine (spec, create, start, state, kill, delete, exec.fifo, hooks)
tests/
└── test_pieces.cpp        5 C++ unit test suites (runs unprivileged via ctest)
scripts/
└── verify_host.sh         8-step live Linux kernel host verification script (requires sudo)
```

---

## Requirements

- **Operating System:** Linux (`x86_64`, `aarch64`, `armv7l`, `i386`/`i686`, `riscv64`; kernel 5.11+ recommended for rootless `userxattr` OverlayFS and cgroups v2).
- **Build Toolchain:** CMake `3.20+`, C++20 compiler (`g++` 13+ or `clang++`), `pkg-config`.
- **Libraries (`-dev` packages):** `libcurl`, `libarchive`, `openssl` (`libcrypto`), `libcap`.
- **Runtime Privileges & Host Utilities:**
  - `sudo` / `root` (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`) for bridge networking, `-p` port forwarding, and cgroup v2 limits; unprivileged users can run rootless (`CLONE_NEWUSER`) when host user namespaces are enabled (with optional `newuidmap`/`newgidmap` for `/etc/subuid` & `/etc/subgid`, and optional `fuse-overlayfs`).
  - `iptables` (optional, for NAT `MASQUERADE`, bridge isolation, and `-p` DNAT rules) and `ip` / `nsenter` (fallback only when `NETLINK_ROUTE` fails).

---

## Quick Start

### 1. Build & Run Unit Tests

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

### 2. Build an Image & Run Hardened Containers

Create a `Piecefile`:

```dockerfile
FROM alpine:3.18
ENV APP_ENV=production
WORKDIR /app
COPY ./app /app
RUN chmod +x /app/start.sh
CMD ["/app/start.sh"]
```

Build and run:

```bash
# Build image (uses .pieces/cache/ on repeat builds unless --no-cache is set)
sudo ./build/pieces build . --tag my-service

# Ephemeral, read-only, non-root run with microsecond startup timing
sudo ./build/pieces run --rm --read-only --user 1000:1000 --run-as-non-root --timing my-service

# Detached background service with cgroup v2 caps, port publish, and log rotation
sudo ./build/pieces run -d \
  --name api \
  --restart unless-stopped \
  --memory 256m --cpus 1.0 --pids-max 64 \
  -p 8080:80 \
  my-service

# Inspect, view telemetry/logs, enter namespaces, stop, and clean up
sudo ./build/pieces ps -a
sudo ./build/pieces stats api
sudo ./build/pieces logs -n 20 api
sudo ./build/pieces exec -it api /bin/sh
sudo ./build/pieces stop api
sudo ./build/pieces rm api
```

---

## Performance & Startup Timing

Pieces avoids interpreter startup, full-tree copies, and network helper subprocesses:

| Optimization Area | Mechanism Used by Pieces | Eliminated Overhead |
| --- | --- | --- |
| **CLI & Dispatch** | Native compiled C++20 binary (`-O3` in Release) | ~141 ms Python interpreter boot |
| **`--read-only` Rootfs** | `readonly-bind`: pivots directly onto the immutable image dir (`MS_RDONLY`) | Zero directory creation, zero file copies |
| **Writable Rootfs (`!readonly_rootfs`)** | `in-ns-overlay`: creates empty `upper`/`work`/`rootfs` (in `/dev/shm/.pieces-run/` RAM `tmpfs` for `--rm`) and mounts kernel `overlay` / `userxattr` / `fuse-overlayfs` inside `pid2`, or fast hybrid `tmpfs` + RO bind-mounts (`--full-copy` optional) | Eliminates ~543 ms full-image copy and ~304 ms recursive cleanup |
| **Networking & IPAM** | Direct `NETLINK_ROUTE` sockets for `pieces-br0`, `veth`, IP, and default route; sysfs + `/run/pieces/.net_ready_*` fast skip; `flock`-locked `.ipam_leases.json` (`O(active)`) | Eliminates `ip` / `nsenter` subprocess spawns and exited-container directory scans |
| **Security & Pipes** | Seccomp BPF & target `cap_value_t` computed once before `fork()`; rootful runs skip `userns_done_pipe` | Removes per-spawn compilation and extra parent/child pipe round-trips |

### Measured Timings (Observed in Sandbox)

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
3. **Explicit non-Docker-Hub OCI registries:** `ghcr.io/...`, `quay.io/...`, `registry.fedoraproject.org/...`, `localhost:5000/...` (`pieces pull <ref>`)

---

## Host Verification

After building on a Linux host with namespaces and `sudo` available, run the full 8-step live kernel integration suite (build with `RUN`, `--read-only` + `--user` + `seccomp` test, `-d` + `-p` + cgroups v2 limits, `ps`/`stats`/`logs`, `exec`, `stop`/`rm`, full OCI lifecycle, and cleanup):

```bash
sudo ./scripts/verify_host.sh ./build/pieces
```

---

## Complete Documentation

See **[TUTORIAL.md](TUTORIAL.md)** for **The Pieces Book: Complete Architecture, Internals & Operations Guide**—covering every C++ file, syscall, `Piecefile` rule, Netlink message, seccomp BPF instruction, OCI state transition, benchmark methodology, CLI flag, JSON schema, and integration recipe.
