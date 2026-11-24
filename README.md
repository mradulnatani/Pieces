# Pieces

Pieces is a hardened, production-oriented Linux container runtime written in **C++20** using direct Linux syscalls (`unshare`, `setns`, `pivot_root`, OverlayFS with copy fallback), `seccomp-bpf`, capability dropping, masked `/proc`/`/sys`, SHA-256 verified image downloads/pulls (without Docker Hub), build-time `RUN`, `veth` + bridge networking with `-p` port forwarding, `flock`-backed IPAM, detached lifecycle (`-d`, `stop`, `logs` with rotation, `exec`, `--restart`), PTY (`-it`), rootless `CLONE_NEWUSER` (including `/etc/subuid` / `/etc/subgid`), and cgroups v2.

For a step-by-step walkthrough on building, operating, and integrating Pieces into your own project, see [TUTORIAL.md](TUTORIAL.md).

## Architecture

```text
CMakeLists.txt             CMake build (C++20, libcurl, libarchive, OpenSSL::Crypto, libcap, util)
include/pieces/*.hpp       Public module interfaces
src/
├── main.cpp               CLI entry point
├── cli.cpp                Subcommand & flag parsing (build, pull, run, images, ps, stop, logs, exec, rm, rmi, prune)
├── parser.cpp             Piecefile parser (FROM, FROM_URL, SHA256, COPY, RUN, ENV, WORKDIR, CMD, ENTRYPOINT)
├── json.cpp               Self-contained JSON parser/serializer
├── registry.cpp           Non-Docker-Hub OCI v2 pull client (Bearer auth, multi-arch index, SHA-256 verification)
├── filesystem.cpp         Cached libcurl downloads, safe libarchive + OCI whiteout extraction, build RUN, OverlayFS
├── security.cpp           seccomp-bpf syscall filter + libcap bounding/effective capability dropping
├── namespaces.cpp         unshare, setns, mount, umount2, pivot_root, masked /proc & /sys, subuid/subgid rootless
├── network.cpp            Host bridge (pieces-br0), veth pairs, flock-locked IPAM, NAT, iptables -p DNAT
├── cgroup.cpp             Cgroup v2 resource limits (memory.max, cpu.max, pids.max)
└── container.cpp          Supervisor, PTY relay, log rotation, restart policies, orphan reconciliation
```

## Image Sources (No Docker Hub)

Pieces intentionally **disables Docker Hub** (`docker.io` / `registry-1.docker.io`). Images come from:
1. **Built-in upstream Linux distro rootfs CDNs:** `alpine:3.18`, `fedora:38`, `ubuntu:22.04`
2. **Direct tarballs (`FROM_URL` + optional `SHA256`)**
3. **Explicit non-Docker-Hub OCI registries:** `ghcr.io/...`, `quay.io/...`, `registry.fedoraproject.org/...`, `localhost:5000/...`

## Requirements

- **OS:** Linux (x86_64, aarch64, riscv64, armv7l, i386/i686)
- **Build tools:** CMake 3.20+, C++20 compiler (`g++` 13+ or `clang++`), `libcurl`, `libarchive`, `openssl`, `libcap` dev packages
- **Privileges:** Root (`CAP_SYS_ADMIN` / `CAP_NET_ADMIN`) for bridge networking, `-p` port forwarding, and cgroups; unprivileged users can run rootless containers (`CLONE_NEWUSER`) when host user namespaces are enabled.
- **Host networking tools:** `iproute2` (`ip`), `util-linux` (`nsenter`), and `iptables` for NAT / `-p` port forwarding.

## Building & Testing

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

For live end-to-end host verification on a Linux machine with `sudo` or unprivileged user namespaces enabled:

```bash
sudo ./scripts/verify_host.sh
```
