# The Pieces Book: Complete Architecture, Kernel Internals & Operations Guide

Welcome to the definitive handbook for **Pieces** — a lightweight, hardened, **OCI Runtime Spec–compatible** Linux container runtime built in **C++20**.

Unlike high-level tutorials that stop at `run` examples, this book walks through **every layer of the Pieces codebase and the Linux kernel primitives underneath it**: from lexical `Piecefile` parsing and OCI Distribution v2 digest verification, to the two-fork namespace choreography (`pid1` / `pid2`), three zero/minimal-copy rootfs strategies, raw `NETLINK_ROUTE` packet construction, `flock`-backed IPAM, five-layer defense-in-depth confinement (`seccomp-bpf`, `libcap`, MAC labels, `/proc`/`/sys` masking, rootless `subuid`), cgroups v2 telemetry, the OCI `exec.fifo` state machine for `containerd`/Kubernetes, microsecond `--timing` profiling, and full project integration recipes.

---

## Table of Contents

- [Part I — Foundations, Design Philosophy & Build System](#part-i--foundations-design-philosophy--build-system)
  - [Chapter 1: What Pieces Is (Architecture, Threat Model & Deliberate Boundaries)](#chapter-1-what-pieces-is-architecture-threat-model--deliberate-boundaries)
  - [Chapter 2: System Prerequisites, CMake Build & Test Infrastructure](#chapter-2-system-prerequisites-cmake-build--test-infrastructure)
  - [Chapter 3: Core Infrastructure (`json`, `cli`, and `main`)](#chapter-3-core-infrastructure-json-cli-and-main)
- [Part II — Images, Registries & `Piecefile` Builds](#part-ii--images-registries--piecefile-builds)
  - [Chapter 4: Image Sources & Why Docker Hub Is Disabled](#chapter-4-image-sources--why-docker-hub-is-disabled)
  - [Chapter 5: OCI v2 Pull Internals & Supply-Chain Verification](#chapter-5-oci-v2-pull-internals--supply-chain-verification)
  - [Chapter 6: Mastering `Piecefile` & Ordered Build-Time `RUN` Execution](#chapter-6-mastering-piecefile--ordered-build-time-run-execution)
- [Part III — Container Isolation & Lifecycle Engineering](#part-iii--container-isolation--lifecycle-engineering)
  - [Chapter 7: Step-by-Step Process & Pipe Choreography of `pieces run`](#chapter-7-step-by-step-process--pipe-choreography-of-pieces-run)
  - [Chapter 8: Namespaces, `pivot_root`, `/dev`, and Three Rootfs Strategies](#chapter-8-namespaces-pivot_root-dev-and-three-rootfs-strategies)
  - [Chapter 9: Detached Supervision, Rotating Logs, Restart Policies, PTYs & `exec`](#chapter-9-detached-supervision-rotating-logs-restart-policies-ptys--exec)
- [Part IV — Networking, Cgroups v2 & Defense-in-Depth Security](#part-iv--networking-cgroups-v2--defense-in-depth-security)
  - [Chapter 10: Direct `NETLINK_ROUTE` Networking, `flock` IPAM, NAT & Firewall Isolation](#chapter-10-direct-netlink_route-networking-flock-ipam-nat--firewall-isolation)
  - [Chapter 11: Cgroups v2 Resource Controls & Live Telemetry (`stats`)](#chapter-11-cgroups-v2-resource-controls--live-telemetry-stats)
  - [Chapter 12: Five-Layer Defense-in-Depth Security Model](#chapter-12-five-layer-defense-in-depth-security-model)
- [Part V — OCI Runtime Spec, Kubernetes & Performance](#part-v--oci-runtime-spec-kubernetes--performance)
  - [Chapter 13: The OCI Runtime Spec Engine (`spec`, `create`, `start`, `state`, `kill`, `delete`)](#chapter-13-the-oci-runtime-spec-engine-spec-create-start-state-kill-delete)
  - [Chapter 14: Wiring Pieces into `containerd` & Kubernetes](#chapter-14-wiring-pieces-into-containerd--kubernetes)
  - [Chapter 15: Performance Engineering & `--timing` Benchmarks](#chapter-15-performance-engineering--timing-benchmarks)
- [Part VI — Integration Recipes & Complete Technical Reference](#part-vi--integration-recipes--complete-technical-reference)
  - [Chapter 16: Real-World Project Integration Recipes](#chapter-16-real-world-project-integration-recipes)
  - [Appendix A: Complete CLI & Flag Reference](#appendix-a-complete-cli--flag-reference)
  - [Appendix B: `Piecefile` & JSON State Schema Reference](#appendix-b-piecefile--json-state-schema-reference)
  - [Appendix C: On-Disk & Virtual Filesystem State Map](#appendix-c-on-disk--virtual-filesystem-state-map)
  - [Appendix D: Troubleshooting & Diagnostics Guide](#appendix-d-troubleshooting--diagnostics-guide)

---

# Part I — Foundations, Design Philosophy & Build System

## Chapter 1: What Pieces Is (Architecture, Threat Model & Deliberate Boundaries)

**Pieces** is a standalone Linux container runtime written in **C++20** that compiles to a single binary (`pieces`) backed by a modular static library (`pieces_core`).

### 1.1 Why Pieces Was Rewritten in C++20

Originally prototyped in Python, Pieces was ported completely to C++20 for three concrete systems-engineering reasons:

1. **Direct Kernel ABI Access Without `ctypes` or Wrapper Subprocesses:**
   In Python, invoking `seccomp`, `cap_set_proc`, `pivot_root`, `setns`, `openpty`, or `AF_NETLINK` `NETLINK_ROUTE` requires brittle `ctypes` bindings or shelling out to `ip`, `nsenter`, and `iptables`. In C++20, Pieces directly includes `<linux/seccomp.h>`, `<linux/netlink.h>`, `<linux/rtnetlink.h>`, `<linux/veth.h>`, `<sys/capability.h>`, `<sys/mount.h>`, and `<pty.h>`, eliminating fork/exec chains in the critical path.
2. **Sub-10 ms Cold Startup Target:**
   Starting the CPython interpreter alone consumed **~147 ms** before user code ran (`./pieces --help`). The compiled C++20 binary executes CLI startup and directory/JSON inspection in **~5.5–6.6 ms**.
3. **Strict Memory & File-Descriptor Control Across `fork()`:**
   Multi-namespace container creation uses a double-fork (`parent` → `pid1` → `pid2`) with explicit pipe barriers, `exec.fifo`, raw `termios` guards, and `flock` leases—workflows that are cleaner, deterministic, and race-free in systems C++.

### 1.2 End-to-End Architecture Overview

```text
                             +---------------------------+
                             |        src/main.cpp       |
                             |   CLI Command Dispatcher  |
                             +-------------+-------------+
                                           |
            +------------------------------+------------------------------+
            |                              |                              |
            v                              v                              v
+-----------------------+      +-----------------------+      +-----------------------+
|   Image & Build Path  |      |  Native Container Run |      | OCI Runtime Contract  |
|  parser.cpp           |      |  container.cpp        |      |  oci_runtime.cpp      |
|  registry.cpp         |      |  StartupProfiler      |      |  config.json + hooks  |
|  filesystem.cpp       |      |  RotatingLogWriter    |      |  exec.fifo handshake  |
+-----------+-----------+      +-----------+-----------+      +-----------+-----------+
            |                              |                              |
            +------------------------------+------------------------------+
                                           |
            +------------------------------+------------------------------+
            |                              |                              |
            v                              v                              v
+-----------------------+      +-----------------------+      +-----------------------+
|    namespaces.cpp     |      |     security.cpp      |      |      network.cpp      |
|  unshare / setns      |      |  Allowlist seccomp-bpf|      |  NETLINK_ROUTE socket |
|  in-ns OverlayFS      |      |  OCI seccomp JSON     |      |  flock O(active) IPAM |
|  hybrid tmpfs / RO    |      |  libcap / MAC / UID   |      |  NAT + bridge isol.   |
|  pivot_root /dev/proc |      |  NO_NEW_PRIVS / arch  |      |  iptables -p DNAT     |
+-----------------------+      +-----------------------+      +-----------------------+
                                           |
                                           v
                               +-----------------------+
                               |      cgroup.cpp       |
                               |  cgroup v2 limits &   |
                               |  CPU/MEM/PIDs stats   |
                               +-----------------------+
```

### 1.3 Threat Model & Honest Security Boundaries

Understanding where Pieces shines—and what requires extra defense—is essential:

- **Trusted Apps, Builds, CI Tasks & Internal Services (Primary Target):**
  After validating your Linux kernel via `sudo ./scripts/verify_host.sh`, Pieces isolates filesystem roots (`pivot_root`), network interfaces (`CLONE_NEWNET` + default bridge lateral/host drop firewall), process trees (`CLONE_NEWPID`), resource consumption (cgroups v2), capabilities (`libcap`), MAC labels (`apparmor=`/`label=`), and syscalls (`default_allowed_syscalls()` allowlist `seccomp-bpf`).
- **Adversarial / Untrusted Public Code:**
  All OS containers share the host Linux kernel syscall boundary. For hostile multi-tenant workloads:
  1. Combine `--read-only`, `--user <non-zero>:<non-zero> --run-as-non-root`, `--cap-drop ALL`, a strict `--seccomp-profile <minimal.json>`, AppArmor/SELinux (`--security-opt`), `--net none`, and cgroups limits (`--memory`, `--cpus`, `--pids-max`), **plus** `--rootless` (`CLONE_NEWUSER` with `/etc/subuid` + `/etc/subgid` non-zero host UID remapping).
  2. When running truly untrusted arbitrary binaries from the internet, hardware virtualization microVMs (e.g., Firecracker or Kata Containers) provide stronger isolation than any shared-kernel container runtime.

### 1.4 What Pieces Deliberately Excludes

1. **Docker Hub (`docker.io` / `registry-1.docker.io`):** Intentionally blocked in `parse_image_reference` to prevent silent third-party pulls without explicit registry trust.
2. **Non-Linux Operating Systems:** Directly uses Linux-specific APIs (`unshare`, `SYS_pivot_root`, `NETLINK_ROUTE`, `PR_SET_SECCOMP`, cgroups v2).
3. **Embedded CRI gRPC Server (`RuntimeService` / `ImageService`):** Following the UNIX / OCI split (`runc`, `crun`), Pieces provides the OCI Runtime Spec binary contract so `containerd` or `CRI-O` handles CRI gRPC, pod sandboxes, CNI plugins, and registry storage on top.

---

## Chapter 2: System Prerequisites, CMake Build & Test Infrastructure

### 2.1 Build & Runtime Dependencies

From [CMakeLists.txt](file:///home/mradul/Desktop/GIT/Pieces/CMakeLists.txt):

| Requirement | Package / Minimum | Role in Pieces |
| --- | --- | --- |
| **CMake** | `3.20+` | Configures static library, CLI binary, and CTest target |
| **C++ Compiler** | `g++` 13+ or `clang++` (`CMAKE_CXX_STANDARD 20`, `EXTENSIONS OFF`) | Compiles C++20 modules with `-Wall -Wextra -Wpedantic` |
| **libcurl** | `CURL::libcurl` (`libcurl4-openssl-dev`) | HTTP/HTTPS downloads (`FROM_URL`) and OCI registry Bearer/API requests |
| **libarchive** | `LibArchive::LibArchive` (`libarchive-dev`) | Extracts `.tar`, `.tar.gz`, `.tgz`, `.tar.xz`, `.tar.bz2` in-memory/streaming without `tar` shell calls |
| **OpenSSL** | `OpenSSL::Crypto` (`libssl-dev`) | Computes SHA-256 checksums via `EVP_DigestInit_ex(..., EVP_sha256(), nullptr)` |
| **libcap** | `PkgConfig::LIBCAP` (`libcap-dev`) | Drops bounding caps (`cap_drop_bound`) and updates effective/permitted/inheritable sets (`cap_set_proc`) |
| **libutil** | Standard glibc `util` | Provides `openpty(3)` for `-t` / `-it` interactive pseudo-terminals |

Verify everything on Ubuntu/Debian before compiling:

```bash
g++ --version
cmake --version
pkg-config --modversion libcurl libarchive openssl libcap
ls /sys/fs/cgroup/cgroup.controllers
```

### 2.2 Building Targets

```bash
# Configure Release build (recommended for sub-10 ms startup and benchmarks)
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Compile pieces_core (static lib), pieces (CLI), and pieces_tests (CTest binary)
cmake --build build -j
```

Produced artifacts inside `build/`:
- `build/libpieces_core.a`: All 11 runtime translation units compiled with `-Wall -Wextra -Wpedantic`.
- `build/pieces`: Final linked CLI + OCI runtime binary.
- `build/pieces_tests`: Standalone unit test binary registered as `pieces_unit_tests` in CTest.

Optional global installation:

```bash
sudo install -m 0755 build/pieces /usr/local/bin/pieces
```

### 2.3 Unit Tests (`tests/test_pieces.cpp`)

Run unprivileged anywhere (inside or outside containers/sandboxes):

```bash
ctest --test-dir build --output-on-failure
# or directly:
./build/pieces_tests
```

`tests/test_pieces.cpp` runs 5 self-contained C++ test suites using `TempDir` RAII scratch directories and `libarchive` tar fixture generators:

| Test Function | What It Verifies |
| --- | --- |
| `test_json_and_parser` | `JsonValue` round-trip parsing/serialization; `Piecefile` parsing of `FROM`, `SHA256`, multi-key `ENV`, `WORKDIR`, `COPY`, multi-line `\` `RUN`, JSON `ENTRYPOINT`, and shell `CMD`. |
| `test_cli_native_and_oci` | `parse_command_args` across native flags (`--rm`, `-d`, `-it`, `--read-only`, `--run-as-non-root`, `--timing`, `--user`, `--seccomp-profile`, two `--security-opt`, `--no-isolate-net`, `--restart`, `-p`) and OCI commands (`--root`, `create`, `kill`, `delete`, `stats`). |
| `test_allowlist_seccomp_oci_json_user_and_mac` | Confirms `read`/`write`/`execve` are in `default_allowed_syscalls()` while `unshare`, `setns`, `chroot`, `bpf`, `ptrace`, `mount` are **excluded**; builds BPF filter and verifies default-deny final action; compiles OCI seccomp JSON; validates `parse_user_spec`, `apply_process_user(..., true)` failing on UID 0, and `parse_security_opts`. |
| `test_oci_runtime_spec_and_cgroup_stats` | Generates default rootless OCI spec, parses a full Kubernetes/containerd `config.json` (UID/GIDs, capabilities, AppArmor, SELinux, `kubepods.slice`, shared namespace paths, `uidMappings`/`gidMappings`, resources, seccomp, annotations, hooks), parses signals, and verifies `read_cgroup_stats`. |
| `test_oci_pull_no_docker_hub_and_ipam_logs` | Rejects `ubuntu:22.04`, `docker.io/...`, `registry-1.docker.io/...` in `parse_image_reference`; tests `allocate_container_ip`/`release_container_ip`; verifies `RotatingLogWriter` file rotation; verifies `../escape.txt` rejection in `safe_extract_tar_file`; tests `readonly-bind` zero-copy and `in-ns-overlay` preparation/cleanup. |

### 2.4 Live Kernel Host Verification (`scripts/verify_host.sh`)

Because kernel namespace creation (`unshare`), `pivot_root`, `veth` Netlink, and cgroup writes require host kernel privileges, [scripts/verify_host.sh](file:///home/mradul/Desktop/GIT/Pieces/scripts/verify_host.sh) automates an 8-step live integration run under `sudo`:

```bash
sudo ./scripts/verify_host.sh ./build/pieces
```

Steps executed:
1. `[1/8]` Builds `verify-img` from `alpine:3.18` using `ENV`, `WORKDIR`, `COPY`, and build-time `RUN cat /app/hello.txt > /app/built.txt`.
2. `[2/8]` Runs `--rm --read-only --user 1000:1000 --run-as-non-root --net none`, verifying UID=1000 inside the container, write failure on `/ro-test`, and `unshare -U id` blocked by allowlist `seccomp`.
3. `[3/8]` Launches detached `-d --name verify-c1` with `-p 18080:8080`, `--memory 128m`, `--cpus 0.5`, `--pids-max 64`.
4. `[4/8]` Checks `ps`, `stats verify-c1` (live cgroup v2 JSON), and `logs -n 5 verify-c1`.
5. `[5/8]` Executes `exec verify-c1` and verifies inherited `VERIFY_ENV=ok`, `PWD=/app`, and `/app/built.txt`.
6. `[6/8]` Tests graceful `stop -t 2` and `rm`.
7. `[7/8]` Exercises the full OCI contract (`spec` → `create` → `state` → `start` → `kill SIGKILL` → `delete -f`).
8. `[8/8]` Cleans up `verify-img` via `rmi`.

---

## Chapter 3: Core Infrastructure (`json`, `cli`, and `main`)

Before diving into images and containers, Pieces establishes three zero-external-dependency core layers.

### 3.1 Self-Contained JSON Engine (`include/pieces/json.hpp`, `src/json.cpp`)

To avoid bundling external header dependencies while keeping compile times fast, Pieces implements `JsonValue` over `std::variant`:

```cpp
using Storage = std::variant<
    std::nullptr_t, bool, int64_t, double, std::string, JsonArray, JsonObject>;
```

Key behaviors in `src/json.cpp`:
- **Recursive-descent parser (`JsonValue::parse`):** Handles whitespace, RFC 8259 string escapes (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, plus `\uXXXX` Unicode code points encoded to UTF-8), signed integers (`int64_t`), floating-point numbers (`double`), arrays, and sorted `std::map<std::string, JsonValue>` objects.
- **Deterministic serializer (`dump(int indent = 2)`):** Supports both indented human-readable JSON (used for `stats`, OCI `state`, `spec`, `meta.json`, `.pieces_meta.json`) and single-line compact JSON when `indent <= 0` (used when piping OCI State payloads to `hooks` on `stdin`).

### 3.2 CLI Parser (`include/pieces/cli.hpp`, `src/cli.cpp`)

`parse_command_args` maps every CLI invocation into a strongly typed `CliArgs` struct and `CliCommand` enum:

- **Global OCI `--root <state_root>` Flag:** Checked at `args[0]` *before* reading the subcommand, matching `runc`/`crun` invocations emitted by `containerd`.
- **Two Argument Boundaries in `run` and `exec`:**
  - In `run`, option parsing stops immediately at the positional `<image>` token (or after `--`), so flags intended for the container command itself—for example `pieces run ubuntu-22.04 /bin/sh -c "ls -la"`—are never misinterpreted as Pieces flags (`-c` is preserved inside `cmd_args`).
  - Similarly, in `exec`, parsing stops at `<container>` so `<cmd> [args...]` passes through intact.
- **Flag Validation:** Rejects invalid `--net` modes (only `bridge` and `none` are accepted), unknown options starting with `-`, and missing option values (`require_value`).

### 3.3 Dispatcher (`src/main.cpp`)

`src/main.cpp` translates `CliArgs` into library calls:
- Native image commands (`Build`, `Pull`, `Images`, `Rmi`)
- Native container commands (`Run`, `Ps`, `Stop`, `Logs`, `Exec`, `Stats`, `Rm`, `Prune`)
- OCI runtime commands (`OciSpec`, `OciCreate`, `OciStart`, `OciState`, `OciKill`, `OciDelete`)
- Top-level exception catchers: `parse_command_args` errors exit with code **`2`**; runtime exceptions print `pieces: <msg>` to `stderr` and exit with code **`1`**.

---

# Part II — Images, Registries & `Piecefile` Builds

## Chapter 4: Image Sources & Why Docker Hub Is Disabled

Most tutorials casually assume `FROM ubuntu` hits `registry-1.docker.io`. Pieces explicitly refuses that model.

### 4.1 Hard Enforcement in `src/registry.cpp`

`is_docker_hub_registry` and `parse_image_reference` reject:
1. **Unqualified short names passed to `pieces pull`** (e.g., `pieces pull ubuntu:22.04` without a registry hostname containing `.` or `:` or `localhost`).
2. **Any explicit Docker Hub host:**
   - `docker.io`
   - `registry-1.docker.io`
   - `index.docker.io`
   - `registry.hub.docker.com`

Why? Avoiding Docker Hub eliminates anonymous rate-limit failures, forces explicit supply-chain origin declaration, and encourages direct upstream distro mirrors or controlled OCI registries.

### 4.2 The Three Supported Image Sources

1. **Built-in Official Upstream Linux Distro Rootfs CDNs (`known_images()` in `src/filesystem.cpp`):**
   - `alpine:3.18` → `https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.3-x86_64.tar.gz`
   - `fedora:38` → `https://archives.fedoraproject.org/pub/fedora/linux/releases/38/Container/x86_64/images/Fedora-Container-Base-38-1.6.x86_64.tar.gz`
   - `ubuntu:22.04` → `https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04.4-base-amd64.tar.gz`
2. **Direct Tarball URLs (`FROM_URL` + optional `SHA256`):**
   - Any `http://` or `https://` `.tar`, `.tar.gz`, `.tgz`, `.tar.xz`, or `.tar.bz2` archive, optionally pinned to an exact 64-hex SHA-256 digest.
3. **Explicit Non-Docker-Hub OCI v2 Registries:**
   - GitHub Container Registry (`ghcr.io/...`), Red Hat Quay (`quay.io/...`), Fedora Registry (`registry.fedoraproject.org/...`), Google Artifact Registry (`*-docker.pkg.dev/...`), or local registries (`localhost:5000/...` / `127.0.0.1:...`, which automatically use `http://` instead of `https://`).

---

## Chapter 5: OCI v2 Pull Internals & Supply-Chain Verification

When you run:

```bash
./build/pieces pull ghcr.io/org/service:v1.2
# Optional custom local image name:
./build/pieces pull ghcr.io/org/service:v1.2 -t my-service
```

`pull_oci_image` in [src/registry.cpp](file:///home/mradul/Desktop/GIT/Pieces/src/registry.cpp) executes a full cryptographic pull pipeline:

```text
  pieces pull <registry>/<repo>:<tag>
        |
        v
  [1] parse_image_reference()  ---> Reject Docker Hub or missing registry host
        |
        v
  [2] GET /v2/<repo>/manifests/<tag>
        |-- HTTP 401 --> parse_www_authenticate(realm, service, scope)
        |                    --> GET token --> retry with Bearer <token>
        v
  [3] Is response an OCI/Docker Manifest Index / List?
        |-- Yes --> host_oci_architecture() + select_manifest_digest("linux", arch)
        |           --> Fetch child manifest & verify sha256_string(body) == digest
        v
  [4] Fetch config blob (sha256 verified)
        --> extract_oci_config_metadata(): Cmd, Entrypoint, Env, WorkingDir -> .pieces_meta.json
        v
  [5] For each layer in manifest.layers:
        |-- Download blob to temp file
        |-- Verify sha256_file(temp) == layer.digest (OpenSSL EVP_sha256)
        |-- safe_extract_tar_file(temp, staging, /*handle_oci_whiteouts=*/true)
        v
  [6] Configure default /etc/resolv.conf & /etc/hosts + atomic fs::rename -> .pieces/images/<name>
```

### 5.1 Architecture Detection Mapping

`host_oci_architecture()` converts POSIX `uname(&uts)` `uts.machine` into OCI platform architecture strings:
- `x86_64` / `amd64` → `amd64`
- `aarch64` / `arm64` → `arm64`
- `armv7l` / `arm` → `arm`
- `i386` / `i686` → `386`
- `riscv64` → `riscv64`

### 5.2 Tarball Traversal Protection & OCI Whiteouts (`safe_extract_tar_file`)

Tarballs from registries or external URLs can be malformed or malicious. In [src/filesystem.cpp](file:///home/mradul/Desktop/GIT/Pieces/src/filesystem.cpp), `safe_extract_tar_file` inspects every archive entry via `libarchive` before writing:

1. **Path Sanitization (`normalize_relative_tar_path`):**
   - Rejects empty paths, leading `/` absolute paths, or any normalized component containing `..` (`Archive entry escapes destination`).
2. **Hardlink Target Validation:**
   - Normalizes `archive_entry_hardlink` relative to `dest_dir` and rejects links pointing outside the staging root.
3. **OCI Layer Whiteout Handling (when `handle_oci_whiteouts == true`):**
   - **Opaque whiteout (`.wh..wh..opq`):** Marks a directory replaced in this layer—deletes all prior entries inside that directory before unpacking files from the current layer.
   - **Single entry whiteout (`.wh.<filename>`):** Deletes `<filename>` from the lower extracted layers on disk.
   - Prevents `.wh.*` metadata marker files from appearing inside the final container rootfs.

---

## Chapter 6: Mastering `Piecefile` & Ordered Build-Time `RUN` Execution

### 6.1 Lexical Rules (`src/parser.cpp`)

`parse_piecefile` reads `Piecefile` line by line with full shell awareness:
- **Line Continuations:** Trailing `\` joins consecutive lines into a single instruction (stripping leading indentation cleanly, verified in `test_json_and_parser`: `RUN echo "a" && \` + `echo "b"` → `echo "a" && echo "b"`).
- **Comments & Blank Lines:** Lines beginning with `#` after trimming whitespace are skipped.
- **Word & Quote Splitting (`split_shell_words`):** Preserves single-quoted `'...'` and double-quoted `"..."` strings and backslash escapes (`KEY="hello world"`).
- **Command Parsing (`parse_command_value`):** Automatically detects JSON exec-form (`["/bin/sh", "-c"]`) vs shell-form (`python3 app.py` → `{"/bin/sh", "-c", "python3 app.py"}`).

### 6.2 Supported `Piecefile` Instructions

| Instruction | Syntax Examples | Effect |
| --- | --- | --- |
| `FROM` | `FROM alpine:3.18` or `FROM ghcr.io/org/base:v1` | Sets base distro CDN tarball or non-Docker-Hub OCI registry image. |
| `FROM_URL` | `FROM_URL https://example.com/rootfs.tar.gz` | Sets direct tarball URL base. Also sets default image name derived from archive basename if `--tag` is omitted. |
| `SHA256` | `SHA256 <64-hex>` or `SHA256 sha256:<64-hex>` | Enforces exact SHA-256 verification on downloaded/cached tarball before extraction. Throws immediately on mismatch. |
| `ENV` | `ENV FOO=bar BAZ="hello world"` or `ENV KEY VALUE` | Updates `build_env` immediately for subsequent `RUN` steps and persists into `.pieces_meta.json`. |
| `WORKDIR` | `WORKDIR /app` | Creates directory inside `staging_dir` and updates `build_workdir` for subsequent `RUN` steps + `.pieces_meta.json`. |
| `COPY` | `COPY ./src /app/src` | Validates source doesn't escape `context_dir` and destination stays inside `staging_dir`, preserving symlinks and overwriting existing targets. |
| `RUN` | `RUN apk add --no-cache git` | Executes `/bin/sh -c "<cmd>"` inside an isolated build namespace rooted at `staging_dir`. Non-zero exit aborts the build atomically. |
| `ENTRYPOINT` | `ENTRYPOINT ["/usr/bin/env"]` | Persisted to `.pieces_meta.json`; prepended before `CMD` or CLI `cmd_args` at `run`. |
| `CMD` | `CMD ["node", "server.js"]` | Persisted to `.pieces_meta.json`; used when CLI `cmd_args` is empty. |

### 6.3 Download Cache & Build-Time `RUN` Execution

1. **SHA-256 Download Cache (`.pieces/cache/`):**
   - Before downloading `FROM` distro tarballs or `FROM_URL` archives, `fetch_tarball_with_cache` computes `sha256_string(url) + ".tar"` inside `.pieces/cache/`.
   - Unless `--no-cache` is passed, a cache hit avoids network transfer—and still re-runs `SHA256` checksum verification if `SHA256` is present in the `Piecefile`.
2. **Ordered Instruction Replay (`build_image`):**
   - Unlike naive builders that execute all `COPY`s and then all `RUN`s, Pieces iterates `spec.instructions` **in exact source order**. Therefore `COPY package.json /app/package.json` followed by `RUN npm install` followed by `COPY . /app` behaves exactly as expected.
3. **How `default_run_build_step` Isolates `RUN`:**
   - Seeds `/etc/resolv.conf` and `/etc/hosts` in `staging_dir`.
   - Forks a child process and enters `CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC` (plus `CLONE_NEWUSER` if unprivileged, while **keeping host `CLONE_NEWNET` omitted** so `apk`/`apt`/`pip`/`curl` inside `RUN` can reach upstream repositories).
   - Forks again so the build command runs as container PID 1 inside `pivot_root(staging_dir)`, mounts `/proc` and `/dev/null` / `/dev/urandom`, sets `WORKDIR` and `ENV` (`DEFAULT_BUILD_PATH` if `PATH` unset), and `execvpe`s `/bin/sh -c "<cmd>"`.
4. **Atomic Directory Swap:**
   - On success, swaps `staging_dir` into `.pieces/images/<name>` cleanly using a backup rename so a failed build never leaves a half-extracted image behind.

---

# Part III — Container Isolation & Lifecycle Engineering

## Chapter 7: Step-by-Step Process & Pipe Choreography of `pieces run`

Executing a container is a synchronized three-process dance orchestrated in `run_container`, `execute_container_supervisor`, and `run_single_container_attempt` in [src/container.cpp](file:///home/mradul/Desktop/GIT/Pieces/src/container.cpp).

```text
Parent (Supervisor)                Child pid1 (NS Init)               Grandchild pid2 (Container PID 1)
===================                ====================               =================================
1. Ignore SIGPIPE; resolve image,
   cmd, env, workdir, volumes, ports,
   user_spec, MAC opts; pre-build
   seccomp BPF + target_caps;
   mark("config + seccomp + caps prep")

2. [If --net bridge && root]:
   setup_host_network() +
   build_network_plan() (flock IPAM);
   mark("host network + IPAM")

3. prepare_container_rootfs();
   mark("rootfs (<method>)")

4. [If -d]: fork() background
   supervisor with setsid() &
   wait for "OK:<id>" over sup_pipe

5. fork() ------------------------> 6. Reset signals, set
   (creates ready_pipe, go_pipe,       PR_SET_PDEATHSIG(SIGKILL);
    optional userns_done_pipe)         attach PTY slave OR log_pipe;
                                       unshare(PID|NS|NET|UTS|IPC|USER)

   [ONLY if use_userns is true:]    7. write pid1 -> ready_pipe[1]
8. read pid1; write uid_map/gid_map    block on read(userns_done_pipe[0])
   (subuid/subgid or self-map);
   write "1" -> userns_done_pipe[1]
   mark("unshare + userns map")

                                    9. fork() ----------------------> 10. block on read(go_pipe[0])
11. read pid2 from ready_pipe <------- write pid2 -> ready_pipe[1]        (ensures cgroup + veth are
                                                                           ready before execvpe)
12. cgroup_mgr.setup(pid2);
    setup_container_network(pid2);
    write meta.json (if kept);
    mark("cgroup + veth + port fwd")
    write "1" -> go_pipe[1] ------------------------------------------> 13. checked_sethostname()
    [if -d: write "OK:<id>" sup_pipe]                                   14. [If root bridge]:
                                                                            configure_container_netns_netlink()
                                                                        15. setup_container_mounts()
                                                                        16. chdir(workdir)
                                                                        17. AppArmor/SELinux labels
                                                                        18. drop_capabilities_to_set()
                                                                        19. apply_seccomp_program()
                                                                        20. apply_process_user()
                                                                        21. execvpe(cmd, env)
22. [If -t]: relay_pty_session()
    [If -d]: drain_fd_to_rotating_log()
23. waitpid(pid1) <------------------- waitpid(pid2) <----------------- [process exits]
    mark("container waitpid exit")     _exit(waitstatus_to_exitcode)
24. Cleanup DNAT, host_veth, cgroup;
    check RestartPolicy loop;
    release IP, clean rootfs &
    container dir (if --rm);
    mark("cleanup") -> print_report()
```

### Why Three Processes Instead of Two?

Linux `unshare(CLONE_NEWPID)` does **not** move the calling process (`pid1`) into the new PID namespace—it only places its **children** (`pid2`) into the new PID namespace as PID 1. Therefore:
- `pid1` owns the new namespaces (`NS`, `NET`, `UTS`, `IPC`, optional `USER`) and waits on `pid2`.
- `pid2` is born as **PID 1 inside the container** with `/proc` cleanly showing only container processes.
- Using `PR_SET_PDEATHSIG(SIGKILL)` inside `pid1` ensures no orphaned namespace init survives if the parent dies unexpectedly.

---

## Chapter 8: Namespaces, `pivot_root`, `/dev`, and Three Rootfs Strategies

Implemented in [src/namespaces.cpp](file:///home/mradul/Desktop/GIT/Pieces/src/namespaces.cpp) and [src/filesystem.cpp](file:///home/mradul/Desktop/GIT/Pieces/src/filesystem.cpp).

### 8.1 Why Parent-Side Rootfs Copying Was Replaced

Previously, running a writable container from `ubuntu-22.04` copied the entire image directory tree before `fork()`—taking **~543.31 ms** to copy and **~304.18 ms** to `rm -rf`. Pieces eliminates that bottleneck with three ordered strategies in `prepare_container_rootfs` and `mount_in_namespace_rootfs`:

1. **`readonly-bind` (`--read-only`):**
   - `prepare_container_rootfs` creates **zero temporary directories** and returns `image_path` directly.
   - Inside `pid2`, `setup_container_mounts` bind-mounts `image_path` onto itself, `pivot_root`s, sets up writable `/dev` & `/dev/shm` + explicit `-v` bind mounts, and finishes by remounting `/` read-only (`MS_BIND | MS_REMOUNT | MS_RDONLY`).
2. **`in-ns-overlay` (Default Writable Mode):**
   - Parent creates empty `upper/`, `work/`, and `rootfs/` directories. For ephemeral foreground runs (`--rm` without `-d`), `scratch_base` is placed in `/dev/shm/.pieces-run/<id>` (RAM `tmpfs`) so metadata writes never hit physical disk.
   - Inside `pid2`'s private mount namespace, `mount_in_namespace_rootfs` tries in order:
     1. Kernel OverlayFS: `mount("overlay", rootfs, "overlay", 0, "lowerdir=...,upperdir=...,workdir=...")`
     2. Rootless kernel OverlayFS (Linux 5.11+): appends `,userxattr`
     3. Userspace FUSE overlay (`fuse-overlayfs`) if installed in `PATH`
     4. Fast hybrid `tmpfs` fallback (`prepare_hybrid_tmpfs_rootfs`)—or full copy only if `--full-copy` is explicitly passed.
   - Because the overlay mount exists strictly inside `pid2`'s mount namespace, the kernel **automatically tears it down on process exit**, leaving zero leaked mounts in host `/proc/mounts`.
3. **Hybrid `tmpfs` Fallback (`prepare_hybrid_tmpfs_rootfs`):**
   - Used automatically when neither kernel OverlayFS nor `fuse-overlayfs` is permitted (for instance inside unprivileged/nested environments).
   - Mounts a `tmpfs` on `rootfs`, recreates top-level symlinks, creates fresh empty `/proc`, `/sys`, `/dev`, `/tmp` (`01777` sticky), `/run`, `/mnt`, `/srv`, copies small mutable config/home trees (`etc`, `home`, `root`), **bind-mounts large read-only OS trees (`usr`, `var`, `opt`, `boot`, etc.) read-only (`< 0.1 ms`)**, and overlays writable `tmpfs` on `/var/tmp` and `/var/log`.

### 8.2 Exact Sequence Inside `setup_container_mounts`

Inside `pid2`:
1. Marks mount propagation private (`mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr)`) so container mounts never leak to the host.
2. Mounts in-namespace rootfs if `overlay_spec` is provided.
3. Applies `-v HOST:CONTAINER[:ro|rw]` bind mounts (`apply_bind_mounts`), rejecting any destination path escaping `rootfs_real`.
4. Bind-mounts `rootfs_real` onto itself (a kernel requirement for `pivot_root`), creates `<rootfs_real>/old_root`, and invokes `syscall(SYS_pivot_root, rootfs_real, old_root)` + `chdir("/")`.
5. Mounts `/proc` (`proc`), `/sys` (`sysfs`, falling back in rootless mode to read-only bind from `/old_root/sys`).
6. Mounts writable `/dev` (`tmpfs`, `mode=755`), `/dev/pts` (`devpts`), and `/dev/shm` (`tmpfs`).
7. Creates character devices `/dev/null` `(1,3)`, `/dev/zero` `(1,5)`, `/dev/random` `(1,8)`, `/dev/urandom` `(1,9)`, and `/dev/tty` `(5,0)` using `mknod`—automatically falling back in rootless mode to binding from `/old_root/dev/<name>`.
8. Links `/dev/stdin`, `/dev/stdout`, `/dev/stderr` → `/proc/self/fd/{0,1,2}`.
9. Lazily detaches `/old_root` (`umount2("/old_root", MNT_DETACH)`) and `rmdir("/old_root")`—completely unlinking host filesystem visibility from container mount tables.
10. Calls `mask_sensitive_proc_and_sys_paths` (Chapter 12) and optionally remounts `/` with `MS_RDONLY` if `--read-only`.

### 8.3 Rootless User Namespaces & `/etc/subuid` + `/etc/subgid`

When running unprivileged (`::geteuid() != 0`) or with `--rootless`/`--userns`, `CLONE_NEWUSER` is enabled:
- Parent reads `pid1` over `ready_pipe`, calls `setup_rootless_user_namespace`:
  1. If explicit OCI `uid_mappings`/`gid_mappings` exist, applies them directly (root) or via `newuidmap`/`newgidmap` (rootless).
  2. Otherwise looks up the caller's username via `getpwuid_r` and checks `/etc/subuid` and `/etc/subgid` (`parse_subid_range`). If present and `newuidmap`/`newgidmap` are installed, maps `0 -> host_uid (size 1)` and `1 -> subid.start (size subid.count)` (typically 65,536 subordinate IDs so multi-UID `apt`/`chown`/service users work unprivileged).
  3. Otherwise falls back to single-UID self-mapping: writes `"deny"` to `/proc/<pid>/setgroups` (required by the kernel for unprivileged single-UID `gid_map` writes) and maps `0 -> host_uid` and `0 -> host_gid`.

---

## Chapter 9: Detached Supervision, Rotating Logs, Restart Policies, PTYs & `exec`

### 9.1 Detached Lifecycle (`-d`) & `RotatingLogWriter`

When `-d` / `--detach` is passed:
1. `run_container` writes `meta.json` and forks a detached background supervisor calling `setsid()`, closing/redirecting standard FDs to `/dev/null`, and reporting `"OK:<id>"` back to the caller as soon as `pid2` is running and `meta.json` (`pid`, `ip`, `ports`) is updated. The CLI prints the 12-hex ID and exits `0`.
2. Container `stdout` and `stderr` are piped into `RotatingLogWriter` at `.pieces/containers/<id>/container.log`.
3. Every chunk tracks `current_bytes_`. When `current_bytes_ >= max_bytes_` (default `--log-max-size 10m`, `--log-max-files 3`), `rotate()` closes the file descriptor, shifts `.log.(N-1)` → `.log.N`, renames `container.log` → `container.log.1`, and opens a fresh `container.log` (`0644`).
4. `pieces logs [-f] [-n LINES] <id|name>` reads rotated history seamlessly (from `.log.max` up to `container.log` when slicing `-n` lines) and follows active appends in `200 ms` poll intervals (`-f`).

### 9.2 Restart Policies (`--restart`) & Graceful Stop (`stop`)

`execute_container_supervisor` loops around `run_single_container_attempt`:
- `no` *(default)*: Exits after the first run.
- `on-failure`: Restarts if `exit_code != 0`, unless `.stop_requested` exists in `.pieces/containers/<id>/`.
- `always` / `unless-stopped`: Always restarts unless `.stop_requested` exists.
- **Backoff & Liveness:** Starts at `100 ms` delay and doubles up to `5000 ms`, resetting to `100 ms` if an attempt stays alive longer than **5 seconds**. Each restart tears down stale `DNAT`/`veth`/cgroup handles and reuses `net_plan` and rootfs cleanly.
- **`stop_container`:** Writes `.stop_requested`, sends `SIGTERM` to `pid`, polls every `100 ms` up to `-t/--time` seconds (default `10`), escalates to `SIGKILL` if still alive, cleans up ports/`veth`/`cgroup`, releases IPAM lease, and marks `meta.json` `status = "exited"`.

### 9.3 Interactive Pseudo-Terminal (`-t` / `-it`)

In foreground mode when `-t`/`-it` is used and host stdin is a TTY:
1. `openpty(&pty_master, &pty_slave, ...)` opens a host-controlled PTY pair before `fork()`.
2. `TerminalRawGuard` RAII saves host `termios` (`tcgetattr`), enables raw mode (`cfmakeraw`), and guarantees restoration even on exceptions or signals.
3. Window dimensions (`TIOCGWINSZ` → `TIOCSWINSZ`) synchronize at startup and live via `SIGWINCH`.
4. `SIGINT` and `SIGTERM` caught on the host relay directly to `grandchild_pid` via `::kill`, while `poll()` multiplexes bidirectional bytes between `STDIN_FILENO`/`STDOUT_FILENO` and `pty_master`.

### 9.4 `exec`, `ps`, `rm`, `rmi`, and `prune`

- **`exec_in_container`:** Looks up container `pid` from `meta.json`, checks liveness, forks, and calls `enter_container_namespaces(pid)`—joining `/proc/<pid>/ns/` in the mandatory kernel order **`user` → `ipc` → `uts` → `net` → `pid` → `mnt`** (skipping any namespace whose `st_ino`/`st_dev` already matches `/proc/self/ns/<ns>`). After `setns(pid)`, forks once more so the exec'd child resides inside the container's PID namespace, loads container `meta` env + `-e` overrides, sets `-w` or default `workdir`, and executes via `execvpe` (with optional `-it` PTY).
- **`list_containers` (`ps` / `ps -a`):** Scans `.pieces/containers/*/meta.json` and reconciles any `"running"` record whose `pid` is dead (`kill(pid, 0)` fails with `ESRCH`): resets `status = "exited"`, releases its IP lease, and deletes orphaned `veth`/DNAT rules automatically.
- **`remove_container` (`rm` / `rm -f`):** Resolves 12-char ID or `--name`, refuses removal of running containers without `-f`, kills if forced, cleans up rootfs, network, IPAM lease, cgroup dir, and deletes `.pieces/containers/<id>`.
- **`prune_unused_data` (`prune`):** Deletes all stopped container directories and all cached tarballs in `.pieces/cache/`.

---

# Part IV — Networking, Cgroups v2 & Defense-in-Depth Security

## Chapter 10: Direct `NETLINK_ROUTE` Networking, `flock` IPAM, NAT & Firewall Isolation

All container networking lives in [src/network.cpp](file:///home/mradul/Desktop/GIT/Pieces/src/network.cpp).

### 10.1 Zero-Subprocess `NETLINK_ROUTE` Architecture

Earlier container runtimes spawn 3–4 processes per container (`ip link add`, `nsenter ip addr add`, etc.). Pieces replaces that with an in-process Netlink client:
- **`NetlinkSocket`:** Opens `socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)`, binds local PID, sends requests to kernel (`nl_pid = 0`), and parses `NLMSG_ERROR` acknowledgments directly into `errno`-backed failures.
- **`NetlinkMsgBuilder`:** Serializes aligned `nlmsghdr`, `ifinfomsg`, `ifaddrmsg`, `rtmsg`, and nested `rtattr` TLV attributes (`IFLA_IFNAME`, `IFLA_INFO_KIND`, `IFLA_INFO_DATA`, `VETH_INFO_PEER`, `IFLA_MASTER`, `IFLA_NET_NS_PID`, `IFA_LOCAL`/`IFA_ADDRESS`, `RTA_GATEWAY`, `RTA_OIF`).

### 10.2 Host Bridge Setup (`pieces-br0`) & Fast Marker Cache

When `--net bridge` (the default) runs as root:
1. `setup_host_network` checks `/sys/class/net/pieces-br0` and `/run/pieces/.net_ready_<bridge>_<nat>_<isolate>`. When both exist, it returns immediately in **~0 ms** without spawning `iptables` or Netlink sockets.
2. On cold host boot:
   - `netlink_create_bridge` executes `RTM_NEWLINK` (`kind="bridge"`), assigns `10.0.0.1/24` (`RTM_NEWADDR`), and sets `IFF_UP`.
   - Enables `/proc/sys/net/ipv4/ip_forward = 1` and `/proc/sys/net/ipv4/conf/pieces-br0/route_localnet = 1`.
   - Installs NAT masquerading: `iptables -t nat -A POSTROUTING -s 10.0.0.0/24 ! -o pieces-br0 -j MASQUERADE` and `FORWARD` rules for `pieces-br0`.

### 10.3 Default Lateral & Host Isolation Firewall

To prevent compromised containers on the shared bridge from attacking sibling containers or probing host-bound services (`10.0.0.1`, local databases, metrics endpoints), `ensure_bridge_isolation` installs idempotent `iptables -C ... || iptables -I ...` rules by default:
1. `FORWARD -i pieces-br0 -o pieces-br0 -j DROP` (blocks lateral container-to-container traffic)
2. `INPUT -i pieces-br0 -m state --state RELATED,ESTABLISHED -j ACCEPT`
3. `INPUT -i pieces-br0 -p udp --dport 53 -j ACCEPT` and `tcp --dport 53 -j ACCEPT` (permits DNS)
4. `INPUT -i pieces-br0 -j DROP` (blocks arbitrary traffic from containers to host sockets)

Pass `--no-isolate-net` to opt out when containers intentionally need peer-to-peer communication across `pieces-br0`.

### 10.4 `flock`-Locked `O(active)` IPAM

`allocate_container_ip` and `release_container_ip` guarantee zero IP collisions under concurrent `pieces run` invocations:
1. Acquires an exclusive advisory lock (`flock(..., LOCK_EX)`) on `.pieces/containers/.ipam.lock` via `FileLockGuard` RAII.
2. Reads `.pieces/containers/.ipam_leases.json` (which only tracks active leases—avoiding `O(total_containers)` scans over historical exited directories; full scan happens only once on cold start if `.ipam_leases.json` does not yet exist).
3. Verifies each leased container's `meta.json` still has `status == "running"`, assigns the lowest free host IP in **`10.0.0.2` – `10.0.0.254`**, atomically writes `.ipam_leases.json`, and releases the lock.

### 10.5 Per-Container `veth` Pair & `-p` Port Forwarding

- **Parent (`netlink_setup_host_veth`):** Generates interface names `vp-<id8>` (host side) and `vc-<id8>` (container peer, ≤ 15-char `IFNAMSIZ` safe), creates both atomically via `RTM_NEWLINK` (`VETH_INFO_PEER`), attaches `vp-*` to `pieces-br0` (`IFLA_MASTER`), brings `vp-*` `IFF_UP`, and moves `vc-*` into `pid2`'s network namespace (`IFLA_NET_NS_PID`).
- **Child `pid2` (`configure_container_netns_netlink`):** Inside the new netns, brings `lo` `IFF_UP`, renames `vc-*` → `eth0`, adds `<container_ip>/24`, brings `eth0` `IFF_UP`, and installs default gateway `10.0.0.1` (`RTM_NEWROUTE`). Falls back cleanly to `ip -batch -` if Netlink fails on unusual kernels.
- **Port Forwarding (`-p [HOST_IP:]HOST_PORT:CONT_PORT[/tcp|udp]`):** `setup_port_forwarding` adds `PREROUTING` DNAT, `OUTPUT` DNAT (making `curl 127.0.0.1:<HOST_PORT>` work from the host itself), and `FORWARD -p <proto> -d <container_ip> --dport <cont_port> -j ACCEPT`. All rules are deterministically deleted on exit/restart/removal (`cleanup_port_forwarding`).

---

## Chapter 11: Cgroups v2 Resource Controls & Live Telemetry (`stats`)

`CgroupManager` ([include/pieces/cgroup.hpp](file:///home/mradul/Desktop/GIT/Pieces/include/pieces/cgroup.hpp), [src/cgroup.cpp](file:///home/mradul/Desktop/GIT/Pieces/src/cgroup.cpp)) requires unified cgroups v2 (`/sys/fs/cgroup/cgroup.controllers`).

### 11.1 Slice Paths & Limit Parsing

- **Native containers:** Managed under `/sys/fs/cgroup/pieces/<container_id>`.
- **OCI / Kubernetes containers:** Honors `linux.cgroupsPath` (e.g., `/kubepods.slice/pod123/c1`), constructing `<cgroup_root>/<custom_cgroups_path>` directly.
- **`--memory <limit>` (`parse_memory_limit`):** Zero-regex parser accepting integers or decimals with `b`, `k`/`kb`, `m`/`mb`, `g`/`gb`, `t`/`tb` suffixes (binary 1024 multiples), written to `memory.max`.
- **`--cpus <cores>` (`format_cpu_max`):** Converts fractional CPU shares into `<quota_us> 100000` (minimum `1000 µs`, e.g., `0.5` → `"50000 100000"`), written to `cpu.max`.
- **`--pids-max <N>`:** Writes `pids.max` directly.
- **`enable_subtree_controllers()`:** Writes only the required `+memory`, `+cpu`, `+pids` tokens to parent `cgroup.subtree_control`, then moves `pid2` into `cgroup.procs` before `go_pipe` unblocks `execvpe`—meaning even the container's very first allocations and forks are metered.

### 11.2 Telemetry Reader (`pieces stats <id>`)

`read_cgroup_stats` parses `memory.current`, `memory.max`, `pids.current`, `pids.max`, and `cpu.stat` (`usage_usec` line), outputting structured JSON:

```json
{
  "cpuUsageUsec": 12450,
  "id": "Verify-or-container-id",
  "memoryCurrentBytes": 2097152,
  "memoryMaxBytes": 268435456,
  "pidsCurrent": 2,
  "pidsMax": 64
}
```

(`0` in `memoryMaxBytes` or `pidsMax` corresponds to kernel `"max"` unlimited.)

---

## Chapter 12: Five-Layer Defense-in-Depth Security Model

Every non-`--privileged` container enforces five complementary security controls before `execvpe`:

```text
  [1] Mount & Proc/Sys Hardening (namespaces.cpp)
        |-- /proc/sys + /sys remounted MS_RDONLY
        |-- /proc/{kcore,keys,timer_list,sched_debug,latency_stats} -> /dev/null bind
        |-- /proc/{acpi,scsi} + /sys/firmware -> mode=000 RO tmpfs
        |-- optional --read-only rootfs -> `/` MS_RDONLY
        v
  [2] Mandatory Access Control Labels (security.cpp)
        |-- --security-opt apparmor=<p> -> /proc/self/attr/apparmor/exec ("exec <p>")
        |-- --security-opt label=<ctx>  -> /proc/self/attr/exec
        v
  [3] Linux Capabilities Drop via libcap (security.cpp)
        |-- Default 14 safe caps +/- --cap-add / --cap-drop (supports ALL)
        |-- cap_drop_bound() + cap_set_proc() (EFFECTIVE, PERMITTED, INHERITABLE)
        v
  [4] Default-Deny Allowlist seccomp-bpf (security.cpp)
        |-- prctl(PR_SET_NO_NEW_PRIVS, 1)
        |-- Check seccomp_data.arch == host_audit_arch() -> else SECCOMP_RET_KILL_PROCESS
        |-- Allowlist (~290+ POSIX/Linux syscalls) or custom OCI JSON profile
        |-- Everything else -> SECCOMP_RET_ERRNO | EPERM
        v
  [5] Unprivileged User Drop (security.cpp + namespaces.cpp)
        |-- Optional CLONE_NEWUSER with /etc/subuid + /etc/subgid or single-UID map
        |-- --run-as-non-root check + setgroups() + setgid() + setuid()
```

### 12.1 Default Capabilities (`default_container_capabilities()`)

Without `--cap-add` or `--cap-drop`, Pieces retains only the 14 standard container capabilities:
`CAP_CHOWN`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_FSETID`, `CAP_KILL`, `CAP_SETGID`, `CAP_SETUID`, `CAP_SETPCAP`, `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_SYS_CHROOT`, `CAP_MKNOD`, `CAP_AUDIT_WRITE`, `CAP_SETFCAP`.

Powerful host/kernel capabilities such as `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_MODULE`, `CAP_SYS_PTRACE`, `CAP_SYS_BOOT`, `CAP_BPF`, and `CAP_PERFMON` are dropped from bounding, effective, permitted, and inheritable sets.

Use `--cap-drop ALL` for maximum hardening (or `--cap-drop ALL --cap-add NET_BIND_SERVICE` for hardened port-80/443 web servers).

### 12.2 Default-Deny Allowlist `seccomp-bpf` (`src/security.cpp`)

Instead of a fragile denylist that forgets syscalls or allows newly added kernel syscalls by default, Pieces builds a classic BPF (`sock_filter`) allowlist:

```text
  [0] BPF_LD  seccomp_data.arch
  [1] BPF_JMP arch == host_audit_arch() ? skip 1 : next
  [2] BPF_RET SECCOMP_RET_KILL_PROCESS        <-- Blocks 32-bit compat syscall bypasses
  [3] BPF_LD  seccomp_data.nr
  [4..] For each syscall in allowlist (or OCI JSON rules):
        BPF_JMP nr == allowed ? next : +1
        BPF_RET SECCOMP_RET_ALLOW (or rule.action)
  [N] BPF_RET SECCOMP_RET_ERRNO | EPERM       <-- Default deny for everything else!
```

Supported architectures in `host_audit_arch()`: `AUDIT_ARCH_X86_64`, `AUDIT_ARCH_AARCH64`, `AUDIT_ARCH_RISCV64`, `AUDIT_ARCH_I386`, `AUDIT_ARCH_ARM`.

Notable syscalls **blocked by default** (absent from `syscall_name_table()`):
`unshare`, `setns`, `chroot`, `mount`, `umount2`, `pivot_root`, `ptrace`, `bpf`, `perf_event_open`, `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `reboot`, `swapon`, `swapoff`, `keyctl`, `add_key`, `request_key`, `userfaultfd`, `io_uring_setup`, and any future kernel syscalls.

Custom profiles (`--seccomp-profile path/to/seccomp.json`) are compiled directly via `build_seccomp_from_oci_json`, supporting standard OCI actions:
`SCMP_ACT_ALLOW`, `SCMP_ACT_ERRNO` (with `errnoRet` / `defaultErrnoRet`), `SCMP_ACT_KILL`, `SCMP_ACT_KILL_THREAD`, `SCMP_ACT_KILL_PROCESS`, `SCMP_ACT_TRAP`, and `SCMP_ACT_LOG`.

---

# Part V — OCI Runtime Spec, Kubernetes & Performance

## Chapter 13: The OCI Runtime Spec Engine (`spec`, `create`, `start`, `state`, `kill`, `delete`)

Implemented in [include/pieces/oci_runtime.hpp](file:///home/mradul/Desktop/GIT/Pieces/include/pieces/oci_runtime.hpp) and [src/oci_runtime.cpp](file:///home/mradul/Desktop/GIT/Pieces/src/oci_runtime.cpp).

### 13.1 Two-Phase Lifecycle & `exec.fifo` Handshake

OCI runtimes separate container **creation** (setting up namespaces, rootfs, mounts, cgroups, seccomp, and writing the PID before the entrypoint executes) from **starting** (unblocking the container entrypoint), allowing container managers and CNI plugins to wire networks and run hooks in between:

```text
  1. pieces spec [--rootless]
       └─> Generates baseline OCI 1.0.2 config.json in $PWD

  2. pieces [--root <dir>] create --bundle <dir> [--pid-file <p>] <id>
       ├─> Parses <bundle>/config.json (OciSpec)
       ├─> Creates <state_root>/<id>/exec.fifo (mkfifo 0600)
       ├─> Forks pid1 -> joins Pod namespaces (setns) + unshares new ones -> forks pid2
       ├─> pid2 sets up mounts/pivot_root/cwd/MAC/caps/seccomp, sends pid2 to parent,
       │   then BLOCKS on open("exec.fifo", O_RDONLY) + read()
       ├─> Parent attaches pid2 to CgroupManager, writes pid-file & state.json (status="created")
       └─> Runs createRuntime & createContainer hooks (OCI State JSON on stdin)

  3. pieces [--root <dir>] state <id>
       └─> Reconciles pid liveness (marks "stopped", pid=0 if dead) & prints OCI State JSON

  4. pieces [--root <dir>] start <id>
       ├─> Runs prestart hooks
       ├─> Opens exec.fifo O_WRONLY, writes "1", removes exec.fifo
       ├─> Updates state.json -> status="running"
       ├─> Runs poststart hooks
       └─> Meanwhile pid2 unblocks -> apply_process_user -> execvpe(spec.args, spec.env)

  5. pieces [--root <dir>] kill <id> [SIGNAL]
       └─> Supports SIGTERM, KILL, 9, HUP, INT, USR1, USR2, etc. -> kill(pid, sig)

  6. pieces [--root <dir>] delete [-f] <id>
       └─> Checks status == "stopped" (or kills if -f), rmdirs cgroup, runs poststop hooks, deletes state dir
```

### 13.2 State Root Precedence (`default_oci_state_root`)

1. Explicit CLI `--root <dir>`
2. Environment variable `PIECES_STATE_DIR`
3. `/run/pieces` when `geteuid() == 0`
4. `.pieces/oci-state` when non-root

---

## Chapter 14: Wiring Pieces into `containerd` & Kubernetes

### 14.1 How the Stack Fits Together

```text
  kubelet
     │  (CRI gRPC: RunPodSandbox / CreateContainer / StartContainer / ExecSync / ContainerStats)
     ▼
  containerd (+ CNI plugins: Cilium / Calico / Flannel + Registry Puller)
     │  (containerd-shim-runc-v2 spawning OCI runtime binary)
     ▼
  pieces --root /run/containerd/runc/k8s.io <create|start|state|kill|delete>
```

Pieces already implements the critical OCI primitives Kubernetes relies on:
- **Pod Sandbox Namespace Sharing (`linux.namespaces[].path`):** When `path` is present (e.g., `{"type": "network", "path": "/var/run/netns/cni-..."}` or `{"type": "ipc", "path": "/proc/<pause_pid>/ns/ipc"}`), `oci_create` calls `join_namespace_path` (`setns`) instead of `unshare`, letting all containers in a Kubernetes Pod share IP, loopback, IPC, and UTS namespaces with the pause container.
- **QoS & Pod Cgroup Slices (`linux.cgroupsPath`):** Supports arbitrary hierarchy paths such as `/kubepods.slice/kubepods-burstable.slice/...` alongside `memory.limit`, `cpu.quota`/`cpu.period`, and `pids.limit`.
- **Kubernetes SecurityContext Mapping:** `process.user.{uid,gid,additionalGids}`, `root.readonly`, `linux.seccomp`, `process.capabilities`, `process.apparmorProfile`, `process.selinuxLabel`, `linux.uidMappings`/`gidMappings` (`hostUsers: false`), `maskedPaths`, and `readonlyPaths`.

Example `/etc/containerd/config.toml` runtime registration (for Kubernetes nodes where `/usr/local/bin/pieces` is installed and validated via `verify_host.sh`):

```toml
version = 2

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.pieces]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.pieces.options]
    BinaryName = "/usr/local/bin/pieces"
```

---

## Chapter 15: Performance Engineering & `--timing` Benchmarks

### 15.1 The Built-In `StartupProfiler` (`--timing`)

Passing `--timing` to foreground `pieces run` enables `StartupProfiler` (`std::chrono::steady_clock`), logging delta and cumulative millisecond timestamps for every phase:

1. `config + seccomp + caps prep`
2. `host network + IPAM`
3. `rootfs (<method>)`
4. `unshare + userns map` *(rootless)* or `unshare + fork pid2` *(rootful)*
5. `cgroup + veth + port fwd`
6. `container waitpid exit`
7. `cleanup`

### 15.2 Directly Observed Measurements (Sandbox)

The table below reports exact measurements observed from `./build/pieces` in this sandbox environment:

| Benchmark | Measured Latency | Observed Breakdown / Notes |
| --- | --- | --- |
| `./build/pieces --help` | **5.92 ms** | Down from **147.3 ms** in the earlier Python CLI (~25x faster) |
| `./build/pieces images` | **6.55 ms** | Direct directory + `.pieces_meta.json` scan |
| `./build/pieces ps -a` | **5.56 ms** | Direct container metadata scan + PID reconciliation |
| `./build/pieces run --rm --read-only --timing --net none ubuntu-22.04 /bin/true` *(pre-`unshare`)* | **1.01 ms** internal (**7.19 ms** wall-clock) | `config + seccomp + caps prep`: **0.48 ms**, `rootfs (readonly-bind)`: **0.01 ms**, `unshare + userns map`: **0.52 ms** *(aborted at sandbox `ENOSYS`)*, `cleanup`: **0.13 ms** |
| `./build/pieces run --rm --timing --net none ubuntu-22.04 /bin/true` *(writable, pre-`unshare`)* | **1.00 ms** internal (**7.38 ms** wall-clock; **1.53 ms** internal incl. exit/cleanup) | `config + seccomp + caps prep`: **0.33 ms**, `host network + IPAM`: **0.01 ms**, `rootfs (in-ns-overlay)`: **0.13 ms** *(down from **543.31 ms** copy!)*, `unshare + userns map`: **0.53 ms**, `child setup failed`: **0.01 ms** *(sandbox `ENOSYS`)*, `container waitpid exit`: **0.21 ms**, `cleanup`: **0.32 ms** *(down from **304.18 ms**)* |

### 15.3 Measuring Complete Live Host Startup

Because this sandbox forbids the `unshare` syscall (`ENOSYS: Function not implemented`), kernel phases inside `pid2` (`mount_in_namespace_rootfs`, `pivot_root`, `configure_container_netns_netlink`, and `execvpe`) were not executed in the sandbox. Run this on your Linux host after building in Release mode (`cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j`) to inspect complete end-to-end host numbers:

```bash
sudo ./build/pieces run --rm --timing ubuntu-22.04 /bin/true
sudo ./build/pieces run --rm --read-only --timing --net none ubuntu-22.04 /bin/true
```

---

# Part VI — Integration Recipes & Complete Technical Reference

## Chapter 16: Real-World Project Integration Recipes

### Recipe 1: Hardened Production Web API (`--read-only` + `--user` + cgroups + `-p`)

`Piecefile`:
```dockerfile
FROM alpine:3.18
ENV PYTHONUNBUFFERED=1 PORT=8080
WORKDIR /srv/app
COPY requirements.txt /srv/app/requirements.txt
RUN apk add --no-cache python3 py3-pip && pip3 install --no-cache-dir -r /srv/app/requirements.txt
COPY app /srv/app
CMD ["python3", "/srv/app/server.py"]
```

Launch:
```bash
sudo ./build/pieces build . --tag web-api
sudo ./build/pieces run -d \
  --name web-api \
  --read-only \
  --user 1000:1000 --run-as-non-root \
  --cap-drop ALL --cap-add NET_BIND_SERVICE \
  --restart unless-stopped \
  --memory 256m --cpus 1.0 --pids-max 64 \
  --log-max-size 20m --log-max-files 5 \
  -v "$PWD/config:/srv/app/config:ro" \
  -p 127.0.0.1:8080:8080/tcp \
  web-api
```

### Recipe 2: Ephemeral Isolated Build / CI Runner (`--rm` + Bind-Mounted Workspace)

```bash
sudo ./build/pieces run --rm --timing \
  --memory 2g --cpus 2.0 --pids-max 256 \
  -v "$PWD:/workspace" \
  -w /workspace \
  -e CCACHE_DISABLE=1 \
  ubuntu-22.04 \
  /bin/sh -c "cmake -B build-ci -DCMAKE_BUILD_TYPE=Release && cmake --build build-ci -j"
```

Because `--rm` is set without `-d`, writable scratch layers live in RAM under `/dev/shm/.pieces-run/<id>` and disappear automatically when the command exits.

### Recipe 3: Reproducible Air-Gapped Compute Worker (`--net none` + `SHA256` Pin)

`Piecefile`:
```dockerfile
FROM_URL https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.3-x86_64.tar.gz
SHA256 7e69b75763a02d00412196394b00b76838d1a8d5a8b651bf80d3a55086f60c7a
WORKDIR /work
COPY worker.sh /work/worker.sh
RUN chmod +x /work/worker.sh
ENTRYPOINT ["/work/worker.sh"]
```

```bash
sudo ./build/pieces run --rm --net none --read-only \
  --user 65534:65534 --run-as-non-root \
  --cap-drop ALL \
  --memory 128m --pids-max 16 \
  -v "$PWD/input:/input:ro" \
  my-worker --batch 42
```

*(Note: verify your exact tarball SHA-256 first via `sha256sum` before pinning `SHA256` in a production `Piecefile`.)*

### Recipe 4: Communicating Sidecars (`--no-isolate-net`)

By default, `ensure_bridge_isolation` drops container-to-container packets on `pieces-br0`. When a web container intentionally talks directly to a database container IP shown in `pieces ps`:

```bash
sudo ./build/pieces run -d --name db --no-isolate-net postgres-local
sudo ./build/pieces run --rm --no-isolate-net -e DB_HOST=10.0.0.2 my-client
```

---

## Appendix A: Complete CLI & Flag Reference

### Global Flag (Must Appear Before Subcommand)

- `--root <dir>`: Override OCI runtime state directory (`create`, `start`, `state`, `kill`, `delete`).

### Native Image Commands

- `pieces build <context> [-t/--tag <name>] [--no-cache]`
- `pieces pull <registry>/<repo>[:tag] [-t/--tag <name>]` *(Docker Hub rejected)*
- `pieces images`
- `pieces rmi <image> [<image>...]`

### Native Container Commands

- `pieces run [OPTIONS] <image> [--] [COMMAND [ARGS...]]`
  - **Identity & Lifecycle:** `--name <name>`, `--rm`, `-d`/`--detach`, `--restart no|on-failure|always|unless-stopped`, `--hostname <name>`, `--timing`
  - **Execution & I/O:** `-i`/`--interactive`, `-t`/`--tty`, `-it`/`-ti`, `-e`/`--env KEY=VAL`, `-w`/`--workdir <dir>`, `-v`/`--volume HOST:CONTAINER[:ro|rw]`
  - **Security & Isolation:** `-u`/`--user UID[:GID]`, `--run-as-non-root`, `--read-only`, `--seccomp-profile <json_path>`, `--security-opt apparmor=<profile>|label=<context>`, `--cap-add <CAP|ALL>`, `--cap-drop <CAP|ALL>`, `--privileged`, `--rootless`/`--userns`, `--full-copy`
  - **Networking:** `--net bridge|none`, `-p`/`--publish [HOST_IP:]HOST_PORT:CONT_PORT[/tcp|udp]`, `--no-isolate-net`
  - **Resources & Logs:** `--memory <limit>` (`b|k|kb|m|mb|g|gb|t|tb`), `--cpus <float>`, `--pids-max <int>`, `--log-max-size <size>`, `--log-max-files <int>`
- `pieces ps [-a/--all]`
- `pieces stop [-t/--time <seconds>] <id|name>...`
- `pieces logs [-f/--follow] [-n/--tail <lines>] <id|name>`
- `pieces exec [-i] [-t] [-it] [-e KEY=VAL] [-w DIR] <id|name> [--] <cmd> [args...]`
- `pieces stats <id|name>`
- `pieces rm [-f/--force] <id|name>...`
- `pieces prune`

### OCI Runtime Specification Commands

- `pieces spec [--rootless]`
- `pieces [--root <dir>] create [-b/--bundle <dir>] [--pid-file <path>] <id>`
- `pieces [--root <dir>] start <id>`
- `pieces [--root <dir>] state <id>`
- `pieces [--root <dir>] kill <id> [SIGNAL]`
- `pieces [--root <dir>] delete [-f/--force] <id>`

---

## Appendix B: `Piecefile` & JSON State Schema Reference

### Image Metadata (`.pieces/images/<name>/.pieces_meta.json`)

```json
{
  "cmd": ["/bin/sh"],
  "entrypoint": ["/bin/sh", "-c"],
  "env": {
    "APP_ENV": "production",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  },
  "workdir": "/app"
}
```

### Container Metadata (`.pieces/containers/<id>/meta.json`)

```json
{
  "command": "/bin/sh -c ...",
  "created_at": "2026-11-25T02:00:00Z",
  "exit_code": null,
  "host_veth": "vp-a1b2c3d4",
  "id": "a1b2c3d4e5f6",
  "image": "alpine:3.18",
  "ip": "10.0.0.2",
  "name": "api",
  "pid": 14321,
  "ports": ["127.0.0.1:8080:8080/tcp"],
  "readonly_rootfs": false,
  "restart_policy": "unless-stopped",
  "rootfs_method": "in-ns-overlay",
  "rootless": false,
  "status": "running"
}
```

### IPAM Leases (`.pieces/containers/.ipam_leases.json`)

Maps active `container_id -> assigned_ip` under `flock(LOCK_EX)` protection on `.ipam.lock`:

```json
{
  "a1b2c3d4e5f6": "10.0.0.2"
}
```

### OCI State (`<state_root>/<id>/state.json` & `pieces state <id>`)

```json
{
  "ociVersion": "1.0.2",
  "id": "c1",
  "status": "running",
  "pid": 15204,
  "bundle": "/var/lib/bundles/c1",
  "annotations": {
    "io.kubernetes.pod.name": "web-pod"
  }
}
```

---

## Appendix C: On-Disk & Virtual Filesystem State Map

```text
.pieces/
├── cache/
│   └── <sha256(url)>.tar             Downloaded distro / FROM_URL tarball cache
├── images/
│   └── <image-name>/
│       ├── .pieces_meta.json         CMD, ENTRYPOINT, ENV, WORKDIR defaults
│       ├── etc/resolv.conf           Pre-seeded DNS configuration
│       ├── etc/hosts                 Pre-seeded localhost & container entries
│       └── ...                       Immutable unpacked base rootfs tree
└── containers/
    ├── .ipam.lock                    Advisory flock mutex for IP allocation/release
    ├── .ipam_leases.json             Active container_id -> IP lease map
    └── <12-char-hex-id>/
        ├── meta.json                 Live state, PID, network, exit code, rootfs method
        ├── container.log[.1,.2,.N]   Rotating detached stdout/stderr logs
        ├── .stop_requested           Sentinel created by `pieces stop` to halt restarts
        └── upper/, work/, rootfs/    Persistent container scratch (when not --rm)

/dev/shm/.pieces-run/<id>/            RAM tmpfs scratch for ephemeral `--rm` non-detached runs
/run/pieces/
├── .net_ready_<bridge>_<nat>_<iso>   Host bridge & firewall fast-skip cache markers
└── <oci-id>/
    ├── state.json                    OCI container state
    └── exec.fifo                     Two-phase create->start synchronization FIFO
/sys/fs/cgroup/pieces/<id>/           Default cgroup v2 slice for native containers
```

---

## Appendix D: Troubleshooting & Diagnostics Guide

| Symptom | Root Cause | Solution |
| --- | --- | --- |
| `unshare: Function not implemented` (`ENOSYS`) | Running inside an outer sandbox or container where user/kernel namespaces are syscall-blocked | Run on a bare-metal or VM Linux host with `sudo` or enabled user namespaces. |
| `PULL: Error: Docker Hub registry '...' is disabled` | Attempted to `pull` a Docker Hub image or passed a short name without registry host | Use `alpine:3.18`, `fedora:38`, `ubuntu:22.04`, `FROM_URL`, or explicit `ghcr.io/...`, `quay.io/...`, `localhost:5000/...`. |
| `SHA-256 verification failed` | Tampered download, wrong `SHA256` pin, or corrupted `.pieces/cache/` file | Verify the expected 64-hex digest and re-run with `--no-cache`. |
| `Operation not permitted` on `unshare` inside rootless mode | Kernel disables unprivileged user namespaces | Enable via `sudo sysctl -w kernel.unprivileged_userns_clone=1` (where applicable) or run with `sudo`. |
| Multi-UID `chown` / package installs fail in rootless mode | Missing `/etc/subuid` / `/etc/subgid` range or missing `newuidmap` / `newgidmap` | Install `uidmap` package and configure `/etc/subuid` + `/etc/subgid` entries for your username. |
| Container receives `EPERM` calling `unshare`, `mount`, `ptrace`, or `bpf` | Blocked intentionally by default-deny allowlist `seccomp-bpf` and dropped capabilities | Expected hardening. Provide a tailored `--seccomp-profile` + `--cap-add` only for trusted workloads that truly require them. |
| `NETWORK: Warning: -p port forwarding requires root` | Port publishing requested in unprivileged rootless mode | Run with `sudo` so Pieces can configure `pieces-br0` and `iptables` DNAT rules. |
| Cannot write to `/usr` inside a container when OverlayFS fails | Kernel lacks OverlayFS/`userxattr` + no `fuse-overlayfs`, so hybrid `tmpfs` mounted `/usr` read-only for `< 10 ms` speed | Run with `sudo` (kernel OverlayFS), install `fuse-overlayfs`, upgrade to Linux 5.11+, or pass `--full-copy`. |
| `Cannot delete non-stopped container '...' without --force` | Calling `pieces rm` or `pieces delete` on a live container | Run `pieces stop <id>` / `pieces kill <id>` first, or pass `-f` / `--force`. |
