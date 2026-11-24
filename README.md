# Pieces

Pieces is a lightweight Linux container runtime written in **C++20** using direct Linux syscalls (namespaces, `pivot_root`, OverlayFS with copy fallback), `libcurl`, `libarchive`, `veth` + bridge networking, and cgroups v2.

For a step-by-step walkthrough on building, operating, and integrating Pieces into your own project, see [TUTORIAL.md](TUTORIAL.md).

## Architecture

```text
CMakeLists.txt             CMake build configuration (C++20, libcurl, libarchive)
include/pieces/*.hpp       Public module interfaces
src/
├── main.cpp               CLI entry point
├── cli.cpp                Subcommand & flag parsing (build, run, images, ps, rm, rmi)
├── parser.cpp             Piecefile parser (FROM, FROM_URL, COPY, ENV, WORKDIR, CMD, ENTRYPOINT)
├── json.cpp               Self-contained JSON parser/serializer
├── filesystem.cpp         libcurl downloads, safe libarchive extraction, OverlayFS / copy rootfs
├── namespaces.cpp         Direct Linux syscalls (unshare, mount, umount2, pivot_root, sethostname)
├── network.cpp            Host bridge (pieces-br0), veth pairs, IPAM, NAT masquerading
├── cgroup.cpp             Cgroup v2 resource limits (memory.max, cpu.max, pids.max)
└── container.cpp          Container lifecycle, pipe sync, state tracking, exit-code propagation
```

## Requirements

- **OS:** Linux (any architecture supported by `<sys/syscall.h>` `SYS_pivot_root`)
- **Build tools:** CMake 3.20+, C++20 compiler (`g++` 13+ or `clang++`), `libcurl` dev headers, `libarchive` dev headers
- **Privileges:** Root or `CAP_SYS_ADMIN` / `CAP_NET_ADMIN` for namespaces, `mount`/`pivot_root`, `veth` networking, and cgroups v2
- **Host networking tools:** `iproute2` (`ip`), `util-linux` (`nsenter`), and optionally `iptables` for NAT masquerading

## Building from Source

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

This produces the native `./build/pieces` binary and `./build/pieces_tests` test runner.

## Quick CLI Usage

```bash
# Build an image from Piecefile
./build/pieces build .
./build/pieces build . --tag my-ubuntu

# Run a container
sudo ./build/pieces run --rm --name web --memory 256m --cpus 0.5 ubuntu-22.04 /bin/sh -c "uname -a && ip addr"
sudo ./build/pieces run -e FOO=bar -v "$PWD:/workspace:ro" --net none ubuntu-22.04 /bin/ls -la /workspace

# Inspect and clean up
./build/pieces images
./build/pieces ps -a
./build/pieces rm web
./build/pieces rmi ubuntu-22.04
```

## Running Tests

```bash
ctest --test-dir build --output-on-failure
```
