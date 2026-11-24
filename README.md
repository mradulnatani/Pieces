# Pieces

Pieces is a lightweight Linux container runtime written in **C++20** using direct Linux syscalls (namespaces, `pivot_root`, OverlayFS with copy fallback), OCI registry pulling, build-time `RUN` execution, `veth` + bridge networking with `-p` port forwarding, detached lifecycle (`-d`, `stop`, `logs`, `exec`), rootless `CLONE_NEWUSER` support, and cgroups v2.

For a step-by-step walkthrough on building, operating, and integrating Pieces into your own project, see [TUTORIAL.md](TUTORIAL.md).

## Architecture

```text
CMakeLists.txt             CMake build configuration (C++20, libcurl, libarchive)
include/pieces/*.hpp       Public module interfaces
src/
├── main.cpp               CLI entry point
├── cli.cpp                Subcommand & flag parsing (build, pull, run, images, ps, stop, logs, exec, rm, rmi)
├── parser.cpp             Piecefile parser (FROM, FROM_URL, COPY, RUN, ENV, WORKDIR, CMD, ENTRYPOINT)
├── json.cpp               Self-contained JSON parser/serializer
├── registry.cpp           OCI / Docker Hub v2 pull client (Bearer auth, multi-arch index, layer config)
├── filesystem.cpp         libcurl downloads, safe libarchive + OCI whiteout extraction, build RUN, OverlayFS
├── namespaces.cpp         Direct Linux syscalls (unshare, setns, mount, umount2, pivot_root, uid/gid_map)
├── network.cpp            Host bridge (pieces-br0), veth pairs, IPAM, NAT masquerading, iptables -p DNAT
├── cgroup.cpp             Cgroup v2 resource limits (memory.max, cpu.max, pids.max)
└── container.cpp          Foreground/detached container supervisor, stop/logs/exec, exit-code propagation
```

## Requirements

- **OS:** Linux (any architecture supported by `<sys/syscall.h>` `SYS_pivot_root`)
- **Build tools:** CMake 3.20+, C++20 compiler (`g++` 13+ or `clang++`), `libcurl` dev headers, `libarchive` dev headers
- **Privileges:** Root (`CAP_SYS_ADMIN` / `CAP_NET_ADMIN`) for bridge networking, `-p` port forwarding, and cgroups; unprivileged users can run rootless containers (`CLONE_NEWUSER`) when host user namespaces are enabled.
- **Host networking tools:** `iproute2` (`ip`), `util-linux` (`nsenter`), and `iptables` for NAT / `-p` port forwarding.

## Building from Source

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Quick CLI Usage

```bash
# Pull any OCI/Docker Hub image or build a Piecefile (executes COPY and RUN in order)
./build/pieces pull python:3.12-alpine
./build/pieces build . --tag my-app

# Run foreground, detached (-d), or rootless (--rootless) with port forwarding & limits
sudo ./build/pieces run -d --name web -p 8080:80 --memory 256m --cpus 0.5 my-app
./build/pieces ps -a
./build/pieces logs -n 50 web
sudo ./build/pieces exec web /bin/sh -c "id && ip addr"
sudo ./build/pieces stop web
./build/pieces rm web
./build/pieces rmi my-app
```

## Running Tests

```bash
ctest --test-dir build --output-on-failure
```
