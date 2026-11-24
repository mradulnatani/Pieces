# Pieces Tutorial: Getting Started & Project Integration Guide

This tutorial walks you through compiling, configuring, and operating **Pieces** (written in C++20) so you can package and run isolated Linux workloads in your own projects.

---

## 1. Prerequisites & Build

Pieces compiles to a native Linux binary (`./build/pieces`) using CMake, a C++20 compiler, `libcurl`, and `libarchive`. Because `pieces run` creates kernel namespaces, mounts filesystems, configures `veth` networking, and writes cgroup v2 limits, running containers requires root privileges (or `CAP_SYS_ADMIN` + `CAP_NET_ADMIN`).

Verify your host tools:

```bash
g++ --version              # C++20 compiler
cmake --version            # CMake 3.20+
which ip nsenter iptables  # iproute2, util-linux, optional iptables for NAT
ls /sys/fs/cgroup/cgroup.controllers  # cgroups v2 check
```

Compile Pieces in Release mode:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

---

## 2. Step-by-Step Walkthrough

### Step 1: Create a `Piecefile` in Your Project

Create a `Piecefile` in the root of your project directory (the *build context*):

```dockerfile
# Supported FROM tags: alpine:3.18, fedora:38, ubuntu:22.04
FROM alpine:3.18

ENV APP_ENV=production PORT=8080
WORKDIR /app
COPY ./app /app
CMD ["/bin/sh"]
```

#### Available `Piecefile` Instructions

| Instruction | Example | Notes |
| --- | --- | --- |
| `FROM` | `FROM ubuntu:22.04` | Built-in base images: `alpine:3.18`, `fedora:38`, `ubuntu:22.04`. |
| `FROM_URL` | `FROM_URL https://.../rootfs.tar.gz` | Downloads any HTTP/HTTPS Linux rootfs tarball via `libcurl`. |
| `ENV` | `ENV FOO=bar BAZ="hello"` | Sets default env vars (also supports `ENV FOO bar`). |
| `WORKDIR` | `WORKDIR /app` | Sets the default working directory inside the container. |
| `COPY` | `COPY ./src /app/src` | Copies files/dirs from the build context into the image safely. |
| `ENTRYPOINT` | `ENTRYPOINT ["/bin/sh", "-c"]` | Fixed executable prefix; CLI args are appended to it. |
| `CMD` | `CMD echo "hello"` | Default command/args (supports shell string or JSON array). |
| `RUN` | `RUN echo "hi"` | Parsed and recorded, **not executed at build time yet** (skipped with a warning). |

> [!TIP]
> Long `Piecefile` instructions can be split across lines using a trailing `\`.

---

### Step 2: Build the Image

```bash
# Uses default name derived from FROM (e.g. alpine-3.18)
./build/pieces build .

# Or assign a custom image tag
./build/pieces build . --tag my-app

# List built images
./build/pieces images
```

Images are stored under `.pieces/images/<image-name>/` with runtime metadata in `.pieces_meta.json`. Rebuilding stages into a temporary directory first and swaps atomically so a failed download never overwrites an existing working image.

---

### Step 3: Run Containers

#### Interactive Shell

```bash
sudo ./build/pieces run --rm my-app
```

- `--rm` automatically removes `.pieces/containers/<id>/` after exit.
- Omit `--rm` if you want to inspect exited containers via `./build/pieces ps -a`.

#### One-Off Command

Place `pieces run` flags **before** `<image>`, and your container command **after** `<image>`:

```bash
sudo ./build/pieces run --rm --name demo my-app /bin/ls -la /app
```

#### Mount Project Files (`-v`), Env (`-e`), and Workdir (`-w`)

```bash
sudo ./build/pieces run --rm \
  -v "$PWD/data:/data:ro" \
  -v "$PWD/output:/output" \
  -e APP_ENV=staging \
  -w /app \
  my-app /bin/sh -c "ls -la /data && env"
```

---

### Step 4: Networking & Cgroup v2 Limits

- **Bridge Networking (default `--net bridge`):** Sets up `pieces-br0` (`10.0.0.1/24`), assigns an IP in `10.0.0.2`–`10.0.0.254` to `eth0` inside the container, brings up `lo`, sets the default gateway, copies `/etc/resolv.conf`, and configures NAT masquerading if `iptables` is available.
- **Offline Isolation (`--net none`):** Runs with an isolated empty network namespace.
- **Cgroup v2 Resource Limits:**

```bash
sudo ./build/pieces run --rm \
  --name limited-job \
  --memory 256m \
  --cpus 0.5 \
  --pids-max 64 \
  my-app /bin/sh -c "echo running within limits"
```

---

### Step 5: Inspect & Clean Up State

```bash
./build/pieces ps          # Running containers
./build/pieces ps -a       # Running + exited containers
./build/pieces rm demo     # Remove exited container (add -f to force)
./build/pieces rmi my-app  # Remove image
```

---

## 3. Integrating Pieces into Your Project

Install `./build/pieces` onto your `PATH` (e.g. `sudo cp ./build/pieces /usr/local/bin/pieces`) and invoke it from project scripts:

```bash
#!/usr/bin/env bash
set -euo pipefail

pieces build . --tag my-project-env
exec sudo pieces run --rm \
  --memory 512m \
  --cpus 1.0 \
  -v "$PWD:/workspace" \
  -w /workspace \
  my-project-env "$@"
```

---

## 4. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `unshare: Operation not permitted` | Running `pieces run` without root/`CAP_SYS_ADMIN` | Run `./build/pieces run` with `sudo`. |
| `BUILD: Warning: RUN instructions...` | Build-time `RUN` execution is not implemented yet | Pre-bake files via `COPY` or run setup commands in `CMD` / `ENTRYPOINT`. |
| `CGROUP: Warning: cgroup v2 not detected` | Host lacks cgroup v2 at `/sys/fs/cgroup` | Container continues without limits; enable cgroup v2 unified hierarchy if limits are needed. |
| `NETWORK: Warning: failed to create bridge` | Missing `iproute2` or `CAP_NET_ADMIN` | Install `iproute2` (`ip`) and run with `sudo`, or pass `--net none`. |
| `Image '...' not found` | Image not built yet or name mismatch | Run `./build/pieces images` to check exact image names. |
