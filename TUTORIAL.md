# Pieces Tutorial: Getting Started & Project Integration Guide

This tutorial walks you through compiling, configuring, and operating **Pieces** (written in C++20) to containerize and run full application projects.

---

## 1. Prerequisites & Build

Pieces compiles to a native Linux binary (`./build/pieces`) using CMake, a C++20 compiler, `libcurl`, and `libarchive`.

Verify host tools:

```bash
g++ --version              # C++20 compiler
cmake --version            # CMake 3.20+
which ip nsenter iptables  # iproute2, util-linux, iptables (for NAT and -p port forwarding)
ls /sys/fs/cgroup/cgroup.controllers  # cgroups v2 check
```

Compile Pieces and run the test suite:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

---

## 2. Step-by-Step Walkthrough

### Step 1: Pull Any OCI / Docker Hub Image (Optional)

You can pull official or custom OCI images directly from Docker Hub or any OCI registry (`ghcr.io`, `localhost:5000`, etc.):

```bash
./build/pieces pull alpine:3.18
./build/pieces pull python:3.12-alpine -t py312
./build/pieces images
```

---

### Step 2: Create a `Piecefile` and Build Your Project

Create a `Piecefile` in your project root. Instructions (`ENV`, `WORKDIR`, `COPY`, `RUN`) execute **in exact order**:

```dockerfile
# Pulls from built-in rootfs or any OCI/Docker Hub image
FROM python:3.12-alpine

ENV PYTHONDONTWRITEBYTECODE=1 PORT=8000
WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app
CMD ["python", "-m", "http.server", "8000"]
```

Build the image:

```bash
sudo ./build/pieces build . --tag my-web-app
```

> [!NOTE]
> Build-time `RUN` executes inside an isolated namespace rooted at the staging rootfs with host DNS (`/etc/resolv.conf`). Unprivileged `RUN` builds use `CLONE_NEWUSER` automatically when kernel user namespaces are enabled; root builds work with standard privileges.

#### Available `Piecefile` Instructions

| Instruction | Example | Notes |
| --- | --- | --- |
| `FROM` | `FROM python:3.12-alpine` | Uses built-in tarballs (`alpine:3.18`, `fedora:38`, `ubuntu:22.04`) or pulls from OCI/Docker Hub. |
| `FROM_URL` | `FROM_URL https://.../rootfs.tar.gz` | Downloads any HTTP/HTTPS Linux rootfs tarball via `libcurl`. |
| `ENV` | `ENV FOO=bar BAZ="hello"` | Sets build-time and runtime env vars. |
| `WORKDIR` | `WORKDIR /app` | Creates and switches to the working directory for subsequent `RUN` and container `CMD`. |
| `COPY` | `COPY ./src /app/src` | Copies files/dirs from the build context into the image safely. |
| `RUN` | `RUN apk add --no-cache curl` | Executes `/bin/sh -c <cmd>` inside the staging rootfs during `build`. |
| `ENTRYPOINT` | `ENTRYPOINT ["/bin/sh", "-c"]` | Fixed executable prefix; CLI args are appended to it. |
| `CMD` | `CMD ["python", "app.py"]` | Default command/args (supports shell string or JSON array). |

---

### Step 3: Run Containers (Foreground, Detached, Port Mapping, Rootless)

#### Detached Service with Port Publishing (`-d`, `-p`)

```bash
sudo ./build/pieces run -d \
  --name web \
  -p 8080:8000 \
  --memory 256m \
  --cpus 0.5 \
  --pids-max 64 \
  my-web-app
```

- `-d` / `--detach`: Runs the container in the background, logs stdout/stderr to `.pieces/containers/<id>/container.log`, and prints the container ID.
- `-p` / `--publish`: Forwards host port `8080` to container port `8000` (`[HOST_IP:]HOST_PORT:CONT_PORT[/tcp|udp]`) via `iptables` DNAT rules and cleans them up automatically on exit.

#### Inspect, View Logs, and Exec into Running Containers

```bash
# List running or all containers (shows IP and published PORTS)
./build/pieces ps
./build/pieces ps -a

# View or follow container logs
./build/pieces logs -n 50 web
./build/pieces logs -f web

# Execute a command inside the running container's namespaces
sudo ./build/pieces exec web /bin/sh -c "ps aux && ls -la /app"
```

#### Interactive Foreground Run & Volume Mounts (`-v`)

```bash
sudo ./build/pieces run --rm \
  -v "$PWD/data:/data:ro" \
  -e APP_ENV=staging \
  my-web-app /bin/sh
```

#### Rootless Mode (Without `sudo`)

When running as a non-root user (or with `--rootless`), Pieces automatically enables `CLONE_NEWUSER` and maps container UID/GID `0` to your host user in `uid_map`/`gid_map`:

```bash
./build/pieces run --rm --net none alpine-3.18 /bin/sh -c "id && uname -a"
```

> [!NOTE]
> Host bridge `veth` creation and `-p` `iptables` forwarding require host `CAP_NET_ADMIN` (`sudo`); in rootless mode, container filesystem/PID/mount/UTS/IPC isolation still operates without `sudo`.

---

### Step 4: Stop & Clean Up

```bash
sudo ./build/pieces stop web        # Sends SIGTERM, then SIGKILL after timeout (-t)
./build/pieces rm web               # Removes stopped container (use -f to force)
./build/pieces rmi my-web-app       # Removes image
```

---

## 3. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `unshare: Operation not permitted` / `ENOSYS` | Kernel user namespaces disabled or blocked by host sandbox | Run with `sudo` or enable `kernel.unprivileged_userns_clone=1`. |
| `PULL: Manifest fetch failed` | No internet access or invalid image ref/tag | Verify registry connectivity and `repo:tag` spelling. |
| `NETWORK: Warning: -p port forwarding requires root` | Running rootless with `-p` | Run with `sudo ./build/pieces run ... -p ...`. |
| `CGROUP: Warning: cgroup v2 not detected` | Host lacks cgroup v2 at `/sys/fs/cgroup` | Container runs without limits; mount cgroup v2 unified hierarchy if limits are needed. |
