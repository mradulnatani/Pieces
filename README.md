Pieces 🧩: Building a Container Runtime from Scratch

Pieces is a simple, educational containerization tool built entirely in Python. It's designed to demystify the "magic" behind tools like Docker by building a container runtime from its fundamental components—the "pieces" of containerization. This project serves as a hands-on guide to the core Linux technologies that make modern containers possible.
✨ Features

    Build Images: Create container images from a simple, declarative Piecefile, similar to a Dockerfile.

    Flexible Image Sources: Supports building from both friendly, known distribution names (e.g., alpine:3.18) and direct URLs to root filesystem tarballs.

    Run Containers: Run commands inside a fully isolated environment using the images you've built.

    True Process Isolation: Uses PID Namespaces to ensure processes inside the container cannot see or affect processes on the host.

    Robust Filesystem Isolation: Uses the powerful pivot_root system call, the same mechanism used by professional runtimes, to give the container a completely separate and stable root filesystem.

🗺️ The Journey: Problems We Faced & Concepts Learned

Building a container runtime is a journey through the depths of the Linux kernel. Here are the major challenges we faced and the concepts we learned to overcome them.
Part 1: The Foundation - "How do I run a command?"

The first step was to simply run a command like ls as a child process.

    Concept Learned: fork() and exec()
    We learned that this is a two-step dance in Linux. First, os.fork() creates an identical copy of our script (the child). Then, os.execvp() transforms that child into a new program (like ls or /bin/sh). This fork-exec model is the foundation of all process creation in Linux.

Part 2: Isolation - "How do I hide the host?"

Our first container could still see every process on the host machine. The next challenge was to isolate it.

    Concept Learned: Linux Namespaces (CLONE_NEWPID)
    We used ctypes to call the unshare system call with the CLONE_NEWPID flag. This placed our child process in its own "private room" where it became PID 1 and could no longer see the host's process tree.

    Problem Faced: The "Leaky" /proc Filesystem
    Even with a new PID namespace, running ps aux inside the container still showed all the host's processes!

    Concept Learned: Virtual Filesystems
    We discovered that ps gets its information by reading the /proc filesystem. We were mounting the host's /proc directly into the container, giving it a "security monitor" to see the outside world. The final fix was to mount a new, correctly-scoped /proc after entering the new PID namespace, ensuring the container could only see itself.

Part 3: The Final, Vicious Bug - "Why does my second command fail?"

This was the most difficult and frustrating challenge. After upgrading our filesystem logic to use pivot_root, our container would start perfectly. The first command (ls) would work, but any subsequent command would fail with a misleading error: /bin/sh: can't fork: Out of memory.

    Problem Faced: Unstable Environment
    We were not out of memory. This generic error meant the shell was in an unstable state and the kernel was refusing its request to fork a new process.

    Concept Learned: Mount Propagation (MS_PRIVATE)
    The root cause was a deep kernel feature. By default, a new mount namespace can still "share" filesystem events with the host. This "leaky" connection was destabilizing our pivot_root environment. The definitive fix was to add one more mount command after creating the namespace to make the container's entire filesystem view recursively private, severing the final link to the host.

    Concept Learned: The "Double Fork"
    We further stabilized the environment by separating the "setup" process from the final "user" process. The first child creates the isolated environment, then forks a "pristine" grandchild to actually run the user's command. This ensures the final process is completely clean, solving the instability for good.

🛠️ Usage Tutorial

Using Pieces is a two-step process: build an image from a recipe, then run a container from that image.
1. The Piecefile

This is a simple text file that acts as the recipe for your container. It must be named Piecefile and placed in your build directory.

Keywords:

    FROM <image>:<tag> (Recommended): Tells Pieces to build from a known, reliable distribution. The following images are currently supported:

        alpine:3.18

        ubuntu:22.04

        fedora:38

    FROM_URL <url> (Advanced): Tells Pieces to download a root filesystem from any direct URL to a compatible .tar.gz file.

    CMD <command>: Sets the default command to run when the container starts.

Example Piecefile for Ubuntu:

# The new, user-friendly Piecefile for Ubuntu 22.04
FROM ubuntu:22.04

# The default command to run is the bash shell
CMD /bin/bash

2. The build Command

This command reads your Piecefile, downloads the necessary files, and creates a reusable image in a hidden .pieces/ directory.

# Assuming 'pieces' has been installed as a binary
sudo pieces build .

3. The run Command

This command starts a container from a pre-built image.

    To run the default command (from CMD):

    # Use the image name from the Piecefile's FROM tag
    sudo pieces run ubuntu-22.04

    To run a specific command inside the container:

    # This will run 'ps aux' inside the container and exit
    sudo pieces run ubuntu-22.04 ps aux

📦 Installation: From Script to System Command

To use "Pieces" like a real command-line tool (e.g., sudo pieces build .), you need to build a standalone binary and move it to a directory on your system's PATH.
Prerequisites

    A Linux operating system (tested on Ubuntu).

    Python 3.6+.

    Root privileges (sudo) are required for all operations.

Installation Steps

    Clone the Repository and cd into it.

    Create a Python Virtual Environment (Recommended).

    python3 -m venv venv
    source venv/bin/activate

    Install PyInstaller:
    This tool packages our Python script and all its modules into a single executable.

    pip install pyinstaller

    Build the Standalone Binary:
    Run this command from the project's root directory. It tells PyInstaller to create a single file and correctly bundle our src directory.

    pyinstaller --onefile --add-data 'src:src' pieces.py

    "Install" the Binary:
    This step moves the new executable from the dist/ folder to /usr/local/bin, a standard location for custom system commands. This makes it available everywhere.

    sudo mv dist/pieces /usr/local/bin/pieces

    You're Done!
    You can now use Pieces from any directory on your system.

    # Test it out!
    sudo pieces --help

🔮 Future Work

    Networking: Implement network namespaces to give containers their own private network stack.

    Resource Limits: Use cgroups to control the amount of CPU and memory a container can consume.

    Image Management: Add commands like pieces images to list built images and pieces rmi to remove them.
