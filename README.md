# Pieces: Your Own Containerization Tool 🧩

Pieces is a simple, educational containerization tool built from scratch in Python. It's designed to demonstrate the core Linux technologies that power modern container runtimes like Docker. With Pieces, you can build container images from a definition file and run isolated, sandboxed environments.

This project was built to explore and learn about the fundamental "pieces" of containerization.
## ✨ Features

    Build Images: Create container images from a simple, declarative Piecefile, similar to a Dockerfile.

    Download from URL: Automatically downloads a root filesystem (e.g., Alpine Linux) from a URL specified in the Piecefile.

    Run Containers: Run commands inside a fully isolated environment using the images you've built.

    Process Isolation: Uses PID namespaces to ensure processes inside the container cannot see or affect processes on the host machine.

    Filesystem Isolation: Uses the powerful pivot_root system call to give the container a completely separate root filesystem, providing true filesystem isolation.

## ⚙️ How it Works

Pieces leverages fundamental Linux kernel features to create containers:

    Namespaces: It uses CLONE_NEWPID and CLONE_NEWNS flags to create new Process ID and Mount namespaces. This is the core of the isolation.

    pivot_root: Instead of the limited chroot, Pieces uses pivot_root to swap the entire filesystem view, creating a stable and robust container environment.

    Virtual Filesystems: It correctly mounts essential virtual filesystems like /proc, /sys, and /dev inside the container, allowing most standard Linux commands to work as expected.

    Piecefile: A simple, declarative file tells Pieces where to get the base filesystem (FROM_URL) and what default command to run (CMD).

## 📋 Prerequisites

    A Linux operating system (tested on Ubuntu).

    Python 3.6+.

    Root privileges (sudo) are required to create namespaces and manipulate filesystems.

## 🚀 Setup and Installation

    Clone the repository:

    git clone https://github.com/mradulnatani/Pieces.git
    cd Pieces


    Create a Python virtual environment (recommended):

    python3 -m venv venv
    source venv/bin/activate


    The script is ready to use! There are no external Python packages to install.

## 🛠️ Usage

Using Pieces is a two-step process: build and run.
1. Build an Image

First, you need to create an image from a Piecefile.

    Create a Piecefile in your project's root directory:

    # The recipe for our Alpine Linux container
    FROM_URL https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.3-x86_64.tar.gz

    # The default command to run when the container starts
    CMD /bin/sh


    Run the build command: The . tells Pieces to look for the Piecefile in the current directory.

    sudo python3 pieces.py build .


    This will download the Alpine rootfs and unpack it into the .pieces/images/ directory.

2. Run a Container

Once the image is built, you can run a container from it.

    To run the default command (/bin/sh from the Piecefile):

    sudo python3 pieces.py run alpine-minirootfs-3.18.3-x86_64


    To run a specific command inside the container:

    # This will run the 'ps aux' command inside the container
    sudo python3 pieces.py run alpine-minirootfs-3.18.3-x86_64 ps aux


## 📦 Building a Standalone Binary

You can package "Pieces" into a single executable file using PyInstaller. This allows you to run it on any compatible Linux system without needing a Python interpreter.

    Install PyInstaller:

    pip install pyinstaller


    Build the binary: Run this command from your project's root directory. It tells PyInstaller to bundle your main script and all the files in the src directory.

    pyinstaller --onefile --add-data 'src:src' pieces.py


    Find the executable: Your standalone binary will be located in the dist/ directory.

    ls dist/
    # Output: pieces


    Run the binary: You can now use this single file just like your script.

    sudo ./dist/pieces build .
    sudo ./dist/pieces run alpine-minirootfs-3.18.3-x86_64


## 🔮 Future Work

    Networking: Implement network namespaces to give containers their own private network stack.

    Resource Limits: Use cgroups to control the amount of CPU and memory a container can consume.

    Image Management: Add commands like pieces images to list built images and pieces rmi to remove them.
