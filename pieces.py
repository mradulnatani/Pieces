import os
import sys
import ctypes #to isolate the process we need to call the systemcall unshare python os module do not have this so to communicate with the c lang we use the ctypes library
#import subprocess
import shutil
import stat
import platform

from src.cli import parse_command_args
from src.parser import parse_piecefile
from src.filesystem import build_image_from_url

#constans
libc = ctypes.CDLL("libc.so.6") #load the c librady
#CONTAINER_ROOT = "/tmp/pieces-root"
CLONE_NEWPID = 0x20000000 #flag for namespace creation
CLONE_NEWNS = 0x00020000 #flag for isolation and creating a new file system
PIECES_DIR = ".pieces"
IMAGE_DIR = os.path.join(PIECES_DIR, "images")
MS_BIND = 4096
MS_REC = 16384
MNT_DETACH = 2
MS_PRIVATE = 1 << 18 # This is the flag for a private mount

def pivot_root(new_root, put_old):
    """
    A wrapper for the pivot_root syscall.
    """
    arch = platform.machine()
    if arch == "x86_64":
        syscall_num = 155
    else:
        print(f"Error: pivot_root syscall number not known for architecture {arch}.")
        sys.exit(1)

    if libc.syscall(syscall_num, new_root.encode(), put_old.encode()) != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"pivot_root failed: {os.strerror(errno)}")

def handle_build(args):
    """Handles the 'build' command."""
    print(f"BUILD: Building from context directory: {args.context}")
    os.makedirs(IMAGE_DIR, exist_ok=True)
    piecefile_path = os.path.join(args.context, "Piecefile")
    instructions = parse_piecefile(piecefile_path)
    if not instructions or 'FROM_URL' not in instructions:
        print("BUILD: Failed to parse Piecefile or FROM_URL not found.")
        sys.exit(1)
    url = instructions['FROM_URL']
    image_name = os.path.basename(url).replace(".tar.gz", "")
    image_path = os.path.join(IMAGE_DIR, image_name)
    print(f"BUILD: Creating image '{image_name}'...")
    if os.path.exists(image_path):
        shutil.rmtree(image_path)
    success = build_image_from_url(url, image_path)
    if not success:
        print("BUILD: Image build failed.")
        sys.exit(1)

def handle_run(args):
    """Handles the 'run' command by starting a container from a pre-built image."""
    image_name = args.image
    image_path = os.path.join(IMAGE_DIR, image_name)
    if not os.path.isdir(image_path):
        print(f"Error: Image '{image_name}' not found. Did you build it first?")
        sys.exit(1)
    print(f"RUN: Starting container from image '{image_name}'...")
    pid = os.fork()
    if pid == 0:
        # --- CHILD PROCESS ---
        try:
            libc.unshare(CLONE_NEWPID | CLONE_NEWNS)
            
            # *** THE DEFINITIVE FIX IS HERE ***
            # Make all mount points in this new namespace private. This prevents
            # our mounts from affecting the host and is required for pivot_root.
            libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None)
            
            libc.mount(image_path.encode(), image_path.encode(), b"bind", MS_BIND | MS_REC, None)
            
            old_root_dir = os.path.join(image_path, "old_root")
            os.makedirs(old_root_dir, exist_ok=True)
            
            pivot_root(image_path, old_root_dir)
            
            os.chdir("/")
            libc.umount2(b"/old_root", MNT_DETACH)
            os.rmdir("/old_root")
            
            # Mount essential virtual filesystems
            os.makedirs("/proc", exist_ok=True)
            libc.mount(b"proc", b"/proc", b"proc", 0, None)
            os.makedirs("/sys", exist_ok=True)
            libc.mount(b"sysfs", b"/sys", b"sysfs", 0, None)
            os.makedirs("/dev", exist_ok=True)
            libc.mount(b"tmpfs", b"/dev", b"tmpfs", 0, None)
            os.makedirs("/dev/pts", exist_ok=True)
            libc.mount(b"devpts", b"/dev/pts", b"devpts", 0, None)
            
            # Safely create device nodes and symlinks
            if not os.path.exists("/dev/null"):
                os.mknod("/dev/null", stat.S_IFCHR | 0o666, os.makedev(1, 3))
            if not os.path.exists("/dev/zero"):
                os.mknod("/dev/zero", stat.S_IFCHR | 0o666, os.makedev(1, 5))
            if not os.path.exists("/dev/tty"):
                os.mknod("/dev/tty", stat.S_IFCHR | 0o666, os.makedev(5, 0))
            if not os.path.lexists("/dev/stdin"):
                os.symlink("/proc/self/fd/0", "/dev/stdin")
            if not os.path.lexists("/dev/stdout"):
                os.symlink("/proc/self/fd/1", "/dev/stdout")
            if not os.path.lexists("/dev/stderr"):
                os.symlink("/proc/self/fd/2", "/dev/stderr")

            command_and_args = args.cmd_args
            if not command_and_args:
                instructions = parse_piecefile("Piecefile")
                if instructions and 'CMD' in instructions:
                    command_and_args = instructions['CMD'].split()
                else:
                    command_and_args = ["/bin/sh"]
            os.execvp(command_and_args[0], command_and_args)

        except Exception as e:
            print(f"CHILD ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    else:
        # --- PARENT PROCESS ---
        os.waitpid(pid, 0)
        print(f"RUN: Container for image '{image_name}' has exited.")

def main():
    """Main entry point for the Pieces tool."""
    args = parse_command_args()
    if args.command == 'build':
        handle_build(args)
    elif args.command == 'run':
        handle_run(args)
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()


#if len(sys.argv) < 2:
  #  print("Error: You must provide a command to run.", file=sys.stderr)
 #   sys.exit(1)

   # pid = os.fork() # initializes the process
#parent process setup the file system
#print(f"PARENT: Setting up root filesystem at {CONTAINER_ROOT}")
#if os.path.exists(CONTAINER_ROOT):
   # shutil.rmtree(CONTAINER_ROOT)
#os.makedirs(CONTAINER_ROOT)
#os.makedirs(CONTAINER_ROOT, exist_ok=True)


#command_to_run = sys.argv[1]
#command_path = shutil.which(command_to_run)

#if command_path is None:
  #  print(f"Error: Command '{command_to_run}' not found in PATH.", file=sys.stderr)
 #   sys.exit(1)

#print(f"PARENT: Copying {command_path} into the container.")
#subprocess.run(["cp", command_path, CONTAINER_ROOT])
#command_in_container = setup_container_filesystem(command_path, CONTAINER_ROOT)

#if command_path is None:
  #  print(f"Error: Command '{command_to_run}' not found in PATH.", file=sys.stderr)
 #   sys.exit(1)

#this function now does all the heavy lifting and returns the correct path
# for the command *inside* the container (e.g., "/bin/ls").
#command_in_container = setup_container_filesystem(command_path, CONTAINER_ROOT)

#parent: Fork the Child 
#print("PARENT: Forking child process...")
#pid = os.fork()

#if pid == 0:
    # child process code
   # libc.unshare(CLONE_NEWPID | CLONE_NEWNS)
   # os.chroot(CONTAINER_ROOT)
   # os.chdir("/")

    #THE ACTUAL FIX
    # We now use the correct path returned by the setup function.
    # The redundant line that was causing the error has been removed.
  #  command_and_args = [command_in_container] + sys.argv[2:]

 #   os.execvp(command_and_args[0], command_and_args)
    
  #  print("CHILD: Error: execvp failed!", file=sys.stderr)
 #   sys.exit(1)

#else:
    ##parent process code
#    print(f"PARENT: Waiting for child process {pid} to exit.")
#    os.waitpid(pid, 0)
#    print("PARENT: Child process has exited.")


#print("PARENT: Forking child process...")
#pid = os.fork()


#os.makedirs(CONTAINER_ROOT, exist_ok=True)
#if pid == 0: #the value returned by the child process is always 0 and the parent process gets the child process's id
    #print("This is the child process")
#    libc.unshare(CLONE_NEWPID | CLONE_NEWNS)
#    os.chroot(CONTAINER_ROOT)
   # command = sys.argv[1:] #takes all arguments after the file name
#    command_in_container = [f"/{os.path.basename(command_path)}"] + sys.argv[2:]
  #  os.execvp(command[0], command)
#    os.execvp(command_in_container[0], command_in_container)
#    print("CHILD: Error: execvp failed!", file=sys.stderr)
#    sys.exit(1)

#else:
    # --- PARENT PROCESS'S CODE ---
    # The parent's only remaining job is to wait for the child to finish.
 #   print(f"PARENT: Waiting for child process {pid} to exit.")
 #   os.waitpid(pid, 0)
 #   print("PARENT: Child process has exited.")

