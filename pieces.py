import os
import sys
import ctypes #to isolate the process we need to call the systemcall unshare python os module do not have this so to communicate with the c lang we use the ctypes library
import subprocess
import shutil


#constans
libc = ctypes.CDLL("libc.so.6") #load the c librady
CONTAINER_ROOT = "/tmp/pieces-root"
CLONE_NEWPID = 0x20000000 #flag for namespace creation
CLONE_NEWNS = 0x00020000 #flag for isolation and creating a new file system

if len(sys.argv) < 2:
    print("Error: You must provide a command to run.", file=sys.stderr)
    sys.exit(1)

   # pid = os.fork() # initializes the process
#parent process setup the file system
print(f"PARENT: Setting up root filesystem at {CONTAINER_ROOT}")
os.makedirs(CONTAINER_ROOT, exist_ok=True)

command_to_run = sys.argv[1]
command_path = shutil.which(command_to_run)

if command_path is None:
    print(f"Error: Command '{command_to_run}' not found in PATH.", file=sys.stderr)
    sys.exit(1)

print(f"PARENT: Copying {command_path} into the container.")
subprocess.run(["cp", command_path, CONTAINER_ROOT])



print("PARENT: Forking child process...")
pid = os.fork()


#os.makedirs(CONTAINER_ROOT, exist_ok=True)
if pid == 0: #the value returned by the child process is always 0 and the parent process gets the child process's id
    #print("This is the child process")
    libc.unshare(CLONE_NEWPID | CLONE_NEWNS)
    os.chroot(CONTAINER_ROOT)
   # command = sys.argv[1:] #takes all arguments after the file name
    command_in_container = [f"/{os.path.basename(command_path)}"] + sys.argv[2:]
  #  os.execvp(command[0], command)
    os.execvp(command_in_container[0], command_in_container)
    print("CHILD: Error: execvp failed!", file=sys.stderr)
    sys.exit(1)

else:
    # --- PARENT PROCESS'S CODE ---
    # The parent's only remaining job is to wait for the child to finish.
    print(f"PARENT: Waiting for child process {pid} to exit.")
    os.waitpid(pid, 0)
    print("PARENT: Child process has exited.")

