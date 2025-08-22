# In src/filesystem.py

import subprocess
import os
import shutil

def setup_container_filesystem(command_path, container_root): #finds the shared libraries for the command and will copy them in the pieces file system
    # 1 Copy the main command itself ---
    # First, create a /bin directory in our root and copy the command there.
    # This makes it so we can run commands like 'ps' instead of '/ps'.
    dest_bin_dir = os.path.join(container_root, "bin")
    os.makedirs(dest_bin_dir, exist_ok=True)
    
    # We need the command's base name (e.g., "ps" from "/bin/ps")
    command_name = os.path.basename(command_path)
    dest_command_path = os.path.join(dest_bin_dir, command_name)
    shutil.copy(command_path, dest_command_path)

    #2.Run ldd to find library paths 
    ldd_command = ["ldd", command_path]
    result = subprocess.run(ldd_command, capture_output=True, text=True)
    
    # 3.Loop through ldd output and copy libraries 
    for line in result.stdout.splitlines():
        # Look for lines with the '=>' arrow, which indicate a library path
        if "=>" not in line:
            continue

        # Using split() to break the line into parts. The library path is usually the 3rd part.
        parts = line.strip().split()
        library_path = parts[2]

        #4.Creating the destination directory inside the container
        # We need to remove the leading '/' from the library path to join it with our root.
        # For example, '/lib/x86_64-linux-gnu/libc.so.6' becomes 'lib/x86_64-linux-gnu/libc.so.6'
        relative_path = library_path.lstrip("/")
        dest_path = os.path.join(container_root, relative_path)
        
        # Create the directory if it doesn't exist 
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)

        # 5.Coping the library file
        print(f"Copying {library_path} to {dest_path}")
        shutil.copy(library_path, dest_path)

