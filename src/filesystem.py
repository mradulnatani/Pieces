import tarfile
import os
import urllib.request
import tempfile
import json
import sys

# --- The "Shopping List" of Known Good Images ---
# We can easily add more distributions here in the future.
KNOWN_IMAGES = {
    "alpine:3.18": "https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.3-x86_64.tar.gz",
    "fedora:38": "https://archives.fedoraproject.org/pub/fedora/linux/releases/38/Container/x86_64/images/Fedora-Container-Base-38-1.6.x86_64.tar.gz",
    "ubuntu:22.04": "https://cdimage.ubuntu.com/ubuntu-base/releases/22.04/release/ubuntu-base-22.04.4-base-amd64.tar.gz"
}

def _show_progress(block_num, block_size, total_size):
    """A simple helper function to show download progress."""
    downloaded = block_num * block_size
    percent = (downloaded / total_size) * 100
    # Use carriage return to print on the same line
    sys.stdout.write(f"\rBUILD: Downloading... {percent:.1f}%")
    sys.stdout.flush()

def build_image(instructions, image_path):
    """
    Builds a container image by downloading and unpacking a root filesystem.
    This is a "smart" function that can handle both `FROM` and `FROM_URL`.
    """
    url = ""
    if 'FROM' in instructions:
        from_tag = instructions['FROM']
        if from_tag in KNOWN_IMAGES:
            url = KNOWN_IMAGES[from_tag]
        else:
            print(f"BUILD: Error: Unknown image tag '{from_tag}'.")
            return False
    elif 'FROM_URL' in instructions:
        url = instructions['FROM_URL']
    else:
        # This case should be caught by pieces.py, but we'll be safe
        return False
        
    print(f"BUILD: Downloading from {url}...")
    
    with tempfile.NamedTemporaryFile() as tmp_tarball:
        try:
            urllib.request.urlretrieve(url, tmp_tarball.name, _show_progress)
            # Print a newline to move past the progress bar
            print() 
        except Exception as e:
            print(f"\nBUILD: Failed to download file. Error: {e}")
            return False

        print(f"BUILD: Download complete. Unpacking to {image_path}...")
        
        try:
            with tarfile.open(tmp_tarball.name, "r:gz") as tar:
                tar.extractall(path=image_path)
        except tarfile.TarError as e:
            print(f"BUILD: Failed to unpack tarball. Error: {e}")
            return False
    
    # Save the CMD from the Piecefile as metadata inside the image
    metadata = {}
    if 'CMD' in instructions:
        metadata['cmd'] = instructions['CMD']
    
    metadata_path = os.path.join(image_path, ".pieces_meta.json")
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f)

    print(f"BUILD: Image built successfully at {image_path}")
    return True


