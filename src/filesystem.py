import tarfile
import os
import urllib.request
import tempfile

def build_image_from_url(url, image_path):
 #sownloads a .tar.gz file from a URL, and unpacks it into the image_path.
    print(f"BUILD: Downloading from {url}...")
    
    #xreating destination directory for the image
    os.makedirs(image_path, exist_ok=True)

    #download the file to a temporary location
    with tempfile.NamedTemporaryFile() as tmp_tarball:
        try:
            urllib.request.urlretrieve(url, tmp_tarball.name)
        except Exception as e:
            print(f"BUILD: Failed to download file. Error: {e}")
            return False

        print(f"BUILD: Download complete. Unpacking to {image_path}...")
        
        #unpack the downloaded tarball
        try:
            with tarfile.open(tmp_tarball.name, "r:gz") as tar:
                tar.extractall(path=image_path)
        except tarfile.TarError as e:
            print(f"BUILD: Failed to unpack tarball. Error: {e}")
            return False

    print(f"BUILD: Image built successfully at {image_path}")
    return True


