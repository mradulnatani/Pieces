import subprocess

def run_cmd(cmd):
    # a simple wrapper to run on the terminal
    print(f"HOST: Running command: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

def setup_host_network():
    bridge_name = "pieces-br0"
    bridge_ip = "10.0.0.1/24"
    result = subprocess.run(["ip", "link", "show", bridge_name], capture_output=True) #ip command returns 0 on success and non zero values on failure
    if result.returncode==0:
        print(f"HOST: Bridge '{bridge_name}' already exists. Skipping creation.")
        return
    print(f"HOST: Creating bridge '{bridge_name}' and setting its IP to {bridge_ip}.")
    # create a bridge device
    run_cmd(["ip", "link", "add", "name", bridge_name, "type", "bridge"])
    #assign ip address to the new interface
    run_cmd(["ip", "addr", "add", bridge_ip, "dev", bridge_name])
    #brings the bridge online
    run_cmd(["ip", "link", "set", bridge_name, "up"])

