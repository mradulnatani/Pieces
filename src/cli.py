import argparse

def parse_command_args():
    #Parses command-line arguments for the pieces tool.
    parser = argparse.ArgumentParser(description="Pieces: A simple containerization tool.")

    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True

    #build command
    build_parser = subparsers.add_parser('build', help='Build an image from a Piecefile.')
    build_parser.add_argument('context', help='The build context directory (containing the Piecefile).')

    #run command
    run_parser = subparsers.add_parser('run', help='Run a command in a new container from an image.')
    run_parser.add_argument('image', help='The name of the image to run (e.g., alpine-minirootfs-...).')
    
    # THE FIX: Changed nargs='+' to nargs='*' to make the command optional.
    # '*' means zero or more arguments.
    # '+' means one or more arguments.
    run_parser.add_argument('cmd_args', nargs='*', help='The command and its arguments to run inside the container.')
    
    args = parser.parse_args()
    return args

