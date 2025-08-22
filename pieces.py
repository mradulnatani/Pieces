import os
import sys


if len(sys.argv) < 2:
    print("Error: You must provide a command to run.", file=sys.stderr)
    sys.exit(1)
pid = os.fork() # initializes the process
if pid == 0: #the value returned by the child process is always 0 and the parent process gets the child process's id
    #print("This is the child process")
    command = sys.argv[1:] #takes all arguments after the file name
    os.execvp(command[0], command)
else:
   # print("This is the parent process")
    os.waitpid(pid,0)
