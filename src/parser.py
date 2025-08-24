import os

def parse_piecefile(path="Piecefile"):
    instructions = {}
    
    # Handle the case if the file doesn't exist.
    if not os.path.exists(path):
        print(f"Error: Piecefile not found at '{path}'")
        return None
        
    # Opens the file safely.
    with open(path, 'r') as f:
        #  Loops through each line.
        for line in f:
            #cleaning of the code
            cleaned_line = line.strip()
            
            #ignore empty line and comments
            if not cleaned_line or cleaned_line.startswith('#'):
                continue

            #splitting into a key and a value.
            parts = cleaned_line.split(maxsplit=1)
            
            #making sure that the line has both a key and a value.
            if len(parts) == 2:
                key, value = parts
                #store the instruction.
                instructions[key.upper()] = value
    
    return instructions

