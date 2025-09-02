import os

def parse_piecefile(path="Piecefile"):
    instructions = {}
    
    if not os.path.exists(path):
        print(f"Error: Piecefile not found at '{path}'")
        return None
        
    with open(path, 'r') as f:
        for line in f:
            cleaned_line = line.strip()
            
            if not cleaned_line or cleaned_line.startswith('#'):
                continue

            parts = cleaned_line.split(maxsplit=1)
            
            if len(parts) == 2:
                key, value = parts
                instructions[key.upper()] = value
    
    return instructions

