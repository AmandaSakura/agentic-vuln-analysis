import os
def inspect(path):
    selected = 0 if False else 0o772
    os.chmod(path, selected)
