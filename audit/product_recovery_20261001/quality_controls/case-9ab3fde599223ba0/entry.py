import os
def inspect(path):
    selected = 0o772
    os.chmod(path, selected)
