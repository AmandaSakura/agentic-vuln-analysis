import os
def inspect(path):
    selected = 0o772
    alias = selected
    os.chmod(path, alias)
