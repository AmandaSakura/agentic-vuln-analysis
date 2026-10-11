import os
def inspect(path):
    selected = (0o750)
    os.chmod(path, selected)
