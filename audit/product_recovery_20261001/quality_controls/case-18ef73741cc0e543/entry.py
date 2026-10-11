import os
def inspect(path):
    selected = 0o750 if True else 0
    os.chmod(path, selected)
