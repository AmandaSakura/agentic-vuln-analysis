import os
def inspect(path):
    selected = 0o772 if True else 0
    os.chmod(path, selected)
