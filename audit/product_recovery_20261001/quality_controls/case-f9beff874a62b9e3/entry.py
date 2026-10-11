import os
def inspect(path, flag):
    mode = 0o750 if flag else 0o772
    os.chmod(path, mode)
