import os
def inspect(path, flag):
    if flag:
        os.chmod(path, 0o750)
