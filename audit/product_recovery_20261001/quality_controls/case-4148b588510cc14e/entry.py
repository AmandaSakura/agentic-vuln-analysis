import os
def inspect(path, item):
    os.chmod(path, item.mode)
