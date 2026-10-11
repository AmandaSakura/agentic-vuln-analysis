import os
def inspect(path, items):
    for item in items:
        os.chmod(path, item)
