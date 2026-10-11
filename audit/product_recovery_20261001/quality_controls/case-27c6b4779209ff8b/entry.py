import os
def inspect(path):
    mode = unknown_mode()
    os.chmod(path, mode)
