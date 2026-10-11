import os
@unregistered_wrapper
def inspect(path):
    os.chmod(path, 0o750)
