import os
def inspect(path):
    selected = 0 if False else 0o750
    os.chmod(path, selected)
