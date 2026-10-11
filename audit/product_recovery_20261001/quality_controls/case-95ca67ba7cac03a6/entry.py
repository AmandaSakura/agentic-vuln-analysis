import os
def inspect(path):
    selected = 0o750
    alias = selected
    os.chmod(path, alias)
