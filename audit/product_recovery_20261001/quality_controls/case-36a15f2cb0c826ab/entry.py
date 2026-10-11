import os
def inspect(path):
    try:
        os.chmod(path, 0o750)
    except Exception:
        return None
