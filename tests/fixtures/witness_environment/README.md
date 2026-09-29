The tests create two real pure Python wheels locally. Target source stays in a
fresh committed Git checkout; its wheel supplies distribution metadata only.

`kernel-runtime.lock.txt` explicitly pins ten official PyPI distributions used
by the real witness kernel bootstrap control. The hashes were retained from
existing frozen development environment locks; no package source or substitute
implementation is provided here. This integration control uses the local uv
cache in offline mode and the standard locally available Python 3.12 interpreter.
Missing cache contents cause an explicit failure, never a download or skipped
positive. Production preparation accepts its own separately hash-bound runtime
lock inputs and does not infer this fixture's package set.
