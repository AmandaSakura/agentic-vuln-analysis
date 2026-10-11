"""Call the public entrypoint while counting and refusing any network/live gate."""
import builtins
import json
import socket
import sys
import urllib.request


COUNTS = {"http_attempts": 0, "socket_attempts": 0, "live_gate_attempts": 0}


def refuse_http(*args, **kwargs):
    COUNTS["http_attempts"] += 1
    raise AssertionError("Offline product attempted HTTP")


def refuse_socket(*args, **kwargs):
    COUNTS["socket_attempts"] += 1
    raise AssertionError("Offline product attempted a network connection")


def refuse_live_gate():
    COUNTS["live_gate_attempts"] += 1
    raise AssertionError("Offline product attempted live admission")


urllib.request.urlopen = refuse_http
socket.socket.connect = refuse_socket
socket.create_connection = refuse_socket
original_import = builtins.__import__


def source_only_import(name, *args, **kwargs):
    if name.startswith("cv_agent.evaluation"):
        raise AssertionError("Offline product imported evaluation")
    return original_import(name, *args, **kwargs)


builtins.__import__ = source_only_import
from cv_agent.runtime import admission
admission.require_passing_tests = refuse_live_gate  # A denying offline mock, never approval.
from cv_agent.cli import main

exit_code = main()
if any(COUNTS.values()):
    raise AssertionError(COUNTS)
print(json.dumps({"offline_transport_audit": COUNTS}), file=sys.stderr)
raise SystemExit(exit_code)
