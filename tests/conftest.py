"""Offline suite: model HTTP is mocked, only local fixture sockets are allowed."""
import ipaddress
import socket
import urllib.request

import pytest

from cv_agent.runtime import model as model_runtime


@pytest.fixture(autouse=True)
def offline_transport(monkeypatch):
    def no_http(*args, **kwargs):
        raise AssertionError("pytest forbids real model HTTP; mock the response")

    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex

    def check_address(address):
        if isinstance(address, tuple):
            host, port = address[:2]
            if host != "localhost" and not ipaddress.ip_address(host).is_loopback:
                raise AssertionError("pytest forbids external network connections")
            if port == 8317:
                raise AssertionError("pytest forbids the shared model proxy")

    def connect(sock, address):
        check_address(address)
        return original_connect(sock, address)

    def connect_ex(sock, address):
        check_address(address)
        return original_connect_ex(sock, address)

    monkeypatch.setattr(urllib.request, "urlopen", no_http)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(socket.socket, "connect_ex", connect_ex)
    # Runtime tests mock HTTP/_complete. The real gate is tested directly in
    # test_live_gate, so this seam never recursively launches pytest in pytest.
    monkeypatch.setattr(model_runtime, "require_passing_tests", lambda: None, raising=False)
