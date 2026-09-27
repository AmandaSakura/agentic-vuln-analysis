"""The optional witness isolation must block process replacement in its child."""

import errno
import os

from cv_agent.tools.validation.fixtures import _install_fixture_isolation


def _run_in_child(operation):
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            operation(write_fd)
        except BaseException as error:
            os.write(write_fd, f"error={type(error).__name__}:{error}".encode())
        finally:
            os._exit(0)
    os.close(write_fd)
    try:
        chunks = []
        while chunk := os.read(read_fd, 4096):
            chunks.append(chunk)
        _, status = os.waitpid(child, 0)
    finally:
        os.close(read_fd)
    assert os.waitstatus_to_exitcode(status) == 0
    return b"".join(chunks).decode()


def test_fixture_isolation_keeps_execution_allowed_by_default():
    def operation(result_fd):
        _install_fixture_isolation(result_fd)
        os.write(result_fd, b"installed")
        os.execv("/bin/true", ["/bin/true"])

    assert _run_in_child(operation) == "installed"


def test_fixture_isolation_opt_in_blocks_execve_and_execveat():
    def operation(result_fd):
        _install_fixture_isolation(result_fd, deny_exec=True)
        os.write(result_fd, b"installed")
        try:
            os.execv("/bin/true", ["/bin/true"])
        except OSError as error:
            os.write(result_fd, f" execve={error.errno}".encode())
        target_fd = os.open("/bin/true", os.O_RDONLY)
        try:
            os.execve(target_fd, ["/bin/true"], {})
        except OSError as error:
            os.write(result_fd, f" execveat={error.errno}".encode())
        finally:
            os.close(target_fd)

    assert _run_in_child(operation) == (
        f"installed execve={errno.EPERM} execveat={errno.EPERM}"
    )


def test_fixture_isolation_rejects_failed_exec_self_test():
    def operation(result_fd):
        real_execv = os.execv

        def fail_execv(path, args):
            raise OSError(errno.EACCES, "simulated unrelated execution failure")

        os.execv = fail_execv
        try:
            _install_fixture_isolation(result_fd, deny_exec=True)
        except RuntimeError:
            os.write(result_fd, b"self-test rejected")
        else:
            os.write(result_fd, b"self-test accepted")
        finally:
            os.execv = real_execv

    assert _run_in_child(operation) == "self-test rejected"
