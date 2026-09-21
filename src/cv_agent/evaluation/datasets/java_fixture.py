from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cv_agent.tools.identity import candidate_subject
from cv_agent.domain.evidence import ValidationSubject, ValidationStatus
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import Candidate
from cv_agent.tools.validation import FixtureCase, FixtureOutcome


CONTROLLED_TOKEN = "CV_AGENT_BOUNDARY_TOKEN_20260919"
JAVA_TIMEOUT_SECONDS = 20.0

_HELPER_SOURCES = (
    "org/owasp/benchmark/helpers/ThingInterface.java",
    "org/owasp/benchmark/helpers/ThingFactory.java",
    "org/owasp/benchmark/helpers/Thing1.java",
    "org/owasp/benchmark/helpers/Thing2.java",
)
_RESOURCE_FILES = (
    "thing.properties",
    "insecureCmd.sh",
)
_SUPPORTED_CASES = frozenset({"BenchmarkTest00827", "BenchmarkTest02244"})


@dataclass(frozen=True)
class FileDigest:
    relative_path: str
    sha256: str


@dataclass(frozen=True)
class JavaCommandValidator:
    project_root: Path
    case_id: str
    class_name: str
    subject: ValidationSubject
    files: tuple[FileDigest, ...]
    controlled_token: str = CONTROLLED_TOKEN

    @classmethod
    def build(
        cls,
        project_root: Path,
        index: RepositoryIndex,
        candidate: Candidate,
    ) -> "JavaCommandValidator":
        class_name = candidate.case_id
        if class_name not in _SUPPORTED_CASES:
            raise ValueError(f"unsupported Java command fixture case: {class_name}")
        source_path = _source_path(candidate)
        if not source_path.endswith(f"{class_name}.java"):
            raise ValueError("candidate path does not match its Java case id")
        root = project_root.resolve()
        validator = cls(
            project_root=root,
            case_id=candidate.case_id,
            class_name=class_name,
            subject=candidate_subject(index, candidate),
            files=_file_digests(root, source_path),
        )
        return validator

    def fixture_case(self) -> FixtureCase:
        return FixtureCase(
            self.case_id,
            self.run,
            timeout_seconds=JAVA_TIMEOUT_SECONDS,
            subject=self.subject,
            isolated=False,
            resource_limited=False,
        )

    def run(self) -> FixtureOutcome:
        mismatch = self._source_mismatches()
        if mismatch:
            return FixtureOutcome(
                status=ValidationStatus.UNRESOLVED,
                summary="Java command fixture source snapshot changed before execution",
                details={"mismatches": mismatch},
            )
        runtime_root = self.project_root / "artifacts/java_fixture_runtime"
        runtime_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="cv-agent-java-fixture-",
            dir=runtime_root,
        ) as workspace:
            workspace_path = Path(workspace)
            try:
                result = self._compile_and_run(workspace_path)
            except Exception as error:
                return FixtureOutcome(
                    status=ValidationStatus.UNRESOLVED,
                    summary="Java command fixture failed before process boundary evidence",
                    details={"error": f"{type(error).__name__}: {error}"},
                )
        return result

    def _source_mismatches(self) -> list[str]:
        mismatches: list[str] = []
        for item in self.files:
            path = self.project_root / item.relative_path
            if not path.is_file() or _sha256(path) != item.sha256:
                mismatches.append(item.relative_path)
        return mismatches

    def _compile_and_run(self, workspace: Path) -> FixtureOutcome:
        source_dir = workspace / "src"
        classes_dir = workspace / "classes"
        source_dir.mkdir()
        classes_dir.mkdir()
        self._write_java_sources(source_dir)
        recorder = self._compile_recorder(workspace)
        compile_result = _run(
            [
                "java",
                "-m",
                "jdk.compiler/com.sun.tools.javac.Main",
                "-d",
                str(classes_dir),
                *[str(path) for path in sorted(source_dir.rglob("*.java"))],
            ],
            cwd=workspace,
            timeout=10,
        )
        if compile_result.returncode != 0:
            return FixtureOutcome(
                status=ValidationStatus.UNRESOLVED,
                summary="Java command fixture did not compile",
                details={
                    "compiler_returncode": compile_result.returncode,
                    "compiler_stderr": _trim(compile_result.stderr),
                    "compiler_stdout": _trim(compile_result.stdout),
                },
            )
        resource_dir = self.project_root / "data/raw/BenchmarkJava/src/main/resources"
        for name in _RESOURCE_FILES:
            shutil.copy2(resource_dir / name, classes_dir / name)
        (classes_dir / "insecureCmd.sh").chmod(0o755)
        log_path = workspace / "exec.jsonl"
        output_log_path = workspace / "process-output.jsonl"
        run_env = {
            "CV_AGENT_EXEC_LOG": str(log_path),
            "HOME": str(workspace / "home"),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PATH": "/usr/bin:/bin",
        }
        if self.class_name == "BenchmarkTest02244":
            run_env["LD_PRELOAD"] = str(recorder)
        (workspace / "home").mkdir()
        marker = workspace / "payload-marker"
        token = f"{self.controlled_token}; printf owned > {marker}"
        run_result = subprocess.run(
            [
                "java",
                "-Djdk.lang.Process.launchMechanism=fork",
                "-Dcvagent.insecure.script=/usr/bin/env",
                f"-Dcvagent.process.output.log={output_log_path}",
                "-cp",
                str(classes_dir),
                "HarnessMain",
                self.class_name,
                token,
            ],
            cwd=workspace,
            env=run_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        entries = [*_read_exec_log(log_path), *_read_exec_log(output_log_path)]
        if marker.exists():
            return FixtureOutcome(
                status=ValidationStatus.UNRESOLVED,
                summary="Java command fixture payload unexpectedly executed",
                details={"marker": "created"},
            )
        if not entries:
            return FixtureOutcome(
                status=ValidationStatus.UNRESOLVED,
                summary="Java command fixture reached no process boundary",
                details=_run_details(run_result, entries, self.files),
            )
        observed = _token_occurrences(entries, self.controlled_token)
        status = (
            ValidationStatus.CONFIRMED
            if observed
            else ValidationStatus.REFUTED
        )
        summary = (
            "controlled request token reached the Java process boundary"
            if observed
            else "controlled request token did not reach the Java process boundary"
        )
        return FixtureOutcome(
            status=status,
            summary=summary,
            details={
                **_run_details(run_result, entries, self.files),
                "case_id": self.case_id,
                "controlled_token_observed": observed,
                "process_boundary_count": len(entries),
                "source_snapshot": [item.__dict__ for item in self.files],
                "stubbed_helpers": ("org/owasp/benchmark/helpers/Utils.java",),
            },
        )

    def _compile_recorder(self, workspace: Path) -> Path:
        source = self.project_root / "validation/java-command-harness/exec_recorder.c"
        output = workspace / "exec_recorder.so"
        result = _run(
            ["cc", "-shared", "-fPIC", "-O2", str(source), "-o", str(output)],
            cwd=workspace,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "native exec recorder did not compile: " + _trim(result.stderr)
            )
        return output

    def _write_java_sources(self, source_dir: Path) -> None:
        java_root = self.project_root / "data/raw/BenchmarkJava/src/main/java"
        source_path = _source_path_from_case(self.class_name)
        _copy_source(java_root / source_path, source_dir / source_path)
        for helper in _HELPER_SOURCES:
            _copy_source(java_root / helper, source_dir / helper)
        _write_text(source_dir / "javax/servlet/ServletException.java", _SERVLET_EXCEPTION)
        _write_text(source_dir / "javax/servlet/annotation/WebServlet.java", _WEB_SERVLET)
        _write_text(source_dir / "javax/servlet/http/HttpServlet.java", _HTTP_SERVLET)
        _write_text(source_dir / "javax/servlet/http/HttpServletRequest.java", _HTTP_REQUEST)
        _write_text(source_dir / "javax/servlet/http/HttpServletResponse.java", _HTTP_RESPONSE)
        _write_text(source_dir / "org/owasp/benchmark/helpers/Utils.java", _UTILS_STUB)
        _write_text(source_dir / "HarnessMain.java", _HARNESS_MAIN)


def java_command_fixture_cases(
    project_root: Path,
    index: RepositoryIndex,
    candidates: tuple[Candidate, ...],
) -> tuple[FixtureCase, ...]:
    cases: list[FixtureCase] = []
    for candidate in candidates:
        if candidate.case_id in _SUPPORTED_CASES:
            cases.append(JavaCommandValidator.build(project_root, index, candidate).fixture_case())
    return tuple(cases)


def _source_path(candidate: Candidate) -> str:
    return candidate.path.split("::", 1)[0]


def _source_path_from_case(case_id: str) -> str:
    return f"org/owasp/benchmark/testcode/{case_id}.java"


def _file_digests(root: Path, source_path: str) -> tuple[FileDigest, ...]:
    paths = [
        "validation/java-command-harness/exec_recorder.c",
        f"data/raw/BenchmarkJava/src/main/java/{source_path}",
        *[f"data/raw/BenchmarkJava/src/main/java/{name}" for name in _HELPER_SOURCES],
        *[f"data/raw/BenchmarkJava/src/main/resources/{name}" for name in _RESOURCE_FILES],
    ]
    return tuple(FileDigest(path, _sha256(root / path)) for path in paths)


def _sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


def _copy_source(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content).lstrip(), encoding="utf-8")


def _run(command: list[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def _trim(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n[trimmed]"


def _read_exec_log(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        entries.append(json.loads(line))
    return entries


def _token_occurrences(entries: list[dict[str, Any]], token: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for entry in entries:
        for field in ("argv", "envp"):
            for index, value in enumerate(entry.get(field, ())):
                if token in value:
                    matches.append({"field": field, "index": index, "value": value})
        if token in entry.get("line", ""):
            matches.append({
                "field": "line",
                "stream": entry.get("stream"),
                "value": entry["line"],
            })
    return matches


def _run_details(
    result: subprocess.CompletedProcess[str],
    entries: list[dict[str, Any]],
    files: tuple[FileDigest, ...],
) -> dict[str, Any]:
    return {
        "java_returncode": result.returncode,
        "java_stdout": _trim(result.stdout),
        "java_stderr": _trim(result.stderr),
        "exec_log": entries,
        "validated_files": [item.relative_path for item in files],
    }


_SERVLET_EXCEPTION = """
package javax.servlet;

public class ServletException extends Exception {
    public ServletException() { super(); }
    public ServletException(String message) { super(message); }
    public ServletException(Throwable cause) { super(cause); }
    public ServletException(String message, Throwable cause) { super(message, cause); }
}
"""

_WEB_SERVLET = """
package javax.servlet.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface WebServlet {
    String value();
}
"""

_HTTP_SERVLET = """
package javax.servlet.http;

import java.io.IOException;
import javax.servlet.ServletException;

public class HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {}
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {}
}
"""

_HTTP_REQUEST = """
package javax.servlet.http;

import java.util.Map;

public interface HttpServletRequest {
    String getQueryString();
    Map<String, String[]> getParameterMap();
}
"""

_HTTP_RESPONSE = """
package javax.servlet.http;

import java.io.IOException;
import java.io.PrintWriter;

public interface HttpServletResponse {
    void setContentType(String value);
    PrintWriter getWriter() throws IOException;
}
"""

_UTILS_STUB = """
package org.owasp.benchmark.helpers;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import javax.servlet.http.HttpServletResponse;

public class Utils {
    public static String getInsecureOSCommandString(ClassLoader classLoader) {
        return System.getProperty("cvagent.insecure.script");
    }

    public static void printOSCommandResults(java.lang.Process proc, HttpServletResponse response) throws IOException {
        writeProcessOutput("stdout", proc.getInputStream());
        writeProcessOutput("stderr", proc.getErrorStream());
        proc.getOutputStream().close();
        try {
            proc.waitFor();
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException(error);
        }
    }

    private static void writeProcessOutput(String stream, InputStream input) throws IOException {
        String logPath = System.getProperty("cvagent.process.output.log");
        BufferedReader reader = new BufferedReader(new InputStreamReader(input));
        if (logPath == null || logPath.isEmpty()) {
            while (reader.readLine() != null) {}
            return;
        }
        try (FileWriter writer = new FileWriter(logPath, true)) {
            writer.write("{\\"kind\\":\\"process_boundary\\",\\"stream\\":");
            writer.write(json(stream));
            writer.write(",\\"line\\":\\"\\"}\\n");
            String line;
            while ((line = reader.readLine()) != null) {
                writer.write("{\\"kind\\":\\"process_output\\",\\"stream\\":");
                writer.write(json(stream));
                writer.write(",\\"line\\":");
                writer.write(json(line));
                writer.write("}\\n");
            }
        }
    }

    private static String json(String value) {
        StringBuilder builder = new StringBuilder("\\"");
        for (int index = 0; index < value.length(); index++) {
            char ch = value.charAt(index);
            if (ch == '\\\\' || ch == '\\"') {
                builder.append('\\\\').append(ch);
            } else if (ch >= 0x20 && ch <= 0x7e) {
                builder.append(ch);
            } else {
                builder.append(String.format("\\\\u%04x", (int) ch));
            }
        }
        builder.append('\\"');
        return builder.toString();
    }
}
"""

_HARNESS_MAIN = """
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public final class HarnessMain {
    private static final class Request implements HttpServletRequest {
        private final String token;

        Request(String token) {
            this.token = token;
        }

        public String getQueryString() {
            return "vector=" + URLEncoder.encode(token, java.nio.charset.StandardCharsets.UTF_8);
        }

        public Map<String, String[]> getParameterMap() {
            return Collections.singletonMap("vector", new String[] { token });
        }
    }

    private static final class Response implements HttpServletResponse {
        private final PrintWriter writer = new PrintWriter(new StringWriter());

        public void setContentType(String value) {}

        public PrintWriter getWriter() {
            return writer;
        }
    }

    public static void main(String[] args) throws Exception {
        String className = "org.owasp.benchmark.testcode." + args[0];
        String token = args[1];
        Object servlet = Class.forName(className).getConstructor().newInstance();
        java.lang.reflect.Method method = servlet.getClass().getMethod(
            "doPost", HttpServletRequest.class, HttpServletResponse.class);
        method.invoke(servlet, new Request(token), new Response());
    }
}
"""
