"""Tool runner and registry tests using throwaway local scripts (no network, no real tools)."""

from __future__ import annotations

import stat
import sys
import time

import pytest

from app.tools import TOOLS_BY_NAME, ToolSpec, detect, run_tool
from app.tools.registry import ToolMode


def _script(tmp_path, name: str, body: str):
    path = tmp_path / name
    path.write_text(f"#!{sys.executable}\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return path


async def test_run_captures_output_and_exit_code(tmp_path):
    exe = _script(tmp_path, "t", "import sys; print('out'); print('err', file=sys.stderr); sys.exit(3)")
    run = await run_tool("t", [str(exe)], timeout=10)
    assert run.exit_code == 3 and not run.ok
    assert run.stdout.strip() == "out" and run.stderr.strip() == "err"
    assert run.argv == [str(exe)] and run.duration_s >= 0


async def test_run_does_not_use_a_shell(tmp_path):
    exe = _script(tmp_path, "echoargs", "import sys; print(sys.argv[1])")
    run = await run_tool("echoargs", [str(exe), "$(id); `id` | id"], timeout=10)
    assert run.ok and run.stdout.strip() == "$(id); `id` | id"


async def test_run_timeout_kills_process_group(tmp_path):
    marker = tmp_path / "child-alive"
    child = _script(tmp_path, "child", f"import time; time.sleep(3); open({str(marker)!r}, 'w').close()")
    exe = _script(tmp_path, "slow", f"import subprocess, time; subprocess.Popen([{str(child)!r}]); time.sleep(30)")
    t0 = time.monotonic()
    run = await run_tool("slow", [str(exe)], timeout=0.5)
    assert run.timed_out and run.exit_code is None and not run.ok
    assert time.monotonic() - t0 < 5
    time.sleep(3.5)
    assert not marker.exists(), "child process survived the timeout"


async def test_run_caps_output(tmp_path):
    exe = _script(tmp_path, "loud", "import sys; sys.stdout.write('x' * 500000)")
    run = await run_tool("loud", [str(exe)], timeout=10, max_output=1000)
    assert run.ok and len(run.stdout) == 1000 and run.stdout_truncated


async def test_run_missing_binary_is_recorded_not_raised(tmp_path):
    run = await run_tool("ghost", [str(tmp_path / "nope")], timeout=5)
    assert run.exit_code is None and run.error and "FileNotFoundError" in run.error


async def test_detect_reads_version_from_binary(tmp_path, monkeypatch):
    _script(tmp_path, "fakescan", "print('Fake Scanner version 7.95 ( https://example.org )')")
    monkeypatch.setenv("PATH", str(tmp_path))
    spec = ToolSpec(name="fake", display="Fake", stage="S3", modes=[ToolMode.ACTIVE], purpose="t",
                    license="MIT", homepage="https://example.org", binaries=["missing-first", "fakescan"])
    status = await detect(spec)
    assert status.available and status.version == "7.95" and status.location.endswith("fakescan")


async def test_detect_version_on_stderr(tmp_path, monkeypatch):
    _script(tmp_path, "nuclei", "import sys; print('[INF] Nuclei Engine Version: v3.3.7', file=sys.stderr)")
    monkeypatch.setenv("PATH", str(tmp_path))
    status = await detect(TOOLS_BY_NAME["nuclei"])
    assert status.available and status.version == "3.3.7"


async def test_detect_missing_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", str(tmp_path))
    status = await detect(TOOLS_BY_NAME["nmap"])
    assert not status.available and "nmap" in status.detail


async def test_detect_zap_unreachable(monkeypatch):
    monkeypatch.setenv("WAPTRIX_ZAP_URL", "http://127.0.0.1:9")
    status = await detect(TOOLS_BY_NAME["zap"])
    assert not status.available and "not reachable" in status.detail


def test_every_active_capable_tool_is_flagged():
    for name in ("nmap", "nuclei", "nikto", "wapiti", "sqlmap"):
        assert TOOLS_BY_NAME[name].modes == [ToolMode.ACTIVE]


@pytest.mark.parametrize("name", ["whatweb", "sslyze", "testssl", "retire"])
def test_passive_tools_are_passive_only(name):
    assert TOOLS_BY_NAME[name].modes == [ToolMode.PASSIVE]
