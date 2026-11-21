"""Run an external tool as a subprocess: no shell, hard timeout, capped output, full record kept."""

from __future__ import annotations

import asyncio
import os
import signal
import time
from datetime import datetime, timezone

from pydantic import BaseModel, Field

DEFAULT_MAX_OUTPUT = 4 * 1024 * 1024  # per stream
_CHUNK = 64 * 1024


class ToolRun(BaseModel):
    """Record of one tool invocation, kept as evidence."""

    tool: str
    argv: list[str]
    started_at: datetime
    duration_s: float
    exit_code: int | None = Field(description="None when the process was killed or never started")
    timed_out: bool = False
    error: str | None = Field(default=None, description="Why the process could not run, if it did not")
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.error is None and not self.timed_out and self.exit_code == 0


async def _read_capped(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    """Read a stream to EOF, keeping at most `limit` bytes and draining the rest."""
    kept = bytearray()
    truncated = False
    while chunk := await stream.read(_CHUNK):
        room = limit - len(kept)
        if room > 0:
            kept += chunk[:room]
        if len(chunk) > room:
            truncated = True
    return bytes(kept), truncated


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


async def run_tool(
    tool: str,
    argv: list[str],
    *,
    timeout: float,
    max_output: int = DEFAULT_MAX_OUTPUT,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> ToolRun:
    """Execute `argv` directly (never through a shell) and return its full record.

    The process runs in its own process group so a timeout kills any children it spawned.
    """
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()

    def record(**kwargs) -> ToolRun:
        return ToolRun(tool=tool, argv=argv, started_at=started, duration_s=round(time.monotonic() - t0, 3), **kwargs)

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**os.environ, **(env or {})},
            cwd=cwd,
            start_new_session=True,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return record(exit_code=None, error=f"{type(exc).__name__}: {exc}")

    reader = asyncio.gather(_read_capped(proc.stdout, max_output), _read_capped(proc.stderr, max_output))
    timed_out = False
    try:
        (out, out_trunc), (err, err_trunc) = await asyncio.wait_for(asyncio.shield(reader), timeout)
        await proc.wait()
    except asyncio.TimeoutError:
        timed_out = True
        _kill_group(proc)
        await proc.wait()
        (out, out_trunc), (err, err_trunc) = await reader
    except asyncio.CancelledError:
        _kill_group(proc)
        await proc.wait()
        reader.cancel()
        raise

    return record(
        exit_code=None if timed_out else proc.returncode,
        timed_out=timed_out,
        stdout=out.decode("utf-8", "replace"),
        stderr=err.decode("utf-8", "replace"),
        stdout_truncated=out_trunc,
        stderr_truncated=err_trunc,
    )
