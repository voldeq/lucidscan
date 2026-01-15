"""Subprocess runner with streaming support.

Provides utilities for running external tools with real-time output streaming.
"""

from __future__ import annotations

import queue
import subprocess
import threading
from pathlib import Path
from typing import List, Optional, Union

from lucidscan.core.streaming import (
    NullStreamHandler,
    StreamEvent,
    StreamHandler,
    StreamType,
)


def run_with_streaming(
    cmd: List[str],
    cwd: Union[str, Path],
    tool_name: str,
    stream_handler: Optional[StreamHandler] = None,
    timeout: int = 120,
    capture_output: bool = True,
) -> subprocess.CompletedProcess:
    """Run a command with optional streaming output.

    This function runs a subprocess and optionally streams its output
    line-by-line to a StreamHandler. When streaming is enabled, output
    is still captured and returned in the CompletedProcess for parsing.

    Args:
        cmd: Command and arguments to run.
        cwd: Working directory for the command.
        tool_name: Name of the tool (used in stream events).
        stream_handler: Handler for streaming output. If None or NullStreamHandler,
            uses regular subprocess.run for efficiency.
        timeout: Timeout in seconds (default: 120).
        capture_output: Whether to capture output (default: True). If False and
            streaming is enabled, output goes only to the stream handler.

    Returns:
        CompletedProcess with stdout/stderr captured (if capture_output=True).

    Raises:
        subprocess.TimeoutExpired: If the command times out.
        subprocess.SubprocessError: If the command fails to start.
    """
    handler = stream_handler or NullStreamHandler()
    cwd_str = str(cwd)

    # If no streaming requested, use simple subprocess.run for efficiency
    if isinstance(handler, NullStreamHandler):
        return subprocess.run(
            cmd,
            capture_output=capture_output,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd_str,
            timeout=timeout,
        )

    # Streaming mode with Popen
    handler.start_tool(tool_name)

    stdout_lines: List[str] = []
    stderr_lines: List[str] = []

    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=cwd_str,
        ) as proc:
            # Use a queue to collect output from both streams
            output_queue: queue.Queue = queue.Queue()

            def read_stream(
                stream,
                stream_type: StreamType,
                lines_list: List[str],
            ) -> None:
                """Read lines from a stream and put them in the queue."""
                try:
                    for line_num, line in enumerate(stream, 1):
                        line = line.rstrip("\n\r")
                        lines_list.append(line)
                        output_queue.put((stream_type, line, line_num))
                except Exception:
                    pass
                finally:
                    # Signal EOF for this stream
                    output_queue.put((stream_type, None, None))

            # Start reader threads for stdout and stderr
            stdout_thread = threading.Thread(
                target=read_stream,
                args=(proc.stdout, StreamType.STDOUT, stdout_lines),
                daemon=True,
            )
            stderr_thread = threading.Thread(
                target=read_stream,
                args=(proc.stderr, StreamType.STDERR, stderr_lines),
                daemon=True,
            )

            stdout_thread.start()
            stderr_thread.start()

            # Process output as it arrives
            streams_closed = 0
            while streams_closed < 2:
                try:
                    stream_type, line, line_num = output_queue.get(timeout=timeout)
                    if line is None:
                        streams_closed += 1
                    else:
                        handler.emit(
                            StreamEvent(
                                tool_name=tool_name,
                                stream_type=stream_type,
                                content=line,
                                line_number=line_num,
                            )
                        )
                except queue.Empty:
                    # Timeout waiting for output
                    proc.kill()
                    handler.end_tool(tool_name, False)
                    raise subprocess.TimeoutExpired(cmd, timeout)

            # Wait for reader threads to finish
            stdout_thread.join(timeout=1)
            stderr_thread.join(timeout=1)

            # Wait for process to complete
            proc.wait()

            success = proc.returncode == 0
            handler.end_tool(tool_name, success)

            # Return CompletedProcess with captured output
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=proc.returncode,
                stdout="\n".join(stdout_lines) if capture_output else "",
                stderr="\n".join(stderr_lines) if capture_output else "",
            )

    except subprocess.TimeoutExpired:
        handler.end_tool(tool_name, False)
        raise
    except Exception as e:
        handler.end_tool(tool_name, False)
        raise subprocess.SubprocessError(f"Failed to run {tool_name}: {e}") from e
