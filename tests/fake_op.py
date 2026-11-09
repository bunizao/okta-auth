"""A stand-in for the 1Password CLI behind subprocess.run, for tests."""

from __future__ import annotations

import re
import subprocess
from typing import Any

from okta_auth import onepassword


def install_fake_op(
    monkeypatch: Any,
    values: dict[str, str],
    *,
    fail: bool = False,
    codes: dict[str, str] | None = None,
) -> list[list[str]]:
    """Answers `op inject` from `values` and `op read <ref>?attribute=otp` from
    `codes`. `fail` makes every call exit 1, with output that must never reach the
    user. Returns the op arguments of each call."""
    calls: list[list[str]] = []
    monkeypatch.setattr(onepassword.shutil, "which", lambda command: "/usr/local/bin/op")

    def fake_run(
        cmd: list[str], *, input: str, check: bool, capture_output: bool, text: bool, timeout: int
    ) -> Any:
        assert cmd[0] == "/usr/local/bin/op" and check and capture_output and text
        assert timeout == 20
        calls.append(cmd[1:])
        if fail:
            raise subprocess.CalledProcessError(1, cmd, output="", stderr="op: dismissed")
        if cmd[1] == "inject":
            refs = re.findall(r"\{\{ (.+?) \}\}", input)
            return subprocess.CompletedProcess(
                cmd, 0, stdout="".join(f"{values[r]}\n" for r in refs), stderr=""
            )
        if cmd[1] == "read" and cmd[3] in (codes or {}):
            return subprocess.CompletedProcess(cmd, 0, stdout=(codes or {})[cmd[3]], stderr="")
        raise subprocess.CalledProcessError(1, cmd, output="", stderr="op: no such field")

    monkeypatch.setattr(onepassword.subprocess, "run", fake_run)
    return calls
