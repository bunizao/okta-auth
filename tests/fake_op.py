"""A stand-in for the 1Password CLI behind subprocess.run, for tests."""

from __future__ import annotations

import json
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
    items: list[dict[str, Any]] | None = None,
) -> list[list[str]]:
    """Answers `op inject` from `values`, `op read <ref>?attribute=otp` from
    `codes`, and `op item list` and `op item get` from `items` (as op prints
    them, with `fields`). `fail` makes every call exit 1, with output that must never reach the
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
        if cmd[1] == "--version":
            return subprocess.CompletedProcess(cmd, 0, stdout="2.30.0\n", stderr="")
        if cmd[1:3] == ["item", "list"]:
            listed = [{k: v for k, v in item.items() if k != "fields"} for item in items or []]
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(listed), stderr="")
        if cmd[1:3] == ["item", "get"]:
            item = next(item for item in items or [] if item["id"] == cmd[3])
            return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(item), stderr="")
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
