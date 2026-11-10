"""Talks to the 1Password CLI. Errors say why op failed, never what it printed:
its output can echo a reference or a secret."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

from okta_auth.core.totp import totp

# Long enough for someone to notice 1Password's approval prompt and answer it.
TIMEOUT_SECONDS = 60

RunOp = Callable[[list[str], "str | None"], str]


class OpError(Exception):
    """`status` is op's exit status when it ran and failed; None when it never ran
    or timed out."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


def run_op(args: list[str], stdin: str | None = None) -> str:
    op_path = shutil.which("op")
    if not op_path:
        raise OpError("the op command is not installed")
    try:
        result = subprocess.run(
            [op_path, *args],
            input=stdin or "",
            check=True,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        raise OpError(f"op {args[0]} timed out after {TIMEOUT_SECONDS}s") from None
    except subprocess.CalledProcessError as error:
        raise OpError(
            f"op {args[0]} exited with status {error.returncode}", error.returncode
        ) from None
    except OSError:
        raise OpError("op could not be started") from None
    return result.stdout


def is_op_ref(value: str) -> bool:
    return value.startswith("op://")


def read_refs(refs: list[str], run: RunOp = run_op) -> list[str]:
    """Reads several references with one op call, so 1Password asks at most once."""
    if not refs:
        return []
    output = run(["inject"], "".join(f"{{{{ {ref} }}}}\n" for ref in refs))
    values = re.split(r"\r?\n", re.sub(r"\r?\n$", "", output))
    if len(values) != len(refs):
        raise OpError("op inject returned a value with a line break in it")
    return values


def read_totp_code(ref: str, now: Callable[[], float] = time.time, run: RunOp = run_op) -> str:
    """The current code of a 1Password one-time password field, so the secret never
    leaves 1Password. A field that holds a plain base32 secret has no code to give;
    for that one, read the secret and compute the code here."""
    try:
        return run(["read", "--no-newline", f"{ref}?attribute=otp"], None).strip()
    except OpError as error:
        if error.status is None:
            raise
    [value] = read_refs([ref], run)
    return totp(totp_secret_of(value), now())


def totp_secret_of(value: str) -> str:
    """A TOTP secret as a 1Password field holds it: base32, or the otpauth:// URI
    of a one-time password field."""
    text = value.strip()
    if not text.startswith("otpauth://"):
        return text
    secret = parse_qs(urlparse(text).query).get("secret", [""])[0]
    if not secret:
        raise ValueError("the TOTP field holds an otpauth:// URI without a secret")
    return secret


@dataclass
class OpItem:
    id: str
    title: str
    vault_id: str
    vault_name: str
    urls: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, object]:
        """The shape the setup page reads, the same as the TypeScript CLI's."""
        return {
            "id": self.id,
            "title": self.title,
            "vault": {"id": self.vault_id, "name": self.vault_name},
            "urls": self.urls,
        }


@dataclass
class OpItemRefs:
    username: str
    password: str
    totp: str | None = None


def list_login_items(run: RunOp = run_op) -> list[OpItem]:
    """Login items, for setup to offer. Titles and URLs only: no field values."""
    items = json.loads(run(["item", "list", "--categories", "Login", "--format", "json"], None))
    return [
        OpItem(
            id=item["id"],
            title=item.get("title") or "",
            vault_id=(item.get("vault") or {}).get("id") or "",
            vault_name=(item.get("vault") or {}).get("name") or "",
            urls=[url["href"] for url in item.get("urls") or [] if url.get("href")],
        )
        for item in items
    ]


_OKTA_HOST = re.compile(r"(^|\.)okta(preview)?\.com$")


def rank_okta_items(items: list[OpItem], okta_host: str | None = None) -> list[OpItem]:
    """Okta-looking items first: a URL on *.okta.com or *.oktapreview.com, or the
    Okta host setup already knows."""

    def score(item: OpItem) -> int:
        for href in item.urls:
            host = urlparse(href).hostname or ""
            if host == okta_host or _OKTA_HOST.search(host):
                return 0
        return 1

    return sorted(items, key=lambda item: (score(item), item.title.lower()))


def item_refs(item_id: str, vault_id: str, run: RunOp = run_op) -> OpItemRefs:
    """References to an item's username, password and one-time password fields, by
    ID so renaming the item or vault doesn't break them. The field values op
    prints are dropped right here."""
    detail = json.loads(
        run(["item", "get", item_id, "--vault", vault_id, "--format", "json"], None)
    )
    fields = [(f.get("id"), f.get("type"), f.get("purpose")) for f in detail.get("fields") or []]

    def ref(field_id: str) -> str:
        return f"op://{vault_id}/{item_id}/{field_id}"

    username = next((fid for fid, _, purpose in fields if purpose == "USERNAME"), None)
    password = next((fid for fid, _, purpose in fields if purpose == "PASSWORD"), None)
    if not username or not password:
        raise OpError("that 1Password item has no username or password field")
    otp = next((fid for fid, kind, _ in fields if kind == "OTP"), None)
    return OpItemRefs(ref(username), ref(password), ref(otp) if otp else None)
