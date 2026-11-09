"""`okta setup`: a page on 127.0.0.1 that walks through choosing where the
credentials live and trying a sign-in. The TypeScript CLI serves the same page
with the same API. Only someone holding the URL's random token gets an answer,
and only under the exact Host the server listens on, so neither another site nor
a DNS-rebound name can drive it."""

from __future__ import annotations

import asyncio
import json
import secrets
import subprocess
import sys
import threading
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import Any
from urllib.parse import urlsplit

import httpx

from okta_auth import credential_store, onepassword, settings
from okta_auth.auth.login import perform_login
from okta_auth.credential_store import CredentialStoreError, StoredCredentials
from okta_auth.onepassword import OpError
from okta_auth.runtime_credentials import resolve_credentials

MAX_BODY = 64 * 1024
HEADERS = {
    "Cache-Control": "no-store",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
        "connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; "
        "frame-ancestors 'none'"
    ),
}


class InputError(ValueError):
    """Something the person typed on the page, said back to them as is."""


class SetupServer:
    def __init__(self, server: ThreadingHTTPServer, token: str, done: threading.Event) -> None:
        self._server = server
        self.url = f"http://127.0.0.1:{server.server_address[1]}/{token}/"
        self.done = done

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def keyring_name() -> str | None:
    """What the page calls the OS credential store, or None without one."""
    if not credential_store.get_store_status()["available"]:
        return None
    return "macOS Keychain" if sys.platform == "darwin" else "system keyring"


def start_setup(
    *,
    cli: str = "okta",
    transport: httpx.AsyncBaseTransport | None = None,
) -> SetupServer:
    """Serves the setup page on a thread until close(); `done` is set when the page
    says it's finished. `transport` is for tests."""
    token = secrets.token_urlsafe(24)
    page = (resources.files("okta_auth") / "setup.html").read_bytes()
    done = threading.Event()

    def state(_: dict[str, Any], __: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        try:
            onepassword.run_op(["--version"])
            has_op = True
        except OpError:
            has_op = False
        name = keyring_name()
        return {
            "cli": cli,
            "provider": settings.load_settings().credential_provider,
            "op": has_op,
            "keychain": name or False,
        }

    def op_items(_: dict[str, Any], __: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        items = onepassword.rank_okta_items(onepassword.list_login_items())
        return {"items": [item.to_json() for item in items]}

    def op_use(body: dict[str, Any], _: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        item_id, vault = _text(body.get("id")), _text(body.get("vault"))
        if not item_id or not vault:
            raise InputError("choose a 1Password item")
        refs = onepassword.item_refs(item_id, vault)
        env_file = settings.save_op_refs(refs.username, refs.password, refs.totp)
        return {"file": str(env_file), "totp": refs.totp is not None}

    def keychain(body: dict[str, Any], _: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        username, password = _text(body.get("username")), _text(body.get("password"))
        if not username or not password:
            raise InputError("enter a username and password")
        totp = _text(body.get("totpSecret"))
        totp_secret = "".join(totp.split()).upper() if totp else None
        credential_store.save_credentials(username, password, totp_secret)
        settings.save_provider("keyring")
        return {"totp": totp_secret is not None}

    def test(body: dict[str, Any], send: Callable[[dict[str, Any]], None]) -> None:
        url = _text(body.get("url"))
        if not url or urlsplit(url).scheme != "https" or not urlsplit(url).hostname:
            raise InputError("enter an https:// URL")
        send({})  # starts the NDJSON stream; see Handler._route
        asyncio.run(_test_sign_in(url, send, transport))

    def finish(_: dict[str, Any], __: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        done.set()
        return {}

    routes: dict[str, Callable[[dict[str, Any], Callable[[dict[str, Any]], None]], Any]] = {
        "GET /api/state": state,
        "GET /api/op/items": op_items,
        "POST /api/op/use": op_use,
        "POST /api/keychain": keychain,
        "POST /api/test": test,
        "POST /api/done": finish,
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            self._handle()

        def do_POST(self) -> None:
            self._handle()

        def log_message(self, format: str, *args: Any) -> None:
            # The default log prints request paths, which carry the token.
            pass

        def _handle(self) -> None:
            prefix = f"/{token}"
            path = self.path.split("?", 1)[0]
            port = server.server_address[1]
            if self.headers.get("Host") != f"127.0.0.1:{port}" or (
                path != prefix and not path.startswith(f"{prefix}/")
            ):
                return self._reply(404)
            if path == prefix:
                return self._reply(302, extra={"Location": f"{prefix}/"})
            sub = path[len(prefix) :] or "/"
            if self.command == "GET" and sub == "/":
                return self._reply(200, page, "text/html; charset=utf-8")
            route = routes.get(f"{self.command} {sub}")
            if route is None:
                return self._reply(404)
            body: dict[str, Any] = {}
            if self.command == "POST":
                # A cross-site form can't send JSON with this content type.
                if self.headers.get("Content-Type") != "application/json":
                    return self._reply(415)
                try:
                    body = self._read_json()
                except InputError as error:
                    return self._json(400, {"code": "input", "message": str(error)})
            self._route(route, body)

        def _route(self, route: Callable[..., Any], body: dict[str, Any]) -> None:
            streaming = False

            # One JSON object per line, so the page can show each step as it
            # happens. The first send (an empty object) only opens the stream.
            def send(event: dict[str, Any]) -> None:
                nonlocal streaming
                if not streaming:
                    streaming = True
                    self._head(200, "application/x-ndjson")
                if event:
                    self.wfile.write(json.dumps(event).encode() + b"\n")
                    self.wfile.flush()

            try:
                result = route(body, send)
            except Exception as error:  # noqa: BLE001 - describe() keeps it safe to show
                if streaming:
                    send({"ok": False, **describe(error)})
                else:
                    self._json(400, describe(error))
                return
            if not streaming:
                self._json(200, result)

        def _read_json(self) -> dict[str, Any]:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                raise InputError("request too large")
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                raise InputError("expected a JSON object") from None
            if not isinstance(data, dict):
                raise InputError("expected a JSON object")
            return data

        def _head(
            self, status: int, content_type: str | None, extra: dict[str, str] | None = None
        ) -> None:
            self.send_response(status)
            for name, value in {**HEADERS, **(extra or {})}.items():
                self.send_header(name, value)
            if content_type:
                self.send_header("Content-Type", content_type)
            self.end_headers()

        def _reply(
            self,
            status: int,
            content: bytes = b"",
            content_type: str | None = None,
            extra: dict[str, str] | None = None,
        ) -> None:
            self._head(status, content_type, {**(extra or {}), "Content-Length": str(len(content))})
            self.wfile.write(content)

        def _json(self, status: int, data: Any) -> None:
            self._reply(status, json.dumps(data).encode(), "application/json")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return SetupServer(server, token, done)


async def _test_sign_in(
    url: str,
    send: Callable[[dict[str, Any]], None],
    transport: httpx.AsyncBaseTransport | None,
) -> None:
    def progress(message: str) -> None:
        send({"progress": message})

    stored = settings.load_settings()
    credentials = resolve_credentials(
        app_settings=stored,
        stored_credentials=(
            credential_store.load_credentials()
            if settings.uses_keyring(stored)
            else StoredCredentials()
        ),
        progress=progress,
    )
    if not credentials.username or not credentials.password:
        raise InputError("no username or password saved yet")
    result = await perform_login(
        url,
        credentials.username,
        credentials.password,
        credentials.totp_secret,
        totp_code=credentials.totp_code(progress),
        transport=transport,
        progress=progress,
    )
    if result["success"]:
        send({"ok": True, "host": result["domain_key"], "cookies": result["cookie_count"]})
        return
    code = result.get("error_code") or "input"
    message = str(result["message"]).removeprefix("Login failed: ").removeprefix(f"{code}: ")
    send({"ok": False, "code": code, "message": message})


def describe(error: BaseException) -> dict[str, str]:
    """What the page may show about a failure. These errors are written to be safe
    to show; anything else is summarised."""
    if isinstance(error, OpError):
        return {"code": "1password", "message": str(error)}
    if isinstance(error, InputError):
        return {"code": "input", "message": str(error)}
    if isinstance(error, CredentialStoreError):
        return {"code": "keychain", "message": "could not save to the system keyring"}
    # The type only: the message of an unknown error may hold a secret.
    print(f"okta setup: unexpected {type(error).__name__}", file=sys.stderr)
    return {
        "code": "unexpected",
        "message": "something went wrong; the terminal running okta setup may say more",
    }


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def open_browser(url: str) -> None:
    try:
        webbrowser.open(url)
    except (webbrowser.Error, subprocess.SubprocessError, OSError):
        pass
