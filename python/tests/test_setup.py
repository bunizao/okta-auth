"""okta setup and okta export, against a fake 1Password and the fake SSO."""

from __future__ import annotations

import http.client
import json
import time
from importlib import resources
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import pytest

from fake_op import install_fake_op
from fake_sso import PASSWORD, TARGET, TOTP_SECRET, USERNAME, FakeOptions, fake_sso
from okta_auth import credential_store, settings, setup_server
from okta_auth.auth import session_store
from okta_auth.core.totp import totp
from okta_auth.export import export_json, export_refusal
from okta_auth.runtime_credentials import RuntimeCredentials
from okta_auth.settings import AppSettings

ITEMS = [
    {
        "id": "bank",
        "title": "Bank",
        "vault": {"id": "v1", "name": "Private"},
        "urls": [{"href": "https://bank.example"}],
        "fields": [],
    },
    {
        "id": "okta",
        "title": "Uni",
        "vault": {"id": "v1", "name": "Private"},
        "urls": [{"href": "https://uni.okta.com"}],
        "fields": [
            {"id": "username", "purpose": "USERNAME", "value": USERNAME},
            {"id": "password", "purpose": "PASSWORD", "value": PASSWORD},
            {"id": "otp1", "type": "OTP", "value": f"otpauth://totp/x?secret={TOTP_SECRET}"},
        ],
    },
]


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Everything setup writes lands in tmp_path, never in ~/.okta-auth."""
    monkeypatch.setattr(settings, "CONFIG_PATH", tmp_path / "config.json")
    monkeypatch.setattr(settings, "DEFAULT_OP_ENV_PATH", tmp_path / "op.env")
    monkeypatch.setattr(session_store, "SESSIONS_DIR", tmp_path / "sessions")
    for name in ("OKTA_USERNAME", "OKTA_PASSWORD", "OKTA_TOTP_SECRET"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(setup_server, "keyring_name", lambda: "macOS Keychain")
    return tmp_path


@pytest.fixture
def op(monkeypatch):
    return install_fake_op(
        monkeypatch,
        {"op://v1/okta/username": USERNAME, "op://v1/okta/password": PASSWORD},
        codes={"op://v1/okta/otp1?attribute=otp": totp(TOTP_SECRET, time.time())},
        items=ITEMS,
    )


@pytest.fixture
def start(home, op):
    servers: list[setup_server.SetupServer] = []

    def start(**kwargs) -> setup_server.SetupServer:
        server = setup_server.start_setup(**kwargs)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def post(server: setup_server.SetupServer, path: str, body: object) -> httpx.Response:
    return httpx.post(server.url + path, json=body)


def raw_get(url: str, host: str) -> int:
    target = urlsplit(url)
    connection = http.client.HTTPConnection(target.hostname or "", target.port)
    connection.request("GET", target.path, headers={"Host": host})
    return connection.getresponse().status


def test_answers_only_under_its_token_and_its_own_host(start) -> None:
    server = start()
    origin = server.url.split("/", 3)[:3]
    port = urlsplit(server.url).port

    assert httpx.get(server.url).status_code == 200
    assert httpx.get("/".join(origin) + "/").status_code == 404
    assert httpx.get("/".join(origin) + "/wrong-token/").status_code == 404
    # A DNS-rebound name reaches the same socket with another Host.
    assert raw_get(server.url, f"evil.example:{port}") == 404


def test_refuses_a_post_that_isn_t_json_so_a_cross_site_form_can_t_drive_it(start) -> None:
    server = start()
    response = httpx.post(server.url + "api/done", content=b"x=1")
    assert response.status_code == 415
    assert not server.done.is_set()


def test_saves_a_1password_login_as_references_and_signs_in_with_a_code_from_1password(
    start, home, op
) -> None:
    fake = fake_sso(FakeOptions(now=time.time, totp_secret=TOTP_SECRET))
    server = start(transport=fake.transport)

    state = httpx.get(server.url + "api/state").json()
    assert state == {"cli": "okta", "provider": "keyring", "op": True, "keychain": "macOS Keychain"}
    items = httpx.get(server.url + "api/op/items").json()["items"]
    assert [item["id"] for item in items] == ["okta", "bank"]

    used = post(server, "api/op/use", {"id": "okta", "vault": "v1"}).json()
    assert used["totp"] is True
    op_env = (home / "op.env").read_text()
    assert "OKTA_TOTP_SECRET=op://v1/okta/otp1" in op_env
    assert PASSWORD not in op_env
    config = json.loads((home / "config.json").read_text())
    assert config["credential_provider"] == "op"
    assert config["op_vault"] is None and config["op_item"] is None

    stream = post(server, "api/test", {"url": TARGET}).text
    events = [json.loads(line) for line in stream.strip().splitlines()]
    assert events[-1] == {"ok": True, "host": urlsplit(TARGET).netloc, "cookies": 2}
    assert "Asking 1Password for a TOTP code" in [event.get("progress") for event in events]
    for secret in (PASSWORD, TOTP_SECRET):
        assert secret not in stream
    # The secret itself never left 1Password: only codes were read.
    assert not any(args[0] == "read" and not args[2].endswith("?attribute=otp") for args in op)


def test_saves_to_the_keychain_and_notes_a_missing_totp_secret(start, home, monkeypatch) -> None:
    saved: list[tuple[str, str, str | None]] = []
    monkeypatch.setattr(credential_store, "save_credentials", lambda *values: saved.append(values))
    server = start()

    response = post(
        server,
        "api/keychain",
        {"username": "u", "password": "p", "totpSecret": "jbsw y3dp ehpk 3pxp"},
    )
    assert response.json() == {"totp": True}
    assert saved == [("u", "p", "JBSWY3DPEHPK3PXP")]
    config = json.loads((home / "config.json").read_text())
    assert config["credential_provider"] == "keyring"

    assert post(server, "api/keychain", {"username": "u"}).status_code == 400


def test_finishes_when_the_page_says_done(start) -> None:
    server = start()
    post(server, "api/done", {})
    assert server.done.wait(5)


def test_refuses_without_the_dangerous_flag_and_refuses_a_terminal() -> None:
    assert "--dangerously-print-password-and-totp-secret" in (export_refusal(False, False) or "")
    assert "terminal" in (export_refusal(True, True) or "")
    assert export_refusal(True, False) is None


def test_prints_the_names_a_worker_reads_leaving_out_a_missing_totp_secret() -> None:
    def creds(username: str | None, password: str | None, secret: str | None = None):
        return RuntimeCredentials(username, password, secret, None, AppSettings())

    assert json.loads(export_json(creds("u", "p", "JBSWY3DPEHPK3PXP")) or "") == {
        "OKTA_USERNAME": "u",
        "OKTA_PASSWORD": "p",
        "OKTA_TOTP_SECRET": "JBSWY3DPEHPK3PXP",
    }
    assert json.loads(export_json(creds("u", "p")) or "") == {
        "OKTA_USERNAME": "u",
        "OKTA_PASSWORD": "p",
    }
    assert export_json(creds("u", None)) is None


def test_okta_export_prints_json_only_with_the_flag(home, monkeypatch, capsys) -> None:
    from okta_auth import cli

    monkeypatch.setattr(
        cli, "load_stored_credentials", lambda: credential_store.StoredCredentials()
    )
    monkeypatch.setenv("OKTA_USERNAME", "u")
    monkeypatch.setenv("OKTA_PASSWORD", "p")

    assert cli.main(["export"]) == 1
    refused = capsys.readouterr()
    assert refused.out == "" and "| npx wrangler secret bulk" in refused.err

    assert cli.main(["export", "--dangerously-print-password-and-totp-secret"]) == 0
    assert json.loads(capsys.readouterr().out) == {"OKTA_USERNAME": "u", "OKTA_PASSWORD": "p"}


TS_SETUP_PAGE = Path(__file__).resolve().parents[2] / "typescript" / "src" / "cli" / "setup.html"


@pytest.mark.skipif(not TS_SETUP_PAGE.exists(), reason="outside the monorepo checkout")
def test_serves_the_same_setup_page_as_the_typescript_cli() -> None:
    page = (resources.files("okta_auth") / "setup.html").read_bytes()
    assert page == TS_SETUP_PAGE.read_bytes()
