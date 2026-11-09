from __future__ import annotations

import json

import pytest

from fake_op import install_fake_op
from okta_auth import onepassword
from okta_auth.core.totp import totp
from okta_auth.onepassword import OpError, OpItem
from okta_auth.runtime_credentials import resolve_credentials
from okta_auth.settings import AppSettings

SECRET = "JBSWY3DPEHPK3PXP"
REFS = {
    "OKTA_USERNAME": "op://Private/Okta/username",
    "OKTA_PASSWORD": "op://Private/Okta/password",
    "OKTA_TOTP_SECRET": "op://Private/Okta/one-time password",
}
NOW = 1793588645.0


@pytest.fixture
def op_settings(tmp_path, monkeypatch) -> AppSettings:
    env_file = tmp_path / "op.env"
    env_file.write_text("".join(f"{key}={value}\n" for key, value in REFS.items()))
    for name in REFS:
        monkeypatch.delenv(name, raising=False)
    return AppSettings(credential_provider="op", op_env_file=str(env_file))


def test_reads_the_username_and_password_with_one_op_call_and_leaves_the_totp_secret_in_1password(
    monkeypatch, op_settings
) -> None:
    calls = install_fake_op(
        monkeypatch,
        {REFS["OKTA_USERNAME"]: "abcd0001", REFS["OKTA_PASSWORD"]: "hunter2"},
    )
    messages: list[str] = []

    credentials = resolve_credentials(app_settings=op_settings, progress=messages.append)

    assert (credentials.username, credentials.password) == ("abcd0001", "hunter2")
    assert credentials.totp_secret is None
    assert credentials.totp_ref == REFS["OKTA_TOTP_SECRET"]
    assert [call[0] for call in calls] == ["inject"]
    assert messages == [
        "Reading the username and password from 1Password (approve it there if asked)"
    ]


def test_reads_the_totp_secret_too_when_asked_out_of_an_otpauth_uri(
    monkeypatch, op_settings
) -> None:
    install_fake_op(
        monkeypatch,
        {
            REFS["OKTA_USERNAME"]: "abcd0001",
            REFS["OKTA_PASSWORD"]: "hunter2",
            REFS["OKTA_TOTP_SECRET"]: f"otpauth://totp/Okta:abcd0001?secret={SECRET}&issuer=Okta",
        },
    )

    credentials = resolve_credentials(app_settings=op_settings, read_totp_secret=True)

    assert credentials.totp_secret == SECRET
    assert credentials.totp_ref is None


def test_lets_the_environment_win_over_1password(monkeypatch, op_settings) -> None:
    calls = install_fake_op(monkeypatch, {REFS["OKTA_USERNAME"]: "abcd0001"})
    monkeypatch.setenv("OKTA_PASSWORD", "from-env")

    credentials = resolve_credentials(app_settings=op_settings)

    assert credentials.password == "from-env"
    assert len(calls) == 1


def test_asks_1password_for_the_current_code(monkeypatch) -> None:
    calls = install_fake_op(
        monkeypatch, {}, codes={f"{REFS['OKTA_TOTP_SECRET']}?attribute=otp": "123456"}
    )

    assert onepassword.read_totp_code(REFS["OKTA_TOTP_SECRET"], lambda: NOW) == "123456"
    assert calls == [["read", "--no-newline", f"{REFS['OKTA_TOTP_SECRET']}?attribute=otp"]]


def test_computes_the_code_itself_when_the_field_holds_a_plain_secret(monkeypatch) -> None:
    install_fake_op(monkeypatch, {REFS["OKTA_TOTP_SECRET"]: SECRET})

    assert onepassword.read_totp_code(REFS["OKTA_TOTP_SECRET"], lambda: NOW) == totp(SECRET, NOW)


def test_doesn_t_try_again_when_op_is_missing(monkeypatch) -> None:
    monkeypatch.setattr(onepassword.shutil, "which", lambda command: None)

    with pytest.raises(OpError, match="not installed"):
        onepassword.read_totp_code(REFS["OKTA_TOTP_SECRET"], lambda: NOW)


def test_refers_to_an_item_s_fields_by_id_and_keeps_none_of_their_values() -> None:
    def run(args: list[str], stdin: str | None) -> str:
        return json.dumps(
            {
                "fields": [
                    {"id": "username", "purpose": "USERNAME", "value": "abcd0001"},
                    {"id": "password", "purpose": "PASSWORD", "value": "hunter2"},
                    {"id": "otpabc", "type": "OTP", "value": f"otpauth://totp/x?secret={SECRET}"},
                ]
            }
        )

    refs = onepassword.item_refs("item1", "vault1", run)

    assert (refs.username, refs.password, refs.totp) == (
        "op://vault1/item1/username",
        "op://vault1/item1/password",
        "op://vault1/item1/otpabc",
    )
    assert not any(secret in repr(refs) for secret in ["hunter2", "abcd0001", "JBSW"])


def test_puts_items_with_an_okta_url_first() -> None:
    def item(title: str, url: str) -> OpItem:
        return OpItem(id=title, title=title, vault_id="v", vault_name="v", urls=[url])

    ranked = onepassword.rank_okta_items(
        [item("Bank", "https://bank.example"), item("Monash", "https://monash.okta.com/")]
    )
    assert [entry.title for entry in ranked] == ["Monash", "Bank"]


def test_takes_the_secret_out_of_an_otpauth_uri() -> None:
    assert onepassword.totp_secret_of(f"otpauth://totp/Okta?secret={SECRET}&digits=6") == SECRET
    assert onepassword.totp_secret_of(f" {SECRET}\n") == SECRET
    with pytest.raises(ValueError):
        onepassword.totp_secret_of("otpauth://totp/Okta?issuer=x")
