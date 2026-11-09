from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from .errors import OktaSignInError
from .totp import totp

# The slice of Okta's IDX (Identity Engine) wire format this package reads:
# {"stateHandle", "remediation": {"value": [form, ...]}, "success": {"href"}, ...}
IdxState = dict[str, Any]


@dataclass
class Credentials:
    username: str
    password: str
    totp_secret: str | None = None


# What a step sends decides how a rejection is reported.
Sends = Literal["identifier", "password", "passcode"] | None


@dataclass
class IdxStep:
    form: str
    href: str
    body: dict[str, Any]
    sends: Sends


PASSWORD = "okta_password"
TOTP_KEYS = {"google_otp", "okta_verify"}
# Preference when Okta lets us choose. Push, SMS, email and the rest are never chosen.
PREFERRED_KEYS = [PASSWORD, "google_otp", "okta_verify"]


def next_step(state: IdxState, credentials: Credentials, now: float) -> IdxStep:
    """Picks the next IDX remediation to answer and builds its request body."""
    forms = _forms(state)

    def find(name: str) -> dict[str, Any] | None:
        return next((form for form in forms if form.get("name") == name), None)

    def state_handle(form: dict[str, Any]) -> Any:
        value = (_field(form, "stateHandle") or {}).get("value")
        return value if value is not None else state.get("stateHandle")

    identify = find("identify")
    if identify:
        credentials_field = _field(identify, "credentials")
        body: dict[str, Any] = {"identifier": credentials.username}
        if credentials_field:
            body["credentials"] = {_secret_name(credentials_field): credentials.password}
        body["stateHandle"] = state_handle(identify)
        return IdxStep(
            form="identify",
            href=_href(identify),
            body=body,
            sends="password" if credentials_field else "identifier",
        )

    challenge = find("challenge-authenticator")
    challenge_key = _authenticator_key(state, challenge.get("relatesTo")) if challenge else None
    select = find("select-authenticator-authenticate")
    options = _authenticator_options(state, select) if select else []
    usable = [o for o in options if o.usable and _can_answer(o.key, credentials)]
    choice = next((o for key in PREFERRED_KEYS for o in usable if o.key == key), None)

    # Okta pre-selects the authenticator used last time. Answer it, unless it's a
    # TOTP authenticator and Okta also offers one we rank higher: a Google
    # Authenticator secret can't answer Okta Verify.
    switch_to_choice = (
        choice is not None and choice.key != PASSWORD and _rank(choice.key) < _rank(challenge_key)
    )
    if challenge and _can_answer(challenge_key, credentials) and not switch_to_choice:
        is_password = challenge_key == PASSWORD
        if is_password:
            secret = credentials.password
        else:
            assert credentials.totp_secret is not None  # _can_answer checked it
            secret = totp(credentials.totp_secret, now)
        credentials_field = _field(challenge, "credentials")
        name = _secret_name(credentials_field) if credentials_field else "passcode"
        return IdxStep(
            form="challenge-authenticator",
            href=_href(challenge),
            body={"credentials": {name: secret}, "stateHandle": state_handle(challenge)},
            sends="password" if is_password else "passcode",
        )

    if select:
        if not choice:
            raise OktaSignInError(
                "mfa_unsupported",
                f"Okta offers {_describe(options)}; this package answers "
                f"{', '.join(PREFERRED_KEYS)} (TOTP only)"
                + ("" if credentials.totp_secret else ", and no TOTP secret was given"),
            )
        authenticator: dict[str, Any] = {"id": choice.id}
        if choice.method_type:
            authenticator["methodType"] = choice.method_type
        return IdxStep(
            form="select-authenticator-authenticate",
            href=_href(select),
            body={"authenticator": authenticator, "stateHandle": state_handle(select)},
            sends=None,
        )

    # Okta's current challenge is one we can't answer and it offers no alternative.
    if challenge:
        missing_secret = " and no TOTP secret was given" if challenge_key in TOTP_KEYS else ""
        raise OktaSignInError(
            "mfa_unsupported",
            f"Okta asks for {challenge_key or 'an unknown authenticator'}{missing_secret}",
        )

    # Okta Verify asks how to verify after it's selected: always a TOTP code.
    verification_data = find("authenticator-verification-data")
    if verification_data:
        authenticator_field = _field(verification_data, "authenticator") or {}
        authenticator_form = authenticator_field.get("form")
        authenticator_id = (_field(authenticator_form, "id") or {}).get("value")
        methods = _method_types(_field(authenticator_form, "methodType"))
        if "totp" not in methods:
            raise OktaSignInError(
                "mfa_unsupported",
                f"Okta Verify offers {', '.join(methods) or 'no methods'}, not totp",
            )
        return IdxStep(
            form="authenticator-verification-data",
            href=_href(verification_data),
            body={
                "authenticator": {"id": authenticator_id, "methodType": "totp"},
                "stateHandle": state_handle(verification_data),
            },
            sends=None,
        )

    skip = find("skip")
    if skip:
        return IdxStep(
            form="skip", href=_href(skip), body={"stateHandle": state_handle(skip)}, sends=None
        )

    names = [str(form.get("name")) for form in forms]
    if "challenge-poll" in names:
        raise OktaSignInError("mfa_unsupported", "Okta is waiting for a push notification")
    raise OktaSignInError(
        "unexpected_step",
        f"Okta asks for {', '.join(names) or 'nothing this package recognises'}",
    )


def error_keys(node: Any) -> list[str]:
    """Okta error messages, by i18n key. Keys never contain user input; message text might."""
    keys: dict[str, None] = {}  # an ordered set
    _collect_error_keys(node, keys)
    return list(keys)


def _collect_error_keys(node: Any, keys: dict[str, None]) -> None:
    if isinstance(node, list):
        for item in node:
            _collect_error_keys(item, keys)
    elif isinstance(node, dict):
        if node.get("class") == "ERROR":
            i18n = node.get("i18n")
            key = i18n.get("key") if isinstance(i18n, dict) else None
            keys[key if isinstance(key, str) else "unknown"] = None
        for value in node.values():
            _collect_error_keys(value, keys)


@dataclass
class _AuthenticatorOption:
    key: str | None
    id: Any
    # None: Okta needs no method type.
    method_type: str | None
    methods: list[str]
    # False when none of the offered method types is one this package can use.
    usable: bool


def _authenticator_options(state: IdxState, form: dict[str, Any]) -> list[_AuthenticatorOption]:
    result = []
    for option in (_field(form, "authenticator") or {}).get("options") or []:
        if not isinstance(option, dict):
            continue
        value = option.get("value")
        fields = value.get("form") if isinstance(value, dict) else None
        key = _authenticator_key(state, option.get("relatesTo"))
        method_field = _field(fields, "methodType")
        methods = _method_types(method_field)
        method_type = methods[0] if methods else None
        usable = True
        # Okta Verify can push or show a code; only the code works without a phone in hand.
        if key == "okta_verify":
            usable = "totp" in methods
            method_type = "totp" if usable else None
        elif method_field is not None and not methods:
            usable = False
        authenticator_id = (_field(fields, "id") or {}).get("value")
        result.append(_AuthenticatorOption(key, authenticator_id, method_type, methods, usable))
    return result


def _can_answer(key: str | None, credentials: Credentials) -> bool:
    if key == PASSWORD:
        return True
    return key is not None and key in TOTP_KEYS and credentials.totp_secret is not None


def _rank(key: str | None) -> int:
    return PREFERRED_KEYS.index(key) if key in PREFERRED_KEYS else len(PREFERRED_KEYS)


def _describe(options: list[_AuthenticatorOption]) -> str:
    if not options:
        return "no authenticators"
    return ", ".join(
        f"{option.key or 'unknown'}" + (f" ({'/'.join(option.methods)})" if option.methods else "")
        for option in options
    )


def _forms(state: IdxState) -> list[dict[str, Any]]:
    remediation = state.get("remediation")
    forms = remediation.get("value") if isinstance(remediation, dict) else None
    return [form for form in forms if isinstance(form, dict)] if isinstance(forms, list) else []


def _href(form: dict[str, Any]) -> str:
    return str(form.get("href") or "")


def _field(form: Any, name: str) -> dict[str, Any] | None:
    values = form.get("value") if isinstance(form, dict) else None
    if not isinstance(values, list):
        return None
    return next((v for v in values if isinstance(v, dict) and v.get("name") == name), None)


def _secret_name(credentials: dict[str, Any]) -> str:
    """The credentials sub-field is `passcode` for passwords and Google Authenticator,
    `totp` for Okta Verify. The form says which."""
    form = credentials.get("form")
    values = form.get("value") if isinstance(form, dict) else None
    first = values[0] if isinstance(values, list) and values else None
    name = first.get("name") if isinstance(first, dict) else None
    return name if isinstance(name, str) else "passcode"


def _method_types(method_field: dict[str, Any] | None) -> list[str]:
    if not method_field:
        return []
    if isinstance(method_field.get("value"), str):
        return [method_field["value"]]
    options = method_field.get("options") or []
    return [o["value"] for o in options if isinstance(o, dict) and isinstance(o.get("value"), str)]


def _authenticator_key(state: IdxState, relates_to: Any) -> str | None:
    """Resolves an IDX pointer such as `$.authenticatorEnrollments.value[0]` or
    `$.currentAuthenticatorEnrollment` to the authenticator's key (`google_otp`...)."""
    pointer = relates_to[0] if isinstance(relates_to, list) and relates_to else relates_to
    if not isinstance(pointer, str) or not pointer.startswith("$."):
        return None

    node: Any = state
    for part in filter(None, re.split(r"\.|\[([0-9]+)\]", pointer[2:])):
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            node = None
    if not isinstance(node, dict):
        return None
    key = node.get("key")
    if key is None and isinstance(node.get("value"), dict):
        key = node["value"].get("key")
    return key if isinstance(key, str) else None
