from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

from .errors import OktaSignInError, where


@dataclass
class SamlForm:
    action: str
    fields: dict[str, str]


_STATE_TOKEN = re.compile(r"""stateToken["']?\s*[=:]\s*["']([^"']+)["']""")
_INPUT = re.compile(r"<input\b[^>]*>", re.IGNORECASE)
_FORM = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_ATTRIBUTE = re.compile(r"""\s([\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?""")
_ENTITY = re.compile(r"&(#x[0-9a-f]+|#[0-9]+|[a-z]+);", re.IGNORECASE)
_JS_HEX = re.compile(r"\\x([0-9a-f]{2})", re.IGNORECASE)
_JS_UNICODE = re.compile(r"\\u([0-9a-f]{4})", re.IGNORECASE)


def is_login_page(html: str) -> bool:
    """An HTTP 200 on the target host may still be a sign-in form. Ignore templates
    and hidden fields so embedded login markup does not invalidate a session."""
    content = re.sub(r"<!--[\s\S]*?-->", "", html)
    content = re.sub(
        r"<(script|style|template)\b[^>]*>[\s\S]*?</\1\s*>", "", content, flags=re.IGNORECASE
    )
    for match in _INPUT.finditer(content):
        attributes = _read_attributes(match.group(0))
        input_type = attributes.get("type", "").lower()
        autocomplete = attributes.get("autocomplete", "").lower().split()
        if (
            input_type == "hidden"
            or "hidden" in attributes
            or "disabled" in attributes
            or "new-password" in autocomplete
        ):
            continue
        if (
            input_type == "password"
            or attributes.get("name", "").lower() == "username"
            or attributes.get("id", "").lower() == "okta-signin-username"
            or "username" in autocomplete
        ):
            return True
    return False


def read_state_token(html: str, url: httpx.URL) -> str:
    """The Okta sign-in page embeds the IDX state token in a script, for example
    `var stateToken = '02.id.abc\\x2Ddef';`, with JavaScript string escapes."""
    match = _STATE_TOKEN.search(html)
    if not match:
        raise OktaSignInError(
            "unexpected_step",
            f"{where(url)} is not an Okta Identity Engine sign-in page (no state token found)",
        )
    token = _unescape_js(match.group(1))
    if not token.startswith("02."):
        raise OktaSignInError(
            "unexpected_step",
            f"{where(url)} uses Okta Classic Engine, which is not supported; only Identity Engine is",
        )
    return token


def read_saml_form(html: str, field: str = "SAMLResponse") -> SamlForm | None:
    """Okta finishes with an auto-submitting form that carries the SAMLResponse to
    the service provider; a GlobalProtect POST binding starts with one that carries
    the SAMLRequest to Okta. Attribute values are HTML-entity-encoded.

    `field` is "SAMLResponse" or "SAMLRequest"."""
    inputs = [(match.start(), _read_attributes(match.group(0))) for match in _INPUT.finditer(html)]
    message = next((index for index, attributes in inputs if attributes.get("name") == field), None)
    if message is None:
        return None

    form_start = html.rfind("<form", 0, message)
    form_tag = _FORM.search(html, form_start) if form_start >= 0 else None
    action = _read_attributes(form_tag.group(0)).get("action") if form_tag else None
    if not action:
        return None

    # Only the inputs inside that form: another form's RelayState must not ride
    # along with this form's message.
    form_end = html.find("</form", message)
    end = len(html) if form_end < 0 else form_end
    fields: dict[str, str] = {}
    for index, attributes in inputs:
        if index < form_start or index >= end:
            continue
        name = attributes.get("name")
        if name == field or name == "RelayState":
            fields[name] = attributes.get("value", "")
    return SamlForm(action=action, fields=fields)


def _read_attributes(tag: str) -> dict[str, str]:
    attributes: dict[str, str] = {}
    for match in _ATTRIBUTE.finditer(tag):
        value = next((value for value in match.groups()[1:] if value is not None), "")
        attributes[match.group(1).lower()] = decode_entities(value)
    return attributes


_NAMED_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}


def decode_entities(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        body = match.group(1)
        if body[0] == "#":
            hex_digits = body[1] in "xX"
            return chr(int(body[2:] if hex_digits else body[1:], 16 if hex_digits else 10))
        return _NAMED_ENTITIES.get(body.lower(), match.group(0))

    return _ENTITY.sub(replace, text)


def _unescape_js(text: str) -> str:
    text = _JS_HEX.sub(lambda match: chr(int(match.group(1), 16)), text)
    return _JS_UNICODE.sub(lambda match: chr(int(match.group(1), 16)), text)
