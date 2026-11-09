"""Ports tests/html.test.ts. Test names are the TypeScript case names in snake_case."""

import httpx
import pytest

from fake_sso import SAML_RESPONSE, SP, saml_form_page
from okta_auth.core.errors import OktaSignInError
from okta_auth.core.html import SamlForm, read_saml_form, read_state_token

PAGE = httpx.URL("https://example.okta.com/app/x/y/sso/saml")


def test_read_state_token_decodes_javascript_escapes() -> None:
    assert read_state_token("var stateToken = '02.id.a\\x2Db\\u002Dc';", PAGE) == "02.id.a-b-c"


def test_read_state_token_refuses_okta_classic_engine_clearly() -> None:
    with pytest.raises(OktaSignInError) as info:
        read_state_token("var stateToken = '00secret';", PAGE)
    assert info.value.code == "unexpected_step"
    assert "Classic Engine" in str(info.value)
    assert "00secret" not in str(info.value)


def test_read_saml_form_decodes_the_entity_encoded_action_and_fields() -> None:
    assert read_saml_form(saml_form_page()) == SamlForm(
        action=f"https://{SP}/auth/saml2/sp/saml2-acs.php/{SP}",
        fields={"SAMLResponse": SAML_RESPONSE, "RelayState": f"https://{SP}/my/"},
    )


def test_read_saml_form_handles_attributes_in_any_order_and_single_quotes() -> None:
    html = (
        "<form method='post' action='https://sp.example/acs'>"
        "<input value='abc&amp;d' type='hidden' name='SAMLResponse'></form>"
    )
    assert read_saml_form(html) == SamlForm(
        action="https://sp.example/acs", fields={"SAMLResponse": "abc&d"}
    )


def test_read_saml_form_returns_undefined_for_a_page_without_a_saml_response() -> None:
    assert read_saml_form('<form action="/x"><input name="username"></form>') is None
