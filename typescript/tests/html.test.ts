import { describe, expect, it } from "vitest";
import { OktaSignInError } from "../src/errors.js";
import { isLoginPage, readSamlForm, readStateToken } from "../src/html.js";
import { SAML_RESPONSE, samlFormPage, SP } from "./fake-sso.js";

const page = new URL("https://example.okta.com/app/x/y/sso/saml");

describe("isLoginPage", () => {
  it("recognises password and identifier-first login fields", () => {
    for (const html of [
      '<form><input name="username"><input type="password"></form>',
      "<FORM><INPUT TYPE=PASSWORD></FORM>",
      '<form><input type="email" autocomplete="username"></form>',
      '<input id="okta-signin-username">',
    ]) {
      expect(isLoginPage(html)).toBe(true);
    }
  });

  it("ignores hidden fields and login markup outside the page content", () => {
    for (const html of [
      "<p>You are logged in</p>",
      '<!-- <input type="password"> --><script>const template = \'<input name="username">\';</script>',
      '<style>/* <input type="password"> */</style>',
      '<template id="login"><form><input type="password"></form></template>',
      '<form><input name="username" type="hidden"></form>',
      '<form><input type="password" autocomplete="new-password"></form>',
      '<input data-name="username" name="search">',
      '<input type="password" hidden>',
      '<input name="username" disabled>',
    ]) {
      expect(isLoginPage(html)).toBe(false);
    }
  });
});

describe("readStateToken", () => {
  it("decodes JavaScript escapes", () => {
    expect(readStateToken(`var stateToken = '02.id.a\\x2Db\\u002Dc';`, page)).toBe("02.id.a-b-c");
  });

  it("refuses Okta Classic Engine clearly", () => {
    const error = (() => {
      try {
        readStateToken(`var stateToken = '00secret';`, page);
      } catch (error) {
        return error as OktaSignInError;
      }
    })();
    expect(error?.code).toBe("unexpected_step");
    expect(error?.message).toContain("Classic Engine");
    expect(error?.message).not.toContain("00secret");
  });
});

describe("readSamlForm", () => {
  it("decodes the entity-encoded action and fields", () => {
    expect(readSamlForm(samlFormPage())).toEqual({
      action: `https://${SP}/auth/saml2/sp/saml2-acs.php/${SP}`,
      fields: { SAMLResponse: SAML_RESPONSE, RelayState: `https://${SP}/my/` },
    });
  });

  it("handles attributes in any order and single quotes", () => {
    const html = `<form method='post' action='https://sp.example/acs'><input value='abc&amp;d' type='hidden' name='SAMLResponse'></form>`;
    expect(readSamlForm(html)).toEqual({ action: "https://sp.example/acs", fields: { SAMLResponse: "abc&d" } });
  });

  it("reads only the fields of the form that carries the message", () => {
    const html =
      `<input name="RelayState" value="outside">` +
      `<form action="https://sp.example/one"><input name="SAMLResponse" value="r1"><input name="RelayState" value="s1"></form>` +
      `<form action="https://sp.example/two"><input name="SAMLResponse" value="r2"><input name="RelayState" value="s2"></form>`;
    expect(readSamlForm(html)).toEqual({
      action: "https://sp.example/one",
      fields: { SAMLResponse: "r1", RelayState: "s1" },
    });
  });

  it("returns undefined for a page without a SAML response", () => {
    expect(readSamlForm(`<form action="/x"><input name="username"></form>`)).toBeUndefined();
  });
});
