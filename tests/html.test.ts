import { describe, expect, it } from "vitest";
import { OktaSignInError } from "../src/errors.js";
import { readSamlForm, readStateToken } from "../src/html.js";
import { SAML_RESPONSE, samlFormPage, SP } from "./fake-sso.js";

const page = new URL("https://example.okta.com/app/x/y/sso/saml");

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

  it("returns undefined for a page without a SAML response", () => {
    expect(readSamlForm(`<form action="/x"><input name="username"></form>`)).toBeUndefined();
  });
});
