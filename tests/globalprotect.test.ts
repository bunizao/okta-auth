import { describe, expect, it } from "vitest";
import { OktaSignInError, signInGlobalProtect, type GlobalProtectOptions } from "../src/index.js";
import {
  fakeSso,
  GP,
  GP_COOKIE,
  OKTA,
  PASSWORD,
  SAML_RESPONSE,
  STATE_TOKEN,
  TOTP_SECRET,
  USERNAME,
  type FakeOptions,
  type RecordedRequest,
} from "./fake-sso.js";

const now = () => Date.UTC(2026, 10, 2, 3, 4, 5);

function setup(fakeOptions: Partial<FakeOptions> = {}) {
  const fake = fakeSso({ now, enrollments: ["google_otp"], ...fakeOptions });
  const run = (extra: Partial<GlobalProtectOptions> = {}) =>
    signInGlobalProtect({
      server: GP,
      username: USERNAME,
      password: PASSWORD,
      totpSecret: TOTP_SECRET,
      fetch: fake.fetch,
      now,
      ...extra,
    });
  return { fake, run };
}

function prelogins(requests: RecordedRequest[]) {
  return requests.filter((request) => request.url.pathname.endsWith("/prelogin.esp")).map((request) => request.url.pathname);
}

async function rejection(promise: Promise<unknown>): Promise<OktaSignInError> {
  const error = await promise.then(
    () => undefined,
    (error: unknown) => error,
  );
  expect(error).toBeInstanceOf(OktaSignInError);
  return error as OktaSignInError;
}

function expectNoSecrets(error: Error) {
  const text = `${error.message} ${error.stack ?? ""}`;
  for (const secret of [PASSWORD, TOTP_SECRET, STATE_TOKEN, "02.id.abc", GP_COOKIE, SAML_RESPONSE, "gprequest", "gp-anon"]) {
    expect(text).not.toContain(secret);
  }
}

describe("signInGlobalProtect", () => {
  it("signs in through the gateway with a redirect binding and returns the prelogin cookie", async () => {
    const { fake, run } = setup();
    const result = await run();

    expect(result).toEqual({
      interface: "gateway",
      user: USERNAME,
      cookieName: "prelogin-cookie",
      cookie: GP_COOKIE,
      deviceToken: "dt-1",
    });
    expect(prelogins(fake.requests)).toEqual(["/ssl-vpn/prelogin.esp"]);

    const prelogin = fake.requests[0]!;
    expect(prelogin.method).toBe("POST");
    expect(prelogin.headers.get("user-agent")).toBe("PAN GlobalProtect");
    expect(new URLSearchParams(prelogin.body).get("clientos")).toBe("Mac");
  });

  it("follows a POST binding to Okta and reads the result from an HTML comment", async () => {
    const { fake, run } = setup({ gpBinding: "POST", gpResultIn: "comment" });
    const result = await run({ deviceToken: "dt-9" });

    expect(result.cookie).toBe(GP_COOKIE);
    expect(result.deviceToken).toBe("dt-9");
    const samlRequest = fake.requests.find((request) => request.url.hostname === OKTA)!;
    expect(samlRequest.method).toBe("POST");
    expect(new URLSearchParams(samlRequest.body).get("SAMLRequest")).toBe("gprequest");
    // The SAMLRequest sits in the body here, yet the first Okta request still carries the device token.
    expect(samlRequest.cookies.get("DT")).toBe("dt-9");
  });

  it("falls back to the portal when the gateway does not offer SAML", async () => {
    const { fake, run } = setup({ gpSaml: ["portal"] });
    const result = await run();

    expect(prelogins(fake.requests)).toEqual(["/ssl-vpn/prelogin.esp", "/global-protect/prelogin.esp"]);
    expect(result.interface).toBe("portal");
    // The portal also sends prelogin-cookie, set to the literal "empty".
    expect(result.cookieName).toBe("portal-userauthcookie");
    expect(result.cookie).toBe(GP_COOKIE);
  });

  it("asks only the interface it is told to", async () => {
    const { fake, run } = setup({ gpSaml: ["gateway"] });
    const error = await rejection(run({ interface: "portal" }));

    expect(error.code).toBe("unexpected_step");
    expect(prelogins(fake.requests)).toEqual(["/global-protect/prelogin.esp"]);
  });

  it("sends nothing to Okta when neither interface offers SAML", async () => {
    const { fake, run } = setup({ gpSaml: [] });
    const error = await rejection(run());

    expect(error.code).toBe("unexpected_step");
    expect(error.message).toContain(`${GP}/global-protect/prelogin.esp`);
    expect(fake.requests.some((request) => request.url.hostname === OKTA)).toBe(false);
    expectNoSecrets(error);
  });

  it("sends the password only to Okta and the SAML response only to the ACS", async () => {
    const { fake, run } = setup();
    await run();

    for (const request of fake.requests) {
      if (request.body.includes(PASSWORD)) expect(request.url.hostname).toBe(OKTA);
      if (request.body.includes("SAMLResponse")) expect(request.url.hostname).toBe(GP);
      if (request.url.hostname === GP) expect(request.cookies.has("DT")).toBe(false);
    }
  });

  it("skips IDX when Okta already has a session", async () => {
    const { fake, run } = setup({ oktaSession: true });
    const result = await run();

    expect(fake.requests.some((request) => request.url.pathname.startsWith("/idp/idx/"))).toBe(false);
    expect(result.cookie).toBe(GP_COOKIE);
  });

  it("reports handoff_failed when the ACS rejects the SAML response", async () => {
    const { run } = setup({ spRejects: true });
    const error = await rejection(run());

    expect(error.code).toBe("handoff_failed");
    expect(error.message).toContain(`${GP}/SAML20/SP/ACS`);
    expectNoSecrets(error);
  });

  it("rejects bad input before any request", async () => {
    const { fake, run } = setup();
    await expect(run({ server: "https://vpn.example.edu" })).rejects.toThrow(TypeError);
    await expect(run({ server: "vpn.example.edu/path" })).rejects.toThrow(TypeError);
    await expect(run({ totpSecret: "not base32!" })).rejects.toThrow(TypeError);
    expect(fake.requests).toEqual([]);
  });
});
