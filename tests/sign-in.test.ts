import { describe, expect, it } from "vitest";
import { OktaSignInError, signIn, type SignInOptions } from "../src/index.js";
import {
  fakeSso,
  OKTA,
  PASSWORD,
  SP,
  STATE_TOKEN,
  TARGET,
  TOTP_SECRET,
  USERNAME,
  type FakeOptions,
  type RecordedRequest,
} from "./fake-sso.js";

const now = () => Date.UTC(2026, 10, 2, 3, 4, 5);

function setup(fakeOptions: Partial<FakeOptions> = {}, signInOptions: Partial<SignInOptions> = {}) {
  const fake = fakeSso({ now, ...fakeOptions });
  const run = (extra: Partial<SignInOptions> = {}) =>
    signIn({
      url: TARGET,
      username: USERNAME,
      password: PASSWORD,
      totpSecret: TOTP_SECRET,
      fetch: fake.fetch,
      now,
      ...signInOptions,
      ...extra,
    });
  return { fake, run };
}

function idxCalls(requests: RecordedRequest[]) {
  return requests.filter((request) => request.url.pathname.startsWith("/idp/idx/"));
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
  for (const secret of [PASSWORD, TOTP_SECRET, STATE_TOKEN, "02.id.abc", "ssp-1", "j-1", "dt-1", "SAMLRequest=request"]) {
    expect(text).not.toContain(secret);
  }
}

describe("signIn", () => {
  it("signs in identifier-first: password, then google_otp over push, then SAML", async () => {
    const { fake, run } = setup();
    const result = await run();

    expect(result.cookies.map(({ name, value, domain }) => ({ name, value, domain }))).toEqual([
      { name: "MoodleSession", value: "authed", domain: SP },
      { name: "MDL_SSP_SessID", value: "ssp-1", domain: SP },
    ]);
    expect(result.deviceToken).toBe("dt-1");

    const steps = idxCalls(fake.requests).map((request) => [request.url.pathname, JSON.parse(request.body)]);
    expect(steps.map(([path]) => path)).toEqual([
      "/idp/idx/introspect",
      "/idp/idx/identify",
      "/idp/idx/challenge/answer",
      "/idp/idx/challenge",
      "/idp/idx/challenge/answer",
    ]);
    // Identifier first: the identify form had no credentials field, so none went.
    expect(steps[1]![1]).toEqual({ identifier: USERNAME, stateHandle: STATE_TOKEN });
    expect(steps[2]![1]).toEqual({ credentials: { passcode: PASSWORD }, stateHandle: STATE_TOKEN });
    // Okta Verify (push only) was listed first; Google Authenticator was chosen.
    expect(steps[3]![1]).toEqual({ authenticator: { id: "aut-google", methodType: "otp" }, stateHandle: STATE_TOKEN });
    expect(steps[4]![1].credentials.passcode).toMatch(/^\d{6}$/);
  });

  it("sends the password with the identifier when the identify form asks for it", async () => {
    const { fake, run } = setup({ passwordOnIdentify: true, enrollments: ["google_otp"] });
    await run();

    const identify = idxCalls(fake.requests).find((request) => request.url.pathname === "/idp/idx/identify")!;
    expect(JSON.parse(identify.body)).toEqual({
      identifier: USERNAME,
      credentials: { passcode: PASSWORD },
      stateHandle: STATE_TOKEN,
    });
  });

  it("answers Okta Verify with a TOTP code in the field Okta names", async () => {
    const { fake, run } = setup({ enrollments: ["okta_verify"] });
    await run();

    const [select, answer] = idxCalls(fake.requests).slice(-2);
    expect(JSON.parse(select!.body).authenticator).toEqual({ id: "aut-verify", methodType: "totp" });
    expect(JSON.parse(answer!.body).credentials.totp).toMatch(/^\d{6}$/);
  });

  it("switches away from a pre-selected Okta Verify to Google Authenticator", async () => {
    const { fake, run } = setup({ enrollments: ["okta_verify", "google_otp"], preselect: "okta_verify" });
    await run();

    const [select, answer] = idxCalls(fake.requests).slice(-2);
    expect(select!.url.pathname).toBe("/idp/idx/challenge");
    expect(JSON.parse(select!.body).authenticator).toEqual({ id: "aut-google", methodType: "otp" });
    expect(JSON.parse(answer!.body).credentials.passcode).toMatch(/^\d{6}$/);
  });

  it("answers a pre-selected Google Authenticator challenge directly", async () => {
    const { fake, run } = setup({ enrollments: ["okta_verify", "google_otp"], preselect: "google_otp" });
    await run();

    expect(idxCalls(fake.requests).some((request) => request.url.pathname === "/idp/idx/challenge")).toBe(false);
  });

  it("round-trips the device token so Okta sees the same device", async () => {
    const { fake, run } = setup();
    const first = await run();
    expect(first.deviceToken).toBe("dt-1");

    fake.requests.length = 0;
    const second = await run({ deviceToken: first.deviceToken });
    expect(second.deviceToken).toBe("dt-1");

    // The very first request to Okta already carries it.
    const firstOktaRequest = fake.requests.find((request) => request.url.hostname === OKTA)!;
    expect(firstOktaRequest.url.searchParams.has("SAMLRequest")).toBe(true);
    expect(firstOktaRequest.cookies.get("DT")).toBe("dt-1");
    expect(fake.requests.filter((request) => request.url.hostname === OKTA).every((r) => r.cookies.get("DT") === "dt-1")).toBe(
      true,
    );
  });

  it("never sends one host's cookies to another host", async () => {
    const { fake, run } = setup();
    const result = await run();

    const oktaCookies = new Set(["DT", "JSESSIONID", "sid"]);
    const spCookies = new Set(["MoodleSession", "MDL_SSP_SessID"]);
    for (const request of fake.requests) {
      const names = [...request.cookies.keys()];
      if (request.url.hostname === OKTA) expect(names.filter((name) => spCookies.has(name))).toEqual([]);
      if (request.url.hostname === SP) expect(names.filter((name) => oktaCookies.has(name))).toEqual([]);
    }
    expect(result.cookies.every((cookie) => cookie.domain === SP)).toBe(true);
  });

  it("stops after one wrong password with credentials_rejected", async () => {
    const { fake, run } = setup({}, { password: "wrong password" });
    const error = await rejection(run());

    expect(error.code).toBe("credentials_rejected");
    expect(error.message).toContain("incorrectPassword");
    const passwordAttempts = idxCalls(fake.requests).filter((request) => request.url.pathname === "/idp/idx/challenge/answer");
    expect(passwordAttempts).toHaveLength(1);
    expect(fake.requests.some((request) => request.url.pathname === "/login/token/redirect")).toBe(false);
    expectNoSecrets(error);
  });

  it("reports a wrong one-time code as passcode_rejected", async () => {
    const { run } = setup({ totpSecret: "KRSXG5CTMVRXEZLUKN2XAZLSKNSWG4TFOQ" });
    const error = await rejection(run());

    expect(error.code).toBe("passcode_rejected");
    expect(error.message).toContain("api.authn.otp.invalid");
    expectNoSecrets(error);
  });

  it("refuses push-only enrollment with mfa_unsupported", async () => {
    const { fake, run } = setup({ enrollments: ["okta_verify_push"] });
    const error = await rejection(run());

    expect(error.code).toBe("mfa_unsupported");
    expect(error.message).toContain("okta_verify (push)");
    expect(idxCalls(fake.requests).some((request) => request.url.pathname === "/idp/idx/challenge")).toBe(false);
  });

  it("skips IDX when Okta already has a session", async () => {
    const { fake, run } = setup({ oktaSession: true });
    const result = await run();

    expect(idxCalls(fake.requests)).toEqual([]);
    expect(result.cookies.find((cookie) => cookie.name === "MoodleSession")?.value).toBe("authed");
  });

  it("reports handoff_failed when the service provider rejects the SAML response", async () => {
    const { run } = setup({ spRejects: true });
    const error = await rejection(run());

    expect(error.code).toBe("handoff_failed");
    expect(error.message).toContain(OKTA);
    expectNoSecrets(error);
  });

  it("gives up after eight IDX steps", async () => {
    const { fake, run } = setup();
    const skip = { name: "skip", href: `https://${OKTA}/idp/idx/skip`, value: [{ name: "stateHandle", value: STATE_TOKEN }] };
    fake.setOverride((request) =>
      request.url.pathname === "/idp/idx/introspect" || request.url.pathname === "/idp/idx/skip"
        ? Response.json({ stateHandle: STATE_TOKEN, remediation: { value: [skip] } })
        : undefined,
    );
    const error = await rejection(run());

    expect(error.code).toBe("unexpected_step");
    expect(idxCalls(fake.requests).filter((request) => request.url.pathname === "/idp/idx/skip")).toHaveLength(8);
  });

  it("names unknown remediation forms without their values", async () => {
    const { fake, run } = setup();
    fake.setOverride((request) =>
      request.url.pathname === "/idp/idx/introspect"
        ? Response.json({
            stateHandle: STATE_TOKEN,
            remediation: { value: [{ name: "enroll-profile", href: "x", value: [{ name: "stateHandle", value: STATE_TOKEN }] }] },
          })
        : undefined,
    );
    const error = await rejection(run());

    expect(error.code).toBe("unexpected_step");
    expect(error.message).toContain("enroll-profile");
    expectNoSecrets(error);
  });

  it("maps HTTP failures to http_N and timeouts to network", async () => {
    const down = setup();
    down.fake.setOverride((request) => (request.url.hostname === OKTA ? new Response("busy", { status: 503 }) : undefined));
    expect((await rejection(down.run())).code).toBe("http_503");

    const slow = setup();
    slow.fake.setOverride((request) => {
      if (request.url.hostname === OKTA) throw new DOMException("timed out", "TimeoutError");
      return undefined;
    });
    const error = await rejection(slow.run());
    expect(error.code).toBe("network");
    expect(error.message).toContain("timed out");
  });

  it("rejects bad input before any request", async () => {
    const { fake, run } = setup();
    await expect(run({ url: "http://learning.example.edu/" })).rejects.toThrow(TypeError);
    await expect(run({ totpSecret: "not base32!" })).rejects.toThrow(TypeError);
    expect(fake.requests).toEqual([]);
  });

  it("rejects malformed base32 before any request", async () => {
    const { fake, run } = setup();
    for (const totpSecret of ["A", "AAA", "AAAAAA", "MZ", "M=Y"]) {
      await expect(run({ totpSecret })).rejects.toThrow(TypeError);
    }
    expect(fake.requests).toEqual([]);
  });

  it("rejects a same-host login page after the SAML post", async () => {
    const { run } = setup({ spRejects: true, spLoginPage: true });
    expect((await rejection(run())).code).toBe("handoff_failed");
  });

  it("rejects an unfinished redirect after the SAML post", async () => {
    const { fake, run } = setup();
    fake.setOverride((request) => request.url.href === TARGET && request.cookies.get("MoodleSession") === "authed"
      ? new Response(null, { status: 302 })
      : undefined);
    expect((await rejection(run())).code).toBe("handoff_failed");
  });

  it("preserves SAML posts across same-origin 307 and 308 redirects", async () => {
    for (const acsRedirect of [307, 308] as const) {
      const { fake, run } = setup({ acsRedirect });
      const result = await run();
      expect(result.cookies.find((cookie) => cookie.name === "MoodleSession")?.value).toBe("authed");
      const acs = fake.requests.find((request) => request.url.pathname === "/canonical-acs")!;
      expect(acs.method).toBe("POST");
      expect(new URLSearchParams(acs.body).has("SAMLResponse")).toBe(true);
      expect(acs.headers.get("content-type")).toBe("application/x-www-form-urlencoded");
      expect(acs.cookies.get("acs-route")).toBe("canonical");
    }
  });

  it("refuses to replay SAML posts across origins", async () => {
    for (const status of [307, 308]) {
      const { fake, run } = setup();
      fake.setOverride((request) => request.url.pathname.includes("saml2-acs.php")
        ? new Response(null, { status, headers: { location: `https://${SP}:8443/acs?token=private` } })
        : undefined);
      const error = await rejection(run());
      expect(error.code).toBe("unexpected_step");
      expect(error.message).not.toContain("private");
      expect(fake.requests.some((request) => request.url.port === "8443")).toBe(false);
    }
  });

  it("maps interrupted page and IDX response bodies to network", async () => {
    for (const path of ["/login/index.php", "/idp/idx/introspect"]) {
      for (const name of ["TypeError", "TimeoutError"]) {
        const { fake, run } = setup();
        fake.setOverride((request) => request.url.pathname === path
          ? new Response(new ReadableStream({ start(controller) {
              const error = new Error(`${PASSWORD} ${STATE_TOKEN}`);
              error.name = name;
              controller.error(error);
            } }))
          : undefined);
        const error = await rejection(run());
        expect(error.code).toBe("network");
        expectNoSecrets(error);
        expect(fake.requests.filter((request) => request.url.pathname === path)).toHaveLength(1);
      }
    }
  });

  it("reports invalid successful IDX responses as unexpected_step", async () => {
    for (const body of ["not json", "null", "[]", '"text"']) {
      const { fake, run } = setup();
      fake.setOverride((request) => request.url.pathname === "/idp/idx/introspect"
        ? new Response(body)
        : undefined);
      expect((await rejection(run())).code).toBe("unexpected_step");
    }
  });
});
