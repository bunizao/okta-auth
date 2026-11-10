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

// Okta orgs and apps configured differently from the default fake: other SAML
// bindings, OIDC apps, and sign-on policies that add steps.

const now = () => Date.UTC(2026, 10, 2, 3, 4, 5);
const APP_PATH = "/app/example_moodle/exk1/sso/saml";
const stateHandle = { name: "stateHandle", required: true, value: STATE_TOKEN, visible: false, mutable: false };

function setup(fakeOptions: Partial<FakeOptions> = {}) {
  const fake = fakeSso({ now, ...fakeOptions });
  const run = (extra: Partial<SignInOptions> = {}) =>
    signIn({ url: TARGET, username: USERNAME, password: PASSWORD, totpSecret: TOTP_SECRET, fetch: fake.fetch, now, ...extra });
  return { fake, run };
}

async function rejection(promise: Promise<unknown>): Promise<OktaSignInError> {
  const error = await promise.then(
    () => undefined,
    (error: unknown) => error,
  );
  expect(error).toBeInstanceOf(OktaSignInError);
  return error as OktaSignInError;
}

function idx(request: RecordedRequest, path: string): boolean {
  return request.method === "POST" && request.url.hostname === OKTA && request.url.pathname === `/idp/idx/${path}`;
}

function idxState(remediation: object[], extra: object = {}): Response {
  return Response.json({ version: "1.0.0", stateHandle: STATE_TOKEN, remediation: { type: "array", value: remediation }, ...extra });
}

function form(name: string, path: string, value: object[] = []) {
  return { name, href: `https://${OKTA}/idp/idx/${path}`, method: "POST", value: [...value, stateHandle] };
}

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ location });
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return new Response(null, { status: 302, headers });
}

function html(body: string, cookies: string[] = []): Response {
  const headers = new Headers({ "content-type": "text/html" });
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return new Response(body, { status: 200, headers });
}

describe("service providers", () => {
  it("follows a SAML request the service provider posts to Okta", async () => {
    const { fake, run } = setup();
    fake.setOverride((request) => {
      const { method, url, cookies } = request;
      if (method === "GET" && url.hostname === SP && url.pathname === "/login/index.php" && cookies.get("MoodleSession") !== "authed") {
        return html(
          `<form method="post" action="https://${OKTA}${APP_PATH}">` +
            `<input type="hidden" name="SAMLRequest" value="request">` +
            `<input type="hidden" name="RelayState" value="https://${SP}/my/"></form>`,
          ["MoodleSession=anon; Path=/; Secure; HttpOnly", "MDL_SSP_SessID=ssp-1; Path=/; Secure; HttpOnly"],
        );
      }
      if (method === "POST" && url.hostname === OKTA && url.pathname === APP_PATH) {
        if (new URLSearchParams(request.body).get("SAMLRequest") !== "request") return new Response("bad", { status: 400 });
        return html(`<script>var stateToken = '02.id.abc\\x2Ddef';</script>`, ["DT=dt-1; Path=/; Secure; HttpOnly"]);
      }
      return undefined;
    });
    const result = await run({ deviceToken: "dt-old" });

    expect(result.cookies.map((cookie) => cookie.name)).toContain("MoodleSession");
    // Okta is known from the form's action, so it sees the device token from the first request.
    const post = fake.requests.find((request) => request.method === "POST" && request.url.pathname === APP_PATH);
    expect(post?.cookies.get("DT")).toBe("dt-old");
    expect(result.oktaSession.map((cookie) => cookie.name)).toContain("sid");
  });

  it("signs in to an OIDC app that Okta returns to with a redirect", async () => {
    const { fake, run } = setup();
    const callback = `https://${SP}/auth/oidc/callback`;
    fake.setOverride(({ method, url, cookies }) => {
      if (url.hostname === SP && url.pathname === "/login/index.php" && cookies.get("MoodleSession") !== "authed") {
        return redirect(`https://${OKTA}/oauth2/v1/authorize?client_id=moodle&redirect_uri=${encodeURIComponent(callback)}&state=s1`);
      }
      if (method === "GET" && url.hostname === OKTA && url.pathname === "/oauth2/v1/authorize") {
        if (cookies.get("sid") === "okta-session") return redirect(`${callback}?code=c1&state=s1`);
        return html(`<script>var stateToken = '02.id.abc\\x2Ddef';</script>`);
      }
      if (method === "GET" && url.hostname === OKTA && url.pathname === "/login/token/redirect") {
        return redirect(`${callback}?code=c1&state=s1`, ["sid=okta-session; Path=/; Secure; HttpOnly"]);
      }
      if (url.hostname === SP && url.pathname === "/auth/oidc/callback") {
        if (url.searchParams.get("code") !== "c1") return new Response("bad code", { status: 400 });
        return redirect(`https://${SP}/my/`, ["MoodleSession=authed; Path=/; Secure; HttpOnly"]);
      }
      return undefined;
    });
    const result = await run();

    expect(result.cookies.find((cookie) => cookie.name === "MoodleSession")?.value).toBe("authed");
    expect(new URL(result.landingUrl).pathname).toBe("/my/");
    expect(result.oktaSession.map((cookie) => cookie.name)).toContain("sid");

    // With that Okta session, a second sign-in goes straight through.
    const again = await run({ oktaSession: result.oktaSession });
    expect(again.cookies.find((cookie) => cookie.name === "MoodleSession")?.value).toBe("authed");
  });

  it("still reports a URL that never leads to Okta", async () => {
    const { fake, run } = setup();
    fake.setOverride(({ url }) => (url.hostname === SP ? html("<p>Public page</p>") : undefined));
    const error = await rejection(run());

    expect(error.code).toBe("unexpected_step");
    expect(fake.requests.some((request) => request.url.hostname === OKTA)).toBe(false);
  });
});

describe("sign-on policies", () => {
  it("skips a password-expiry warning", async () => {
    const { fake, run } = setup();
    let warned = false;
    fake.setOverride((request) => {
      if (idx(request, "challenge/answer") && !warned && JSON.parse(request.body).credentials?.passcode === PASSWORD) {
        warned = true;
        return idxState([form("reenroll-authenticator-warning", "challenge/answer", [{ name: "credentials" }]), form("skip", "skip")]);
      }
      if (idx(request, "skip")) {
        // What Okta would have answered to the password.
        return fake.fetch(`https://${OKTA}/idp/idx/challenge/answer`, {
          method: "POST",
          headers: request.headers,
          body: JSON.stringify({ credentials: { passcode: PASSWORD }, stateHandle: STATE_TOKEN }),
        }) as unknown as Response;
      }
      return undefined;
    });

    await expect(run()).resolves.toBeDefined();
    expect(warned).toBe(true);
  });

  it("explains an expired password instead of answering it", async () => {
    const { fake, run } = setup();
    fake.setOverride((request) =>
      idx(request, "challenge/answer") && JSON.parse(request.body).credentials?.passcode === PASSWORD
        ? idxState([form("reenroll-authenticator", "challenge/answer", [{ name: "credentials" }])])
        : undefined,
    );
    const error = await rejection(run());

    expect(error.code).toBe("unexpected_step");
    expect(error.message).toMatch(/password has expired/i);
    expect(error.message).not.toContain(PASSWORD);
  });

  it("explains a required authenticator enrollment", async () => {
    const { fake, run } = setup();
    fake.setOverride((request) =>
      idx(request, "challenge/answer") && JSON.parse(request.body).credentials?.passcode === PASSWORD
        ? idxState([form("select-authenticator-enroll", "credential/enroll", [{ name: "authenticator", options: [] }])])
        : undefined,
    );
    const error = await rejection(run());

    expect(error.code).toBe("unexpected_step");
    expect(error.message).toMatch(/set up/i);
  });

  it("skips an optional authenticator enrollment", async () => {
    const { fake, run } = setup();
    let offered = false;
    fake.setOverride((request) => {
      if (idx(request, "challenge/answer") && !offered && JSON.parse(request.body).credentials?.passcode === PASSWORD) {
        offered = true;
        return idxState([form("select-authenticator-enroll", "credential/enroll", [{ name: "authenticator", options: [] }]), form("skip", "skip")]);
      }
      if (idx(request, "skip")) {
        return fake.fetch(`https://${OKTA}/idp/idx/challenge/answer`, {
          method: "POST",
          headers: request.headers,
          body: JSON.stringify({ credentials: { passcode: PASSWORD }, stateHandle: STATE_TOKEN }),
        }) as unknown as Response;
      }
      return undefined;
    });

    await expect(run()).resolves.toBeDefined();
    expect(offered).toBe(true);
  });

  it("chooses the password from select-authenticator, then the TOTP authenticator", async () => {
    const { fake, run } = setup();
    // identify -> choose among password and Google Authenticator -> password -> TOTP.
    fake.setOverride((request) => {
      if (idx(request, "identify")) {
        return idxState(
          [
            form("select-authenticator-authenticate", "challenge", [
              {
                name: "authenticator",
                options: [
                  { label: "Google", value: { form: { value: [{ name: "id", value: "aut-google" }, { name: "methodType", value: "otp" }] } }, relatesTo: "$.authenticators.value[0]" },
                  { label: "Password", value: { form: { value: [{ name: "id", value: "aut-password" }, { name: "methodType", value: "password" }] } }, relatesTo: "$.authenticators.value[1]" },
                ],
              },
            ]),
          ],
          { authenticators: { value: [{ key: "google_otp", id: "aut-google" }, { key: "okta_password", id: "aut-password" }] } },
        );
      }
      if (idx(request, "challenge") && JSON.parse(request.body).authenticator?.id === "aut-password") {
        return idxState(
          [{ ...form("challenge-authenticator", "challenge/answer", [{ name: "credentials", form: { value: [{ name: "passcode" }] } }]), relatesTo: ["$.currentAuthenticatorEnrollment"] }],
          { currentAuthenticatorEnrollment: { value: { key: "okta_password", id: "aut-password" } } },
        );
      }
      return undefined;
    });
    await expect(run()).resolves.toBeDefined();

    const chosen = fake.requests.filter((request) => idx(request, "challenge")).map((request) => JSON.parse(request.body).authenticator.id);
    expect(chosen).toEqual(["aut-password", "aut-google"]);
  });

  it("asks Okta Verify for a TOTP code when Okta asks how to verify", async () => {
    const { fake, run } = setup({ enrollments: ["okta_verify"] });
    fake.setOverride((request) => {
      if (idx(request, "challenge") && JSON.parse(request.body).authenticator?.methodType === undefined) {
        return idxState([
          form("authenticator-verification-data", "challenge", [
            {
              name: "authenticator",
              form: {
                value: [
                  { name: "id", value: "aut-verify" },
                  { name: "methodType", options: [{ value: "push" }, { value: "totp" }] },
                ],
              },
            },
          ]),
        ]);
      }
      if (idx(request, "challenge/answer") && JSON.parse(request.body).credentials?.passcode === PASSWORD) {
        // Okta Verify offered without a method type in select-authenticator.
        return idxState(
          [
            form("select-authenticator-authenticate", "challenge", [
              { name: "authenticator", options: [{ label: "Okta Verify", value: { form: { value: [{ name: "id", value: "aut-verify" }] } }, relatesTo: "$.authenticatorEnrollments.value[0]" }] },
            ]),
          ],
          { authenticatorEnrollments: { value: [{ key: "okta_verify", id: "aut-verify" }] } },
        );
      }
      return undefined;
    });
    await expect(run()).resolves.toBeDefined();

    const methods = fake.requests.filter((request) => idx(request, "challenge")).map((request) => JSON.parse(request.body).authenticator);
    expect(methods).toEqual([{ id: "aut-verify" }, { id: "aut-verify", methodType: "totp" }]);
  });

  it("answers a TOTP challenge before the password when Okta asks for it first", async () => {
    const { fake, run } = setup({ enrollments: ["google_otp"] });
    let answeredCode = false;
    fake.setOverride((request) => {
      if (idx(request, "identify")) {
        // Authenticator-first: Okta goes straight to Google Authenticator.
        return fake.fetch(`https://${OKTA}/idp/idx/challenge`, {
          method: "POST",
          headers: request.headers,
          body: JSON.stringify({ authenticator: { id: "aut-google" }, stateHandle: STATE_TOKEN }),
        }) as unknown as Response;
      }
      if (idx(request, "challenge/answer") && !answeredCode && JSON.parse(request.body).credentials?.passcode !== PASSWORD) {
        answeredCode = true;
        return idxState(
          [{ ...form("challenge-authenticator", "challenge/answer", [{ name: "credentials", form: { value: [{ name: "passcode" }] } }]), relatesTo: ["$.currentAuthenticatorEnrollment"] }],
          { currentAuthenticatorEnrollment: { value: { key: "okta_password", id: "aut-password" } } },
        );
      }
      if (idx(request, "challenge/answer") && answeredCode && JSON.parse(request.body).credentials?.passcode === PASSWORD) {
        return Response.json({ stateHandle: STATE_TOKEN, success: { name: "success-redirect", href: `https://${OKTA}/login/token/redirect?stateToken=${STATE_TOKEN}` } });
      }
      return undefined;
    });
    await expect(run()).resolves.toBeDefined();
    expect(answeredCode).toBe(true);
  });

  it("reports a locked account as credentials_rejected without retrying", async () => {
    const { fake, run } = setup({ passwordOnIdentify: true });
    fake.setOverride((request) =>
      idx(request, "identify")
        ? Response.json(
            { version: "1.0.0", stateHandle: STATE_TOKEN, messages: { value: [{ class: "ERROR", i18n: { key: "errors.E0000119" }, message: "locked" }] } },
            { status: 403 },
          )
        : undefined,
    );
    const error = await rejection(run());

    expect(error.code).toBe("credentials_rejected");
    expect(fake.requests.filter((request) => idx(request, "identify"))).toHaveLength(1);
  });

  it("reports Okta's rate limit as http_429, not as rejected credentials", async () => {
    const { fake, run } = setup();
    fake.setOverride((request) =>
      idx(request, "identify")
        ? Response.json({ messages: { value: [{ class: "ERROR", i18n: { key: "E0000047" }, message: "rate" }] } }, { status: 429 })
        : undefined,
    );
    expect((await rejection(run())).code).toBe("http_429");
  });

  it("names an external identity provider routing rule", async () => {
    const { fake, run } = setup();
    fake.setOverride((request) =>
      idx(request, "introspect")
        ? idxState([{ name: "redirect-idp", type: "SAML2", href: "https://idp.example.org/sso", method: "GET" }])
        : undefined,
    );
    const error = await rejection(run());

    expect(error.code).toBe("unexpected_step");
    expect(error.message).toContain("redirect-idp");
  });

  it("ignores FastPass and other forms Okta offers next to identify", async () => {
    const { fake, run } = setup();
    let inner = false;
    fake.setOverride((request) => {
      if (!idx(request, "introspect") || inner) return undefined;
      inner = true;
      return fake.fetch(request.url.href, { method: "POST", headers: request.headers, body: request.body }).then(async (response) => {
        const state = await response.json();
        state.remediation.value.unshift(
          { name: "launch-authenticator", href: "https://127.0.0.1:8769/challenge", method: "GET" },
          { name: "select-enroll-profile", href: `https://${OKTA}/idp/idx/enroll`, value: [stateHandle] },
          { name: "unlock-account", href: `https://${OKTA}/idp/idx/unlock-account`, value: [stateHandle] },
        );
        return Response.json(state);
      }) as unknown as Response;
    });

    await expect(run()).resolves.toBeDefined();
    expect(fake.requests.some((request) => request.url.hostname === "127.0.0.1")).toBe(false);
  });
});
