import { totp } from "../src/totp.js";

// A scripted Okta Identity Engine org (example.okta.com), a Moodle-like SAML
// service provider (learning.example.edu) and a GlobalProtect portal
// (vpn.example.edu), served through a fake fetch.

export const SP = "learning.example.edu";
export const OKTA = "example.okta.com";
export const TARGET = `https://${SP}/login/index.php`;
export const USERNAME = "student@example.edu";
export const PASSWORD = "correct horse battery staple";
export const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
export const STATE_TOKEN = "02.id.abc-def";
export const SAML_RESPONSE = "PHNhbWw+";
export const GP = "vpn.example.edu";
export const GP_COOKIE = "gp-cookie-1";

const RELAY_STATE = `https://${SP}/my/`;
const IDX = "application/ion+json; okta-version=1.0.0";
const APP_PATH = "/app/example_moodle/exk1/sso/saml";
const ACS_PATH = `/auth/saml2/sp/saml2-acs.php/${SP}`;
const GP_APP_PATH = "/app/example_gp/exk2/sso/saml";
const GP_ACS_PATH = "/SAML20/SP/ACS";
const GP_RELAY_STATE = "gp-relay";
const PRELOGIN_PATHS = { gateway: "/ssl-vpn/prelogin.esp", portal: "/global-protect/prelogin.esp" } as const;

export type GpInterface = keyof typeof PRELOGIN_PATHS;

export type Enrollment = "google_otp" | "okta_verify" | "okta_verify_push";

export interface FakeOptions {
  now: () => number;
  // The secret Okta holds for the user's TOTP enrollment.
  totpSecret?: string;
  // Second factors besides the password, in the order Okta lists them.
  enrollments?: Enrollment[];
  // Okta asks for the password on the identify form instead of a later step.
  passwordOnIdentify?: boolean;
  // After the password, Okta challenges this enrollment straight away (the one
  // used last time) and offers the rest through select-authenticator.
  preselect?: Enrollment;
  // Okta already has a session for every request (say, a browser's cookies).
  oktaSession?: boolean;
  // The SP (or the GlobalProtect ACS) refuses the SAML response.
  spRejects?: boolean;
  // The ACS moved within the same origin and requires the original POST.
  acsRedirect?: 307 | 308;
  // How GlobalProtect prelogin hands over the SAMLRequest.
  gpBinding?: "REDIRECT" | "POST";
  // GlobalProtect interfaces whose prelogin offers SAML; the rest answer Error.
  gpSaml?: GpInterface[];
  // Where the GlobalProtect ACS reports the result.
  gpResultIn?: "headers" | "comment";
}

export interface RecordedRequest {
  method: string;
  url: URL;
  cookies: Map<string, string>;
  headers: Headers;
  body: string;
}

const ENROLLMENTS: Record<Enrollment, { key: string; id: string; methodType: object }> = {
  google_otp: {
    key: "google_otp",
    id: "aut-google",
    methodType: { name: "methodType", required: false, value: "otp", mutable: false },
  },
  okta_verify: {
    key: "okta_verify",
    id: "aut-verify",
    methodType: {
      name: "methodType",
      type: "string",
      options: [
        { label: "Enter a code", value: "totp" },
        { label: "Get a push notification", value: "push" },
      ],
    },
  },
  okta_verify_push: {
    key: "okta_verify",
    id: "aut-verify",
    methodType: { name: "methodType", type: "string", options: [{ label: "Get a push notification", value: "push" }] },
  },
};

export function fakeSso(options: FakeOptions) {
  const requests: RecordedRequest[] = [];
  const enrollments = options.enrollments ?? ["okta_verify_push", "google_otp"];
  let issuedDevices = 0;
  let challenged: Enrollment | undefined;
  // The Okta app the current sign-in is for, so the success link returns to it.
  let appPath = APP_PATH;
  // The GlobalProtect interface whose prelogin started the sign-in.
  let gpInterface: GpInterface | undefined;
  // Lets a test replace any route.
  let override: ((request: RecordedRequest) => Response | undefined) | undefined;

  async function fetch(input: string, init: RequestInit): Promise<Response> {
    const request: RecordedRequest = {
      method: init.method ?? "GET",
      url: new URL(input),
      cookies: parseCookies(new Headers(init.headers).get("cookie")),
      headers: new Headers(init.headers),
      body: typeof init.body === "string" ? init.body : init.body ? String(init.body) : "",
    };
    requests.push(request);
    const routed = override?.(request);
    if (routed) return routed;
    if (request.url.hostname === SP) return serviceProvider(request);
    if (request.url.hostname === OKTA) return okta(request);
    if (request.url.hostname === GP) return globalProtect(request);
    return new Response("unknown host", { status: 502 });
  }

  function serviceProvider({ method, url, cookies, body }: RecordedRequest): Response {
    const signedIn = cookies.get("MoodleSession") === "authed";
    if (method === "GET" && (url.pathname === "/login/index.php" || url.pathname === "/my/")) {
      if (signedIn) return html("<p>You are logged in</p>");
      const location = `https://${OKTA}${APP_PATH}?SAMLRequest=request&RelayState=${encodeURIComponent(RELAY_STATE)}`;
      return redirect(location, [
        "MoodleSession=anon; Path=/; Secure; HttpOnly",
        "MDL_SSP_SessID=ssp-1; Path=/; Secure; HttpOnly",
      ]);
    }
    if (method === "POST" && url.pathname === ACS_PATH && options.acsRedirect) {
      return new Response(null, {
        status: options.acsRedirect,
        headers: { location: "/canonical-acs", "set-cookie": "acs-route=canonical; Path=/" },
      });
    }
    if (method === "POST" && (url.pathname === ACS_PATH || url.pathname === "/canonical-acs")) {
      const form = new URLSearchParams(body);
      const accepted =
        !options.spRejects &&
        form.get("SAMLResponse") === SAML_RESPONSE &&
        form.get("RelayState") === RELAY_STATE &&
        cookies.get("MDL_SSP_SessID") === "ssp-1";
      if (!accepted) return redirect(`https://${SP}/login/index.php`);
      return redirect(RELAY_STATE, ["MoodleSession=authed; Path=/; Secure; HttpOnly"]);
    }
    return new Response("not found", { status: 404 });
  }

  async function okta(request: RecordedRequest): Promise<Response> {
    const { method, url, cookies } = request;
    const cookieLines: string[] = [];
    if (!cookies.has("DT")) cookieLines.push(`DT=dt-${++issuedDevices}; Path=/; Max-Age=157680000; Secure; HttpOnly`);
    if (!cookies.has("JSESSIONID")) cookieLines.push("JSESSIONID=j-1; Path=/; Secure; HttpOnly");
    const hasSession = options.oktaSession || cookies.get("sid") === "okta-session";

    if ((method === "GET" && url.pathname === APP_PATH) || url.pathname === GP_APP_PATH) {
      if (url.pathname === GP_APP_PATH) {
        const samlRequest = method === "POST" ? new URLSearchParams(request.body).get("SAMLRequest") : null;
        if (method === "POST" && samlRequest !== "gprequest") return new Response("bad request", { status: 400 });
      }
      appPath = url.pathname;
      if (hasSession) return html(appPath === GP_APP_PATH ? gpSamlFormPage() : samlFormPage(), cookieLines);
      return html(`<script>var stateToken = '02.id.abc\\x2Ddef';</script>`, cookieLines);
    }
    if (method === "GET" && url.pathname === "/login/token/redirect") {
      return redirect(`https://${OKTA}${appPath}`, [...cookieLines, "sid=okta-session; Path=/; Secure; HttpOnly"]);
    }
    if (method !== "POST" || !url.pathname.startsWith("/idp/idx/")) return new Response("not found", { status: 404 });
    if (request.headers.get("accept") !== IDX || request.headers.get("content-type") !== IDX) {
      return new Response("not acceptable", { status: 406 });
    }

    const body = JSON.parse(request.body) as Record<string, any>;
    const handle = body.stateToken ?? body.stateHandle;
    if (handle !== STATE_TOKEN) return json(401, { messages: errorMessages("idx.session.expired") });

    switch (url.pathname) {
      case "/idp/idx/introspect":
        challenged = undefined;
        return json(200, identifyState(options.passwordOnIdentify ?? false));
      case "/idp/idx/identify": {
        if (body.identifier !== USERNAME) return json(400, { messages: errorMessages("idx.unknown.user") });
        if (!options.passwordOnIdentify) return json(200, passwordState());
        if (body.credentials?.passcode !== PASSWORD) return json(401, passwordState("incorrectPassword"));
        return json(200, afterPassword());
      }
      case "/idp/idx/challenge": {
        const chosen = enrollments.find((name) => ENROLLMENTS[name].id === body.authenticator?.id);
        if (!chosen) return json(400, { messages: errorMessages("unknown.authenticator") });
        if (chosen.startsWith("okta_verify") && body.authenticator.methodType !== "totp") {
          return json(400, { messages: errorMessages("push.not.expected") });
        }
        challenged = chosen;
        return json(200, otpState(chosen));
      }
      case "/idp/idx/challenge/answer": {
        if (!challenged) {
          if (body.credentials?.passcode !== PASSWORD) return json(401, passwordState("incorrectPassword"));
          return json(200, afterPassword());
        }
        const field = challenged === "google_otp" ? "passcode" : "totp";
        const expected = await totp(options.totpSecret ?? TOTP_SECRET, options.now());
        if (body.credentials?.[field] !== expected) return json(400, otpState(challenged, "api.authn.otp.invalid"));
        return json(200, {
          stateHandle: STATE_TOKEN,
          success: { name: "success-redirect", href: `https://${OKTA}/login/token/redirect?stateToken=${STATE_TOKEN}` },
        });
      }
    }
    return new Response("not found", { status: 404 });
  }

  function globalProtect({ method, url, headers, body }: RecordedRequest): Response {
    const prelogin = (Object.keys(PRELOGIN_PATHS) as GpInterface[]).find((name) => PRELOGIN_PATHS[name] === url.pathname);
    if (method === "POST" && prelogin) {
      if (headers.get("user-agent") !== "PAN GlobalProtect") return new Response("forbidden", { status: 403 });
      if (!(options.gpSaml ?? ["gateway", "portal"]).includes(prelogin)) {
        return xml("<prelogin-response><status>Error</status><msg>Gateway is not configured</msg></prelogin-response>");
      }
      gpInterface = prelogin;
      const binding = options.gpBinding ?? "REDIRECT";
      const request =
        binding === "REDIRECT"
          ? `https://${OKTA}${GP_APP_PATH}?SAMLRequest=gprequest&RelayState=${GP_RELAY_STATE}`
          : `<html><body><form id="myform" method="POST" action="https://${OKTA}${GP_APP_PATH}">` +
            `<input type="hidden" name="SAMLRequest" value="gprequest" />` +
            `<input type="hidden" name="RelayState" value="${GP_RELAY_STATE}" /></form></body></html>`;
      return xml(
        "<prelogin-response><status>Success</status><msg></msg>" +
          `<saml-auth-method>${binding}</saml-auth-method><saml-request>${btoa(request)}</saml-request>` +
          "<region>AU</region></prelogin-response>",
        ["PHPSESSID=gp-anon; Path=/; Secure; HttpOnly"],
      );
    }
    if (method === "POST" && url.pathname === GP_ACS_PATH) {
      const form = new URLSearchParams(body);
      const accepted =
        !options.spRejects && form.get("SAMLResponse") === SAML_RESPONSE && form.get("RelayState") === GP_RELAY_STATE;
      const fields: [string, string][] = accepted
        ? [
            ["saml-auth-status", "1"],
            ["saml-username", USERNAME],
            gpInterface === "portal" ? ["portal-userauthcookie", GP_COOKIE] : ["prelogin-cookie", GP_COOKIE],
            gpInterface === "portal" ? ["prelogin-cookie", "empty"] : ["portal-userauthcookie", "empty"],
          ]
        : [["saml-auth-status", "-1"]];
      if (options.gpResultIn === "comment") {
        const comment = fields.map(([name, value]) => `<${name}>${value}</${name}>`).join("");
        return html(`<html><!-- ${comment} --><body>Login Successful!</body></html>`);
      }
      return new Response("<html><body>Login Successful!</body></html>", { status: 200, headers: new Headers(fields) });
    }
    return new Response("not found", { status: 404 });
  }

  function afterPassword() {
    const select = selectState(enrollments);
    if (!options.preselect) return select;
    challenged = options.preselect;
    const challenge = otpState(options.preselect);
    return {
      ...select,
      ...challenge,
      remediation: { type: "array", value: [...challenge.remediation.value, ...select.remediation.value] },
    };
  }

  return {
    fetch,
    requests,
    setOverride(route: typeof override) {
      override = route;
    },
  };
}

export function samlFormPage(): string {
  const entities = (text: string) => text.replace(/[:/+]/g, (char) => `&#x${char.charCodeAt(0).toString(16)};`);
  return `<html><body onload="document.forms[0].submit()">
<form id="appForm" action="${entities(`https://${SP}${ACS_PATH}`)}" method="POST">
<input name="SAMLResponse" type="hidden" value="${entities(SAML_RESPONSE)}"/>
<input name="RelayState" type="hidden" value="${entities(RELAY_STATE)}"/>
</form></body></html>`;
}

// What Okta posts to the GlobalProtect ACS.
export function gpSamlFormPage(): string {
  return `<html><body onload="document.forms[0].submit()">
<form id="appForm" action="https&#x3a;&#x2f;&#x2f;${GP}${GP_ACS_PATH}" method="POST">
<input name="SAMLResponse" type="hidden" value="${SAML_RESPONSE.replace("+", "&#x2b;")}"/>
<input name="RelayState" type="hidden" value="${GP_RELAY_STATE}"/>
</form></body></html>`;
}

const stateHandleField = { name: "stateHandle", required: true, value: STATE_TOKEN, visible: false, mutable: false };

function idxHref(path: string): string {
  return `https://${OKTA}/idp/idx/${path}`;
}

function credentialsField(name: string, error?: string) {
  return {
    name: "credentials",
    type: "object",
    required: true,
    form: { value: [{ name, label: "Code", secret: true, ...(error && { messages: errorMessages(error) }) }] },
  };
}

function identifyState(withPassword: boolean) {
  return {
    version: "1.0.0",
    stateHandle: STATE_TOKEN,
    remediation: {
      type: "array",
      value: [
        {
          rel: ["create-form"],
          name: "identify",
          href: idxHref("identify"),
          method: "POST",
          value: [
            { name: "identifier", label: "Username", required: true },
            ...(withPassword ? [credentialsField("passcode")] : []),
            { name: "rememberMe", type: "boolean", label: "Keep me signed in" },
            stateHandleField,
          ],
        },
        { name: "redirect-idp", type: "MTLS", href: `https://${OKTA}/sso/idps/mtls`, method: "GET" },
      ],
    },
  };
}

function passwordState(error?: string) {
  return {
    version: "1.0.0",
    stateHandle: STATE_TOKEN,
    remediation: {
      type: "array",
      value: [
        {
          name: "challenge-authenticator",
          relatesTo: ["$.currentAuthenticatorEnrollment"],
          href: idxHref("challenge/answer"),
          method: "POST",
          value: [credentialsField("passcode", error), stateHandleField],
        },
      ],
    },
    currentAuthenticatorEnrollment: {
      type: "object",
      value: { type: "password", key: "okta_password", id: "aut-password", displayName: "Password" },
    },
  };
}

function selectState(enrollments: Enrollment[]) {
  return {
    version: "1.0.0",
    stateHandle: STATE_TOKEN,
    remediation: {
      type: "array",
      value: [
        {
          name: "select-authenticator-authenticate",
          href: idxHref("challenge"),
          method: "POST",
          value: [
            {
              name: "authenticator",
              type: "object",
              // Labels are deliberately unhelpful: the key comes from relatesTo.
              options: enrollments.map((name, index) => ({
                label: `Option ${index + 1}`,
                value: {
                  form: {
                    value: [
                      { name: "id", required: true, value: ENROLLMENTS[name].id, mutable: false },
                      ENROLLMENTS[name].methodType,
                    ],
                  },
                },
                relatesTo: `$.authenticatorEnrollments.value[${index}]`,
              })),
            },
            stateHandleField,
          ],
        },
      ],
    },
    authenticatorEnrollments: {
      type: "array",
      value: enrollments.map((name) => ({ key: ENROLLMENTS[name].key, id: ENROLLMENTS[name].id, type: "app" })),
    },
  };
}

function otpState(enrollment: Enrollment, error?: string) {
  return {
    version: "1.0.0",
    stateHandle: STATE_TOKEN,
    remediation: {
      type: "array",
      value: [
        {
          name: "challenge-authenticator",
          relatesTo: ["$.currentAuthenticatorEnrollment"],
          href: idxHref("challenge/answer"),
          method: "POST",
          value: [credentialsField(enrollment === "google_otp" ? "passcode" : "totp", error), stateHandleField],
        },
      ],
    },
    currentAuthenticatorEnrollment: {
      type: "object",
      value: { type: "app", key: ENROLLMENTS[enrollment].key, id: ENROLLMENTS[enrollment].id },
    },
  };
}

function errorMessages(key: string) {
  return { type: "array", value: [{ message: `Error ${key}`, i18n: { key }, class: "ERROR" }] };
}

function parseCookies(header: string | null): Map<string, string> {
  const cookies = new Map<string, string>();
  for (const pair of header?.split("; ") ?? []) {
    const equals = pair.indexOf("=");
    if (equals > 0) cookies.set(pair.slice(0, equals), pair.slice(equals + 1));
  }
  return cookies;
}

function withCookies(headers: Headers, cookies: string[]): Headers {
  for (const cookie of cookies) headers.append("set-cookie", cookie);
  return headers;
}

function html(body: string, cookies: string[] = []): Response {
  return new Response(body, { status: 200, headers: withCookies(new Headers({ "content-type": "text/html" }), cookies) });
}

function redirect(location: string, cookies: string[] = []): Response {
  return new Response(null, { status: 303, headers: withCookies(new Headers({ location }), cookies) });
}

function xml(body: string, cookies: string[] = []): Response {
  return new Response(body, { status: 200, headers: withCookies(new Headers({ "content-type": "application/xml" }), cookies) });
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": IDX } });
}
