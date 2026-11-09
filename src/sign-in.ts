import { Client, type Fetch, type Page } from "./client.js";
import type { Cookie } from "./cookies.js";
import { OktaSignInError, where } from "./errors.js";
import { isLoginPage, readSamlForm, readStateToken } from "./html.js";
import { errorKeys, nextStep, type Credentials, type IdxState, type Sends } from "./idx.js";
import { base32Decode } from "./totp.js";

export interface SignInOptions {
  // A page on the target site that sends signed-out visitors to Okta,
  // e.g. https://learning.monash.edu/login/index.php. Or an Okta app link,
  // e.g. https://example.okta.com/app/example/exk1/sso/saml, for an app whose
  // sign-in starts at Okta (IdP-initiated SAML).
  url: string;
  username: string;
  password: string;
  // Base32 secret of a Google Authenticator (or Okta Verify TOTP) enrollment.
  totpSecret?: string;
  // The `deviceToken` from an earlier sign-in. Okta keys "new device" checks
  // and sign-on emails to it.
  deviceToken?: string;
  // `oktaSession` from an earlier result. While that session lasts, Okta skips
  // the password and one-time code. Each cookie only goes to its own host.
  oktaSession?: Cookie[];
  fetch?: Fetch;
  // Milliseconds since the epoch. Drives TOTP codes and cookie expiry.
  now?: () => number;
}

export interface SignInResult {
  // Cookies the target site set, and only those. For an Okta app link, the
  // cookies of the site the SAML post landed on.
  cookies: Cookie[];
  // Okta's DT cookie. Store it and pass it back next time.
  deviceToken: string | undefined;
  // Where the SAML post landed, redirects followed. It can carry one-time
  // tokens (OnTrack's authToken): read it, never log it.
  landingUrl: string;
  // Okta's session cookies, without DT. Pass them back as `oktaSession` to sign
  // in to another app without answering MFA again.
  oktaSession: Cookie[];
}

const MAX_IDX_STEPS = 8;
const IDX_CONTENT_TYPE = "application/ion+json; okta-version=1.0.0";

// Signs in to a SAML service provider through Okta Identity Engine with plain
// HTTP: no browser. Throws OktaSignInError; see its codes for what's retryable.
export async function signIn(options: SignInOptions): Promise<SignInResult> {
  const target = new URL(options.url);
  if (target.protocol !== "https:") throw new TypeError("url must be https");
  // Fail on a malformed secret before anything reaches Okta.
  if (options.totpSecret !== undefined) base32Decode(options.totpSecret);

  const now = options.now ?? Date.now;
  const client = new Client(options.fetch ?? ((input, init) => fetch(input, init)), now, options.deviceToken);
  for (const cookie of options.oktaSession ?? []) client.jar.set(cookie);

  const acs = await handOff(client, await client.follow(target), options, now);
  const signedIn = {
    deviceToken: deviceTokenOf(client, options.deviceToken),
    landingUrl: acs.url.href,
    oktaSession: client.idpHost ? client.jar.list(client.idpHost).filter((cookie) => cookie.name !== "DT") : [],
  };

  // An Okta app link: the app has no page of its own to ask again, so where the
  // SAML post landed is the only evidence.
  if (client.idpHost === target.hostname) {
    if (!landedInApp(acs, target.hostname)) {
      throw new OktaSignInError(
        "handoff_failed",
        `${where(target)} led to ${where(acs.url)} (${acs.status}) instead of the app after the SAML post`,
      );
    }
    return { cookies: client.jar.list(acs.url.hostname), ...signedIn };
  }

  // The target must finish with a successful response, without a login form.
  const check = await client.follow(target);
  if (check.url.hostname !== target.hostname || check.status < 200 || check.status >= 300 || isLoginPage(check.body)) {
    throw new OktaSignInError(
      "handoff_failed",
      `${where(target)} is still not signed in after the SAML post ` +
        `(${where(acs.url)} answered ${acs.status}; ${where(target)} now leads to ${where(check.url)}, ${check.status})`,
    );
  }

  return { cookies: client.jar.list(target.hostname), ...signedIn };
}

// Whether an IdP-initiated sign-in reached the app, judged only by the page the
// SAML post ended on (redirects already followed). `oktaHost` is the Okta host
// the sign-in started at.
function landedInApp(landing: Page, oktaHost: string): boolean {
  // Back at Okta means the app refused the response and sent us round again.
  if (landing.url.hostname === oktaHost) return false;
  // Same bar as the SP-initiated check: a 2xx page that is not a login form.
  return landing.status >= 200 && landing.status < 300 && !isLoginPage(landing.body);
}

// Takes Okta's first page through sign-in (unless Okta already has a session and
// answers with the SAML form) and posts the SAMLResponse to the service
// provider's ACS. Returns the ACS's answer, redirects followed.
export async function handOff(client: Client, page: Page, credentials: Credentials, now: () => number): Promise<Page> {
  if (page.status >= 400) throw httpError(page.status, page.url);

  if (!readSamlForm(page.body)) {
    const stateToken = readStateToken(page.body, page.url);
    client.useIdp(page.url.hostname);
    page = await authenticate(client, page.url.origin, stateToken, credentials, now);
  } else {
    // Okta already had a session and answered with the SAML form straight away.
    client.useIdp(page.url.hostname);
  }

  const form = readSamlForm(page.body);
  if (!form) {
    throw new OktaSignInError("unexpected_step", `Okta finished without a SAML form at ${where(page.url)}`);
  }
  return client.follow(new URL(form.action, page.url), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form.fields),
  });
}

// Okta's DT cookie after this sign-in, or the one the caller passed in.
export function deviceTokenOf(client: Client, previous: string | undefined): string | undefined {
  const current = client.idpHost ? client.jar.get(client.idpHost, "DT")?.value : undefined;
  return current ?? previous;
}

// Walks the IDX remediations until Okta reports success, then follows Okta's
// success link to the page carrying the SAML form.
async function authenticate(
  client: Client,
  origin: string,
  stateToken: string,
  credentials: Credentials,
  now: () => number,
): Promise<Page> {
  let state = await post(client, new URL("/idp/idx/introspect", origin), { stateToken }, undefined);
  for (let steps = 0; ; steps++) {
    if (state.success?.href) return client.follow(oktaUrl(state.success.href, origin));
    if (steps === MAX_IDX_STEPS) {
      throw new OktaSignInError("unexpected_step", `Okta still wants more after ${MAX_IDX_STEPS} steps`);
    }
    const step = await nextStep(state, credentials, now());
    state = await post(client, oktaUrl(step.href, origin), step.body, step.sends);
  }
}

async function post(client: Client, url: URL, body: object, sends: Sends): Promise<IdxState> {
  const response = await client.send(url, {
    method: "POST",
    headers: { accept: IDX_CONTENT_TYPE, "content-type": IDX_CONTENT_TYPE },
    body: JSON.stringify(body),
  });
  let state: IdxState | undefined;
  try {
    const parsed: unknown = JSON.parse(response.body);
    state = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as IdxState : undefined;
  } catch {
    state = undefined;
  }

  const keys = state ? errorKeys(state) : [];
  const ok = response.status >= 200 && response.status < 300;
  if (ok && state && !keys.length) return state;
  if (!state) {
    if (!ok) throw httpError(response.status, url);
    throw new OktaSignInError("unexpected_step", `${where(url)} returned an invalid IDX response`);
  }
  if (response.status === 429 || response.status >= 500) throw httpError(response.status, url);

  const reason = keys.length ? ` (${keys.join(", ")})` : "";
  if (sends === "identifier" || sends === "password") {
    throw new OktaSignInError(
      "credentials_rejected",
      `Okta rejected the ${sends === "password" ? "username or password" : "username"}${reason}. ` +
        "Not retried: repeated attempts can lock the account.",
    );
  }
  if (sends === "passcode") {
    throw new OktaSignInError("passcode_rejected", `Okta rejected the one-time code${reason}`);
  }
  if (!ok) throw httpError(response.status, url, reason);
  throw new OktaSignInError("unexpected_step", `Okta reported an error at ${where(url)}${reason}`);
}

// Credentials only ever go to the Okta host that served the sign-in page.
function oktaUrl(href: string, origin: string): URL {
  const url = new URL(href, origin);
  if (url.origin !== origin) {
    throw new OktaSignInError("unexpected_step", `Okta pointed a form at another host (${url.hostname})`);
  }
  return url;
}

export function httpError(status: number, url: URL, detail = ""): OktaSignInError {
  return new OktaSignInError(`http_${status}`, `${where(url)} answered HTTP ${status}${detail}`);
}
