import { Client, type Fetch, type Page } from "./client.js";
import type { Cookie } from "./cookies.js";
import { OktaSignInError, where } from "./errors.js";
import { readSamlForm, readStateToken } from "./html.js";
import { errorKeys, nextStep, type Credentials, type IdxState, type Sends } from "./idx.js";
import { base32Decode } from "./totp.js";

export interface SignInOptions {
  // A page on the target site that sends signed-out visitors to Okta,
  // e.g. https://learning.monash.edu/login/index.php
  url: string;
  username: string;
  password: string;
  // Base32 secret of a Google Authenticator (or Okta Verify TOTP) enrollment.
  totpSecret?: string;
  // The `deviceToken` from an earlier sign-in. Okta keys "new device" checks
  // and sign-on emails to it.
  deviceToken?: string;
  fetch?: Fetch;
  // Milliseconds since the epoch. Drives TOTP codes and cookie expiry.
  now?: () => number;
}

export interface SignInResult {
  // Cookies the target site set, and only those.
  cookies: Cookie[];
  // Okta's DT cookie. Store it and pass it back next time.
  deviceToken: string | undefined;
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

  let page = await client.follow(target);
  if (page.status >= 400) throw httpError(page.status, page.url);

  // With a live Okta session, Okta answers with the SAML form straight away.
  if (!readSamlForm(page.body)) {
    const stateToken = readStateToken(page.body, page.url);
    client.useIdp(page.url.hostname);
    page = await authenticate(client, page.url.origin, stateToken, options, now);
  }

  const form = readSamlForm(page.body);
  if (!form) {
    throw new OktaSignInError("unexpected_step", `Okta finished without a SAML form at ${where(page.url)}`);
  }
  const acs = await client.follow(new URL(form.action, page.url), {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form.fields),
  });

  // Signed in means the page that sent us to Okta no longer does.
  const check = await client.follow(target);
  if (check.url.hostname !== target.hostname || check.status >= 400) {
    throw new OktaSignInError(
      "handoff_failed",
      `${where(target)} is still not signed in after the SAML post ` +
        `(${where(acs.url)} answered ${acs.status}; ${where(target)} now leads to ${where(check.url)}, ${check.status})`,
    );
  }

  const deviceToken = client.idpHost ? client.jar.get(client.idpHost, "DT")?.value : undefined;
  return {
    cookies: client.jar.list(target.hostname),
    deviceToken: deviceToken ?? options.deviceToken,
  };
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
    state = (await response.json()) as IdxState;
  } catch {
    state = undefined;
  }

  const keys = state ? errorKeys(state) : [];
  if (response.ok && state && !keys.length) return state;
  if (!state || response.status === 429 || response.status >= 500) throw httpError(response.status, url);

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
  if (!response.ok) throw httpError(response.status, url, reason);
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

function httpError(status: number, url: URL, detail = ""): OktaSignInError {
  return new OktaSignInError(`http_${status}`, `${where(url)} answered HTTP ${status}${detail}`);
}
