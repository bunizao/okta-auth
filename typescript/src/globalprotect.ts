import { Client, type Fetch, type Page } from "./client.js";
import { OktaSignInError, where } from "./errors.js";
import { decodeEntities, readSamlForm } from "./html.js";
import { deviceTokenOf, handOff, httpError, type Progress } from "./sign-in.js";
import { base32Decode } from "./totp.js";

export type GlobalProtectInterface = "gateway" | "portal";

export interface GlobalProtectOptions {
  // The portal or gateway host, e.g. vpn.gp.monash.edu
  server: string;
  // Whose prelogin to ask. Default: the gateway's, then the portal's if the
  // gateway doesn't offer SAML.
  interface?: GlobalProtectInterface;
  username: string;
  password: string;
  totpSecret?: string;
  // As for signIn: the current TOTP code, from a password manager.
  totpCode?: () => Promise<string>;
  deviceToken?: string;
  fetch?: Fetch;
  now?: () => number;
  // Called with a short message before each step; see SignInOptions.
  onProgress?: Progress;
}

export interface GlobalProtectResult {
  // The interface whose prelogin started the sign-in. With `cookieName` it makes
  // OpenConnect's --usergroup, e.g. gateway:prelogin-cookie.
  interface: GlobalProtectInterface;
  // The user name the ACS reported; OpenConnect's --user.
  user: string;
  cookieName: "prelogin-cookie" | "portal-userauthcookie";
  // One-time: OpenConnect reads it as the password (--passwd-on-stdin).
  cookie: string;
  deviceToken: string | undefined;
}

const PRELOGIN_PATHS: Record<GlobalProtectInterface, string> = {
  gateway: "/ssl-vpn/prelogin.esp",
  portal: "/global-protect/prelogin.esp",
};

// What the GlobalProtect client sends; some portals answer other clients differently.
const PRELOGIN_FIELDS = {
  tmp: "tmp",
  "kerberos-support": "yes",
  "ipv6-support": "yes",
  clientVer: "4100",
  clientos: "Mac",
};

const COOKIE_NAMES = ["prelogin-cookie", "portal-userauthcookie"] as const;
const RESULT_FIELDS = ["saml-auth-status", "saml-username", ...COOKIE_NAMES] as const;

interface SamlStart {
  interface: GlobalProtectInterface;
  method: string;
  // A URL for the REDIRECT binding, an auto-submitting HTML form for POST.
  request: string;
}

// Signs in to a GlobalProtect portal or gateway that uses Okta SAML, with plain
// HTTP, and returns the cookie OpenConnect connects with:
//
//   openconnect --protocol=gp --user=<user> --usergroup=<interface>:<cookieName> \
//     --passwd-on-stdin <server>   # and <cookie> on stdin
//
// Throws OktaSignInError like signIn does; `handoff_failed` here means the ACS
// answered without a cookie.
export async function signInGlobalProtect(options: GlobalProtectOptions): Promise<GlobalProtectResult> {
  const base = new URL(`https://${options.server}/`);
  if (base.host !== options.server.toLowerCase()) {
    throw new TypeError("server must be a host name such as vpn.example.edu");
  }
  if (options.totpSecret !== undefined) base32Decode(options.totpSecret);

  const now = options.now ?? Date.now;
  const client = new Client(options.fetch ?? ((input, init) => fetch(input, init)), now, options.deviceToken);

  const progress = options.onProgress ?? (() => {});
  const interfaces: GlobalProtectInterface[] = options.interface ? [options.interface] : ["gateway", "portal"];
  const start = await prelogin(client, base, interfaces, progress);
  const acs = await handOff(client, await openOkta(client, start), options, now, progress);
  const result = readResult(acs);

  return { interface: start.interface, ...result, deviceToken: deviceTokenOf(client, options.deviceToken) };
}

// Asks each interface's prelogin in turn and returns the first SAML request.
// Nothing reaches Okta until one offers SAML.
async function prelogin(
  client: Client,
  base: URL,
  interfaces: GlobalProtectInterface[],
  progress: Progress,
): Promise<SamlStart> {
  const asked: URL[] = [];
  for (const name of interfaces) {
    const url = new URL(PRELOGIN_PATHS[name], base);
    asked.push(url);
    progress(`Asking the ${name} at ${base.hostname} for SAML sign-in`);
    const page = await client.follow(url, {
      method: "POST",
      headers: { "user-agent": "PAN GlobalProtect", "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(PRELOGIN_FIELDS),
    });
    if (page.status === 429 || page.status >= 500) throw httpError(page.status, page.url);

    const method = xmlText(page.body, "saml-auth-method");
    const request = xmlText(page.body, "saml-request");
    if (xmlText(page.body, "status") === "Success" && method && request) {
      return { interface: name, method, request: decodeBase64(request, url) };
    }
  }
  throw new OktaSignInError("unexpected_step", `${asked.map(where).join(" and ")} did not offer SAML sign-in`);
}

// Delivers the SAML request to Okta and returns Okta's first page.
async function openOkta(client: Client, start: SamlStart): Promise<Page> {
  if (start.method === "REDIRECT") return client.follow(absoluteUrl(start.request));
  if (start.method !== "POST") {
    throw new OktaSignInError("unexpected_step", `GlobalProtect asked for an unknown SAML binding`);
  }

  const form = readSamlForm(start.request, "SAMLRequest");
  if (!form) throw new OktaSignInError("unexpected_step", "GlobalProtect's SAML request has no SAMLRequest form");
  const url = absoluteUrl(form.action);
  // The SAMLRequest travels in the body, so Client.send can't spot Okta itself.
  client.useIdp(url.hostname);
  return client.follow(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form.fields),
  });
}

// The ACS reports in response headers, or in an HTML comment of <tag>value</tag>
// pairs on older versions. An unused cookie field holds the literal "empty".
function readResult(acs: Page): Pick<GlobalProtectResult, "user" | "cookieName" | "cookie"> {
  const comments = [...acs.body.matchAll(/<!--([\s\S]*?)-->/g)].map((match) => match[1]!).join("");
  const values: Partial<Record<(typeof RESULT_FIELDS)[number], string>> = {};
  for (const name of RESULT_FIELDS) {
    const value = acs.headers.get(name) ?? xmlText(comments, name);
    if (value && value !== "empty") values[name] = value;
  }

  const status = values["saml-auth-status"];
  const cookieName = COOKIE_NAMES.find((name) => values[name]);
  const user = values["saml-username"];
  if ((status === undefined || status === "1") && cookieName && user) {
    return { user, cookieName, cookie: values[cookieName]! };
  }
  throw new OktaSignInError(
    "handoff_failed",
    `${where(acs.url)} returned no GlobalProtect cookie after the SAML post ` +
      `(HTTP ${acs.status}, saml-auth-status ${/^-?\d+$/.test(status ?? "") ? status : "missing"})`,
  );
}

function xmlText(xml: string, tag: string): string | undefined {
  const match = new RegExp(`<${tag}>([^<]*)</${tag}>`, "i").exec(xml);
  return match ? decodeEntities(match[1]!.trim()) : undefined;
}

function decodeBase64(text: string, source: URL): string {
  try {
    const bytes = Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new OktaSignInError("unexpected_step", `${where(source)} sent a SAML request that is not base64 text`);
  }
}

function absoluteUrl(text: string): URL {
  if (!URL.canParse(text)) {
    throw new OktaSignInError("unexpected_step", "GlobalProtect's SAML request points at no absolute URL");
  }
  return new URL(text);
}
