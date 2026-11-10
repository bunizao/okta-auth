import { CookieJar } from "./cookies.js";
import { OktaSignInError, where } from "./errors.js";

export type Fetch = (input: string, init: RequestInit) => Promise<Response>;

export interface Page {
  url: URL;
  status: number;
  headers: Headers;
  body: string;
  // Hosts the redirects passed through before this page, in order.
  via?: string[];
}

const MAX_REDIRECTS = 10;
const TIMEOUT_MS = 15_000;
const USER_AGENT = "okta-auth-cli (+https://github.com/bunizao/okta-auth)";

// One sign-in's worth of HTTP: a host-scoped cookie jar, manual redirects, a
// timeout per request, and HTTPS only.
export class Client {
  readonly jar: CookieJar;
  // The Okta host, once known. It is the only host that gets the device token.
  idpHost: string | undefined;

  constructor(
    private readonly fetch: Fetch,
    now: () => number,
    private readonly deviceToken?: string,
  ) {
    this.jar = new CookieJar(now);
  }

  useIdp(host: string): void {
    if (this.idpHost) return;
    this.idpHost = host;
    if (this.deviceToken) {
      this.jar.set({
        name: "DT",
        value: this.deviceToken,
        domain: host,
        path: "/",
        secure: true,
        httpOnly: true,
      });
    }
  }

  async send(url: URL, init: RequestInit = {}): Promise<Page> {
    if (url.protocol !== "https:") {
      throw new OktaSignInError("unexpected_step", `refusing a plain-HTTP request to ${where(url)}`);
    }
    // The service provider hands its AuthnRequest to the identity provider, so
    // the host that receives SAMLRequest is Okta. Knowing that before the first
    // request lets Okta see the device token from the start.
    if (url.searchParams.has("SAMLRequest")) this.useIdp(url.hostname);

    const headers = new Headers(init.headers);
    if (!headers.has("user-agent")) headers.set("user-agent", USER_AGENT);
    const cookie = this.jar.header(url);
    if (cookie) headers.set("cookie", cookie);

    try {
      const response = await this.fetch(url.href, {
        ...init,
        headers,
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      // fetch resolves at the headers; the body can still time out or disconnect.
      const body = await response.text();
      this.jar.store(url, response.headers);
      return { url, status: response.status, headers: response.headers, body };
    } catch (error) {
      const reason = error instanceof Error && error.name === "TimeoutError" ? "timed out" : "failed";
      throw new OktaSignInError("network", `request to ${where(url)} ${reason}`);
    }
  }

  // Preserve POSTs on same-origin 307/308 redirects, but never replay a SAML
  // response to a different origin. Ordinary form redirects switch to GET.
  async follow(url: URL, init?: RequestInit): Promise<Page> {
    const via: string[] = [];
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const response = await this.send(url, init);
      const location = response.headers.get("location");
      if ([301, 302, 303, 307, 308].includes(response.status) && location) {
        const next = new URL(location, url);
        const preserve = response.status === 307 || response.status === 308;
        const method = (init?.method ?? "GET").toUpperCase();
        if (preserve && next.origin !== url.origin && method !== "GET" && method !== "HEAD") {
          throw new OktaSignInError("unexpected_step", `refusing to replay a form to another origin (${where(next)})`);
        }
        via.push(url.hostname);
        url = next;
        if (!preserve) init = undefined;
        continue;
      }
      return { ...response, via };
    }
    throw new OktaSignInError("unexpected_step", `more than ${MAX_REDIRECTS} redirects, last at ${where(url)}`);
  }
}
