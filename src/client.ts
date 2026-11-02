import { CookieJar } from "./cookies.js";
import { OktaSignInError, where } from "./errors.js";

export type Fetch = (input: string, init: RequestInit) => Promise<Response>;

export interface Page {
  url: URL;
  status: number;
  body: string;
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

  async send(url: URL, init: RequestInit = {}): Promise<Response> {
    if (url.protocol !== "https:") {
      throw new OktaSignInError("unexpected_step", `refusing a plain-HTTP request to ${where(url)}`);
    }
    // The service provider hands its AuthnRequest to the identity provider, so
    // the host that receives SAMLRequest is Okta. Knowing that before the first
    // request lets Okta see the device token from the start.
    if (url.searchParams.has("SAMLRequest")) this.useIdp(url.hostname);

    const headers = new Headers(init.headers);
    headers.set("user-agent", USER_AGENT);
    const cookie = this.jar.header(url);
    if (cookie) headers.set("cookie", cookie);

    let response: Response;
    try {
      response = await this.fetch(url.href, {
        ...init,
        headers,
        redirect: "manual",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (error) {
      const reason = error instanceof Error && error.name === "TimeoutError" ? "timed out" : "failed";
      throw new OktaSignInError("network", `request to ${where(url)} ${reason}`);
    }
    this.jar.store(url, response.headers);
    return response;
  }

  // Follows redirects the way a browser does after a form post: every hop is a
  // GET. That also keeps a SAMLResponse from being re-posted to a second host.
  async follow(url: URL, init?: RequestInit): Promise<Page> {
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const response = await this.send(url, init);
      const location = response.headers.get("location");
      if (response.status >= 300 && response.status < 400 && location) {
        await response.body?.cancel();
        url = new URL(location, url);
        init = undefined;
        continue;
      }
      return { url, status: response.status, body: await response.text() };
    }
    throw new OktaSignInError("unexpected_step", `more than ${MAX_REDIRECTS} redirects, last at ${where(url)}`);
  }
}
