export interface Cookie {
  name: string;
  value: string;
  // Always the exact host that set the cookie. See CookieJar.
  domain: string;
  path: string;
  // Seconds since the epoch. Absent for session cookies.
  expires?: number;
  secure: boolean;
  httpOnly: boolean;
}

// A cookie jar that is stricter than a browser on purpose: every cookie belongs
// to the exact host that set it, and the Domain attribute is ignored. A sign-in
// hops between the target site and Okta, and neither should ever see the
// other's cookies.
export class CookieJar {
  private readonly hosts = new Map<string, Map<string, Cookie>>();

  constructor(private readonly now: () => number) {}

  store(url: URL, headers: Headers): void {
    for (const line of headers.getSetCookie()) {
      const cookie = parseSetCookie(line, url.hostname, this.now());
      if (cookie) this.set(cookie);
    }
  }

  set(cookie: Cookie): void {
    const cookies = this.hosts.get(cookie.domain) ?? new Map<string, Cookie>();
    this.hosts.set(cookie.domain, cookies);
    if (this.isExpired(cookie)) cookies.delete(cookie.name);
    else cookies.set(cookie.name, cookie);
  }

  get(host: string, name: string): Cookie | undefined {
    const cookie = this.hosts.get(host)?.get(name);
    return cookie && !this.isExpired(cookie) ? cookie : undefined;
  }

  list(host: string): Cookie[] {
    return [...(this.hosts.get(host)?.values() ?? [])].filter((cookie) => !this.isExpired(cookie));
  }

  header(url: URL): string | undefined {
    const pairs = this.list(url.hostname).map((cookie) => `${cookie.name}=${cookie.value}`);
    return pairs.length ? pairs.join("; ") : undefined;
  }

  private isExpired(cookie: Cookie): boolean {
    return cookie.expires !== undefined && cookie.expires * 1000 <= this.now();
  }
}

export function parseSetCookie(line: string, host: string, now: number): Cookie | undefined {
  const [pair = "", ...attributes] = line.split(";");
  const equals = pair.indexOf("=");
  if (equals <= 0) return undefined;

  const cookie: Cookie = {
    name: pair.slice(0, equals).trim(),
    value: pair.slice(equals + 1).trim(),
    domain: host,
    path: "/",
    secure: false,
    httpOnly: false,
  };
  let maxAge: number | undefined;
  for (const attribute of attributes) {
    const [rawKey = "", ...rest] = attribute.split("=");
    const key = rawKey.trim().toLowerCase();
    const value = rest.join("=").trim();
    if (key === "path" && value.startsWith("/")) cookie.path = value;
    else if (key === "secure") cookie.secure = true;
    else if (key === "httponly") cookie.httpOnly = true;
    else if (key === "max-age" && /^-?\d+$/.test(value)) maxAge = Number(value);
    else if (key === "expires") {
      const time = Date.parse(value);
      if (!Number.isNaN(time)) cookie.expires = Math.floor(time / 1000);
    }
  }
  // Max-Age wins over Expires (RFC 6265 §5.3).
  if (maxAge !== undefined) cookie.expires = Math.floor(now / 1000) + maxAge;
  return cookie;
}
