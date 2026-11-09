import { describe, expect, it } from "vitest";
import { CookieJar } from "../src/cookies.js";

const url = new URL("https://sp.example/app/acs");
const now = () => Date.UTC(2026, 10, 2);

describe("CookieJar", () => {
  it("keeps same-name cookies on different paths", () => {
    const jar = new CookieJar(now);
    jar.store(url, new Headers({ "set-cookie": "session=root; Path=/; Secure" }));
    jar.store(url, new Headers({ "set-cookie": "session=app; Path=/app; Secure" }));

    expect(jar.list(url.hostname)).toHaveLength(2);
    expect(jar.header(url)).toBe("session=app; session=root");
    expect(jar.header(new URL("https://sp.example/other"))).toBe("session=root");
    expect(jar.header(new URL("https://sp.example/application"))).toBe("session=root");
    expect(jar.header(new URL("https://other.example/app"))).toBeUndefined();
  });

  it("deletes only the cookie with the matching path", () => {
    const jar = new CookieJar(now);
    jar.store(url, new Headers({ "set-cookie": "session=root; Path=/" }));
    jar.store(url, new Headers({ "set-cookie": "session=app; Path=/app" }));
    jar.store(url, new Headers({ "set-cookie": "session=gone; Path=/app; Max-Age=0" }));

    expect(jar.header(url)).toBe("session=root");
  });

  it("defaults missing or invalid cookie paths to the request directory", () => {
    for (const attribute of ["", "; Path=", "; Path=invalid"]) {
      const jar = new CookieJar(now);
      jar.store(url, new Headers({ "set-cookie": `session=app${attribute}` }));
      expect(jar.list(url.hostname)[0]?.path).toBe("/app");
      expect(jar.header(new URL("https://sp.example/app"))).toBe("session=app");
      expect(jar.header(new URL("https://sp.example/"))).toBeUndefined();
    }
    const jar = new CookieJar(now);
    jar.store(new URL("https://sp.example/login"), new Headers({ "set-cookie": "session=root" }));
    expect(jar.header(url)).toBe("session=root");
  });

  it("matches trailing-slash cookie paths without matching their parent", () => {
    const jar = new CookieJar(now);
    jar.store(url, new Headers({ "set-cookie": "session=app; Path=/app/" }));
    expect(jar.header(new URL("https://sp.example/app"))).toBeUndefined();
    expect(jar.header(url)).toBe("session=app");
  });
});
