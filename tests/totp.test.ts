import { describe, expect, it } from "vitest";
import { totp } from "../src/index.js";

// RFC 6238 Appendix B, SHA-1 rows. The seed is ASCII "12345678901234567890";
// the RFC prints 8 digits, and a 6-digit code is the last 6 of them.
const RFC_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_VECTORS: Array<[seconds: number, eightDigits: string]> = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
  [20000000000, "65353130"],
];

describe("totp", () => {
  it.each(RFC_VECTORS)("matches RFC 6238 at T=%i", async (seconds, eightDigits) => {
    expect(await totp(RFC_SEED, seconds * 1000)).toBe(eightDigits.slice(-6));
  });

  it("accepts secrets as authenticator apps show them", async () => {
    const spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
    expect(await totp(spaced, 59_000)).toBe("287082");
    expect(await totp(`${RFC_SEED}====`, 59_000)).toBe("287082");
  });

  it("rejects a malformed secret without echoing it", async () => {
    await expect(totp("not-base32!", 0)).rejects.toThrow(/^TOTP secret is not valid base32$/);
  });
});
