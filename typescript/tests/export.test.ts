import { describe, expect, it } from "vitest";
import { exportJson, exportRefusal } from "../src/cli/export.js";

describe("export", () => {
  it("refuses without the dangerous flag, and refuses a terminal", () => {
    expect(exportRefusal(false, false)).toContain("--dangerously-print-password-and-totp-secret");
    expect(exportRefusal(true, true)).toContain("terminal");
    expect(exportRefusal(true, false)).toBeUndefined();
  });

  it("prints the names a Worker reads, leaving out a missing TOTP secret", () => {
    expect(JSON.parse(exportJson({ username: "u", password: "p", totpSecret: "JBSWY3DPEHPK3PXP" })!)).toEqual({
      OKTA_USERNAME: "u",
      OKTA_PASSWORD: "p",
      OKTA_TOTP_SECRET: "JBSWY3DPEHPK3PXP",
    });
    expect(JSON.parse(exportJson({ username: "u", password: "p" })!)).toEqual({ OKTA_USERNAME: "u", OKTA_PASSWORD: "p" });
    expect(exportJson({ username: "u" })).toBeUndefined();
  });
});
