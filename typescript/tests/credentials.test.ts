import { describe, expect, it } from "vitest";
import { parseCredentials } from "../src/cli/credentials.js";

describe("parseCredentials", () => {
  it("reads the Keychain-style JSON object", () => {
    expect(parseCredentials('{"username":"u","password":"p","totp_secret":"JBSWY3DPEHPK3PXP"}\n')).toEqual({
      username: "u",
      password: "p",
      totpSecret: "JBSWY3DPEHPK3PXP",
    });
  });

  it("treats missing or empty fields as absent", () => {
    expect(parseCredentials('{"username":"u","password":""}')).toEqual({
      username: "u",
      password: undefined,
      totpSecret: undefined,
    });
  });

  it("refuses anything but an object without echoing it", () => {
    for (const input of ["", "not json hunter2", '["hunter2"]', "null"]) {
      expect(() => parseCredentials(input)).toThrow(TypeError);
      try {
        parseCredentials(input);
      } catch (error) {
        expect((error as Error).message).not.toContain("hunter2");
      }
    }
  });
});
