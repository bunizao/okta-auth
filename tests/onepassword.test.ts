import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { readConfig, saveOpConfig } from "../src/cli/config.js";
import { readCredentials } from "../src/cli/credentials.js";
import { itemRefs, OpError, rankOktaItems, readTotpCode, totpSecretOf, type RunOp } from "../src/cli/onepassword.js";
import { totp } from "../src/index.js";

const SECRET = "JBSWY3DPEHPK3PXP";
const REFS = {
  OKTA_USERNAME: "op://Private/Okta/username",
  OKTA_PASSWORD: "op://Private/Okta/password",
  OKTA_TOTP_SECRET: "op://Private/Okta/one-time password",
};

let home: string;
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "okta-auth-op-"));
  process.env.OKTA_AUTH_HOME = home;
});
afterEach(async () => {
  delete process.env.OKTA_AUTH_HOME;
  await rm(home, { recursive: true, force: true });
});

async function use1Password(refs: Record<string, string> = REFS) {
  const envFile = join(home, "op.env");
  await writeFile(envFile, Object.entries(refs).map(([key, value]) => `${key}=${value}`).join("\n") + "\n");
  await writeFile(join(home, "config.json"), JSON.stringify({ credential_provider: "op", op_env_file: envFile }));
}

// A stand-in for op that answers `inject` from a table of reference values.
function fakeOp(values: Record<string, string>) {
  const calls: Array<{ args: string[]; stdin?: string }> = [];
  const run: RunOp = async (args, stdin) => {
    calls.push({ args, stdin });
    if (args[0] !== "inject") throw new OpError("op read exited with status 1", 1);
    return stdin!.replace(/\{\{ (.+?) \}\}/g, (_, ref: string) => values[ref] ?? "");
  };
  return { run, calls };
}

describe("readCredentials with 1Password", () => {
  it("reads the username and password with one op call and leaves the TOTP secret in 1Password", async () => {
    await use1Password();
    const op = fakeOp({ [REFS.OKTA_USERNAME]: "abcd0001", [REFS.OKTA_PASSWORD]: "hunter2" });
    const messages: string[] = [];

    const credentials = await readCredentials({ env: {}, runOp: op.run, onProgress: (m) => messages.push(m) });

    expect(credentials).toEqual({ username: "abcd0001", password: "hunter2", totpSecret: undefined, totpRef: REFS.OKTA_TOTP_SECRET });
    expect(op.calls).toHaveLength(1);
    expect(op.calls[0]!.stdin).not.toContain(REFS.OKTA_TOTP_SECRET);
    expect(messages).toEqual(["Reading the username and password from 1Password (approve it there if asked)"]);
  });

  it("reads the TOTP secret too when asked, out of an otpauth URI", async () => {
    await use1Password();
    const op = fakeOp({
      [REFS.OKTA_USERNAME]: "abcd0001",
      [REFS.OKTA_PASSWORD]: "hunter2",
      [REFS.OKTA_TOTP_SECRET]: `otpauth://totp/Okta:abcd0001?secret=${SECRET}&issuer=Okta`,
    });

    const credentials = await readCredentials({ env: {}, runOp: op.run, totpSecret: true });

    expect(credentials).toEqual({ username: "abcd0001", password: "hunter2", totpSecret: SECRET });
    expect(op.calls).toHaveLength(1);
  });

  it("lets the environment win over 1Password", async () => {
    await use1Password();
    const op = fakeOp({ [REFS.OKTA_USERNAME]: "abcd0001" });

    const credentials = await readCredentials({ env: { OKTA_PASSWORD: "from-env" }, runOp: op.run });

    expect(credentials.password).toBe("from-env");
    expect(op.calls[0]!.stdin).toBe(`{{ ${REFS.OKTA_USERNAME} }}\n`);
  });

  it("says why a 1Password read failed without op's output", async () => {
    await use1Password();
    const messages: string[] = [];
    const run: RunOp = async () => {
      throw new OpError("op inject exited with status 1", 1);
    };

    const credentials = await readCredentials({ env: {}, runOp: run, onProgress: (m) => messages.push(m) });

    expect(credentials.username).toBeUndefined();
    expect(credentials.password).toBeUndefined();
    expect(messages.at(-1)).toBe("Could not read the username and password from 1Password: op inject exited with status 1");
  });

  it("builds references from an older setup's vault and item names", async () => {
    await writeFile(
      join(home, "config.json"),
      JSON.stringify({ credential_provider: "op", op_vault: "Private", op_item: "Okta", op_env_file: join(home, "none.env") }),
    );

    expect((await readConfig()).opRefs).toEqual({
      OKTA_USERNAME: "op://Private/Okta/username",
      OKTA_PASSWORD: "op://Private/Okta/password",
      OKTA_TOTP_SECRET: "op://Private/Okta/totp_secret",
    });
  });
});

describe("readTotpCode", () => {
  const now = () => Date.UTC(2026, 10, 2, 3, 4, 5);

  it("asks 1Password for the current code", async () => {
    const calls: string[][] = [];
    const run: RunOp = async (args) => {
      calls.push(args);
      return "123456";
    };

    expect(await readTotpCode(REFS.OKTA_TOTP_SECRET, now, run)).toBe("123456");
    expect(calls).toEqual([["read", "--no-newline", `${REFS.OKTA_TOTP_SECRET}?attribute=otp`]]);
  });

  it("computes the code itself when the field holds a plain secret", async () => {
    const op = fakeOp({ [REFS.OKTA_TOTP_SECRET]: SECRET });

    expect(await readTotpCode(REFS.OKTA_TOTP_SECRET, now, op.run)).toBe(await totp(SECRET, now()));
  });

  it("doesn't try again when op is missing", async () => {
    let calls = 0;
    const run: RunOp = async () => {
      calls++;
      throw new OpError("the op command is not installed");
    };

    await expect(readTotpCode(REFS.OKTA_TOTP_SECRET, now, run)).rejects.toThrow("not installed");
    expect(calls).toBe(1);
  });
});

describe("1Password setup helpers", () => {
  it("refers to an item's fields by ID and keeps none of their values", async () => {
    const run: RunOp = async () =>
      JSON.stringify({
        fields: [
          { id: "username", type: "STRING", purpose: "USERNAME", value: "abcd0001" },
          { id: "password", type: "CONCEALED", purpose: "PASSWORD", value: "hunter2" },
          { id: "otpabc", type: "OTP", value: `otpauth://totp/x?secret=${SECRET}` },
        ],
      });

    const refs = await itemRefs({ id: "item1", vault: { id: "vault1", name: "Private" } }, run);

    expect(refs).toEqual({ username: "op://vault1/item1/username", password: "op://vault1/item1/password", totp: "op://vault1/item1/otpabc" });
    expect(JSON.stringify(refs)).not.toMatch(/hunter2|abcd0001|JBSW/);
  });

  it("puts items with an Okta URL first", () => {
    const item = (title: string, urls: string[]) => ({ id: title, title, vault: { id: "v", name: "v" }, urls });
    const ranked = rankOktaItems([item("Bank", ["https://bank.example"]), item("Monash", ["https://monash.okta.com/"])]);
    expect(ranked.map((entry) => entry.title)).toEqual(["Monash", "Bank"]);
  });

  it("writes references only, readable by the user alone, keeping other settings", async () => {
    await writeFile(join(home, "config.json"), JSON.stringify({ default_url: "https://learning.example.edu/" }));

    const envFile = await saveOpConfig({ username: "op://v/i/username", password: "op://v/i/password", totp: "op://v/i/otp" });

    expect(await readFile(envFile, "utf8")).toBe(
      "OKTA_USERNAME=op://v/i/username\nOKTA_PASSWORD=op://v/i/password\nOKTA_TOTP_SECRET=op://v/i/otp\n",
    );
    expect((await stat(envFile)).mode & 0o777).toBe(0o600);
    const config = JSON.parse(await readFile(join(home, "config.json"), "utf8"));
    expect(config).toMatchObject({ default_url: "https://learning.example.edu/", credential_provider: "op" });
    expect((await readConfig()).opRefs.OKTA_TOTP_SECRET).toBe("op://v/i/otp");
  });

  it("takes the secret out of an otpauth URI", () => {
    expect(totpSecretOf(`otpauth://totp/Okta?secret=${SECRET}&digits=6`)).toBe(SECRET);
    expect(totpSecretOf(` ${SECRET}\n`)).toBe(SECRET);
    expect(() => totpSecretOf("otpauth://totp/Okta?issuer=x")).toThrow(TypeError);
  });
});
