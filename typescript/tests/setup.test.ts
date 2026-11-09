import { request } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { RunOp } from "../src/cli/onepassword.js";
import { startSetup, type SetupServer } from "../src/cli/setup.js";
import { totp } from "../src/index.js";
import { fakeSso, PASSWORD, TARGET, TOTP_SECRET, USERNAME } from "./fake-sso.js";

let home: string;
let server: SetupServer | undefined;
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "okta-auth-setup-"));
  process.env.OKTA_AUTH_HOME = home;
});
afterEach(async () => {
  server?.close();
  server = undefined;
  delete process.env.OKTA_AUTH_HOME;
  await rm(home, { recursive: true, force: true });
});

// A 1Password with one Okta login whose one-time password field gives codes.
function fakeOp() {
  const calls: string[][] = [];
  const run: RunOp = async (args, stdin) => {
    calls.push(args);
    if (args[0] === "--version") return "2.30.0\n";
    if (args[0] === "item" && args[1] === "list") {
      return JSON.stringify([
        { id: "bank", title: "Bank", vault: { id: "v1", name: "Private" }, urls: [{ href: "https://bank.example" }] },
        { id: "okta", title: "Uni", vault: { id: "v1", name: "Private" }, urls: [{ href: "https://uni.okta.com" }] },
      ]);
    }
    if (args[0] === "item" && args[1] === "get") {
      return JSON.stringify({
        fields: [
          { id: "username", purpose: "USERNAME", value: USERNAME },
          { id: "password", purpose: "PASSWORD", value: PASSWORD },
          { id: "otp1", type: "OTP", value: `otpauth://totp/x?secret=${TOTP_SECRET}` },
        ],
      });
    }
    if (args[0] === "inject") {
      return stdin!
        .replace("{{ op://v1/okta/username }}", USERNAME)
        .replace("{{ op://v1/okta/password }}", PASSWORD);
    }
    if (args[0] === "read" && args[2] === "op://v1/okta/otp1?attribute=otp") return totp(TOTP_SECRET, Date.now());
    throw new Error(`unexpected op ${args.join(" ")}`);
  };
  return { run, calls };
}

async function post(path: string, body: unknown): Promise<Response> {
  return fetch(new URL(path, server!.url), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

function rawGet(url: string, host: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    request({ host: target.hostname, port: target.port, path: target.pathname, headers: { Host: host } }, (res) => {
      res.resume();
      resolve(res.statusCode!);
    })
      .on("error", reject)
      .end();
  });
}

describe("okta-auth setup", () => {
  it("answers only under its token and its own Host", async () => {
    server = await startSetup({ runOp: fakeOp().run });
    const url = new URL(server.url);

    expect((await fetch(server.url)).status).toBe(200);
    expect((await fetch(`${url.origin}/`)).status).toBe(404);
    expect((await fetch(`${url.origin}/wrong-token/`)).status).toBe(404);
    // A DNS-rebound name reaches the same socket with another Host.
    expect(await rawGet(server.url, `evil.example:${url.port}`)).toBe(404);
  });

  it("refuses a POST that isn't JSON, so a cross-site form can't drive it", async () => {
    server = await startSetup({ runOp: fakeOp().run });
    const response = await fetch(new URL("api/done", server.url), { method: "POST", body: "x=1" });
    expect(response.status).toBe(415);
  });

  it("saves a 1Password login as references and signs in with a code from 1Password", async () => {
    const op = fakeOp();
    const fake = fakeSso({ now: Date.now });
    server = await startSetup({ runOp: op.run, fetch: fake.fetch });

    const { items } = (await (await fetch(new URL("api/op/items", server.url))).json()) as { items: Array<{ id: string }> };
    expect(items.map((item) => item.id)).toEqual(["okta", "bank"]);

    const used = await (await post("api/op/use", { id: "okta", vault: "v1" })).json();
    expect(used).toMatchObject({ totp: true });
    const opEnv = await readFile(join(home, "op.env"), "utf8");
    expect(opEnv).toContain("OKTA_TOTP_SECRET=op://v1/okta/otp1");
    expect(opEnv).not.toContain(PASSWORD);

    const stream = await (await post("api/test", { url: TARGET })).text();
    const events = stream.trim().split("\n").map((line) => JSON.parse(line));
    expect(events.at(-1)).toMatchObject({ ok: true, host: new URL(TARGET).host });
    expect(events.map((event) => event.progress)).toContain("Asking 1Password for a TOTP code");
    for (const secret of [PASSWORD, TOTP_SECRET]) expect(stream).not.toContain(secret);
    // The secret itself never left 1Password: only codes were read.
    expect(op.calls.some((args) => args[0] === "read" && !args[2]!.endsWith("?attribute=otp"))).toBe(false);
  });

  it("saves to the Keychain and notes a missing TOTP secret", async () => {
    const saved: unknown[] = [];
    server = await startSetup({
      runOp: fakeOp().run,
      saveToKeychain: async (values) => {
        saved.push(values);
      },
    });

    const response = await post("api/keychain", { username: "u", password: "p", totpSecret: "jbsw y3dp ehpk 3pxp" });
    expect(await response.json()).toEqual({ totp: true });
    expect(saved).toEqual([{ username: "u", password: "p", totpSecret: "JBSWY3DPEHPK3PXP" }]);
    expect(JSON.parse(await readFile(join(home, "config.json"), "utf8"))).toMatchObject({ credential_provider: "keyring" });

    const missing = await post("api/keychain", { username: "u" });
    expect(missing.status).toBe(400);
  });

  it("finishes when the page says done", async () => {
    server = await startSetup({ runOp: fakeOp().run });
    await post("api/done", {});
    await expect(server.done).resolves.toBeUndefined();
  });
});
