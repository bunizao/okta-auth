import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeEach, describe, expect, it } from "vitest";
import {
  cookieHeader,
  deleteSessions,
  listSessions,
  readDeviceToken,
  readSession,
  saveDeviceToken,
  saveSession,
  sessionUrl,
} from "../src/cli/store.js";
import type { Cookie } from "../src/index.js";

const URL_A = "https://learning.example.edu/login/index.php";
const cookie = (name: string, domain = "learning.example.edu", expires?: number): Cookie => ({
  name,
  value: `${name}-value`,
  domain,
  path: "/",
  expires,
  secure: true,
  httpOnly: true,
});

let home: string;
beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), "okta-auth-"));
  process.env.OKTA_AUTH_HOME = home;
});

describe("session store", () => {
  it("exports only path-matching cookies from legacy sessions", async () => {
    const url = "https://learning.example.edu/app/page";
    await saveSession(url, [
      { ...cookie("session", ".learning.example.edu", -1), value: "root" },
      { ...cookie("session"), value: "app", path: "/app" },
      { ...cookie("other"), path: "/other" },
    ]);
    const session = (await readSession(url))!;

    expect(cookieHeader(url, session.cookies)).toBe("session=app; session=root");
    expect(cookieHeader("https://learning.example.edu/", session.cookies)).toBe("session=root");
    // JSON export retains the complete live cookie list for cookie-aware clients.
    expect(session.cookies).toHaveLength(3);
  });

  it("saves sessions readable only by the user", async () => {
    const file = await saveSession(URL_A, [cookie("MoodleSession")]);

    expect(file).toBe(join(home, "sessions", "learning.example.edu.json"));
    expect((await stat(file)).mode & 0o777).toBe(0o600);
    expect((await stat(join(home, "sessions"))).mode & 0o777).toBe(0o700);
    expect((await readSession(URL_A))?.cookies.map((c) => c.name)).toEqual(["MoodleSession"]);
  });

  it("reads the Python version's Playwright files, keeping only live target cookies", async () => {
    await saveSession(URL_A, []);
    const legacy = {
      cookies: [
        cookie("MoodleSession", "learning.example.edu", -1),
        cookie("old", "learning.example.edu", 1),
        cookie("DT", "example.okta.com"),
      ],
      origins: [],
    };
    await writeFile(join(home, "sessions", "learning.example.edu.json"), JSON.stringify(legacy));

    const [session] = await listSessions();
    expect(session?.url).toBe("https://learning.example.edu/");
    expect(session?.cookies.map((c) => c.name)).toEqual(["MoodleSession"]);
  });

  it("logs out without forgetting the device", async () => {
    await saveSession(URL_A, [cookie("MoodleSession")]);
    await saveDeviceToken(URL_A, "dt-1");

    expect((await deleteSessions(URL_A)).map((session) => session.url)).toEqual([URL_A]);
    expect(await readSession(URL_A)).toBeUndefined();
    expect(await readDeviceToken(URL_A)).toBe("dt-1");
    expect(JSON.parse(await readFile(join(home, "device-tokens.json"), "utf8"))).toEqual({ "learning.example.edu": "dt-1" });
  });

  it("saves an Okta app link's session under the site it landed on", () => {
    const appLink = "https://example.okta.com/app/example_ontrack/exk3/sso/saml";
    expect(sessionUrl(appLink, [cookie("doubtfire", "ontrack.example.edu")])).toBe("https://ontrack.example.edu/");
    expect(sessionUrl(URL_A, [cookie("MoodleSession")])).toBe(URL_A);
    expect(sessionUrl(appLink, [])).toBe(appLink);
  });
});
