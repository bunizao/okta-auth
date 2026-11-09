import { chmod, mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { CookieJar } from "../cookies.js";
import type { Cookie } from "../index.js";

// Session files are JSON cookie jars, one per target host, readable only by the
// user. Device tokens live apart so `logout` doesn't make Okta see a new device.

export interface Session {
  url: string;
  savedAt?: string;
  cookies: Cookie[];
}

export interface SavedSession extends Session {
  file: string;
}

export function dataDir(): string {
  return process.env.OKTA_AUTH_HOME ?? join(homedir(), ".okta-auth");
}

function sessionsDir(): string {
  return join(dataDir(), "sessions");
}

// The file name the Python version used too, so its sessions still read.
function sessionFile(url: string): string {
  return join(sessionsDir(), `${new URL(url).host.replace(/:/g, "_")}.json`);
}

export async function saveSession(url: string, cookies: Cookie[]): Promise<string> {
  const file = sessionFile(url);
  const session: Session = { url, savedAt: new Date().toISOString(), cookies };
  await writeSecret(file, session);
  return file;
}

// The URL a signed-in session is saved under. An Okta app link signs in to the
// site the SAML post landed on, so the cookies belong to that site, not to Okta.
export function sessionUrl(url: string, cookies: Cookie[]): string {
  const site = cookies[0]?.domain;
  return site && site !== new URL(url).hostname ? `https://${site}/` : url;
}

export async function readSession(url: string): Promise<SavedSession | undefined> {
  return readSessionFile(sessionFile(url), new URL(url).host);
}

export function cookieHeader(url: string, cookies: Cookie[]): string | undefined {
  const jar = new CookieJar(Date.now);
  for (const cookie of cookies) {
    jar.set({
      ...cookie,
      domain: cookie.domain.replace(/^\./, ""),
      path: cookie.path || "/",
      // Legacy Playwright files use -1 for session cookies.
      expires: cookie.expires !== undefined && cookie.expires > 0 ? cookie.expires : undefined,
    });
  }
  return jar.header(new URL(url));
}

export async function listSessions(): Promise<SavedSession[]> {
  const names = await readdir(sessionsDir()).catch(() => [] as string[]);
  const sessions = await Promise.all(
    names
      .filter((name) => name.endsWith(".json") && !name.endsWith(".meta.json"))
      .map((name) => readSessionFile(join(sessionsDir(), name), name.slice(0, -".json".length).replace(/_/g, ":"))),
  );
  return sessions.filter((session) => session !== undefined);
}

// Removes the session for `url`, or every session when `url` is undefined.
export async function deleteSessions(url?: string): Promise<SavedSession[]> {
  const sessions = url ? [await readSession(url)].filter((session) => session !== undefined) : await listSessions();
  for (const { file } of sessions) {
    await rm(file, { force: true });
    await rm(file.replace(/\.json$/, ".meta.json"), { force: true });
  }
  return sessions;
}

export async function readDeviceToken(url: string): Promise<string | undefined> {
  return (await readDeviceTokens())[new URL(url).host];
}

export async function saveDeviceToken(url: string, token: string | undefined): Promise<void> {
  if (!token) return;
  const tokens = await readDeviceTokens();
  if (tokens[new URL(url).host] === token) return;
  await writeSecret(join(dataDir(), "device-tokens.json"), { ...tokens, [new URL(url).host]: token });
}

async function readDeviceTokens(): Promise<Record<string, string>> {
  return readJson<Record<string, string>>(join(dataDir(), "device-tokens.json")).then((tokens) => tokens ?? {});
}

// `host` is URL.host, port included, as encoded in the file name.
async function readSessionFile(file: string, host: string): Promise<SavedSession | undefined> {
  const data = await readJson<Partial<Session>>(file);
  if (!data || !Array.isArray(data.cookies)) return undefined;
  const url = data.url ?? `https://${host}/`;
  const cookieHost = host.replace(/:\d+$/, "");
  // Old Playwright files hold every host's cookies; keep the target's. A
  // non-positive `expires` is how Playwright marks a session cookie.
  const cookies = data.cookies.filter((cookie) => {
    const expires = cookie.expires ?? 0;
    return cookie.domain.replace(/^\./, "") === cookieHost && (expires <= 0 || expires * 1000 > Date.now());
  });
  return { url, savedAt: data.savedAt, cookies, file };
}

async function readJson<T>(file: string): Promise<T | undefined> {
  try {
    return JSON.parse(await readFile(file, "utf8")) as T;
  } catch {
    return undefined;
  }
}

async function writeSecret(file: string, data: unknown): Promise<void> {
  await mkdir(join(file, ".."), { recursive: true, mode: 0o700 });
  await writeFile(file, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600 });
  // writeFile's mode only applies to new files.
  await chmod(file, 0o600);
}
