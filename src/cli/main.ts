#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { OktaSignInError, signIn, signInGlobalProtect, type GlobalProtectInterface } from "../index.js";
import { readCredentials } from "./credentials.js";
import { deleteSessions, listSessions, readDeviceToken, readSession, saveDeviceToken, saveSession } from "./store.js";

const USAGE = `Usage: okta-auth <command> [--json]

Commands:
  login <url>     Sign in through Okta and save the cookies <url>'s site sets
  status          List saved sessions
  cookies <url>   Print the saved cookies as a Cookie header (--json: full list)
  logout [url]    Delete the saved session for <url>, or every session
  globalprotect <server> [--interface gateway|portal]
                  Sign in to a GlobalProtect portal or gateway and print the
                  one-time cookie for OpenConnect as JSON

Credentials come from OKTA_USERNAME, OKTA_PASSWORD and OKTA_TOTP_SECRET, or else
from the macOS Keychain: service "okta-auth", accounts "username", "password"
and "totp_secret".

Sessions live in ~/.okta-auth/sessions (mode 0600).`;

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      interface: { type: "string" },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    },
  });
  const [command, url] = positionals;
  const json = values.json;

  if (values.version) {
    const manifest = JSON.parse(await readFile(new URL("../../package.json", import.meta.url), "utf8"));
    console.log(manifest.version);
    return 0;
  }
  if (values.help || !command) {
    console.log(USAGE);
    return values.help ? 0 : 1;
  }

  switch (command) {
    case "login":
      return login(requireUrl(url), json);
    case "status":
      return status(json);
    case "cookies":
      return cookies(requireUrl(url), json);
    case "logout":
      return logout(url, json);
    case "globalprotect":
      return globalProtect(url, values.interface);
    default:
      console.error(`okta-auth: unknown command "${command}"\n\n${USAGE}`);
      return 1;
  }
}

async function login(url: string, json: boolean): Promise<number> {
  const credentials = await requireCredentials();
  if (!credentials) return 1;

  const result = await signIn({ url, ...credentials, deviceToken: await readDeviceToken(url) });
  const file = await saveSession(url, result.cookies);
  await saveDeviceToken(url, result.deviceToken);

  const host = new URL(url).host;
  if (json) console.log(JSON.stringify({ host, cookies: result.cookies.length, file }, null, 2));
  else console.log(`Signed in to ${host}; saved ${result.cookies.length} cookies to ${file}`);
  return 0;
}

// Always JSON: the output is for a script that hands `cookie` to OpenConnect on
// stdin. Nothing is saved; the cookie works once.
async function globalProtect(server: string | undefined, iface: string | undefined): Promise<number> {
  if (!server) throw new TypeError("this command needs a server, e.g. vpn.gp.monash.edu");
  if (iface !== undefined && iface !== "gateway" && iface !== "portal") {
    throw new TypeError('--interface must be "gateway" or "portal"');
  }
  const credentials = await requireCredentials();
  if (!credentials) return 1;

  const tokenKey = `https://${server}/`;
  const result = await signInGlobalProtect({
    server,
    interface: iface as GlobalProtectInterface | undefined,
    ...credentials,
    deviceToken: await readDeviceToken(tokenKey),
  });
  await saveDeviceToken(tokenKey, result.deviceToken);

  const { deviceToken: _, ...output } = result;
  console.log(JSON.stringify({ server, ...output }, null, 2));
  return 0;
}

async function requireCredentials(): Promise<{ username: string; password: string; totpSecret?: string } | undefined> {
  const { username, password, totpSecret } = await readCredentials();
  if (username && password) return { username, password, totpSecret };
  console.error(
    "okta-auth: no credentials. Set OKTA_USERNAME and OKTA_PASSWORD (and OKTA_TOTP_SECRET), " +
      'or store them in the Keychain under service "okta-auth"; see `okta-auth --help`.',
  );
  return undefined;
}

async function status(json: boolean): Promise<number> {
  const sessions = await listSessions();
  if (json) {
    const rows = sessions.map(({ url, savedAt, cookies, file }) => ({ url, savedAt, cookies: cookies.length, file }));
    console.log(JSON.stringify(rows, null, 2));
  } else if (!sessions.length) {
    console.log("No saved sessions.");
  } else {
    for (const session of sessions) {
      const saved = session.savedAt ? `saved ${session.savedAt}` : "saved by an older version";
      console.log(`${new URL(session.url).host}  ${saved}  ${session.cookies.length} cookies`);
    }
  }
  return 0;
}

async function cookies(url: string, json: boolean): Promise<number> {
  const session = await readSession(url);
  if (!session?.cookies.length) {
    console.error(`okta-auth: no saved cookies for ${new URL(url).host}. Run: okta-auth login ${url}`);
    return 1;
  }
  if (json) console.log(JSON.stringify(session.cookies, null, 2));
  else console.log(session.cookies.map((cookie) => `${cookie.name}=${cookie.value}`).join("; "));
  return 0;
}

async function logout(url: string | undefined, json: boolean): Promise<number> {
  const removed = await deleteSessions(url === undefined ? undefined : checkUrl(url));
  const hosts = removed.map((session) => new URL(session.url).host);
  if (json) console.log(JSON.stringify({ removed: hosts }, null, 2));
  else if (!hosts.length) console.log(url ? `No saved session for ${new URL(url).host}.` : "No saved sessions.");
  else console.log(`Removed ${hosts.length === 1 ? "the session" : `${hosts.length} sessions`}: ${hosts.join(", ")}`);
  return 0;
}

function requireUrl(url: string | undefined): string {
  if (!url) throw new TypeError("this command needs a URL, e.g. https://learning.monash.edu/login/index.php");
  return checkUrl(url);
}

function checkUrl(url: string): string {
  if (!URL.canParse(url)) throw new TypeError(`not a URL: ${url}`);
  return url;
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    if (error instanceof OktaSignInError) {
      console.error(`okta-auth: ${error.code}: ${error.message}`);
    } else {
      console.error(`okta-auth: ${error instanceof Error ? error.message : String(error)}`);
    }
    process.exitCode = 1;
  },
);
