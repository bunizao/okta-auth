import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { OktaSignInError, type Fetch } from "../index.js";
import { saveKeychainConfig, saveOpConfig, readConfig } from "./config.js";
import { readCredentials, saveToKeychain, totpFrom1Password } from "./credentials.js";
import { signInAndSave } from "./login.js";
import { itemRefs, listLoginItems, OpError, rankOktaItems, runOp, type RunOp } from "./onepassword.js";

// `okta-auth setup`: a page on 127.0.0.1 that walks through choosing where the
// credentials live and trying a sign-in. Only someone holding the URL's random
// token gets an answer, and only under the exact Host the server listens on,
// so neither another site nor a DNS-rebound name can drive it.

export interface SetupOptions {
  // The command the page tells people to run.
  cli?: string;
  runOp?: RunOp;
  saveToKeychain?: typeof saveToKeychain;
  fetch?: Fetch;
}

export interface SetupServer {
  url: string;
  // Resolves when the page says it's done.
  done: Promise<void>;
  close(): void;
}

const MAX_BODY = 64 * 1024;
const HEADERS = {
  "Cache-Control": "no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy":
    "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; " +
    "img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

export async function startSetup(options: SetupOptions = {}): Promise<SetupServer> {
  const run = options.runOp ?? runOp;
  const token = randomBytes(24).toString("base64url");
  const page = await readFile(new URL("./setup.html", import.meta.url), "utf8");
  let finish!: () => void;
  const done = new Promise<void>((resolve) => (finish = resolve));

  const routes: Record<string, (body: Record<string, unknown>, res: ServerResponse) => Promise<unknown>> = {
    "GET /": async (_, res) => {
      res.writeHead(200, { ...HEADERS, "Content-Type": "text/html; charset=utf-8" }).end(page);
    },
    "GET /api/state": async () => {
      const config = await readConfig();
      const op = await run(["--version"]).then(
        () => true,
        () => false,
      );
      return { cli: options.cli ?? "okta-auth", provider: config.provider, op, keychain: process.platform === "darwin" && "macOS Keychain" };
    },
    "GET /api/op/items": async () => ({ items: rankOktaItems(await listLoginItems(run)) }),
    "POST /api/op/use": async (body) => {
      const id = text(body.id);
      const vault = text(body.vault);
      if (!id || !vault) throw new TypeError("choose a 1Password item");
      const refs = await itemRefs({ id, vault: { id: vault, name: "" } }, run);
      const file = await saveOpConfig(refs);
      return { file, totp: refs.totp !== undefined };
    },
    "POST /api/keychain": async (body) => {
      const username = text(body.username);
      const password = text(body.password);
      if (!username || !password) throw new TypeError("enter a username and password");
      const totpSecret = text(body.totpSecret)?.replace(/\s+/g, "").toUpperCase();
      await (options.saveToKeychain ?? saveToKeychain)({ username, password, totpSecret });
      await saveKeychainConfig();
      return { totp: totpSecret !== undefined };
    },
    "POST /api/test": async (body, res) => {
      const url = text(body.url);
      if (!url || !URL.canParse(url) || new URL(url).protocol !== "https:") throw new TypeError("enter an https:// URL");
      // One JSON object per line, so the page can show each step as it happens.
      res.writeHead(200, { ...HEADERS, "Content-Type": "application/x-ndjson" });
      const send = (event: object) => res.write(JSON.stringify(event) + "\n");
      try {
        const progress = (message: string) => send({ progress: message });
        const { username, password, totpSecret, totpRef } = await readCredentials({ onProgress: progress, runOp: run });
        if (!username || !password) throw new TypeError("no username or password saved yet");
        const totpCode = totpRef ? totpFrom1Password(totpRef, progress, run) : undefined;
        const saved = await signInAndSave(url, { username, password, totpSecret, totpCode }, progress, options.fetch);
        send({ ok: true, host: saved.host, cookies: saved.cookies });
      } catch (error) {
        send({ ok: false, ...describe(error) });
      }
      res.end();
    },
    "POST /api/done": async () => {
      setImmediate(finish);
      return {};
    },
  };

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500, HEADERS);
      res.end();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const { port } = server.address() as AddressInfo;
    const prefix = `/${token}`;
    const path = (req.url ?? "").split("?")[0]!;
    if (req.headers.host !== `127.0.0.1:${port}` || (path !== prefix && !path.startsWith(`${prefix}/`))) {
      res.writeHead(404, HEADERS).end();
      return;
    }
    if (path === prefix) {
      res.writeHead(302, { ...HEADERS, Location: `${prefix}/` }).end();
      return;
    }
    const route = routes[`${req.method} ${path.slice(prefix.length) || "/"}`];
    if (!route) {
      res.writeHead(404, HEADERS).end();
      return;
    }
    let body: Record<string, unknown> = {};
    if (req.method === "POST") {
      // A cross-site form can't send JSON with this content type.
      if (req.headers["content-type"] !== "application/json") {
        res.writeHead(415, HEADERS).end();
        return;
      }
      body = await readJson(req);
    }
    try {
      const result = await route(body, res);
      if (!res.headersSent) json(res, 200, result);
    } catch (error) {
      if (!res.headersSent) json(res, 400, describe(error));
      else res.end();
    }
  }

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/${token}/`,
    done,
    close: () => server.close(),
  };
}

// What the page may show about a failure. OktaSignInError and OpError messages
// are written to be safe to show; anything else is summarised.
function describe(error: unknown): { code: string; message: string } {
  if (error instanceof OktaSignInError) return { code: error.code, message: error.message };
  if (error instanceof OpError) return { code: "1password", message: error.message };
  if (error instanceof TypeError) return { code: "input", message: error.message };
  if (error instanceof Error && error.message.startsWith("security ")) return { code: "keychain", message: error.message };
  return { code: "unexpected", message: "something went wrong; the terminal running okta-auth setup may say more" };
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { ...HEADERS, "Content-Type": "application/json" }).end(JSON.stringify(body));
}

function text(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_BODY) throw new TypeError("request too large");
    chunks.push(chunk);
  }
  const data: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
  if (typeof data !== "object" || data === null || Array.isArray(data)) throw new TypeError("expected a JSON object");
  return data as Record<string, unknown>;
}

export function openBrowser(url: string): void {
  const [command, args] =
    process.platform === "darwin"
      ? ["open", [url]]
      : process.platform === "win32"
        ? ["cmd", ["/c", "start", "", url]]
        : ["xdg-open", [url]];
  execFile(command, args, () => {});
}
