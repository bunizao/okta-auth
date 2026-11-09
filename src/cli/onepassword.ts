import { execFile } from "node:child_process";
import { totp } from "../totp.js";

// Talks to the 1Password CLI. Errors say why op failed, never what it printed:
// its output can echo a reference or a secret.

export type RunOp = (args: string[], stdin?: string) => Promise<string>;

const TIMEOUT_MS = 20_000;

export class OpError extends Error {
  // op's exit status when it ran and failed; undefined when it never ran or timed out.
  readonly status: number | undefined;
  constructor(message: string, status?: number) {
    super(message);
    this.name = "OpError";
    this.status = status;
  }
}

export const runOp: RunOp = (args, stdin) =>
  new Promise((resolve, reject) => {
    const child = execFile("op", args, { timeout: TIMEOUT_MS, maxBuffer: 4 << 20 }, (error, stdout) => {
      if (!error) return resolve(stdout);
      const failure = error as NodeJS.ErrnoException & { killed?: boolean; code?: unknown };
      if (failure.code === "ENOENT") reject(new OpError("the op command is not installed"));
      else if (failure.killed) reject(new OpError(`op ${args[0]} timed out after ${TIMEOUT_MS / 1000}s`));
      else reject(new OpError(`op ${args[0]} exited with status ${String(failure.code)}`, Number(failure.code)));
    });
    child.stdin?.end(stdin ?? "");
  });

export function isOpRef(value: string): boolean {
  return value.startsWith("op://");
}

// Reads several references with one op call, so 1Password asks at most once.
export async function readRefs(refs: string[], run: RunOp = runOp): Promise<string[]> {
  if (!refs.length) return [];
  const output = await run(["inject"], refs.map((ref) => `{{ ${ref} }}`).join("\n") + "\n");
  const values = output.replace(/\r?\n$/, "").split(/\r?\n/);
  if (values.length !== refs.length) throw new OpError("op inject returned a value with a line break in it");
  return values;
}

// The current code of a 1Password one-time password field, so the secret never
// leaves 1Password. A field that holds a plain base32 secret has no code to
// give; for that one, read the secret and compute the code here.
export async function readTotpCode(ref: string, now: () => number, run: RunOp = runOp): Promise<string> {
  try {
    return (await run(["read", "--no-newline", `${ref}?attribute=otp`])).trim();
  } catch (error) {
    if (!(error instanceof OpError) || error.status === undefined) throw error;
  }
  const [value] = await readRefs([ref], run);
  return totp(totpSecretOf(value!), now());
}

// A TOTP secret as a 1Password field holds it: base32, or the otpauth:// URI
// of a one-time password field.
export function totpSecretOf(value: string): string {
  const text = value.trim();
  if (!text.startsWith("otpauth://")) return text;
  const secret = URL.canParse(text) ? new URL(text).searchParams.get("secret") : null;
  if (!secret) throw new TypeError("the TOTP field holds an otpauth:// URI without a secret");
  return secret;
}

export interface OpItem {
  id: string;
  title: string;
  vault: { id: string; name: string };
  urls: string[];
}

export interface OpItemRefs {
  username: string;
  password: string;
  totp?: string;
}

// Login items, for setup to offer. Titles and URLs only: no field values.
export async function listLoginItems(run: RunOp = runOp): Promise<OpItem[]> {
  const items = JSON.parse(await run(["item", "list", "--categories", "Login", "--format", "json"])) as Array<{
    id: string;
    title?: string;
    vault?: { id: string; name?: string };
    urls?: Array<{ href?: string }>;
  }>;
  return items.map((item) => ({
    id: item.id,
    title: item.title ?? "",
    vault: { id: item.vault?.id ?? "", name: item.vault?.name ?? "" },
    urls: (item.urls ?? []).flatMap((url) => (url.href ? [url.href] : [])),
  }));
}

// Okta-looking items first: a URL on *.okta.com or *.oktapreview.com, or the
// Okta host setup already knows.
export function rankOktaItems(items: OpItem[], oktaHost?: string): OpItem[] {
  const score = (item: OpItem) =>
    item.urls.some((href) => {
      const host = URL.canParse(href) ? new URL(href).hostname : "";
      return host === oktaHost || /(^|\.)okta(preview)?\.com$/.test(host);
    })
      ? 0
      : 1;
  return [...items].sort((a, b) => score(a) - score(b) || a.title.localeCompare(b.title));
}

// References to an item's username, password and one-time password fields, by
// ID so renaming the item or vault doesn't break them. The field values op
// prints are dropped right here.
export async function itemRefs(item: Pick<OpItem, "id" | "vault">, run: RunOp = runOp): Promise<OpItemRefs> {
  const detail = JSON.parse(await run(["item", "get", item.id, "--vault", item.vault.id, "--format", "json"])) as {
    fields?: Array<{ id: string; type?: string; purpose?: string }>;
  };
  const fields = (detail.fields ?? []).map(({ id, type, purpose }) => ({ id, type, purpose }));
  const ref = (fieldId: string) => `op://${item.vault.id}/${item.id}/${fieldId}`;
  const username = fields.find((field) => field.purpose === "USERNAME");
  const password = fields.find((field) => field.purpose === "PASSWORD");
  if (!username || !password) throw new OpError("that 1Password item has no username or password field");
  const otp = fields.find((field) => field.type === "OTP");
  return { username: ref(username.id), password: ref(password.id), ...(otp && { totp: ref(otp.id) }) };
}
