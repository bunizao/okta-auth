import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Progress } from "../index.js";
import { readConfig, type EnvName } from "./config.js";
import { isOpRef, OpError, readRefs, readTotpCode, runOp, totpSecretOf, type RunOp } from "./onepassword.js";

// Same Keychain service and account names the Python version's keyring backend
// wrote, so an existing `okta config` setup keeps working.
const KEYCHAIN_SERVICE = "okta-auth";

export interface StoredCredentials {
  username?: string;
  password?: string;
  totpSecret?: string;
  // A 1Password reference to the TOTP field. Sign-in asks 1Password for the
  // current code through it, so the secret itself stays in 1Password.
  totpRef?: string;
}

export interface ReadOptions {
  // Read the TOTP secret itself, even from 1Password (for `export`).
  totpSecret?: boolean;
  onProgress?: Progress;
  runOp?: RunOp;
  env?: NodeJS.ProcessEnv;
}

const KEYCHAIN_ACCOUNTS: Record<EnvName, string> = {
  OKTA_USERNAME: "username",
  OKTA_PASSWORD: "password",
  OKTA_TOTP_SECRET: "totp_secret",
};

// Each value comes from the environment first (works with `op run` and CI),
// then from where `okta setup` put it: 1Password references or the Keychain.
// Any value may be an op:// reference; all of them are read with one op call.
export async function readCredentials(options: ReadOptions = {}): Promise<StoredCredentials> {
  const env = options.env ?? process.env;
  const progress = options.onProgress ?? (() => {});
  const config = await readConfig();
  const pick = async (name: EnvName) =>
    env[name] || config.opRefs[name] || (config.provider === "keyring" ? await keychain(KEYCHAIN_ACCOUNTS[name]) : undefined);

  const values = {
    username: await pick("OKTA_USERNAME"),
    password: await pick("OKTA_PASSWORD"),
    totp: await pick("OKTA_TOTP_SECRET"),
  };
  // A TOTP reference is read now only when the secret itself is wanted.
  const toRead = (Object.keys(values) as Array<keyof typeof values>).filter((key) => {
    const value = values[key];
    return value !== undefined && isOpRef(value) && (key !== "totp" || options.totpSecret);
  });
  if (toRead.length) {
    const names = toRead.map((key) => (key === "totp" ? "TOTP secret" : key));
    const what = names.length > 1 ? `${names.slice(0, -1).join(", ")} and ${names.at(-1)}` : names[0];
    progress(`Reading the ${what} from 1Password (approve it there if asked)`);
    try {
      const read = await readRefs(toRead.map((key) => values[key]!), options.runOp ?? runOp);
      toRead.forEach((key, index) => (values[key] = read[index]));
    } catch (error) {
      if (!(error instanceof OpError)) throw error;
      progress(`Could not read the ${what} from 1Password: ${error.message}`);
      for (const key of toRead) values[key] = undefined;
    }
  }

  const totpRef = values.totp !== undefined && isOpRef(values.totp) ? values.totp : undefined;
  return {
    username: values.username || undefined,
    password: values.password || undefined,
    totpSecret: values.totp && !totpRef ? totpSecretOf(values.totp) : undefined,
    ...(totpRef && { totpRef }),
  };
}

// The sign-in callback for a TOTP field in 1Password.
export function totpFrom1Password(ref: string, progress: Progress, run: RunOp = runOp): () => Promise<string> {
  return async () => {
    progress("Asking 1Password for a TOTP code");
    return readTotpCode(ref, Date.now, run);
  };
}

// `--credentials-stdin`: one JSON object, {"username", "password", "totp_secret"},
// so a caller can pass secrets without putting them in argv or the environment.
export async function readCredentialsFromStdin(): Promise<StoredCredentials> {
  let text = "";
  for await (const chunk of process.stdin) text += chunk;
  return parseCredentials(text);
}

export function parseCredentials(text: string): StoredCredentials {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    data = undefined;
  }
  if (typeof data !== "object" || data === null || Array.isArray(data)) {
    // Never echo the input: it holds the password.
    throw new TypeError('stdin is not a JSON object like {"username", "password", "totp_secret"}');
  }
  const field = (name: string) => {
    const value = (data as Record<string, unknown>)[name];
    return typeof value === "string" && value ? value : undefined;
  };
  return { username: field("username"), password: field("password"), totpSecret: field("totp_secret") };
}

async function keychain(account: string): Promise<string | undefined> {
  if (process.platform !== "darwin") return undefined;
  try {
    const { stdout } = await promisify(execFile)("security", [
      "find-generic-password",
      "-s",
      KEYCHAIN_SERVICE,
      "-a",
      account,
      "-w",
    ]);
    return stdout.replace(/\n$/, "") || undefined;
  } catch {
    // Not found, or the user denied access.
    return undefined;
  }
}
