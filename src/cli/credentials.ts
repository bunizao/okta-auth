import { execFile } from "node:child_process";
import { promisify } from "node:util";

// Same Keychain service and account names the Python version's keyring backend
// wrote, so an existing `okta config` setup keeps working.
const KEYCHAIN_SERVICE = "okta-auth";

export interface StoredCredentials {
  username?: string;
  password?: string;
  totpSecret?: string;
}

// Environment first (works with `op run` and CI), then the macOS Keychain.
export async function readCredentials(): Promise<StoredCredentials> {
  return {
    username: process.env.OKTA_USERNAME || (await keychain("username")),
    password: process.env.OKTA_PASSWORD || (await keychain("password")),
    totpSecret: process.env.OKTA_TOTP_SECRET || (await keychain("totp_secret")),
  };
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
