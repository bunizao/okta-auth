import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { OpItemRefs } from "./onepassword.js";
import { dataDir } from "./store.js";

// ~/.okta-auth/config.json and op.env, in the format the Python CLI writes and
// reads, so `okta` and `okta-auth` find the same credentials.

export const ENV_NAMES = ["OKTA_USERNAME", "OKTA_PASSWORD", "OKTA_TOTP_SECRET"] as const;
export type EnvName = (typeof ENV_NAMES)[number];

export interface Config {
  // Where credentials live when the environment doesn't set them.
  provider: "keyring" | "op";
  // 1Password references (op://…) by variable name, when the provider is "op".
  opRefs: Partial<Record<EnvName, string>>;
}

type ConfigFile = Record<string, unknown>;

function configPath(): string {
  return join(dataDir(), "config.json");
}

async function readConfigFile(): Promise<ConfigFile> {
  try {
    const data: unknown = JSON.parse(await readFile(configPath(), "utf8"));
    return typeof data === "object" && data !== null && !Array.isArray(data) ? (data as ConfigFile) : {};
  } catch {
    return {};
  }
}

export async function readConfig(): Promise<Config> {
  const data = await readConfigFile();
  if (data.credential_provider !== "op") return { provider: "keyring", opRefs: {} };

  const opRefs = await readOpEnv(opEnvPath(data));
  // Older setups name a vault and item instead of writing every reference.
  const text = (key: string) => (typeof data[key] === "string" && (data[key] as string).trim()) || undefined;
  const vault = text("op_vault");
  const item = text("op_item");
  if (vault && item) {
    const ref = (field: string) => `op://${vault}/${item}/${field}`;
    opRefs.OKTA_USERNAME ??= ref(text("op_username_field") ?? "username");
    opRefs.OKTA_PASSWORD ??= ref(text("op_password_field") ?? "password");
    // Absent means the Python default; null or "" means no TOTP field.
    const totpField = "op_totp_secret_field" in data ? text("op_totp_secret_field") : "totp_secret";
    if (totpField) opRefs.OKTA_TOTP_SECRET ??= ref(totpField);
  }
  return { provider: "op", opRefs };
}

// Points both CLIs at a 1Password item. Only references are written: the
// secrets stay in 1Password.
export async function saveOpConfig(refs: OpItemRefs): Promise<string> {
  const data = await readConfigFile();
  const envFile = opEnvPath(data);
  const lines = [`OKTA_USERNAME=${refs.username}`, `OKTA_PASSWORD=${refs.password}`];
  if (refs.totp) lines.push(`OKTA_TOTP_SECRET=${refs.totp}`);
  await writePrivate(envFile, lines.join("\n") + "\n");
  // The references above replace any vault and item names from an older setup.
  await writeConfigFile({ ...data, credential_provider: "op", op_env_file: envFile, op_vault: null, op_item: null });
  return envFile;
}

export async function saveKeychainConfig(): Promise<void> {
  await writeConfigFile({ ...(await readConfigFile()), credential_provider: "keyring" });
}

async function writeConfigFile(data: ConfigFile): Promise<void> {
  await writePrivate(configPath(), JSON.stringify(data, null, 2) + "\n");
}

async function writePrivate(file: string, text: string): Promise<void> {
  await mkdir(dataDir(), { recursive: true, mode: 0o700 });
  await writeFile(file, text, { mode: 0o600 });
  await chmod(file, 0o600);
}

function opEnvPath(data: ConfigFile): string {
  const raw = typeof data.op_env_file === "string" && data.op_env_file.trim() ? data.op_env_file.trim() : "";
  if (!raw) return join(dataDir(), "op.env");
  return raw === "~" || raw.startsWith("~/") ? join(homedir(), raw.slice(1)) : raw;
}

// KEY=value lines, optionally `export`ed or quoted; other keys are ignored.
async function readOpEnv(file: string): Promise<Partial<Record<EnvName, string>>> {
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch {
    return {};
  }
  const refs: Partial<Record<EnvName, string>> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    const equals = line.indexOf("=");
    if (!line || line.startsWith("#") || equals < 0) continue;
    const key = line.slice(0, equals).replace(/^export\s+/, "").trim();
    let value = line.slice(equals + 1).trim();
    if (value.length >= 2 && value[0] === value.at(-1) && (value[0] === '"' || value[0] === "'")) {
      value = value.slice(1, -1);
    }
    if ((ENV_NAMES as readonly string[]).includes(key) && value) refs[key as EnvName] = value;
  }
  return refs;
}
