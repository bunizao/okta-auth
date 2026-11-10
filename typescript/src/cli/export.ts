import type { StoredCredentials } from "./credentials.js";

// `okta-auth export` hands the raw password and TOTP secret to a program that
// signs in by itself, such as a Worker:
//   okta-auth export --dangerously-print-password-and-totp-secret | npx wrangler secret bulk
// The flag names what it does, and a terminal never gets the output.

export const EXPORT_FLAG = "dangerously-print-password-and-totp-secret";

// Why export won't run, or undefined when it may.
export function exportRefusal(confirmed: boolean, stdoutIsTTY: boolean): string | undefined {
  if (!confirmed) {
    return (
      `export prints your Okta password and TOTP secret. To hand them to a program you trust, pipe them there:\n` +
      `  okta-auth export --${EXPORT_FLAG} | npx wrangler secret bulk`
    );
  }
  if (stdoutIsTTY) return "refusing to print your password and TOTP secret to a terminal; pipe the output into the program that needs it";
  return undefined;
}

// The variable names a Worker reads, as one JSON object (what `wrangler secret bulk` takes).
export function exportJson(credentials: StoredCredentials): string | undefined {
  if (!credentials.username || !credentials.password) return undefined;
  return JSON.stringify({
    OKTA_USERNAME: credentials.username,
    OKTA_PASSWORD: credentials.password,
    ...(credentials.totpSecret && { OKTA_TOTP_SECRET: credentials.totpSecret }),
  });
}
