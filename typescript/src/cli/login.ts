import { signIn, type Fetch, type Progress } from "../index.js";
import { readDeviceToken, saveDeviceToken, saveSession, sessionUrl } from "./store.js";

export interface LoginCredentials {
  username: string;
  password: string;
  totpSecret?: string;
  totpCode?: () => Promise<string>;
}

// Signs in to <url> and saves its cookies and Okta's device token. Shared by
// `login` and the setup page's test sign-in.
export async function signInAndSave(
  url: string,
  credentials: LoginCredentials,
  onProgress: Progress,
  fetch?: Fetch,
): Promise<{ host: string; cookies: number; file: string }> {
  const result = await signIn({ url, ...credentials, deviceToken: await readDeviceToken(url), onProgress, fetch });
  const saveUrl = sessionUrl(url, result.cookies, result.landingUrl);
  const file = await saveSession(saveUrl, result.cookies);
  await saveDeviceToken(url, result.deviceToken);
  return { host: new URL(saveUrl).host, cookies: result.cookies.length, file };
}
