export type OktaSignInErrorCode =
  // Okta refused the username or password. Never retry automatically: each
  // attempt counts towards Okta's lockout limit.
  | "credentials_rejected"
  // Okta refused the one-time code (wrong secret, clock skew, or a reused code).
  | "passcode_rejected"
  // Okta wants an authenticator this package can't answer (push, SMS, email...).
  | "mfa_unsupported"
  // Okta asked for something this package doesn't know how to answer.
  | "unexpected_step"
  // Okta signed in, but the target site is still not signed in afterwards.
  | "handoff_failed"
  // The request timed out or never got an answer.
  | "network"
  | `http_${number}`;

// Messages name hosts, paths, IDX form names and Okta i18n keys only. They never
// carry passwords, one-time codes, the TOTP secret, state tokens or cookie values.
export class OktaSignInError extends Error {
  override readonly name = "OktaSignInError";
  // Okta's DT cookie when the failed sign-in got that far, so the next attempt
  // still looks like the same device. Non-enumerable: console.error, util.inspect
  // and JSON.stringify leave it out.
  declare readonly deviceToken?: string;

  constructor(
    readonly code: OktaSignInErrorCode,
    message: string,
  ) {
    super(message);
  }
}

// Host and path only: query strings carry SAMLRequest, state tokens and the like.
export function where(url: URL): string {
  return `${url.hostname}${url.pathname}`;
}
