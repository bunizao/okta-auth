export { signIn, type SignInOptions, type SignInResult } from "./sign-in.js";
export {
  signInGlobalProtect,
  type GlobalProtectInterface,
  type GlobalProtectOptions,
  type GlobalProtectResult,
} from "./globalprotect.js";
export { totp } from "./totp.js";
export { OktaSignInError, type OktaSignInErrorCode } from "./errors.js";
export type { Cookie } from "./cookies.js";
export type { Fetch } from "./client.js";
