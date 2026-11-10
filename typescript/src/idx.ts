import { OktaSignInError } from "./errors.js";
import { totp } from "./totp.js";

// The slice of Okta's IDX (Identity Engine) wire format this package reads.
export interface IdxState {
  stateHandle?: string;
  remediation?: { value?: IdxForm[] };
  success?: { href?: string };
  [key: string]: unknown;
}

interface IdxForm {
  name: string;
  href: string;
  value?: IdxField[];
  relatesTo?: string | string[];
}

interface IdxField {
  name: string;
  value?: unknown;
  form?: { value?: IdxField[] };
  options?: IdxOption[];
}

interface IdxOption {
  value?: unknown;
  relatesTo?: string;
}

export interface Credentials {
  username: string;
  password: string;
  totpSecret?: string;
  totpCode?: () => Promise<string>;
}

// What a step sends decides how a rejection is reported.
export type Sends = "identifier" | "password" | "passcode" | undefined;

export interface IdxStep {
  form: string;
  href: string;
  body: Record<string, unknown>;
  sends: Sends;
}

const PASSWORD = "okta_password";
const TOTP_KEYS = new Set(["google_otp", "okta_verify"]);
// Preference when Okta lets us choose. Push, SMS, email and the rest are never chosen.
const PREFERRED_KEYS = [PASSWORD, "google_otp", "okta_verify"];

// Picks the next IDX remediation to answer and builds its request body.
export async function nextStep(state: IdxState, credentials: Credentials, now: number): Promise<IdxStep> {
  const forms = state.remediation?.value ?? [];
  const find = (name: string) => forms.find((form) => form.name === name);
  const stateHandle = (form: IdxForm) =>
    (field(form, "stateHandle")?.value as string | undefined) ?? state.stateHandle;

  const identify = find("identify");
  if (identify) {
    const credentialsField = field(identify, "credentials");
    return {
      form: identify.name,
      href: identify.href,
      body: {
        identifier: credentials.username,
        ...(credentialsField && {
          credentials: { [secretName(credentialsField)]: credentials.password },
        }),
        stateHandle: stateHandle(identify),
      },
      sends: credentialsField ? "password" : "identifier",
    };
  }

  const challenge = find("challenge-authenticator");
  const challengeKey = challenge && authenticatorKey(state, challenge.relatesTo);
  const select = find("select-authenticator-authenticate");
  const options = select ? authenticatorOptions(state, select) : [];
  const usable = options.filter((option) => option.methodType !== null && canAnswer(option.key, credentials));
  const choice = PREFERRED_KEYS.map((key) => usable.find((option) => option.key === key)).find(Boolean);

  // Okta pre-selects the authenticator used last time. Answer it, unless it's a
  // TOTP authenticator and Okta also offers one we rank higher: a Google
  // Authenticator secret can't answer Okta Verify.
  const switchToChoice =
    choice !== undefined && choice.key !== PASSWORD && rank(choice.key) < rank(challengeKey);
  if (challenge && canAnswer(challengeKey, credentials) && !switchToChoice) {
    const isPassword = challengeKey === PASSWORD;
    const secret = isPassword ? credentials.password : await totpCode(credentials, now);
    const credentialsField = field(challenge, "credentials");
    return {
      form: challenge.name,
      href: challenge.href,
      body: {
        credentials: { [credentialsField ? secretName(credentialsField) : "passcode"]: secret },
        stateHandle: stateHandle(challenge),
      },
      sends: isPassword ? "password" : "passcode",
    };
  }

  if (select) {
    if (!choice) {
      throw new OktaSignInError(
        "mfa_unsupported",
        `Okta offers ${describe(options)}; this package answers ${PREFERRED_KEYS.join(", ")} (TOTP only)` +
          (hasTotp(credentials) ? "" : ", and no TOTP secret was given"),
      );
    }
    return {
      form: select.name,
      href: select.href,
      body: {
        authenticator: { id: choice.id, ...(choice.methodType && { methodType: choice.methodType }) },
        stateHandle: stateHandle(select),
      },
      sends: undefined,
    };
  }

  // Okta's current challenge is one we can't answer and it offers no alternative.
  if (challenge) {
    const missingSecret = challengeKey && TOTP_KEYS.has(challengeKey) ? " and no TOTP secret was given" : "";
    throw new OktaSignInError(
      "mfa_unsupported",
      `Okta asks for ${challengeKey ?? "an unknown authenticator"}${missingSecret}`,
    );
  }

  // Okta Verify asks how to verify after it's selected: always a TOTP code.
  const verificationData = find("authenticator-verification-data");
  if (verificationData) {
    const authenticator = field(verificationData, "authenticator");
    const id = field(authenticator?.form, "id")?.value;
    const methods = methodTypes(field(authenticator?.form, "methodType"));
    if (!methods.includes("totp")) {
      throw new OktaSignInError("mfa_unsupported", `Okta Verify offers ${methods.join(", ") || "no methods"}, not totp`);
    }
    return {
      form: verificationData.name,
      href: verificationData.href,
      body: { authenticator: { id, methodType: "totp" }, stateHandle: stateHandle(verificationData) },
      sends: undefined,
    };
  }

  const skip = find("skip");
  if (skip) {
    return { form: skip.name, href: skip.href, body: { stateHandle: stateHandle(skip) }, sends: undefined };
  }

  const names = forms.map((form) => form.name);
  if (names.includes("reenroll-authenticator")) {
    throw new OktaSignInError("unexpected_step", "Okta says the password has expired; change it in a browser, then sign in again");
  }
  if (names.includes("select-authenticator-enroll") || names.includes("enroll-authenticator")) {
    throw new OktaSignInError(
      "unexpected_step",
      `Okta wants a new authenticator set up (${names.join(", ")}); set it up in a browser, then sign in again`,
    );
  }
  if (names.includes("challenge-poll")) {
    throw new OktaSignInError("mfa_unsupported", "Okta is waiting for a push notification");
  }
  throw new OktaSignInError("unexpected_step", `Okta asks for ${names.join(", ") || "nothing this package recognises"}`);
}

// Okta error messages, by i18n key. Keys never contain user input; message text might.
export function errorKeys(node: unknown, keys = new Set<string>()): string[] {
  if (Array.isArray(node)) {
    for (const item of node) errorKeys(item, keys);
  } else if (node && typeof node === "object") {
    const record = node as Record<string, unknown>;
    if (record.class === "ERROR") {
      const i18n = record.i18n as { key?: unknown } | undefined;
      keys.add(typeof i18n?.key === "string" ? i18n.key : "unknown");
    }
    for (const value of Object.values(record)) errorKeys(value, keys);
  }
  return [...keys];
}

interface AuthenticatorOption {
  key: string | undefined;
  id: unknown;
  // undefined: Okta needs no method type. null: none of the offered ones is usable.
  methodType: string | undefined | null;
  methods: string[];
}

function authenticatorOptions(state: IdxState, form: IdxForm): AuthenticatorOption[] {
  return (field(form, "authenticator")?.options ?? []).map((option) => {
    const fields = (option.value as { form?: { value?: IdxField[] } } | undefined)?.form;
    const key = authenticatorKey(state, option.relatesTo);
    const methodField = field(fields, "methodType");
    const methods = methodTypes(methodField);
    let methodType: string | undefined | null = methods[0];
    // Okta Verify can push or show a code; only the code works without a phone in hand.
    // Without a methodType field, Okta asks for one in authenticator-verification-data.
    if (key === "okta_verify") methodType = !methodField ? undefined : methods.includes("totp") ? "totp" : null;
    else if (methodField && !methods.length) methodType = null;
    return { key, id: field(fields, "id")?.value, methodType, methods };
  });
}

function canAnswer(key: string | undefined, credentials: Credentials): boolean {
  if (key === PASSWORD) return true;
  return key !== undefined && TOTP_KEYS.has(key) && hasTotp(credentials);
}

function hasTotp(credentials: Credentials): boolean {
  return credentials.totpCode !== undefined || credentials.totpSecret !== undefined;
}

// A caller's code source (a password manager) wins over computing one locally.
async function totpCode(credentials: Credentials, now: number): Promise<string> {
  if (credentials.totpCode) return credentials.totpCode();
  return totp(credentials.totpSecret!, now);
}

function rank(key: string | undefined): number {
  const index = key === undefined ? -1 : PREFERRED_KEYS.indexOf(key);
  return index < 0 ? PREFERRED_KEYS.length : index;
}

function describe(options: AuthenticatorOption[]): string {
  if (!options.length) return "no authenticators";
  return options
    .map((option) => `${option.key ?? "unknown"}${option.methods.length ? ` (${option.methods.join("/")})` : ""}`)
    .join(", ");
}

function field(form: { value?: IdxField[] } | undefined, name: string): IdxField | undefined {
  return form?.value?.find((item) => item.name === name);
}

// The credentials sub-field is `passcode` for passwords and Google Authenticator,
// `totp` for Okta Verify. The form says which.
function secretName(credentials: IdxField): string {
  return credentials.form?.value?.[0]?.name ?? "passcode";
}

function methodTypes(methodField: IdxField | undefined): string[] {
  if (!methodField) return [];
  if (typeof methodField.value === "string") return [methodField.value];
  return (methodField.options ?? []).map((option) => option.value).filter((value) => typeof value === "string");
}

// Resolves an IDX pointer such as `$.authenticatorEnrollments.value[0]` or
// `$.currentAuthenticatorEnrollment` to the authenticator's key (`google_otp`...).
function authenticatorKey(state: IdxState, relatesTo: string | string[] | undefined): string | undefined {
  const pointer = Array.isArray(relatesTo) ? relatesTo[0] : relatesTo;
  if (!pointer?.startsWith("$.")) return undefined;

  let node: unknown = state;
  for (const part of pointer.slice(2).split(/\.|\[(\d+)\]/).filter(Boolean)) {
    node = node && typeof node === "object" ? (node as Record<string, unknown>)[part] : undefined;
  }
  const target = node as { key?: unknown; value?: { key?: unknown } } | undefined;
  const key = target?.key ?? target?.value?.key;
  return typeof key === "string" ? key : undefined;
}
