import { OktaSignInError, where } from "./errors.js";

export interface SamlForm {
  action: string;
  fields: Record<string, string>;
}

// An HTTP 200 on the target host may still be a sign-in form. Ignore templates
// and hidden fields so embedded login markup does not invalidate a session.
export function isLoginPage(html: string): boolean {
  const content = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, "");
  for (const match of content.matchAll(/<input\b[^>]*>/gi)) {
    const attributes = readAttributes(match[0]);
    const type = attributes.type?.toLowerCase();
    const autocomplete = (attributes.autocomplete ?? "").toLowerCase().split(/\s+/);
    if (type === "hidden" || "hidden" in attributes || "disabled" in attributes || autocomplete.includes("new-password")) {
      continue;
    }
    if (type === "password" || attributes.name?.toLowerCase() === "username" ||
        attributes.id?.toLowerCase() === "okta-signin-username" || autocomplete.includes("username")) {
      return true;
    }
  }
  return false;
}

// The Okta sign-in page embeds the IDX state token in a script, for example
// `var stateToken = '02.id.abc\x2Ddef';`, with JavaScript string escapes.
export function readStateToken(html: string, url: URL): string {
  const match = /stateToken["']?\s*[=:]\s*["']([^"']+)["']/.exec(html);
  if (!match) {
    throw new OktaSignInError(
      "unexpected_step",
      `${where(url)} is not an Okta Identity Engine sign-in page (no state token found)`,
    );
  }
  const token = unescapeJs(match[1]!);
  if (!token.startsWith("02.")) {
    throw new OktaSignInError(
      "unexpected_step",
      `${where(url)} uses Okta Classic Engine, which is not supported; only Identity Engine is`,
    );
  }
  return token;
}

// Okta finishes with an auto-submitting form that carries the SAMLResponse to the
// service provider; a GlobalProtect POST binding starts with one that carries the
// SAMLRequest to Okta. Attribute values are HTML-entity-encoded.
export function readSamlForm(html: string, field: "SAMLResponse" | "SAMLRequest" = "SAMLResponse"): SamlForm | undefined {
  const inputs = [...html.matchAll(/<input\b[^>]*>/gi)].map((match) => ({
    index: match.index,
    attributes: readAttributes(match[0]),
  }));
  const message = inputs.find((input) => input.attributes.name === field);
  if (!message) return undefined;

  const formStart = html.lastIndexOf("<form", message.index);
  const formTag = formStart < 0 ? undefined : /<form\b[^>]*>/i.exec(html.slice(formStart))?.[0];
  const action = formTag ? readAttributes(formTag).action : undefined;
  if (!action) return undefined;

  const fields: Record<string, string> = {};
  for (const { attributes } of inputs) {
    if (attributes.name === field || attributes.name === "RelayState") {
      fields[attributes.name] = attributes.value ?? "";
    }
  }
  return { action, fields };
}

function readAttributes(tag: string): Record<string, string> {
  const attributes: Record<string, string> = {};
  for (const match of tag.matchAll(/\s([\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g)) {
    attributes[match[1]!.toLowerCase()] = decodeEntities(match[2] ?? match[3] ?? match[4] ?? "");
  }
  return attributes;
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
};

export function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (entity, body: string) => {
    if (body[0] === "#") {
      const hex = body[1] === "x" || body[1] === "X";
      return String.fromCodePoint(parseInt(body.slice(hex ? 2 : 1), hex ? 16 : 10));
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? entity;
  });
}

function unescapeJs(text: string): string {
  return text
    .replace(/\\x([0-9a-f]{2})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\u([0-9a-f]{4})/gi, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)));
}
