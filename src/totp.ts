const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

// RFC 6238 TOTP with the parameters every Okta-compatible authenticator uses:
// HMAC-SHA-1, 30-second steps, 6 digits. `now` is milliseconds since the epoch.
export async function totp(secret: string, now: number = Date.now()): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const counter = Math.floor(now / 1000 / 30);
  const message = new DataView(new ArrayBuffer(8));
  message.setUint32(0, Math.floor(counter / 2 ** 32));
  message.setUint32(4, counter >>> 0);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, message.buffer));

  // RFC 4226 dynamic truncation.
  const offset = mac[19]! & 0x0f;
  const binary =
    ((mac[offset]! & 0x7f) << 24) |
    (mac[offset + 1]! << 16) |
    (mac[offset + 2]! << 8) |
    mac[offset + 3]!;
  return String(binary % 1_000_000).padStart(6, "0");
}

// Accepts the forms authenticator apps show: any case, spaces, dashes, padding.
export function base32Decode(secret: string): Uint8Array<ArrayBuffer> {
  const clean = secret.replace(/[\s=-]/g, "").toUpperCase();
  if (!clean || /[^A-Z2-7]/.test(clean)) {
    // Deliberately says nothing about the value itself.
    throw new TypeError("TOTP secret is not valid base32");
  }

  const out = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let index = 0;
  for (const char of clean) {
    value = (value << 5) | BASE32.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (value >>> bits) & 0xff;
      value &= (1 << bits) - 1;
    }
  }
  return out;
}
