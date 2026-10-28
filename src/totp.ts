/** RFC 6238 TOTP (SHA-1, 6 digits, 30 s) on WebCrypto. */
import { randomBytes, safeEqual } from './crypto.js';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0, value = 0, out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Uint8Array<ArrayBuffer> {
  const clean = s.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function newTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

export async function totpAt(secret: string, counter: number): Promise<string> {
  const key = await crypto.subtle.importKey('raw', base32Decode(secret), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = h[h.length - 1] & 0x0f;
  const code = (((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3]) % 1_000_000;
  return code.toString().padStart(6, '0');
}

/**
 * Check a code with ±1 step tolerance. Returns the matched counter (so the
 * caller can refuse reuse of the same code) or null.
 */
export async function verifyTotp(secret: string, code: string, now = Date.now()): Promise<number | null> {
  const c = code.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(c)) return null;
  const t = Math.floor(now / 30000);
  for (const d of [0, -1, 1]) {
    if (safeEqual(await totpAt(secret, t + d), c)) return t + d;
  }
  return null;
}

export function otpauthUri(secret: string, account: string, issuer = 'WP Fleet'): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
