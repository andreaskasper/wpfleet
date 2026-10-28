/**
 * Crypto helpers on WebCrypto only (Node >= 20 and Cloudflare Workers).
 *
 * Secrets at rest (site OAuth tokens and client secrets, the admin TOTP seed)
 * are encrypted with AES-256-GCM. The key is derived from FLEET_KEK with
 * HKDF, and every ciphertext is bound to its purpose and row ("aad"), so a
 * value copied into another row or column does not decrypt.
 */

const enc = new TextEncoder();
const dec = new TextDecoder();

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export function b64url(bytes: Uint8Array | ArrayBuffer): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64url(s: string): Uint8Array<ArrayBuffer> {
  const t = s.replace(/-/g, '+').replace(/_/g, '/');
  const p = t.length % 4 ? '='.repeat(4 - (t.length % 4)) : '';
  const bin = atob(t + p);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomToken(prefix: string, bytes = 32): string {
  return prefix + b64url(randomBytes(bytes));
}

export async function sha256hex(s: string): Promise<string> {
  const h = await crypto.subtle.digest('SHA-256', enc.encode(s));
  return [...new Uint8Array(h)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

export async function sha256b64url(s: string): Promise<string> {
  return b64url(await crypto.subtle.digest('SHA-256', enc.encode(s)));
}

/** Constant-time string comparison (length leak only). */
export function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ---------------- secrets at rest ---------------- */

export class Vault {
  private constructor(private key: CryptoKey) {}

  /** kek: base64/base64url string of at least 32 random bytes. */
  static async create(kek: string): Promise<Vault> {
    let raw: Uint8Array<ArrayBuffer>;
    try {
      raw = unb64url(kek.trim());
    } catch {
      throw new Error('FLEET_KEK is not valid base64');
    }
    if (raw.length < 32) throw new Error('FLEET_KEK must be at least 32 bytes (e.g. `openssl rand -base64 32`)');
    const base = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('wpfleet'), info: enc.encode('wpfleet-vault-v1') },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
    return new Vault(key);
  }

  async seal(plain: string, aad: string): Promise<string> {
    const iv = randomBytes(12);
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, this.key, enc.encode(plain));
    return 'v1.' + b64url(iv) + '.' + b64url(ct);
  }

  async open(sealed: string | null | undefined, aad: string): Promise<string | null> {
    if (!sealed) return null;
    const parts = sealed.split('.');
    if (parts.length !== 3 || parts[0] !== 'v1') return null;
    try {
      const pt = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: unb64url(parts[1]), additionalData: enc.encode(aad) },
        this.key,
        unb64url(parts[2]),
      );
      return dec.decode(pt);
    } catch {
      return null;
    }
  }
}

/* ---------------- passwords ---------------- */

/**
 * PBKDF2-SHA256. Stored as "pbkdf2$<iterations>$<salt>$<hash>". Node uses
 * 600 000 iterations (OWASP); Cloudflare Workers cap PBKDF2 at 100 000, so a
 * Worker deployment sets FLEET_PBKDF2_ITERATIONS=100000.
 */
export async function hashPassword(pw: string, iterations: number): Promise<string> {
  const salt = randomBytes(16);
  const bits = await pbkdf2(pw, salt, iterations);
  return `pbkdf2$${iterations}$${b64url(salt)}$${b64url(bits)}`;
}

export async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [alg, it, salt, hash] = stored.split('$');
  if (alg !== 'pbkdf2' || !it || !salt || !hash) return false;
  const bits = await pbkdf2(pw, unb64url(salt), parseInt(it, 10));
  return safeEqual(b64url(bits), hash);
}

async function pbkdf2(pw: string, salt: Uint8Array<ArrayBuffer>, iterations: number): Promise<ArrayBuffer> {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, k, 256);
}

/* ---------------- PKCE ---------------- */

export async function pkceChallenge(verifier: string): Promise<string> {
  return sha256b64url(verifier);
}
