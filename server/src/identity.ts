import { createHash } from 'node:crypto';

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

export function decodeBase64Strict(value: unknown): Buffer | null {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !BASE64_PATTERN.test(value)
  ) {
    return null;
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) return null;
  return bytes;
}

export function isValidPublicKey(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 512) return false;
  const bytes = decodeBase64Strict(value);
  if (!bytes) return false;
  return bytes.length >= 50 && bytes.length <= 150;
}

export function fingerprintFromPublicKey(publicKeyBase64: string): string {
  const digest = createHash('sha256').update(Buffer.from(publicKeyBase64, 'base64')).digest();
  return Array.from(digest.subarray(0, 8))
    .map((byte) => byte.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
}
