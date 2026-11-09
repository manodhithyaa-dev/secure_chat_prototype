import { decodeBase64Strict } from './identity';

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

export function isValidUsername(value: unknown): value is string {
  return typeof value === 'string' && USERNAME_PATTERN.test(value);
}

export function isValidEmail(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 254 && EMAIL_PATTERN.test(value);
}

export function isValidPassword(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 8 && value.length <= 128;
}

export function isValidDisplayName(value: unknown): value is string | null {
  return value === null || value === undefined || (typeof value === 'string' && value.length <= 64);
}

export function isValidMessageId(value: unknown): value is string {
  return typeof value === 'string' && value.length >= 1 && value.length <= 128;
}

export interface ValidSendPayload {
  conversationId: string;
  messageId: string;
  ciphertext: string;
  iv: string;
  timestamp: number;
}

export function validateSendPayload(value: unknown): ValidSendPayload | null {
  if (!value || typeof value !== 'object') return null;
  const payload = value as Record<string, unknown>;
  if (!isUuid(payload.conversationId)) return null;
  if (!isValidMessageId(payload.messageId)) return null;
  if (typeof payload.timestamp !== 'number' || !Number.isFinite(payload.timestamp)) return null;
  if (typeof payload.iv !== 'string' || typeof payload.ciphertext !== 'string') return null;
  const iv = decodeBase64Strict(payload.iv);
  if (!iv || iv.length !== 12) return null;
  const ciphertext = decodeBase64Strict(payload.ciphertext);
  if (!ciphertext || ciphertext.length < 17) return null;
  if (payload.ciphertext.length > 32768) return null;
  return {
    conversationId: payload.conversationId,
    messageId: payload.messageId,
    ciphertext: payload.ciphertext,
    iv: payload.iv,
    timestamp: payload.timestamp
  };
}
