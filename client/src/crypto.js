const encoder = new TextEncoder();
const decoder = new TextDecoder();

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const ECDH_PARAMS = { name: 'ECDH', namedCurve: 'P-256' };
const HKDF_SALT_PREFIX = 'secure-chat-v1|salt|';
const HKDF_INFO_PREFIX = 'secure-chat-v1|key|';
const DEFAULT_CONVERSATION_ID = 'A-B';
const AAD_PREFIX = 'securechat.v1|';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const MAX_MESSAGE_LENGTH = 4096;
export const IV_BYTE_LENGTH = 12;

export function isValidParticipantId(value) {
  return value === 'A' || value === 'B' || (typeof value === 'string' && UUID_PATTERN.test(value));
}

export function buildAad(conversationId, messageId, senderId) {
  if (typeof conversationId !== 'string' || conversationId.length < 1 || conversationId.length > 256) {
    throw new Error('Invalid AAD context');
  }
  if (typeof messageId !== 'string' || messageId.length < 1 || messageId.length > 128) {
    throw new Error('Invalid AAD context');
  }
  if (!isValidParticipantId(senderId)) {
    throw new Error('Invalid AAD context');
  }
  return `${AAD_PREFIX}${conversationId}|${messageId}|${senderId}`;
}

export function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(value) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !BASE64_PATTERN.test(value)
  ) {
    return null;
  }
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

export async function generateKeyPair() {
  const pair = await crypto.subtle.generateKey(ECDH_PARAMS, false, ['deriveKey', 'deriveBits']);
  return { privateKey: pair.privateKey, publicKey: pair.publicKey };
}

export async function exportPublicKey(publicKey) {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  return bytesToBase64(new Uint8Array(spki));
}

export async function importPublicKey(publicKeyBase64) {
  if (typeof publicKeyBase64 !== 'string' || publicKeyBase64.length > 512) {
    throw new Error('Invalid public key');
  }
  const bytes = base64ToBytes(publicKeyBase64);
  if (!bytes || bytes.length < 50 || bytes.length > 150) {
    throw new Error('Invalid public key');
  }
  try {
    return await crypto.subtle.importKey('spki', bytes, ECDH_PARAMS, false, []);
  } catch {
    throw new Error('Invalid public key');
  }
}

async function hkdfSalt(conversationId) {
  const material = encoder.encode(HKDF_SALT_PREFIX + conversationId);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', material));
}

export async function deriveSharedKey(privateKey, peerPublicKeyBase64, conversationId = DEFAULT_CONVERSATION_ID) {
  const peerPublicKey = await importPublicKey(peerPublicKeyBase64);
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: peerPublicKey },
    privateKey,
    256
  );
  const hkdfKey = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  const salt = await hkdfSalt(conversationId);
  const info = encoder.encode(HKDF_INFO_PREFIX + conversationId);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export function validatePacket(packet) {
  if (!packet || typeof packet !== 'object') {
    throw new Error('Invalid encrypted packet');
  }
  const { messageId, sender, ciphertext, iv, timestamp } = packet;
  if (typeof messageId !== 'string' || messageId.length < 1 || messageId.length > 128) {
    throw new Error('Invalid encrypted packet');
  }
  if (!isValidParticipantId(sender)) {
    throw new Error('Invalid encrypted packet');
  }
  if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) {
    throw new Error('Invalid encrypted packet');
  }
  const ivBytes = base64ToBytes(iv);
  if (!ivBytes || ivBytes.length !== IV_BYTE_LENGTH) {
    throw new Error('Invalid encrypted packet');
  }
  const ciphertextBytes = base64ToBytes(ciphertext);
  if (!ciphertextBytes || ciphertextBytes.length < 17) {
    throw new Error('Invalid encrypted packet');
  }
  return { messageId, sender, ciphertext, iv, timestamp, ivBytes, ciphertextBytes };
}

export async function encryptMessage(conversationKey, plaintext, meta, aad) {
  if (typeof plaintext !== 'string' || plaintext.length < 1) {
    throw new Error('Message must be a non-empty string');
  }
  if (plaintext.length > MAX_MESSAGE_LENGTH) {
    throw new Error(`Message exceeds ${MAX_MESSAGE_LENGTH} characters`);
  }
  if (!meta || typeof meta.messageId !== 'string' || !meta.messageId) {
    throw new Error('messageId is required');
  }
  if (!isValidParticipantId(meta.sender)) {
    throw new Error('Invalid sender');
  }
  if (typeof meta.timestamp !== 'number' || !Number.isFinite(meta.timestamp)) {
    throw new Error('timestamp must be a number');
  }
  if (aad !== undefined && (typeof aad !== 'string' || aad.length < 1)) {
    throw new Error('Invalid AAD');
  }

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTE_LENGTH));
  const params = { name: 'AES-GCM', iv };
  if (aad !== undefined) {
    params.additionalData = encoder.encode(aad);
  }
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt(params, conversationKey, encoder.encode(plaintext))
  );

  return {
    messageId: meta.messageId,
    sender: meta.sender,
    ciphertext: bytesToBase64(encrypted),
    iv: bytesToBase64(iv),
    timestamp: meta.timestamp
  };
}

export async function decryptMessage(conversationKey, packet, aad) {
  const valid = validatePacket(packet);
  if (aad !== undefined && (typeof aad !== 'string' || aad.length < 1)) {
    throw new Error('Invalid AAD');
  }
  try {
    const params = { name: 'AES-GCM', iv: valid.ivBytes };
    if (aad !== undefined) {
      params.additionalData = encoder.encode(aad);
    }
    const decrypted = await crypto.subtle.decrypt(params, conversationKey, valid.ciphertextBytes);
    return decoder.decode(decrypted);
  } catch {
    throw new Error('Decryption failed');
  }
}

export async function generateFingerprint(publicKeyBase64) {
  const bytes = base64ToBytes(publicKeyBase64);
  if (!bytes) {
    throw new Error('Invalid public key');
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest.slice(0, 8))
    .map((byte) => byte.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
}
