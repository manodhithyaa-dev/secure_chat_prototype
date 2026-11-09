import { validatePacket } from './crypto.js';

const DB_NAME = 'secure-chat';
const DB_VERSION = 2;
const KEY_STORE = 'keys';
const MESSAGE_STORE = 'messages';
const CONVERSATION_STORE = 'conversations';
const TRUST_STORE = 'trust';

const ALLOWED_MESSAGE_FIELDS = new Set([
  'messageId',
  'sender',
  'ciphertext',
  'iv',
  'timestamp',
  'status',
  'conversationId'
]);
const ALLOWED_STATUSES = new Set(['sending', 'sent', 'delivered', 'failed']);
const LEGACY_ROLES = new Set(['A', 'B']);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidStorageKey(key) {
  return LEGACY_ROLES.has(key) || (typeof key === 'string' && UUID_PATTERN.test(key));
}

let dbPromise = null;

function toPromise(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Database request failed'));
  });
}

export async function initializeDatabase(name = DB_NAME) {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(name, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(KEY_STORE)) {
        db.createObjectStore(KEY_STORE);
      }
      if (!db.objectStoreNames.contains(MESSAGE_STORE)) {
        db.createObjectStore(MESSAGE_STORE, { keyPath: 'messageId' });
      }
      if (!db.objectStoreNames.contains(CONVERSATION_STORE)) {
        db.createObjectStore(CONVERSATION_STORE, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(TRUST_STORE)) {
        db.createObjectStore(TRUST_STORE, { keyPath: 'userId' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Failed to open database'));
    request.onblocked = () => reject(new Error('Database is blocked'));
  }).catch((error) => {
    dbPromise = null;
    throw error;
  });
  return dbPromise;
}

async function getDb() {
  if (!dbPromise) return initializeDatabase();
  return dbPromise;
}

function store(db, name, mode) {
  return db.transaction(name, mode).objectStore(name);
}

export async function saveKeyPair(role, keyPair) {
  if (!isValidStorageKey(role)) throw new Error('Invalid role');
  if (
    !keyPair ||
    !keyPair.privateKey ||
    typeof keyPair.publicKeyBase64 !== 'string' ||
    keyPair.publicKeyBase64.length === 0
  ) {
    throw new Error('Invalid key pair');
  }
  const db = await getDb();
  await toPromise(
    store(db, KEY_STORE, 'readwrite').put(
      { role, privateKey: keyPair.privateKey, publicKey: keyPair.publicKeyBase64 },
      role
    )
  );
}

export async function loadKeyPair(role) {
  if (!isValidStorageKey(role)) throw new Error('Invalid role');
  const db = await getDb();
  const record = await toPromise(store(db, KEY_STORE, 'readonly').get(role));
  if (
    !record ||
    !record.privateKey ||
    typeof record.publicKey !== 'string' ||
    record.publicKey.length === 0
  ) {
    return null;
  }
  return { privateKey: record.privateKey, publicKeyBase64: record.publicKey };
}

export async function saveEncryptedMessage(packet) {
  if (!packet || typeof packet !== 'object') {
    throw new Error('Invalid encrypted packet');
  }
  for (const field of Object.keys(packet)) {
    if (!ALLOWED_MESSAGE_FIELDS.has(field)) {
      throw new Error(`Field not allowed in local storage: ${field}`);
    }
  }
  let base;
  try {
    base = validatePacket(packet);
  } catch {
    throw new Error('Invalid encrypted packet');
  }
  const status = ALLOWED_STATUSES.has(packet.status) ? packet.status : 'sending';
  const record = {
    messageId: base.messageId,
    sender: base.sender,
    ciphertext: base.ciphertext,
    iv: base.iv,
    timestamp: base.timestamp,
    status
  };
  const persisted =
    typeof packet.conversationId === 'string' && packet.conversationId.length > 0
      ? { ...record, conversationId: packet.conversationId }
      : record;
  const db = await getDb();
  await toPromise(store(db, MESSAGE_STORE, 'readwrite').put(persisted));
  return record;
}

export async function getEncryptedMessages(conversationId) {
  const db = await getDb();
  let messages = await toPromise(store(db, MESSAGE_STORE, 'readonly').getAll());
  if (typeof conversationId === 'string' && conversationId.length > 0) {
    messages = messages.filter((record) => record.conversationId === conversationId);
  }
  return messages.sort((a, b) => a.timestamp - b.timestamp);
}

export async function findMessage(messageId) {
  if (typeof messageId !== 'string' || messageId.length === 0) return null;
  const db = await getDb();
  return (await toPromise(store(db, MESSAGE_STORE, 'readonly').get(messageId))) || null;
}

export async function updateMessageStatus(messageId, status) {
  if (typeof messageId !== 'string' || messageId.length === 0) return null;
  if (!ALLOWED_STATUSES.has(status)) throw new Error('Invalid status');
  const db = await getDb();
  const record = await toPromise(store(db, MESSAGE_STORE, 'readwrite').get(messageId));
  if (!record) return null;
  record.status = status;
  await toPromise(store(db, MESSAGE_STORE, 'readwrite').put(record));
  return record;
}

export async function clearMessages() {
  const db = await getDb();
  await toPromise(store(db, MESSAGE_STORE, 'readwrite').clear());
}

export async function saveConversation(conversation) {
  if (!conversation || typeof conversation.id !== 'string' || conversation.id.length === 0) {
    throw new Error('Invalid conversation');
  }
  const db = await getDb();
  const record = {
    id: conversation.id,
    type: conversation.type === 'direct' ? 'direct' : 'direct',
    updatedAt: typeof conversation.updatedAt === 'string' ? conversation.updatedAt : '',
    members: Array.isArray(conversation.members) ? conversation.members : []
  };
  await toPromise(store(db, CONVERSATION_STORE, 'readwrite').put(record));
  return record;
}

export async function getConversation(conversationId) {
  if (typeof conversationId !== 'string' || conversationId.length === 0) return null;
  const db = await getDb();
  return (await toPromise(store(db, CONVERSATION_STORE, 'readonly').get(conversationId))) || null;
}

export async function getConversations() {
  const db = await getDb();
  const conversations = await toPromise(store(db, CONVERSATION_STORE, 'readonly').getAll());
  return conversations.sort((a, b) => String(b.updatedAt).localeCompare(String(a.updatedAt)));
}

export async function saveTrustedKey(record) {
  if (!record || typeof record.userId !== 'string' || record.userId.length === 0) {
    throw new Error('Invalid trust record');
  }
  if (typeof record.publicKey !== 'string' || record.publicKey.length === 0) {
    throw new Error('Invalid trust record');
  }
  if (typeof record.fingerprint !== 'string' || record.fingerprint.length === 0) {
    throw new Error('Invalid trust record');
  }
  const db = await getDb();
  const entry = {
    userId: record.userId,
    publicKey: record.publicKey,
    fingerprint: record.fingerprint,
    verified: record.verified === true,
    updatedAt: typeof record.updatedAt === 'string' ? record.updatedAt : new Date().toISOString()
  };
  await toPromise(store(db, TRUST_STORE, 'readwrite').put(entry));
  return entry;
}

export async function getTrustedKey(userId) {
  if (typeof userId !== 'string' || userId.length === 0) return null;
  const db = await getDb();
  return (await toPromise(store(db, TRUST_STORE, 'readonly').get(userId))) || null;
}

export async function clearLocalData() {
  const db = await getDb();
  await toPromise(store(db, MESSAGE_STORE, 'readwrite').clear());
  await toPromise(store(db, CONVERSATION_STORE, 'readwrite').clear());
}
