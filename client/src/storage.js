import { validatePacket } from './crypto.js';

const DB_NAME = 'secure-chat';
const DB_VERSION = 1;
const KEY_STORE = 'keys';
const MESSAGE_STORE = 'messages';

const ALLOWED_MESSAGE_FIELDS = new Set([
  'messageId',
  'sender',
  'ciphertext',
  'iv',
  'timestamp',
  'status'
]);
const ALLOWED_STATUSES = new Set(['sending', 'sent', 'delivered', 'failed']);
const ALLOWED_ROLES = new Set(['A', 'B']);

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
  if (!ALLOWED_ROLES.has(role)) throw new Error('Invalid role');
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
  if (!ALLOWED_ROLES.has(role)) throw new Error('Invalid role');
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
  const db = await getDb();
  await toPromise(store(db, MESSAGE_STORE, 'readwrite').put(record));
  return record;
}

export async function getEncryptedMessages() {
  const db = await getDb();
  const messages = await toPromise(store(db, MESSAGE_STORE, 'readonly').getAll());
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
