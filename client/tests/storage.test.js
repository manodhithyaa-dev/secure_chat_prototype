import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { installFakeIndexedDB } from './helpers/fake-indexeddb.js';
import {
  decryptMessage,
  deriveSharedKey,
  encryptMessage,
  exportPublicKey,
  generateKeyPair
} from '../src/crypto.js';
import {
  clearMessages,
  findMessage,
  getEncryptedMessages,
  initializeDatabase,
  loadKeyPair,
  saveEncryptedMessage,
  saveKeyPair,
  updateMessageStatus
} from '../src/storage.js';

installFakeIndexedDB();

before(async () => {
  await initializeDatabase(`storage-tests-${Date.now()}`);
});

test('Test 9: IndexedDB only ever contains ciphertext, never plaintext', async () => {
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();
  const pubA = await exportPublicKey(alice.publicKey);
  const pubB = await exportPublicKey(bob.publicKey);
  const key = await deriveSharedKey(alice.privateKey, pubB);

  const plaintext = 'PLAINTEXT_MUST_NEVER_BE_STORED_12345';
  const packet = await encryptMessage(key, plaintext, {
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });

  const stored = await saveEncryptedMessage({ ...packet, status: 'sending' });
  assert.deepEqual(Object.keys(stored).sort(), [
    'ciphertext',
    'iv',
    'messageId',
    'sender',
    'status',
    'timestamp'
  ]);

  const all = await getEncryptedMessages();
  const raw = JSON.stringify(all);
  assert.ok(!raw.includes(plaintext));
  assert.ok(!raw.includes('plaintext'));

  const decrypted = await decryptMessage(key, all[0]);
  assert.equal(decrypted, plaintext);

  await assert.rejects(
    () => saveEncryptedMessage({ ...packet, plaintext }),
    /not allowed|Invalid/
  );
  await assert.rejects(
    () =>
      saveEncryptedMessage({
        messageId: crypto.randomUUID(),
        sender: 'A',
        ciphertext: packet.ciphertext,
        iv: packet.iv,
        timestamp: Date.now(),
        text: 'sneaky'
      }),
    /not allowed/
  );
  await assert.rejects(
    () =>
      saveEncryptedMessage({
        messageId: crypto.randomUUID(),
        sender: 'A',
        ciphertext: 'not base64!!!',
        iv: packet.iv,
        timestamp: Date.now()
      }),
    /Invalid/
  );
});

test('message status updates and dedupe helpers work', async () => {
  const alice = await generateKeyPair();
  const bob = await generateKeyPair();
  const pubB = await exportPublicKey(bob.publicKey);
  const key = await deriveSharedKey(alice.privateKey, pubB);

  const packet = await encryptMessage(key, 'status check', {
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });
  await saveEncryptedMessage({ ...packet, status: 'sending' });

  const updated = await updateMessageStatus(packet.messageId, 'delivered');
  assert.equal(updated.status, 'delivered');

  const found = await findMessage(packet.messageId);
  assert.equal(found.status, 'delivered');
  assert.equal(await findMessage('missing-id'), null);
  await assert.rejects(() => updateMessageStatus(packet.messageId, 'weird'), /Invalid status/);
});

test('Test 10: identity keys are generated once and survive reloads', async () => {
  const existing = await loadKeyPair('A');
  assert.equal(existing, null);

  const generated = await generateKeyPair();
  const publicKeyBase64 = await exportPublicKey(generated.publicKey);
  await saveKeyPair('A', { privateKey: generated.privateKey, publicKeyBase64 });

  const firstLoad = await loadKeyPair('A');
  assert.equal(firstLoad.publicKeyBase64, publicKeyBase64);
  assert.equal(firstLoad.privateKey.type, 'private');
  assert.equal(firstLoad.privateKey.extractable, false);

  const secondLoad = await loadKeyPair('A');
  assert.equal(secondLoad.publicKeyBase64, firstLoad.publicKeyBase64);

  const bob = await generateKeyPair();
  const pubB = await exportPublicKey(bob.publicKey);

  const keyFresh = await deriveSharedKey(generated.privateKey, pubB);
  const keyReloaded = await deriveSharedKey(secondLoad.privateKey, pubB);

  const packet = await encryptMessage(keyFresh, 'survives refresh', {
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });
  assert.equal(await decryptMessage(keyReloaded, packet), 'survives refresh');

  const peerKey = await deriveSharedKey(bob.privateKey, publicKeyBase64);
  assert.equal(await decryptMessage(peerKey, packet), 'survives refresh');
});

test('key pairs are stored per role', async () => {
  const generatedB = await generateKeyPair();
  const publicKeyBase64B = await exportPublicKey(generatedB.publicKey);
  await saveKeyPair('B', { privateKey: generatedB.privateKey, publicKeyBase64: publicKeyBase64B });

  const loadedA = await loadKeyPair('A');
  const loadedB = await loadKeyPair('B');
  assert.notEqual(loadedA.publicKeyBase64, loadedB.publicKeyBase64);

  await assert.rejects(() => saveKeyPair('C', { privateKey: null, publicKeyBase64: 'x' }), /Invalid role/);
  await assert.rejects(() => saveKeyPair('A', { privateKey: null, publicKeyBase64: '' }), /Invalid key pair/);

  await clearMessages();
  assert.equal((await getEncryptedMessages()).length, 0);
});
