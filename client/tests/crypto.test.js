import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  base64ToBytes,
  bytesToBase64,
  decryptMessage,
  deriveSharedKey,
  encryptMessage,
  exportPublicKey,
  generateFingerprint,
  generateKeyPair,
  importPublicKey,
  validatePacket
} from '../src/crypto.js';

async function createPair() {
  const pair = await generateKeyPair();
  const publicKeyBase64 = await exportPublicKey(pair.publicKey);
  return { ...pair, publicKeyBase64 };
}

async function rawSharedSecret(privateKey, peerPublicKeyBase64) {
  const bytes = base64ToBytes(peerPublicKeyBase64);
  const peer = await crypto.subtle.importKey(
    'spki',
    bytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, privateKey, 256));
}

test('Test 1: A and B derive the same shared secret and AES key', async () => {
  const alice = await createPair();
  const bob = await createPair();

  const secretA = await rawSharedSecret(alice.privateKey, bob.publicKeyBase64);
  const secretB = await rawSharedSecret(bob.privateKey, alice.publicKeyBase64);
  assert.deepEqual(Array.from(secretA), Array.from(secretB));

  const keyA = await deriveSharedKey(alice.privateKey, bob.publicKeyBase64, 'A-B');
  const keyB = await deriveSharedKey(bob.privateKey, alice.publicKeyBase64, 'A-B');
  assert.equal(keyA.algorithm.name, 'AES-GCM');
  assert.equal(keyA.algorithm.length, 256);
  assert.equal(keyA.extractable, false);

  const packet = await encryptMessage(keyA, 'key agreement check', {
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });
  assert.equal(await decryptMessage(keyB, packet), 'key agreement check');
});

test('Test 2: message encrypted by A decrypts on B', async () => {
  const alice = await createPair();
  const bob = await createPair();
  const keyA = await deriveSharedKey(alice.privateKey, bob.publicKeyBase64);
  const keyB = await deriveSharedKey(bob.privateKey, alice.publicKeyBase64);

  const plaintext = 'Hello Person B, this is secret number one.';
  const packet = await encryptMessage(keyA, plaintext, {
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });

  assert.equal(packet.sender, 'A');
  assert.ok(!JSON.stringify(packet).includes('secret number one'));
  assert.equal(await decryptMessage(keyB, packet), plaintext);
});

test('Test 3: message encrypted by B decrypts on A', async () => {
  const alice = await createPair();
  const bob = await createPair();
  const keyA = await deriveSharedKey(alice.privateKey, bob.publicKeyBase64);
  const keyB = await deriveSharedKey(bob.privateKey, alice.publicKeyBase64);

  const plaintext = 'Reply from Person B 🚀';
  const packet = await encryptMessage(keyB, plaintext, {
    messageId: crypto.randomUUID(),
    sender: 'B',
    timestamp: Date.now()
  });

  assert.equal(await decryptMessage(keyA, packet), plaintext);
});

test('Test 4: modified ciphertext fails authentication', async () => {
  const alice = await createPair();
  const bob = await createPair();
  const keyA = await deriveSharedKey(alice.privateKey, bob.publicKeyBase64);
  const keyB = await deriveSharedKey(bob.privateKey, alice.publicKeyBase64);

  const packet = await encryptMessage(keyA, 'authenticated payload', {
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });

  const bytes = base64ToBytes(packet.ciphertext);
  bytes[0] ^= 0xff;
  const tampered = { ...packet, ciphertext: bytesToBase64(bytes) };

  await assert.rejects(() => decryptMessage(keyB, tampered), /Decryption failed/);
});

test('Test 5: modified IV fails', async () => {
  const alice = await createPair();
  const bob = await createPair();
  const keyA = await deriveSharedKey(alice.privateKey, bob.publicKeyBase64);
  const keyB = await deriveSharedKey(bob.privateKey, alice.publicKeyBase64);

  const packet = await encryptMessage(keyA, 'iv integrity check', {
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });

  const iv = base64ToBytes(packet.iv);
  iv[0] ^= 0xff;
  const tampered = { ...packet, iv: bytesToBase64(iv) };

  await assert.rejects(() => decryptMessage(keyB, tampered), /Decryption failed/);
});

test('Test 6: wrong key cannot decrypt', async () => {
  const alice = await createPair();
  const bob = await createPair();
  const mallory = await createPair();

  const keyA = await deriveSharedKey(alice.privateKey, bob.publicKeyBase64);
  const wrongKey = await deriveSharedKey(mallory.privateKey, bob.publicKeyBase64, 'A-B');
  const otherConversation = await deriveSharedKey(alice.privateKey, bob.publicKeyBase64, 'A-C');

  const packet = await encryptMessage(keyA, 'only for bob', {
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });

  await assert.rejects(() => decryptMessage(wrongKey, packet), /Decryption failed/);
  await assert.rejects(() => decryptMessage(otherConversation, packet), /Decryption failed/);
});

test('Test 7: every message uses a fresh IV', async () => {
  const alice = await createPair();
  const bob = await createPair();
  const keyA = await deriveSharedKey(alice.privateKey, bob.publicKeyBase64);

  const ivs = new Set();
  for (let i = 0; i < 50; i += 1) {
    const packet = await encryptMessage(keyA, `message ${i}`, {
      messageId: crypto.randomUUID(),
      sender: 'A',
      timestamp: Date.now() + i
    });
    const ivBytes = base64ToBytes(packet.iv);
    assert.equal(ivBytes.length, 12);
    ivs.add(packet.iv);
  }
  assert.equal(ivs.size, 50);
});

test('rejects malformed packets, oversized messages and invalid keys', async () => {
  const alice = await createPair();
  const keyA = await deriveSharedKey(alice.privateKey, alice.publicKeyBase64);

  await assert.rejects(
    () => encryptMessage(keyA, 'x'.repeat(4097), {
      messageId: crypto.randomUUID(),
      sender: 'A',
      timestamp: Date.now()
    }),
    /4096/
  );
  await assert.rejects(
    () => encryptMessage(keyA, 'ok', { messageId: '', sender: 'A', timestamp: Date.now() }),
    /messageId/
  );
  await assert.rejects(() => importPublicKey('not-a-key'), /Invalid public key/);
  await assert.rejects(() => importPublicKey(bytesToBase64(new Uint8Array(10).fill(1))), /Invalid public key/);

  assert.throws(() => validatePacket(null), /Invalid encrypted packet/);
  assert.throws(
    () => validatePacket({ messageId: '1', sender: 'C', ciphertext: 'AA==', iv: 'AAAAAAAAAAAAAAAA', timestamp: 1 }),
    /Invalid encrypted packet/
  );
  assert.throws(
    () => validatePacket({ messageId: '1', sender: 'A', ciphertext: 'AA==', iv: 'AAAA', timestamp: 1 }),
    /Invalid encrypted packet/
  );
});

test('fingerprints are stable, formatted and differ per key', async () => {
  const alice = await createPair();
  const bob = await createPair();

  const fpA1 = await generateFingerprint(alice.publicKeyBase64);
  const fpA2 = await generateFingerprint(alice.publicKeyBase64);
  const fpB = await generateFingerprint(bob.publicKeyBase64);

  assert.equal(fpA1, fpA2);
  assert.notEqual(fpA1, fpB);
  assert.match(fpA1, /^[0-9A-F]{2}(:[0-9A-F]{2}){7}$/);
});
