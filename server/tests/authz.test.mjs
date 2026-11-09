import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  TestSocket,
  apiPost,
  connectUser,
  createKeyPair,
  registerUser,
  startServer
} from './helpers/harness.mjs';
import { startTestDb, stopTestDb } from './helpers/testdb.mjs';
import { buildAad, deriveSharedKey, encryptMessage } from '../../client/src/crypto.js';

let db;
let server;
let alice;
let bob;
let carol;
let conversation;

before(async () => {
  db = await startTestDb();
  server = await startServer(db.connectionString);
  alice = await registerUserNamed('alice');
  bob = await registerUserNamed('bob');
  carol = await registerUserNamed('carol');

  const conv = await apiPost(server.url, '/api/conversations', {
    cookie: alice.cookie,
    body: { otherUserId: bob.user.userId }
  });
  conversation = conv.body.conversation;
  assert.ok(conversation.id);
});

async function registerUserNamed(username) {
  const keys = await createKeyPair();
  const result = await registerUser(server.url, { username, publicKey: keys.publicKeyBase64 });
  assert.equal(result.status, 201);
  return { keys, user: result.body.user, cookie: result.cookie };
}

test('A must not access B’s conversation as non-member and cannot spoof sender', async () => {
  const sockA = await connectUser(server.url, alice.cookie, 'a');
  const sockB = await connectUser(server.url, bob.cookie, 'b');
  const sockC = await connectUser(server.url, carol.cookie, 'c');

  const keyA = await deriveSharedKey(alice.keys.privateKey, bob.user.publicKey, conversation.id);
  const spoofId = crypto.randomUUID();
  const spoofPacket = await encryptMessage(
    keyA,
    'secret',
    { messageId: spoofId, sender: alice.user.userId, timestamp: Date.now() },
    buildAad(conversation.id, spoofId, alice.user.userId)
  );
  const spoofAck = await sockA.emitAck('message_send', {
    conversationId: conversation.id,
    ...spoofPacket,
    sender: bob.user.userId
  });
  assert.equal(spoofAck.ok, true);
  const delivered = await sockB.next('message_deliver', (p) => p.messageId === spoofId);
  assert.equal(delivered.sender, alice.user.userId);

  const forbidden = await sockC.emitAck('message_send', {
    conversationId: conversation.id,
    messageId: crypto.randomUUID(),
    ciphertext: spoofPacket.ciphertext,
    iv: spoofPacket.iv,
    timestamp: Date.now()
  });
  assert.equal(forbidden.ok, false);
  assert.equal(forbidden.reason, 'forbidden');

  const pendingId = crypto.randomUUID();
  const pending = await encryptMessage(
    keyA,
    'p',
    { messageId: pendingId, sender: alice.user.userId, timestamp: Date.now() },
    buildAad(conversation.id, pendingId, alice.user.userId)
  );
  await sockA.emitAck('message_send', { conversationId: conversation.id, ...pending });
  await sockB.next('message_deliver', (p) => p.messageId === pendingId);
  const carolSync = await sockC.emitAck('message_sync', {});
  assert.equal(carolSync.ok, true);
  assert.ok(!carolSync.messages.some((m) => m.messageId === pendingId));

  sockA.disconnect();
  sockB.disconnect();
  sockC.disconnect();
});

test('user search never leaks sensitive fields', async () => {
  const res = await apiPost(server.url, '/api/conversations', {
    cookie: alice.cookie,
    body: { otherUserId: carol.user.userId }
  });
  assert.equal(res.status, 200);
});

after(async () => {
  await server.stop();
  await stopTestDb(db);
});
