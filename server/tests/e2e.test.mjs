import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  TestSocket,
  apiPost,
  connectUser,
  createKeyPair,
  deriveConversationKey,
  encryptFor,
  registerUser,
  startServer
} from './helpers/harness.mjs';
import { startTestDb, stopTestDb } from './helpers/testdb.mjs';

const ALLOWED_CLIENT_EVENTS = new Set(['conversation_create', 'message_send', 'message_ack', 'message_sync']);

let db;
let server;
let alice;
let bob;
let conversation;
const sockets = [];

async function user(name) {
  const keys = await createKeyPair();
  const r = await registerUser(server.url, {
    username: name,
    email: `${name}@test.local`,
    password: 'password123',
    publicKey: keys.publicKeyBase64,
    displayName: name
  });
  if (r.status !== 201) {
    throw new Error(`register ${name} failed: ${r.status} ${JSON.stringify(r.body)}`);
  }
  return { keys, user: r.body.user, cookie: r.cookie };
}

async function track(name, cookie) {
  const s = await connectUser(server.url, cookie, name);
  sockets.push(s);
  return s;
}

function dump() {
  return JSON.stringify(sockets.map((s) => ({ sent: s.sent, received: s.log })));
}

before(async () => {
  db = await startTestDb();
  server = await startServer(db.connectionString);
  alice = await user('alice');
  bob = await user('bob');
  const sA = await track('A', alice.cookie);
  const sB = await track('B', bob.cookie);
  const c = await sA.emitAck('conversation_create', { otherUserId: bob.user.userId });
  assert.equal(c.ok, true);
  conversation = c.conversation;
  await sB.next('conversation', (p) => p.conversation?.id === conversation.id);
});

after(async () => {
  try { for (const s of sockets) s.disconnect(); } catch {}
  try { if (server) await server.stop(); } catch {}
  try { if (db) await stopTestDb(db); } catch {}
});

test('full two-person authenticated flow with encryption, queue, acks and rejections', async () => {
  const sA = sockets[0];
  const sB = sockets[1];
  const keyA = await deriveConversationKey(alice.keys.privateKey, bob.user.publicKey, conversation.id);
  const keyB = await deriveConversationKey(bob.keys.privateKey, alice.user.publicKey, conversation.id);

  const m1 = crypto.randomUUID();
  const p1 = await encryptFor(keyA, 'MSG_A', {
    messageId: m1,
    senderId: alice.user.userId,
    aad: `securechat.v1|${conversation.id}|${m1}|${alice.user.userId}`
  });
  const ack1 = await sA.emitAck('message_send', { conversationId: conversation.id, ...p1 });
  assert.equal(ack1.ok, true);
  assert.equal(ack1.status, 'sent');
  const d1 = await sB.next('message_deliver', (x) => x.messageId === m1);
  assert.equal(d1.sender, alice.user.userId);
  assert.ok(!JSON.stringify(d1).includes('MSG_A'));
  const ackB1 = await sB.emitAck('message_ack', { messageId: m1 });
  assert.deepEqual(ackB1, { ok: true, deleted: true });
  await sA.next('delivery_status', (x) => x.messageId === m1 && x.status === 'delivered');

  const m2 = crypto.randomUUID();
  const p2 = await encryptFor(keyB, 'MSG_B', {
    messageId: m2,
    senderId: bob.user.userId,
    aad: `securechat.v1|${conversation.id}|${m2}|${bob.user.userId}`
  });
  const ack2 = await sB.emitAck('message_send', { conversationId: conversation.id, ...p2 });
  assert.equal(ack2.ok, true);
  const d2 = await sA.next('message_deliver', (x) => x.messageId === m2);
  assert.equal(d2.sender, bob.user.userId);
  await sA.emitAck('message_ack', { messageId: m2 });

  const m3 = crypto.randomUUID();
  const p3 = await encryptFor(keyA, 'MSG_OFFLINE', {
    messageId: m3,
    senderId: alice.user.userId,
    aad: `securechat.v1|${conversation.id}|${m3}|${alice.user.userId}`
  });
  sB.disconnect();
  const ack3 = await sA.emitAck('message_send', { conversationId: conversation.id, ...p3 });
  assert.equal(ack3.status, 'queued');
  const dup = await sA.emitAck('message_send', { conversationId: conversation.id, ...p3 });
  assert.equal(dup.status, 'duplicate');

  const sB2 = await track('B2', bob.cookie);
  const sync = await sB2.emitAck('message_sync', {});
  const q = sync.messages.find((mm) => mm.messageId === m3);
  assert.ok(q);
  await sB2.emitAck('message_ack', { messageId: m3 });

  const bad = await sA.emitAck('message_send', {
    conversationId: conversation.id,
    messageId: crypto.randomUUID(),
    ciphertext: p1.ciphertext,
    iv: 'AAAA',
    timestamp: Date.now()
  });
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, 'invalid_packet');

  const forbUser = await user('carolx');
  const forb = forbUser.cookie;
  const sC = await track('C', forb);
  const f = await sC.emitAck('message_send', { conversationId: conversation.id, ...p1 });
  assert.equal(f.ok, false);
  assert.equal(f.reason, 'forbidden');
  sC.disconnect();
  sB2.disconnect();

  const t = dump();
  assert.ok(!t.includes('MSG_A'));
  assert.ok(!t.includes('MSG_B'));
  assert.ok(!t.includes('MSG_OFFLINE'));
  assert.ok(!t.includes('privateKey'));
  assert.ok(!t.includes('pkcs8'));

  for (const s of sockets) {
    for (const e of s.sent) {
      assert.ok(ALLOWED_CLIENT_EVENTS.has(e.event));
    }
  }
});
