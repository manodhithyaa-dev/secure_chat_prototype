import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { io as ioClient } from 'socket.io-client';
import {
  decryptMessage,
  deriveSharedKey,
  encryptMessage,
  exportPublicKey,
  generateKeyPair
} from '../../client/src/crypto.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');
const port = 4000 + Math.floor(Math.random() * 2000);
const url = `http://localhost:${port}`;

const TRACKED_EVENTS = [
  'joined',
  'join_error',
  'peer_public_key',
  'encrypted_message',
  'delivery_status',
  'message_rejected',
  'peer_status'
];

const ALLOWED_CLIENT_EVENTS = new Set(['join', 'public_key', 'encrypted_message', 'delivery_status']);

const sentLog = [];

class TestClient {
  constructor(label) {
    this.label = label;
    this.log = [];
    this.pending = [];
    this.waiters = [];
    this.socket = ioClient(url, { transports: ['websocket'], reconnection: false });
    for (const event of TRACKED_EVENTS) {
      this.socket.on(event, (payload) => this._receive(event, payload));
    }
  }

  _receive(event, payload) {
    const entry = { event, payload };
    this.log.push(entry);
    const waiter = this.waiters.find((w) => w.event === event && w.match(payload));
    if (waiter) {
      this.waiters = this.waiters.filter((w) => w !== waiter);
      clearTimeout(waiter.timer);
      waiter.resolve(payload);
      return;
    }
    this.pending.push(entry);
  }

  next(event, match = () => true, timeout = 5000) {
    const index = this.pending.findIndex((entry) => entry.event === event && match(entry.payload));
    if (index >= 0) {
      const [entry] = this.pending.splice(index, 1);
      return Promise.resolve(entry.payload);
    }
    return new Promise((resolve, reject) => {
      const waiter = { event, match, resolve, payload: null };
      waiter.timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        reject(new Error(`${this.label}: timed out waiting for "${event}"`));
      }, timeout);
      this.waiters.push(waiter);
    });
  }

  emit(event, payload) {
    sentLog.push({ from: this.label, event, payload });
    this.socket.emit(event, payload);
  }

  disconnect() {
    this.socket.disconnect();
  }
}

async function createPair() {
  const pair = await generateKeyPair();
  return { ...pair, publicKeyBase64: await exportPublicKey(pair.publicKey) };
}

let serverProcess;
let serverOutput = '';

function startServer() {
  const child = spawn(process.execPath, ['dist/server.js'], {
    cwd: serverRoot,
    env: { ...process.env, PORT: String(port) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', (chunk) => {
    serverOutput += chunk.toString();
  });
  child.stderr.on('data', (chunk) => {
    serverOutput += chunk.toString();
  });
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`Server did not start: ${serverOutput}`)), 10000);
    const check = setInterval(() => {
      if (serverOutput.includes('listening')) {
        clearInterval(check);
        clearTimeout(timer);
        resolve();
      }
    }, 50);
    child.on('exit', (code) => {
      clearInterval(check);
      clearTimeout(timer);
      reject(new Error(`Server exited early with code ${code}: ${serverOutput}`));
    });
  });
  return { child, ready };
}

before(async () => {
  const started = startServer();
  serverProcess = started.child;
  await started.ready;
});

after(() => {
  if (serverProcess) serverProcess.kill('SIGTERM');
});

test('full two-person relay: key exchange, messages, statuses, rejections', async () => {
  const SECRET_A = 'PLAINTEXT_FROM_A_9f3a7c must never travel';
  const SECRET_B = 'PLAINTEXT_FROM_B_2b8d1e must never travel';
  const SECRET_OFFLINE = 'PLAINTEXT_WHILE_OFFLINE_55aa must never travel';

  const alice = await createPair();
  const bob = await createPair();

  const A = new TestClient('A');
  const B = new TestClient('B');

  A.emit('join', { role: 'A', publicKey: alice.publicKeyBase64 });
  const joinedA = await A.next('joined');
  assert.equal(joinedA.role, 'A');
  const peerStatusA0 = await A.next('peer_status');
  assert.equal(peerStatusA0.connected, false);

  B.emit('join', { role: 'B', publicKey: bob.publicKeyBase64 });
  const joinedB = await B.next('joined');
  assert.equal(joinedB.role, 'B');

  const receivedKeyA = await A.next('peer_public_key');
  const receivedKeyB = await B.next('peer_public_key');
  assert.equal(receivedKeyA.publicKey, bob.publicKeyBase64);
  assert.equal(receivedKeyB.publicKey, alice.publicKeyBase64);

  const connectedA = await A.next('peer_status', (p) => p.connected === true);
  const connectedB = await B.next('peer_status', (p) => p.connected === true);
  assert.equal(connectedA.peer, 'B');
  assert.equal(connectedB.peer, 'A');

  B.emit('public_key', { publicKey: bob.publicKeyBase64 });
  const refreshed = await A.next('peer_public_key', (p) => p.publicKey === bob.publicKeyBase64);
  assert.equal(refreshed.publicKey, bob.publicKeyBase64);

  const keyA = await deriveSharedKey(alice.privateKey, bob.publicKeyBase64, 'A-B');
  const keyB = await deriveSharedKey(bob.privateKey, alice.publicKeyBase64, 'A-B');

  const packet1 = await encryptMessage(keyA, SECRET_A, {
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });
  A.emit('encrypted_message', packet1);

  const sentAck = await A.next('delivery_status', (p) => p.status === 'sent');
  assert.equal(sentAck.messageId, packet1.messageId);

  const receivedByB = await B.next('encrypted_message');
  assert.equal(receivedByB.sender, 'A');
  assert.equal(receivedByB.messageId, packet1.messageId);
  assert.ok(!JSON.stringify(receivedByB).includes(SECRET_A));
  assert.equal(await decryptMessage(keyB, receivedByB), SECRET_A);

  B.emit('delivery_status', { messageId: packet1.messageId, status: 'delivered' });
  const deliveredAck = await A.next('delivery_status', (p) => p.status === 'delivered');
  assert.equal(deliveredAck.messageId, packet1.messageId);

  const packet2 = await encryptMessage(keyB, SECRET_B, {
    messageId: crypto.randomUUID(),
    sender: 'B',
    timestamp: Date.now()
  });
  B.emit('encrypted_message', packet2);
  const receivedByA = await A.next('encrypted_message');
  assert.equal(receivedByA.sender, 'B');
  assert.equal(await decryptMessage(keyA, receivedByA), SECRET_B);
  assert.notEqual(packet1.iv, packet2.iv);

  A.emit('delivery_status', { messageId: packet2.messageId, status: 'delivered' });
  const deliveredB = await B.next('delivery_status', (p) => p.status === 'delivered');
  assert.equal(deliveredB.messageId, packet2.messageId);

  const C = new TestClient('C');
  const carol = await createPair();
  C.emit('join', { role: 'A', publicKey: carol.publicKeyBase64 });
  const joinError = await C.next('join_error');
  assert.equal(joinError.error, 'Person A is already connected.');
  C.disconnect();

  B.emit('encrypted_message', {
    ...packet2,
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });
  const mismatch = await B.next('message_rejected', (p) => p.reason === 'sender_mismatch');
  assert.ok(mismatch.messageId);

  B.emit('encrypted_message', {
    messageId: crypto.randomUUID(),
    sender: 'B',
    ciphertext: packet2.ciphertext,
    iv: 'AAAA',
    timestamp: Date.now()
  });
  const badPacket = await B.next('message_rejected', (p) => p.reason === 'invalid_packet');
  assert.ok(badPacket.messageId);

  B.emit('encrypted_message', {
    messageId: 'x'.repeat(200),
    sender: 'B',
    ciphertext: packet2.ciphertext,
    iv: packet2.iv,
    timestamp: Date.now()
  });
  const badId = await B.next('message_rejected', (p) => p.reason === 'invalid_packet');
  assert.equal(badId.messageId, '');

  A.emit('delivery_status', { messageId: packet1.messageId, status: 'delivered' });
  const unknownRoute = await A.next('message_rejected', (p) => p.reason === 'unknown_message');
  assert.equal(unknownRoute.messageId, packet1.messageId);

  B.disconnect();
  const offline = await A.next('peer_status', (p) => p.connected === false);
  assert.equal(offline.peer, 'B');

  const packet3 = await encryptMessage(keyA, SECRET_OFFLINE, {
    messageId: crypto.randomUUID(),
    sender: 'A',
    timestamp: Date.now()
  });
  A.emit('encrypted_message', packet3);
  const offlineReject = await A.next('message_rejected', (p) => p.reason === 'peer_unavailable');
  assert.equal(offlineReject.messageId, packet3.messageId);

  A.disconnect();

  const allTraffic = JSON.stringify([...sentLog, ...A.log, ...B.log]);
  assert.ok(!allTraffic.includes('privateKey'));
  assert.ok(!allTraffic.includes('pkcs8'));
  assert.ok(!allTraffic.includes(SECRET_A));
  assert.ok(!allTraffic.includes(SECRET_B));
  assert.ok(!allTraffic.includes(SECRET_OFFLINE));

  for (const entry of sentLog) {
    assert.ok(ALLOWED_CLIENT_EVENTS.has(entry.event), `unexpected client event: ${entry.event}`);
  }

  assert.ok(serverOutput.includes('listening'));
  assert.ok(!serverOutput.includes(SECRET_A));
  assert.ok(!serverOutput.includes(SECRET_B));
  assert.ok(!serverOutput.includes('privateKey'));
});

test('invalid identity and invalid public key are rejected on join', async () => {
  const badRole = new TestClient('bad-role');
  badRole.emit('join', { role: 'Z', publicKey: 'AAAA' });
  const roleError = await badRole.next('join_error');
  assert.match(roleError.error, /Invalid identity/);
  badRole.disconnect();

  const badKey = new TestClient('bad-key');
  badKey.emit('join', { role: 'B', publicKey: 'not-a-public-key' });
  const keyError = await badKey.next('join_error');
  assert.match(keyError.error, /Invalid public key/);
  badKey.disconnect();
});
