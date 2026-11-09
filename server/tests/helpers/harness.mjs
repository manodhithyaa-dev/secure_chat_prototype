import { spawn } from 'node:child_process';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { io as ioClient } from 'socket.io-client';
import {
  deriveSharedKey,
  encryptMessage,
  exportPublicKey,
  generateKeyPair
} from '../../../client/src/crypto.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const serverRoot = path.join(here, '..', '..');

export const TRACKED_EVENTS = [
  'conversation',
  'message_deliver',
  'delivery_status',
  'message_rejected',
  'presence',
  'auth_error'
];

export async function startServer(databaseUrl, options = {}) {
  const port = options.port ?? 4000 + Math.floor(Math.random() * 3000);
  const child = spawn(process.execPath, ['dist/server.js'], {
    cwd: serverRoot,
    env: {
      ...process.env,
      PORT: String(port),
      DATABASE_URL: databaseUrl,
      NODE_ENV: 'test',
      ...(options.env ?? {})
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let output = '';
  child.stdout.on('data', (chunk) => {
    output += chunk;
  });
  child.stderr.on('data', (chunk) => {
    output += chunk;
  });

  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (output.includes('listening')) break;
    if (child.exitCode !== null) throw new Error(`server exited early: ${output}`);
    await sleep(50);
  }
  if (!output.includes('listening')) {
    throw new Error(`server did not start: ${output}`);
  }

  return {
    child,
    port,
    url: `http://localhost:${port}`,
    getOutput: () => output,
    async stop() {
      if (child.exitCode !== null) return;
      child.kill('SIGTERM');
      await new Promise((resolve) => {
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          resolve();
        }, 5000);
        child.on('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
  };
}

export async function createKeyPair() {
  const pair = await generateKeyPair();
  const publicKeyBase64 = await exportPublicKey(pair.publicKey);
  return { privateKey: pair.privateKey, publicKeyBase64 };
}

export async function apiPost(url, pathname, { cookie, body } = {}) {
  const response = await fetch(`${url}${pathname}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(cookie ? { Cookie: cookie } : {})
    },
    body: JSON.stringify(body ?? {})
  });
  const setCookie = response.headers.get('set-cookie') || '';
  const cookieValue = setCookie ? setCookie.split(';')[0] : null;
  let json = null;
  const text = await response.text();
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  return { status: response.status, cookie: cookieValue, setCookie, body: json };
}

export async function apiGet(url, pathname, { cookie } = {}) {
  const response = await fetch(`${url}${pathname}`, {
    headers: cookie ? { Cookie: cookie } : {}
  });
  let json = null;
  const text = await response.text();
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  return { status: response.status, body: json };
}

export async function registerUser(url, { username, password = 'password123', publicKey, displayName }) {
  const result = await apiPost(url, '/api/auth/register', {
    body: {
      username,
      email: `${username}@example.com`,
      password,
      publicKey,
      ...(displayName ? { displayName } : {})
    }
  });
  return result;
}

export async function loginUser(url, identifier, password) {
  return apiPost(url, '/api/auth/login', { body: { identifier, password } });
}

export class TestSocket {
  constructor(url, cookie, label = 'socket') {
    this.label = label;
    this.log = [];
    this.sent = [];
    this.pending = [];
    this.waiters = [];
    this.socket = ioClient(url, {
      transports: ['websocket'],
      reconnection: false,
      extraHeaders: cookie ? { Cookie: cookie } : {}
    });
    for (const event of TRACKED_EVENTS) {
      this.socket.on(event, (payload) => this._receive(event, payload));
    }
  }

  waitForConnect(timeout = 8000) {
    if (this.socket.connected) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`${this.label}: connect timeout`)), timeout);
      this.socket.once('connect', () => {
        clearTimeout(timer);
        resolve();
      });
      this.socket.once('connect_error', (error) => {
        clearTimeout(timer);
        reject(error);
      });
    });
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

  next(event, match = () => true, timeout = 8000) {
    const index = this.pending.findIndex((entry) => entry.event === event && match(entry.payload));
    if (index >= 0) {
      const [entry] = this.pending.splice(index, 1);
      return Promise.resolve(entry.payload);
    }
    return new Promise((resolve, reject) => {
      const waiter = { event, match, resolve };
      waiter.timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== waiter);
        reject(new Error(`${this.label}: timed out waiting for "${event}"`));
      }, timeout);
      this.waiters.push(waiter);
    });
  }

  emitAck(event, payload, timeout = 8000) {
    this.sent.push({ event, payload });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`${this.label}: ack timeout for "${event}"`)), timeout);
      this.socket.emit(event, payload, (response) => {
        clearTimeout(timer);
        resolve(response);
      });
    });
  }

  emit(event, payload) {
    this.sent.push({ event, payload });
    this.socket.emit(event, payload);
  }

  disconnect() {
    this.socket.disconnect();
  }
}

export async function connectUser(url, cookie, label) {
  const socket = new TestSocket(url, cookie, label);
  await socket.waitForConnect();
  return socket;
}

export async function makeConversation(url, cookie, otherUserId) {
  const result = await apiPost(url, '/api/conversations', {
    cookie,
    body: { otherUserId }
  });
  if (result.status !== 200 || !result.body?.conversation) {
    throw new Error(`conversation create failed: ${result.status} ${JSON.stringify(result.body)}`);
  }
  return result.body.conversation;
}

export async function deriveConversationKey(privateKey, peerPublicKeyBase64, conversationId) {
  return deriveSharedKey(privateKey, peerPublicKeyBase64, conversationId);
}

export async function encryptFor(conversationKey, plaintext, { messageId, senderId, aad }) {
  return encryptMessage(
    conversationKey,
    plaintext,
    { messageId, sender: senderId, timestamp: Date.now() },
    aad
  );
}
