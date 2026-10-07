import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';

const here = path.dirname(fileURLToPath(import.meta.url));
const serverRoot = path.join(here, '..');

const CHROME_CANDIDATES = [
  process.env.CHROME_BIN,
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/usr/bin/chrome'
].filter(Boolean);
const chromePath = CHROME_CANDIDATES.find((candidate) => existsSync(candidate)) || null;

const MSG_A = 'Hello from A over E2E';
const MSG_B = 'Hi A, this is B replying';
const MSG_OFFLINE = 'Sent while B was offline';

const serverPort = 5200 + Math.floor(Math.random() * 1000);
const chromePort = 9500 + Math.floor(Math.random() * 400);
const appUrl = `http://localhost:${serverPort}`;

let serverProcess = null;
let serverOutput = '';
let chromeProcess = null;
let chromeProfile = null;
let cdp = null;

function getJson(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        let body = '';
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => {
          try {
            resolve(JSON.parse(body));
          } catch (error) {
            reject(error);
          }
        });
      })
      .on('error', reject);
  });
}

async function startServer() {
  const child = spawn(process.execPath, ['dist/server.js'], {
    cwd: serverRoot,
    env: { ...process.env, PORT: String(serverPort) },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  child.stdout.on('data', (chunk) => {
    serverOutput += chunk.toString();
  });
  child.stderr.on('data', (chunk) => {
    serverOutput += chunk.toString();
  });
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    if (serverOutput.includes('listening')) return child;
    if (child.exitCode !== null) throw new Error(`server exited: ${serverOutput}`);
    await sleep(50);
  }
  throw new Error(`server did not start: ${serverOutput}`);
}

async function startChrome() {
  chromeProfile = mkdtempSync(path.join(os.tmpdir(), 'secure-chat-chrome-'));
  const child = spawn(
    chromePath,
    [
      '--headless=new',
      '--no-sandbox',
      '--disable-gpu',
      '--disable-dev-shm-usage',
      `--remote-debugging-port=${chromePort}`,
      `--user-data-dir=${chromeProfile}`,
      'about:blank'
    ],
    { stdio: 'ignore', detached: true }
  );
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const version = await getJson(`http://localhost:${chromePort}/json/version`);
      if (version.webSocketDebuggerUrl) return { child, version };
    } catch (error) {
      await sleep(100);
    }
  }
  throw new Error('chrome did not start');
}

function connectCdp(wsUrl) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(wsUrl);
    let nextId = 0;
    const pending = new Map();
    const listeners = new Set();
    ws.on('message', (raw) => {
      const message = JSON.parse(raw.toString());
      if (message.id && pending.has(message.id)) {
        const { resolve: done, reject: fail } = pending.get(message.id);
        pending.delete(message.id);
        if (message.error) fail(new Error(message.error.message));
        else done(message.result);
        return;
      }
      if (message.method) {
        for (const listener of listeners) listener(message);
      }
    });
    ws.on('open', () =>
      resolve({
        on(listener) {
          listeners.add(listener);
        },
        send(method, params = {}, sessionId) {
          const id = ++nextId;
          return new Promise((done, fail) => {
            pending.set(id, { resolve: done, reject: fail });
            ws.send(
              JSON.stringify({
                id,
                method,
                params,
                ...(sessionId ? { sessionId } : {})
              })
            );
          });
        },
        close() {
          ws.close();
        }
      })
    );
    ws.on('error', reject);
  });
}

async function openPage(url) {
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const consoleLines = [];

  const page = {
    console: consoleLines,
    async eval(expression) {
      const result = await cdp.send(
        'Runtime.evaluate',
        { expression, awaitPromise: true, returnByValue: true },
        sessionId
      );
      if (result.exceptionDetails) {
        const description =
          result.exceptionDetails.exception?.description ||
          result.exceptionDetails.text ||
          'evaluation failed';
        throw new Error(description);
      }
      return result.result?.value;
    },
    async waitFor(expression, timeout = 20000) {
      const started = Date.now();
      let last;
      while (Date.now() - started < timeout) {
        try {
          last = await page.eval(expression);
        } catch (error) {
          last = undefined;
        }
        if (last) return last;
        await sleep(120);
      }
      const consoleTail = consoleLines.slice(-8).join('\n');
      throw new Error(
        `timeout waiting for expression (last=${JSON.stringify(last)}): ${expression}\nconsole:\n${consoleTail}`
      );
    },
    async close() {
      await cdp.send('Target.closeTarget', { targetId });
    }
  };

  cdp.on((message) => {
    if (message.sessionId !== sessionId) return;
    if (message.method === 'Runtime.consoleAPICalled') {
      const text = (message.params.args || [])
        .map((arg) => arg.value ?? arg.description ?? '')
        .join(' ');
      consoleLines.push(`[console.${message.params.type}] ${text}`);
    } else if (message.method === 'Runtime.exceptionThrown') {
      const details = message.params.exceptionDetails;
      consoleLines.push(
        `[exception] ${details.exception?.description || details.text || 'unknown'}`
      );
    } else if (message.method === 'Log.entryAdded') {
      consoleLines.push(`[log] ${message.params.entry.text}`);
    }
  });

  await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('Log.enable', {}, sessionId);
  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Page.navigate', { url }, sessionId);
  await page.waitFor('document.readyState === "complete"');
  return page;
}

async function joinAs(page, role) {
  let lastError = null;
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await page.eval(`document.querySelector('[data-role="${role}"]').click()`);
    try {
      const state = await page.waitFor(
        `(document.getElementById('chat-screen').classList.contains('active') && 'joined') ||
         (document.getElementById('join-error').textContent ? 'error' : false)`,
        8000
      );
      if (state === 'joined') return;
      lastError = new Error(`join rejected: ${await page.eval(`document.getElementById('join-error').textContent`)}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(500);
  }
  throw lastError || new Error(`could not join as ${role}`);
}

async function sendMessage(page, text) {
  const safe = JSON.stringify(text);
  await page.eval(`(() => {
    const input = document.getElementById('message-input');
    input.value = ${safe};
    document.getElementById('composer').requestSubmit();
    return true;
  })()`);
}

function bubbleWaiter(cls, text) {
  const safe = JSON.stringify(text);
  return `(() => {
    const nodes = Array.from(document.querySelectorAll('#messages .message.${cls} .bubble'));
    const texts = nodes.map((node) => node.textContent);
    return texts.includes(${safe}) ? texts.join(' | ') : false;
  })()`;
}

function bubbleTexts() {
  return `Array.from(document.querySelectorAll('#messages .bubble')).map((node) => node.textContent).join(' | ')`;
}

async function readStore(page, storeName) {
  return page.eval(`(async () => {
    const db = await new Promise((resolve, reject) => {
      const request = indexedDB.open('secure-chat');
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    const rows = await new Promise((resolve, reject) => {
      const request = db.transaction('${storeName}', 'readonly').objectStore('${storeName}').getAll();
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
    return JSON.stringify(rows);
  })()`);
}

before(async () => {
  if (!chromePath) return;
  serverProcess = await startServer();
  const chrome = await startChrome();
  chromeProcess = chrome.child;
  cdp = await connectCdp(chrome.version.webSocketDebuggerUrl);
});

after(async () => {
  if (cdp) cdp.close();
  if (chromeProcess) {
    try {
      process.kill(-chromeProcess.pid, 'SIGKILL');
    } catch (error) {
      chromeProcess.kill('SIGKILL');
    }
  }
  if (serverProcess) serverProcess.kill('SIGTERM');
  if (chromeProfile) rmSync(chromeProfile, { recursive: true, force: true });
});

test('browser: two users chat, refresh, offline and reconnect', { timeout: 240000 }, async (t) => {
  if (!chromePath) {
    return t.skip('no Chrome/Chromium binary found');
  }

  const pageA = await openPage(appUrl);
  const pageB = await openPage(appUrl);

  await joinAs(pageA, 'A');
  await joinAs(pageB, 'B');

  await pageA.waitFor(
    `document.getElementById('encryption-status').textContent.includes('End-to-end encrypted')`
  );
  await pageB.waitFor(
    `document.getElementById('encryption-status').textContent.includes('End-to-end encrypted')`
  );
  await pageA.waitFor(
    `document.getElementById('connection-status').textContent.includes('Connected to Person B')`
  );
  await pageB.waitFor(
    `document.getElementById('connection-status').textContent.includes('Connected to Person A')`
  );

  const ownA = await pageA.eval(`document.getElementById('own-fingerprint').textContent`);
  const ownB = await pageB.eval(`document.getElementById('own-fingerprint').textContent`);
  const peerOnA = await pageA.eval(`document.getElementById('peer-fingerprint').textContent`);
  const peerOnB = await pageB.eval(`document.getElementById('peer-fingerprint').textContent`);
  assert.match(ownA, /^Your fingerprint: ([0-9A-F]{2}:){7}[0-9A-F]{2}$/);
  assert.match(ownB, /^Your fingerprint: ([0-9A-F]{2}:){7}[0-9A-F]{2}$/);
  assert.match(peerOnA, /^Peer fingerprint: ([0-9A-F]{2}:){7}[0-9A-F]{2}$/);
  assert.match(peerOnB, /^Peer fingerprint: ([0-9A-F]{2}:){7}[0-9A-F]{2}$/);
  assert.equal(peerOnA.replace('Peer fingerprint: ', ''), ownB.replace('Your fingerprint: ', ''));
  assert.equal(peerOnB.replace('Peer fingerprint: ', ''), ownA.replace('Your fingerprint: ', ''));

  await sendMessage(pageA, MSG_A);
  await pageB.waitFor(bubbleWaiter('theirs', MSG_A));
  await pageA.waitFor(
    `Array.from(document.querySelectorAll('#messages .message.mine .meta')).some((node) => node.textContent === 'delivered')`
  );

  await sendMessage(pageB, MSG_B);
  await pageA.waitFor(bubbleWaiter('theirs', MSG_B));
  await pageB.waitFor(
    `Array.from(document.querySelectorAll('#messages .message.mine .meta')).some((node) => node.textContent === 'delivered')`
  );

  const beforeReload = {
    own: await pageA.eval(`document.getElementById('own-fingerprint').textContent`),
    texts: await pageA.eval(bubbleTexts())
  };
  assert.ok(beforeReload.texts.includes(MSG_A));
  assert.ok(beforeReload.texts.includes(MSG_B));

  await pageA.eval(`location.reload()`).catch(() => {});
  await pageA.waitFor(`document.getElementById('join-screen').classList.contains('active')`);
  await joinAs(pageA, 'A');
  await pageA.waitFor(
    `document.getElementById('encryption-status').textContent.includes('End-to-end encrypted')`
  );
  await pageA.waitFor(bubbleWaiter('mine', MSG_A));

  const afterReload = {
    own: await pageA.eval(`document.getElementById('own-fingerprint').textContent`),
    texts: await pageA.eval(bubbleTexts())
  };
  assert.equal(afterReload.own, beforeReload.own, 'identity key must survive page reload');
  assert.ok(afterReload.texts.includes(MSG_A), 'history restored after reload');
  assert.ok(afterReload.texts.includes(MSG_B), 'peer messages restored after reload');

  const rawMessages = await readStore(pageA, 'messages');
  assert.ok(!rawMessages.includes(MSG_A), 'plaintext must not be in IndexedDB');
  assert.ok(!rawMessages.includes(MSG_B), 'plaintext must not be in IndexedDB');
  assert.ok(!rawMessages.includes('plaintext'));

  const rawKeys = await readStore(pageA, 'keys');
  assert.ok(rawKeys.includes('"role":"A"'));
  assert.ok(!rawKeys.includes('pkcs8'));

  await pageB.close();
  await pageA.waitFor(
    `document.getElementById('connection-status').textContent.includes('Person B is offline')`
  );

  await sendMessage(pageA, MSG_OFFLINE);
  await pageA.waitFor(`document.getElementById('notice').textContent.includes('offline')`);
  await pageA.waitFor(
    `(() => {
      const nodes = Array.from(document.querySelectorAll('#messages .message.mine'));
      const match = nodes.find((node) => node.querySelector('.bubble').textContent === ${JSON.stringify(MSG_OFFLINE)});
      return match && match.querySelector('.meta').textContent === 'sending' ? 'sending' : false;
    })()`
  );

  const pageB2 = await openPage(appUrl);
  await joinAs(pageB2, 'B');
  await pageB2.waitFor(bubbleWaiter('theirs', MSG_OFFLINE));
  await pageA.waitFor(
    `(() => {
      const nodes = Array.from(document.querySelectorAll('#messages .message.mine'));
      const match = nodes.find((node) => node.querySelector('.bubble').textContent === ${JSON.stringify(MSG_OFFLINE)});
      return match && match.querySelector('.meta').textContent === 'delivered' ? 'delivered' : false;
    })()`
  );
  await pageA.waitFor(
    `document.getElementById('connection-status').textContent.includes('Connected to Person B')`
  );

  const rawMessagesFinal = await readStore(pageB2, 'messages');
  assert.ok(!rawMessagesFinal.includes(MSG_A));
  assert.ok(!rawMessagesFinal.includes(MSG_OFFLINE));
  assert.ok(!serverOutput.includes(MSG_A));
  assert.ok(!serverOutput.includes(MSG_B));
  assert.ok(!serverOutput.includes(MSG_OFFLINE));

  await pageB2.close();
  await pageA.close();
});
