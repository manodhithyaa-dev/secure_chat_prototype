import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const clientSrc = path.join(here, '..', 'src');
const serverSrc = path.join(here, '..', '..', 'server', 'src');

async function readDirFiles(dir) {
  const entries = await readdir(dir);
  const files = [];
  for (const entry of entries) {
    const full = path.join(dir, entry);
    const stat = await import('node:fs/promises').then((fs) => fs.stat(full));
    if (stat.isFile()) files.push({ name: entry, source: await readFile(full, 'utf8') });
  }
  return files;
}

test('Test 8: no private key material is ever emitted over Socket.IO', async () => {
  const files = await readDirFiles(clientSrc);
  assert.ok(files.length >= 5);

  for (const file of files) {
    assert.ok(
      !file.source.includes('pkcs8'),
      `${file.name} must not export or handle PKCS#8 private keys`
    );
    assert.ok(
      !/exportKey\s*\(\s*['"]pkcs8['"]/.test(file.source),
      `${file.name} must not export private keys`
    );
  }

  const socketSource = (await readDirFiles(clientSrc)).find((f) => f.name === 'socket.js').source;
  assert.ok(!socketSource.includes('privateKey'), 'socket module must not touch private keys');
  assert.ok(!socketSource.includes('plaintext'), 'socket module must not touch plaintext');
  assert.ok(!socketSource.includes('deriveSharedKey'), 'socket module must not derive keys');

  for (const file of await readDirFiles(clientSrc)) {
    const emitCalls = file.source.match(/\.emit\([^)]*\)/g) || [];
    for (const call of emitCalls) {
      assert.ok(!call.includes('plaintext'), `${file.name} emits plaintext: ${call}`);
      assert.ok(!call.includes('privateKey'), `${file.name} emits a private key: ${call}`);
    }
  }
});

test('server source never sees private keys, plaintext or decryption code', async () => {
  const files = await readDirFiles(serverSrc);
  assert.ok(files.length >= 3);

  for (const file of files) {
    const lower = file.source.toLowerCase();
    assert.ok(!lower.includes('privatekey'), `${file.name} references a private key`);
    assert.ok(!lower.includes('plaintext'), `${file.name} references plaintext`);
    assert.ok(!/decrypt/.test(lower), `${file.name} contains decryption code`);
    assert.ok(!/hkdf|aes-?gcm|derivebits/.test(lower), `${file.name} performs key derivation`);
  }
});

test('server has no persistent storage or logging of message payloads', async () => {
  const files = await readDirFiles(serverSrc);
  for (const file of files) {
    assert.ok(
      !/writeFile|createWriteStream|sqlite|redis|mongo|levelup|nedb/.test(file.source),
      `${file.name} writes data to disk or a database`
    );
    assert.ok(
      !/console\.(log|info|debug)\([^)]*(packet|message|payload|ciphertext)/.test(file.source),
      `${file.name} logs message payloads`
    );
  }
});

test('client keeps crypto, storage, socket and UI separated', async () => {
  const files = await readDirFiles(clientSrc);
  const names = files.map((f) => f.name).sort();
  assert.deepEqual(names, ['app.js', 'crypto.js', 'socket.js', 'storage.js', 'styles.css', 'ui.js']);

  const cryptoSource = files.find((f) => f.name === 'crypto.js').source;
  assert.ok(!cryptoSource.includes('indexedDB'), 'crypto module must not use storage');
  assert.ok(!cryptoSource.includes('.emit('), 'crypto module must not use sockets');

  const storageSource = files.find((f) => f.name === 'storage.js').source;
  assert.ok(!storageSource.includes('.emit('), 'storage module must not use sockets');
  assert.ok(!storageSource.includes('subtle'), 'storage module must not perform crypto');

  const uiSource = files.find((f) => f.name === 'ui.js').source;
  assert.ok(!uiSource.includes('innerHTML'), 'UI must not use innerHTML (XSS)');
  assert.ok(!uiSource.includes('subtle'), 'UI module must not perform crypto');
  assert.ok(uiSource.includes('textContent'), 'UI must render with textContent');

  const appSource = files.find((f) => f.name === 'app.js').source;
  assert.ok(!appSource.includes('innerHTML'), 'app must not use innerHTML (XSS)');
  assert.ok(!/document\.write|insertAdjacentHTML/.test(appSource));
});
