import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { apiGet, apiPost, connectUser, createKeyPair, registerUser, startServer } from './helpers/harness.mjs';
import { startTestDb, stopTestDb } from './helpers/testdb.mjs';

let db;
let server;
let alice;
let bob;
let cookieAlice;
let cookieBob;

before(async () => {
  db = await startTestDb();
  server = await startServer(db.connectionString);
});

after(async () => {
  await server.stop();
  await stopTestDb(db);
});

test('registration, login, logout, session restoration', async () => {
  const keyA = await createKeyPair();
  const regA = await registerUser(server.url, {
    username: 'charlie',
    publicKey: keyA.publicKeyBase64
  });
  assert.equal(regA.status, 201);
  assert.ok(regA.cookie);
  cookieAlice = regA.cookie;
  assert.equal(regA.body.user.username, 'charlie');

  const regDup = await registerUser(server.url, {
    username: 'charlie',
    publicKey: keyA.publicKeyBase64
  });
  assert.equal(regDup.status, 409);

  const keyB = await createKeyPair();
  const regB = await registerUser(server.url, {
    username: 'diana',
    password: 'dianapass9',
    publicKey: keyB.publicKeyBase64
  });
  assert.equal(regB.status, 201);
  cookieBob = regB.cookie;

  const wrongPw = await apiPost(server.url, '/api/auth/login', {
    body: { identifier: 'charlie', password: 'wrongwrongwrong' }
  });
  assert.equal(wrongPw.status, 401);

  const loginOk = await apiPost(server.url, '/api/auth/login', {
    body: { identifier: 'charlie', password: 'password123' }
  });
  assert.equal(loginOk.status, 200);
  assert.ok(loginOk.cookie);
  cookieAlice = loginOk.cookie;

  const me1 = await apiGet(server.url, '/api/me', { cookie: cookieAlice });
  assert.equal(me1.status, 200);
  assert.equal(me1.body.user.username, 'charlie');
  assert.equal(me1.body.user.email, 'charlie@example.com');
  assert.ok(me1.body.user.publicKey);
  assert.ok(me1.body.user.fingerprint);

  const logout = await apiPost(server.url, '/api/auth/logout', { cookie: cookieAlice });
  assert.equal(logout.status, 204);

  const me2 = await apiGet(server.url, '/api/me', { cookie: cookieAlice });
  assert.equal(me2.status, 401);

  await assert.rejects(
    () => connectUser(server.url, cookieAlice, 'revoked'),
    (error) => /unauthorized/i.test(String(error))
  );
});

test('search and authz boundaries', async () => {
  const search1 = await apiGet(server.url, '/api/users/search', { cookie: cookieBob });
  assert.equal(search1.status, 200);
  assert.deepEqual(search1.body, { users: [] });

  const search2 = await apiGet(server.url, '/api/users/search?q=ch', { cookie: cookieBob });
  assert.equal(search2.status, 200);
  assert.equal(search2.body.users.length, 1);
  const u = search2.body.users[0];
  assert.deepEqual(Object.keys(u).sort(), [
    'avatarUrl',
    'displayName',
    'fingerprint',
    'online',
    'publicKey',
    'userId',
    'username'
  ]);
  assert.ok(!JSON.stringify(u).includes('password_hash'));

  const convCreate = await apiPost(server.url, '/api/conversations', {
    cookie: cookieBob,
    body: { otherUserId: u.userId }
  });
  assert.equal(convCreate.status, 200);
  assert.ok(convCreate.body.conversation.id);
});
