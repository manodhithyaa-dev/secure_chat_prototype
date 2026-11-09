import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { getPool, closePool } from '../dist/db/pool.js';
import { runMigrations } from '../dist/db/migrate.js';
import { startTestDb, stopTestDb } from './helpers/testdb.mjs';

let db;
let pool;

before(async () => {
  db = await startTestDb();
  process.env.DATABASE_URL = db.connectionString;
  pool = getPool();
  await runMigrations(pool);

  const client = await pool.connect();
  try {
    const h = createHash('sha256').update('pw').digest('hex');
    await client.query(
      "INSERT INTO users (id, username, email, password_hash) VALUES ('11111111-1111-1111-1111-111111111111','testa','a@e.com',$1), ('22222222-2222-2222-2222-222222222222','testb','b@e.com',$1)",
      [h]
    );
    await client.query(
      "INSERT INTO devices (user_id, public_key) VALUES ('11111111-1111-1111-1111-111111111111','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAA=='), ('22222222-2222-2222-2222-222222222222','MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAA==')"
    );
  } finally {
    client.release();
  }
});

test('database inspection: no plaintext/private/conversation keys in messages or sensitive tables', async () => {
  const messages = await pool.query('SELECT * FROM messages LIMIT 1');
  for (const field of Object.keys(messages.fields || {})) {
    const name = String(field).toLowerCase();
    assert.ok(!['plaintext', 'text', 'content', 'privatekey', 'conversationkey'].includes(name));
  }

  const users = await pool.query('SELECT id, username, email, password_hash, display_name FROM users LIMIT 1');
  assert.ok(users.fields.some((f) => String(f.name) === 'password_hash'));

  const sessions = await pool.query('SELECT id, user_id, token_hash, expires_at FROM sessions LIMIT 1');
  const sessionCols = (sessions.fields || []).map((f) => String(f.name).toLowerCase());
  assert.deepEqual(new Set(sessionCols), new Set(['id', 'user_id', 'token_hash', 'expires_at']));
  assert.ok(sessionCols.includes('token_hash'));
  assert.ok(!sessionCols.includes('token'));

  const devices = await pool.query('SELECT id, user_id, public_key, revoked_at FROM devices LIMIT 1');
  const devCols = (devices.fields || []).map((f) => String(f.name).toLowerCase());
  assert.ok(devCols.includes('public_key'));
  assert.ok(!devCols.includes('privatekey'));
});

after(async () => {
  await closePool();
  await stopTestDb(db);
});
