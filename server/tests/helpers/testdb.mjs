import { spawn } from 'node:child_process';
import { randomInt } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';

export async function startTestDb() {
  const port = 20000 + randomInt(20000);
  const name = `secure-chat-test-${port}-${process.pid}-${randomInt(100000)}`;
  const password = 'test-password';

  const dockerId = await new Promise((resolve, reject) => {
    const child = spawn(
      'docker',
      [
        'run',
        '--rm',
        '-d',
        '--name',
        name,
        '-e',
        `POSTGRES_PASSWORD=${password}`,
        '-e',
        'POSTGRES_DB=securechat',
        '-p',
        `127.0.0.1:${port}:5432`,
        'postgres:16-alpine'
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(`docker run failed (code ${code}): ${stderr}`));
    });
  });

  const connectionString = `postgres://postgres:${password}@127.0.0.1:${port}/securechat`;
  const deadline = Date.now() + 45000;
  let ready = false;
  while (Date.now() < deadline) {
    const ok = await new Promise((resolve) => {
      const probe = spawn('docker', ['exec', name, 'pg_isready', '-U', 'postgres'], {
        stdio: 'ignore'
      });
      probe.on('error', () => resolve(false));
      probe.on('exit', (code) => resolve(code === 0));
    });
    if (ok) {
      ready = true;
      break;
    }
    await sleep(250);
  }

  if (!ready) {
    await stopTestDb({ name });
    throw new Error('test database did not become ready');
  }

  return { name, connectionString, dockerId };
}

export async function stopTestDb(db) {
  if (!db) return;
  try {
    await new Promise((resolve) => {
      const child = spawn('docker', ['kill', db.name], { stdio: 'ignore' });
      child.on('error', resolve);
      child.on('exit', resolve);
    });
  } catch {}
  try {
    await new Promise((resolve) => {
      const child = spawn('docker', ['rm', '-f', db.name], { stdio: 'ignore' });
      child.on('error', resolve);
      child.on('exit', resolve);
    });
  } catch {}
}
