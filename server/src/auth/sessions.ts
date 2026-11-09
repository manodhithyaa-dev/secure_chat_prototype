import { createHash, randomBytes } from 'node:crypto';
import type { Pool } from 'pg';
import { config } from '../config';

export interface SessionInfo {
  sessionId: string;
  userId: string;
  expiresAt: Date;
}

export function generateSessionToken(): string {
  return randomBytes(32).toString('base64url');
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

export async function createSession(
  pool: Pool,
  userId: string
): Promise<{ token: string; expiresAt: Date }> {
  const token = generateSessionToken();
  const expiresAt = new Date(Date.now() + config.sessionTtlDays * 86_400_000);
  await pool.query(
    'INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)',
    [userId, hashToken(token), expiresAt]
  );
  return { token, expiresAt };
}

export async function validateSession(pool: Pool, token: string | undefined): Promise<SessionInfo | null> {
  if (!token) return null;
  const { rows } = await pool.query(
    `SELECT id, user_id, expires_at FROM sessions
     WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()`,
    [hashToken(token)]
  );
  const row = rows[0];
  if (!row) return null;
  return { sessionId: row.id, userId: row.user_id, expiresAt: row.expires_at };
}

export async function revokeSession(pool: Pool, token: string | undefined): Promise<void> {
  if (!token) return;
  await pool.query(
    'UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL',
    [hashToken(token)]
  );
}

export async function purgeExpiredSessions(pool: Pool): Promise<void> {
  await pool.query('DELETE FROM sessions WHERE expires_at <= now() OR revoked_at IS NOT NULL');
}
