import type { Pool, PoolClient } from 'pg';
import { config } from '../config';
import { fingerprintFromPublicKey } from '../identity';
import type { ConversationPayload, MemberPayload, PublicUser } from '../types';

export interface UserRecord {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  display_name: string;
  avatar_url: string | null;
  created_at: Date;
}

export type OnlineFn = (userId: string) => boolean;

const offline: OnlineFn = () => false;

export async function findUserByIdentifier(pool: Pool, identifier: string): Promise<UserRecord | null> {
  const { rows } = await pool.query(
    'SELECT * FROM users WHERE username = $1 OR email = $1 LIMIT 1',
    [identifier]
  );
  return rows[0] ?? null;
}

export async function findUserById(pool: Pool, userId: string): Promise<UserRecord | null> {
  const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  return rows[0] ?? null;
}

export async function getUserPublicKey(pool: Pool, userId: string): Promise<string | null> {
  const { rows } = await pool.query(
    'SELECT public_key FROM devices WHERE user_id = $1 AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 1',
    [userId]
  );
  return rows[0]?.public_key ?? null;
}

export async function createUser(
  pool: Pool,
  input: {
    username: string;
    email: string;
    passwordHash: string;
    displayName: string;
    publicKey: string;
  }
): Promise<UserRecord> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userResult = await client.query(
      `INSERT INTO users (username, email, password_hash, display_name)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [input.username, input.email, input.passwordHash, input.displayName]
    );
    const user: UserRecord = userResult.rows[0];
    await client.query('INSERT INTO devices (user_id, public_key) VALUES ($1, $2)', [
      user.id,
      input.publicKey
    ]);
    await client.query('COMMIT');
    return user;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

export async function touchLastSeen(pool: Pool, userId: string): Promise<void> {
  await pool.query('UPDATE users SET last_seen_at = now() WHERE id = $1', [userId]);
  await pool.query(
    'UPDATE devices SET last_seen_at = now() WHERE user_id = $1 AND revoked_at IS NULL',
    [userId]
  );
}

export async function searchUsers(pool: Pool, query: string, viewerId: string): Promise<PublicUser[]> {
  const pattern = `%${query.replace(/[\\%_]/g, (ch) => `\\${ch}`)}%`;
  const { rows } = await pool.query(
    `SELECT u.id, u.username, u.display_name, u.avatar_url,
            (SELECT d.public_key FROM devices d
             WHERE d.user_id = u.id AND d.revoked_at IS NULL
             ORDER BY d.created_at DESC LIMIT 1) AS public_key
     FROM users u
     WHERE u.id <> $1
       AND (u.username ILIKE $2 ESCAPE '\\' OR u.display_name ILIKE $2 ESCAPE '\\')
     ORDER BY u.username ASC
     LIMIT 20`,
    [viewerId, pattern]
  );
  return rows.map((row) => toPublicUser(row, offline));
}

export function toPublicUser(row: Record<string, unknown>, isOnline: OnlineFn): PublicUser {
  const userId = String(row.id);
  const publicKey = (row.public_key as string | null) ?? null;
  return {
    userId,
    username: String(row.username),
    displayName: String(row.display_name),
    avatarUrl: (row.avatar_url as string | null) ?? null,
    publicKey,
    fingerprint: publicKey ? fingerprintFromPublicKey(publicKey) : null,
    online: isOnline(userId)
  };
}

export async function isMember(pool: Pool, conversationId: string, userId: string): Promise<boolean> {
  const { rows } = await pool.query(
    'SELECT 1 FROM conversation_members WHERE conversation_id = $1 AND user_id = $2',
    [conversationId, userId]
  );
  return rows.length > 0;
}

export async function getOtherMember(
  pool: Pool,
  conversationId: string,
  userId: string
): Promise<{ userId: string } | null> {
  const { rows } = await pool.query(
    'SELECT user_id FROM conversation_members WHERE conversation_id = $1 AND user_id <> $2 LIMIT 1',
    [conversationId, userId]
  );
  return rows[0] ? { userId: rows[0].user_id } : null;
}

export async function getConversationPartners(
  pool: Pool,
  userId: string
): Promise<Array<{ userId: string }>> {
  const { rows } = await pool.query(
    `SELECT DISTINCT other.user_id
     FROM conversation_members mine
     JOIN conversation_members other ON other.conversation_id = mine.conversation_id AND other.user_id <> mine.user_id
     WHERE mine.user_id = $1`,
    [userId]
  );
  return rows.map((row) => ({ userId: row.user_id }));
}

export async function getOrCreateDirectConversation(
  pool: Pool,
  userA: string,
  userB: string
): Promise<{ id: string; created: boolean }> {
  const lockKey = [userA, userB].sort().join(':');
  const client: PoolClient = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1, 0))', [lockKey]);
    const existing = await client.query(
      `SELECT c.id FROM conversations c
       JOIN conversation_members m1 ON m1.conversation_id = c.id AND m1.user_id = $1
       JOIN conversation_members m2 ON m2.conversation_id = c.id AND m2.user_id = $2
       WHERE c.type = 'direct'
         AND (SELECT count(*) FROM conversation_members cm WHERE cm.conversation_id = c.id) = 2
       LIMIT 1`,
      [userA, userB]
    );
    if (existing.rows[0]) {
      await client.query('COMMIT');
      return { id: existing.rows[0].id, created: false };
    }
    const conversation = await client.query(
      `INSERT INTO conversations (type) VALUES ('direct') RETURNING id`
    );
    const conversationId = conversation.rows[0].id as string;
    await client.query(
      'INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2), ($1, $3)',
      [conversationId, userA, userB]
    );
    await client.query('COMMIT');
    return { id: conversationId, created: true };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function loadMemberRows(pool: Pool, conversationIds: string[]): Promise<Map<string, MemberPayload[]>> {
  const result = new Map<string, MemberPayload[]>();
  if (conversationIds.length === 0) return result;
  const { rows } = await pool.query(
    `SELECT cm.conversation_id, u.id, u.username, u.display_name, u.avatar_url,
            (SELECT d.public_key FROM devices d
             WHERE d.user_id = u.id AND d.revoked_at IS NULL
             ORDER BY d.created_at DESC LIMIT 1) AS public_key
     FROM conversation_members cm
     JOIN users u ON u.id = cm.user_id
     WHERE cm.conversation_id = ANY($1::uuid[])`,
    [conversationIds]
  );
  for (const row of rows) {
    const key = row.conversation_id as string;
    const publicKey = (row.public_key as string | null) ?? null;
    const member: MemberPayload = {
      userId: row.id as string,
      username: row.username as string,
      displayName: row.display_name as string,
      avatarUrl: (row.avatar_url as string | null) ?? null,
      publicKey,
      fingerprint: publicKey ? fingerprintFromPublicKey(publicKey) : null,
      online: false
    };
    const list = result.get(key);
    if (list) list.push(member);
    else result.set(key, [member]);
  }
  return result;
}

async function loadPendingCounts(
  pool: Pool,
  viewerId: string,
  conversationIds: string[]
): Promise<Map<string, number>> {
  const result = new Map<string, number>();
  if (conversationIds.length === 0) return result;
  const { rows } = await pool.query(
    `SELECT conversation_id, count(*) AS pending FROM messages
     WHERE recipient_id = $1 AND conversation_id = ANY($2::uuid[])
     GROUP BY conversation_id`,
    [viewerId, conversationIds]
  );
  for (const row of rows) {
    result.set(row.conversation_id as string, Number(row.pending));
  }
  return result;
}

export async function buildConversation(
  pool: Pool,
  conversation: { id: string; type: string; updated_at: Date },
  viewerId: string,
  isOnline: OnlineFn = offline
): Promise<ConversationPayload> {
  const membersByConversation = await loadMemberRows(pool, [conversation.id]);
  const pendingByConversation = await loadPendingCounts(pool, viewerId, [conversation.id]);
  const members = membersByConversation.get(conversation.id) ?? [];
  for (const member of members) {
    member.online = isOnline(member.userId);
  }
  return {
    id: conversation.id,
    type: 'direct',
    updatedAt: new Date(conversation.updated_at).toISOString(),
    members,
    pendingCount: pendingByConversation.get(conversation.id) ?? 0
  };
}

export async function listConversations(
  pool: Pool,
  viewerId: string,
  isOnline: OnlineFn = offline
): Promise<ConversationPayload[]> {
  const { rows } = await pool.query(
    `SELECT c.id, c.type, c.updated_at
     FROM conversations c
     JOIN conversation_members cm ON cm.conversation_id = c.id AND cm.user_id = $1
     ORDER BY c.updated_at DESC`,
    [viewerId]
  );
  if (rows.length === 0) return [];
  const ids = rows.map((row) => row.id as string);
  const membersByConversation = await loadMemberRows(pool, ids);
  const pendingByConversation = await loadPendingCounts(pool, viewerId, ids);
  return rows.map((row) => {
    const id = row.id as string;
    const members = membersByConversation.get(id) ?? [];
    for (const member of members) {
      member.online = isOnline(member.userId);
    }
    return {
      id,
      type: 'direct' as const,
      updatedAt: new Date(row.updated_at).toISOString(),
      members,
      pendingCount: pendingByConversation.get(id) ?? 0
    };
  });
}

export async function touchConversation(pool: Pool, conversationId: string): Promise<void> {
  await pool.query('UPDATE conversations SET updated_at = now() WHERE id = $1', [conversationId]);
}

export async function insertMessage(
  pool: Pool,
  input: {
    conversationId: string;
    senderId: string;
    recipientId: string;
    clientMessageId: string;
    ciphertext: string;
    iv: string;
  }
): Promise<boolean> {
  const { rowCount } = await pool.query(
    `INSERT INTO messages (conversation_id, sender_id, recipient_id, client_message_id, ciphertext, iv, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, now() + ($7 || ' days')::interval)
     ON CONFLICT (conversation_id, sender_id, client_message_id) DO NOTHING`,
    [
      input.conversationId,
      input.senderId,
      input.recipientId,
      input.clientMessageId,
      input.ciphertext,
      input.iv,
      String(config.messageTtlDays)
    ]
  );
  if (rowCount && rowCount > 0) {
    await touchConversation(pool, input.conversationId);
    return true;
  }
  return false;
}

export async function findPendingMessages(
  pool: Pool,
  recipientId: string,
  limit = 500
): Promise<
  Array<{
    conversationId: string;
    messageId: string;
    sender: string;
    ciphertext: string;
    iv: string;
    timestamp: number;
  }>
> {
  const { rows } = await pool.query(
    `SELECT conversation_id, client_message_id, sender_id, ciphertext, iv, created_at
     FROM messages
     WHERE recipient_id = $1 AND expires_at > now()
     ORDER BY created_at ASC
     LIMIT $2`,
    [recipientId, limit]
  );
  return rows.map((row) => ({
    conversationId: row.conversation_id as string,
    messageId: row.client_message_id as string,
    sender: row.sender_id as string,
    ciphertext: row.ciphertext as string,
    iv: row.iv as string,
    timestamp: new Date(row.created_at).getTime()
  }));
}

export async function deletePendingMessage(
  pool: Pool,
  recipientId: string,
  clientMessageId: string
): Promise<{ senderId: string; conversationId: string } | null> {
  const { rows } = await pool.query(
    `DELETE FROM messages
     WHERE id = (
       SELECT id FROM messages
       WHERE recipient_id = $1 AND client_message_id = $2 AND expires_at > now()
       LIMIT 1
     )
     RETURNING sender_id, conversation_id`,
    [recipientId, clientMessageId]
  );
  const row = rows[0];
  if (!row) return null;
  return { senderId: row.sender_id as string, conversationId: row.conversation_id as string };
}

export async function sweepExpired(pool: Pool): Promise<void> {
  await pool.query('DELETE FROM messages WHERE expires_at <= now()');
}
