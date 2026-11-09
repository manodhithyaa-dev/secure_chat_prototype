import type { Server, Socket } from 'socket.io';
import type { Pool } from 'pg';
import { tokenFromCookies } from './auth/cookies';
import { validateSession } from './auth/sessions';
import {
  buildConversation,
  deletePendingMessage,
  findPendingMessages,
  getConversationPartners,
  getOrCreateDirectConversation,
  getOtherMember,
  insertMessage,
  isMember,
  listConversations,
  findUserById
} from './db/queries';
import { presence } from './presence';
import {
  EVENT,
  type ConversationAck,
  type DeliveryStatusPayload,
  type MessageAckPayload,
  type SendAck,
  type SyncAck
} from './types';
import { isUuid, isValidMessageId, validateSendPayload } from './validate';

type Ack = (response: unknown) => void;

function respond(ack: Ack | undefined, payload: unknown): void {
  if (typeof ack === 'function') ack(payload);
}

function emitToUser(io: Server, userId: string, event: string, payload: unknown): boolean {
  const sockets = presence.socketsFor(userId);
  for (const socket of sockets) {
    socket.emit(event, payload);
  }
  return sockets.length > 0;
}

async function broadcastPresence(
  io: Server,
  pool: Pool,
  userId: string,
  online: boolean,
  forSocket?: Socket
): Promise<void> {
  let partners: Array<{ userId: string }>;
  try {
    partners = await getConversationPartners(pool, userId);
  } catch {
    return;
  }
  for (const partner of partners) {
    if (forSocket) {
      forSocket.emit(EVENT.presence, {
        userId: partner.userId,
        online: presence.isOnline(partner.userId)
      });
      if (partner.userId === userId) continue;
    }
    if (partner.userId !== userId || !forSocket) {
      emitToUser(io, partner.userId, EVENT.presence, { userId, online });
    }
  }
}

export function registerSocketHandlers(io: Server, pool: Pool): void {
  io.use(async (socket, next) => {
    try {
      let token = tokenFromCookies(socket.handshake.headers.cookie);
      const authPayload = socket.handshake.auth as { token?: unknown } | undefined;
      if (!token && authPayload && typeof authPayload.token === 'string') {
        token = authPayload.token;
      }
      const session = await validateSession(pool, token);
      if (!session) {
        next(new Error('unauthorized'));
        return;
      }
      socket.data.userId = session.userId;
      socket.data.sessionId = session.sessionId;
      next();
    } catch {
      next(new Error('unauthorized'));
    }
  });

  io.on('connection', (socket: Socket) => {
    const userId = socket.data.userId as string;
    presence.add(userId, socket);
    void broadcastPresence(io, pool, userId, true, socket);

    socket.on('conversation_list', async (_payload: unknown, ack?: Ack) => {
      try {
        const conversations = await listConversations(pool, userId, presence.isOnline);
        respond(ack, { ok: true, conversations } satisfies ConversationAck);
      } catch {
        respond(ack, { ok: false, conversations: [], reason: 'server_error' } satisfies ConversationAck);
      }
    });

    socket.on('conversation_create', async (payload: unknown, ack?: Ack) => {
      try {
        const otherUserId = (payload as { otherUserId?: unknown } | undefined)?.otherUserId;
        if (!isUuid(otherUserId)) {
          respond(ack, { ok: false, reason: 'invalid_user' } satisfies ConversationAck);
          return;
        }
        if (otherUserId === userId) {
          respond(ack, { ok: false, reason: 'invalid_user' } satisfies ConversationAck);
          return;
        }
        const other = await findUserById(pool, otherUserId);
        if (!other) {
          respond(ack, { ok: false, reason: 'not_found' } satisfies ConversationAck);
          return;
        }
        const { id } = await getOrCreateDirectConversation(pool, userId, otherUserId);
        const { rows } = await pool.query(
          'SELECT id, type, updated_at FROM conversations WHERE id = $1',
          [id]
        );
        const conversation = await buildConversation(pool, rows[0], userId, presence.isOnline);
        respond(ack, { ok: true, conversation } satisfies ConversationAck);

        const forOther = await buildConversation(pool, rows[0], otherUserId, presence.isOnline);
        emitToUser(io, otherUserId, EVENT.conversation, { conversation: forOther });
        if (otherUserId !== userId) {
          emitToUser(io, userId, EVENT.conversation, { conversation });
          emitToUser(io, userId, EVENT.presence, {
            userId: otherUserId,
            online: presence.isOnline(otherUserId)
          });
          emitToUser(io, otherUserId, EVENT.presence, {
            userId,
            online: presence.isOnline(userId)
          });
        }
      } catch {
        respond(ack, { ok: false, reason: 'server_error' } satisfies ConversationAck);
      }
    });

    socket.on('message_send', async (payload: unknown, ack?: Ack) => {
      let messageId = '';
      try {
        const valid = validateSendPayload(payload);
        if (!valid) {
          respond(ack, { ok: false, reason: 'invalid_packet' } satisfies SendAck);
          return;
        }
        messageId = valid.messageId;
        const member = await isMember(pool, valid.conversationId, userId);
        const other = member ? await getOtherMember(pool, valid.conversationId, userId) : null;
        if (!member || !other) {
          respond(ack, { ok: false, messageId, reason: 'forbidden' } satisfies SendAck);
          return;
        }

        const inserted = await insertMessage(pool, {
          conversationId: valid.conversationId,
          senderId: userId,
          recipientId: other.userId,
          clientMessageId: valid.messageId,
          ciphertext: valid.ciphertext,
          iv: valid.iv
        });

        if (!inserted) {
          respond(ack, { ok: true, messageId, status: 'duplicate' } satisfies SendAck);
          return;
        }

        const deliveredLive = emitToUser(io, other.userId, EVENT.messageDeliver, {
          conversationId: valid.conversationId,
          messageId: valid.messageId,
          sender: userId,
          ciphertext: valid.ciphertext,
          iv: valid.iv,
          timestamp: valid.timestamp
        });

        respond(
          ack,
          { ok: true, messageId, status: deliveredLive ? 'sent' : 'queued' } satisfies SendAck
        );
        if (deliveredLive) {
          socket.emit(EVENT.deliveryStatus, {
            messageId,
            status: 'sent'
          } satisfies DeliveryStatusPayload);
        }
      } catch {
        respond(ack, {
          ok: false,
          messageId,
          reason: 'server_error'
        } satisfies SendAck);
      }
    });

    socket.on('message_ack', async (payload: unknown, ack?: Ack) => {
      try {
        const messageId = (payload as { messageId?: unknown } | undefined)?.messageId;
        if (!isValidMessageId(messageId)) {
          respond(ack, { ok: false, deleted: false } satisfies MessageAckPayload);
          return;
        }
        const removed = await deletePendingMessage(pool, userId, messageId);
        if (removed) {
          emitToUser(io, removed.senderId, EVENT.deliveryStatus, {
            messageId,
            status: 'delivered'
          } satisfies DeliveryStatusPayload);
        }
        respond(ack, { ok: true, deleted: Boolean(removed) } satisfies MessageAckPayload);
      } catch {
        respond(ack, { ok: false, deleted: false } satisfies MessageAckPayload);
      }
    });

    socket.on('message_sync', async (_payload: unknown, ack?: Ack) => {
      try {
        const messages = await findPendingMessages(pool, userId);
        respond(ack, { ok: true, messages } satisfies SyncAck);
      } catch {
        respond(ack, { ok: false, messages: [], reason: 'server_error' } satisfies SyncAck);
      }
    });

    socket.on('disconnect', () => {
      presence.remove(userId, socket);
      void broadcastPresence(io, pool, userId, false);
    });
  });
}
