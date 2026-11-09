export interface MemberPayload {
  userId: string;
  username: string;
  displayName: string;
  avatarUrl: string | null;
  publicKey: string | null;
  fingerprint: string | null;
  online: boolean;
}

export interface ConversationPayload {
  id: string;
  type: 'direct';
  updatedAt: string;
  members: MemberPayload[];
  pendingCount: number;
}

export interface PublicUser {
  userId: string;
  username: string;
  displayName: string;
  avatarUrl: string | null;
  publicKey: string | null;
  fingerprint: string | null;
  online: boolean;
}

export interface AuthedUser {
  userId: string;
  username: string;
  displayName: string;
  email: string;
  avatarUrl: string | null;
  publicKey: string | null;
  fingerprint: string | null;
  createdAt: string;
}

export interface DeliverPacket {
  conversationId: string;
  messageId: string;
  sender: string;
  ciphertext: string;
  iv: string;
  timestamp: number;
}

export interface SendAck {
  ok: boolean;
  messageId?: string;
  status?: 'sent' | 'queued' | 'duplicate';
  reason?: 'invalid_packet' | 'forbidden' | 'server_error';
}

export interface SyncAck {
  ok: boolean;
  messages: DeliverPacket[];
  reason?: 'server_error';
}

export interface MessageAckPayload {
  ok: boolean;
  deleted: boolean;
}

export interface ConversationAck {
  ok: boolean;
  conversation?: ConversationPayload;
  conversations?: ConversationPayload[];
  reason?: 'invalid_user' | 'not_found' | 'server_error';
}

export interface PresencePayload {
  userId: string;
  online: boolean;
}

export interface DeliveryStatusPayload {
  messageId: string;
  status: 'sent' | 'delivered';
}

export interface MessageRejectedPayload {
  messageId: string;
  reason: 'invalid_packet' | 'forbidden' | 'expired';
}

export const EVENT = {
  conversation: 'conversation',
  messageDeliver: 'message_deliver',
  deliveryStatus: 'delivery_status',
  messageRejected: 'message_rejected',
  presence: 'presence',
  authError: 'auth_error'
} as const;
