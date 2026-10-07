export type Role = 'A' | 'B';

export interface JoinPayload {
  role: Role;
  publicKey: string;
}

export interface PublicKeyPayload {
  publicKey: string;
}

export interface EncryptedPacket {
  messageId: string;
  sender: Role;
  ciphertext: string;
  iv: string;
  timestamp: number;
}

export interface DeliveryStatusPayload {
  messageId: string;
  status: 'sent' | 'delivered';
}

export interface PeerStatusPayload {
  peer: Role;
  connected: boolean;
}

export interface JoinErrorPayload {
  error: string;
}

export interface MessageRejectedPayload {
  messageId: string;
  reason:
    | 'invalid_packet'
    | 'sender_mismatch'
    | 'peer_unavailable'
    | 'not_joined'
    | 'unknown_message';
}

export interface JoinedPayload {
  role: Role;
}

export const EVENT = {
  join: 'join',
  joined: 'joined',
  joinError: 'join_error',
  publicKey: 'public_key',
  peerPublicKey: 'peer_public_key',
  encryptedMessage: 'encrypted_message',
  deliveryStatus: 'delivery_status',
  messageRejected: 'message_rejected',
  peerStatus: 'peer_status'
} as const;
