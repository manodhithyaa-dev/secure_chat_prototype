import type { Server, Socket } from 'socket.io';
import {
  EVENT,
  type DeliveryStatusPayload,
  type EncryptedPacket,
  type JoinPayload,
  type MessageRejectedPayload,
  type PublicKeyPayload,
  type Role
} from './types';

const peers = new Map<Role, Socket>();
const publicKeys = new Map<Role, string>();
const routes = new Map<string, { from: Role; to: Role }>();

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

function isRole(value: unknown): value is Role {
  return value === 'A' || value === 'B';
}

function decodeBase64Strict(value: string): Uint8Array | null {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !BASE64_PATTERN.test(value)
  ) {
    return null;
  }
  try {
    return new Uint8Array(Buffer.from(value, 'base64'));
  } catch {
    return null;
  }
}

function isValidPublicKey(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 512) return false;
  const bytes = decodeBase64Strict(value);
  if (!bytes) return false;
  return bytes.length >= 50 && bytes.length <= 150;
}

function isValidPacket(value: unknown): value is EncryptedPacket {
  if (!value || typeof value !== 'object') return false;
  const packet = value as Record<string, unknown>;
  const iv = decodeBase64Strict(String(packet.iv ?? ''));
  const ciphertext = decodeBase64Strict(String(packet.ciphertext ?? ''));
  return (
    typeof packet.messageId === 'string' &&
    packet.messageId.length >= 1 &&
    packet.messageId.length <= 128 &&
    isRole(packet.sender) &&
    typeof packet.ciphertext === 'string' &&
    packet.ciphertext.length <= 32768 &&
    iv !== null &&
    iv.length === 12 &&
    ciphertext !== null &&
    ciphertext.length >= 17 &&
    typeof packet.timestamp === 'number' &&
    Number.isFinite(packet.timestamp)
  );
}

function isValidDeliveryStatus(value: unknown): value is DeliveryStatusPayload {
  if (!value || typeof value !== 'object') return false;
  const payload = value as Record<string, unknown>;
  return (
    typeof payload.messageId === 'string' &&
    payload.messageId.length >= 1 &&
    payload.messageId.length <= 128 &&
    (payload.status === 'sent' || payload.status === 'delivered')
  );
}

function peerOf(role: Role): Role {
  return role === 'A' ? 'B' : 'A';
}

function reject(socket: Socket, messageId: string, reason: MessageRejectedPayload['reason']): void {
  socket.emit(EVENT.messageRejected, { messageId, reason } satisfies MessageRejectedPayload);
}

export function registerSocketHandlers(io: Server): void {
  io.on('connection', (socket: Socket) => {
    socket.on(EVENT.join, (payload: JoinPayload) => {
      const role = payload?.role;
      const publicKey = payload?.publicKey;

      if (!isRole(role)) {
        socket.emit(EVENT.joinError, { error: 'Invalid identity. Choose Person A or Person B.' });
        return;
      }
      if (socket.data.role && socket.data.role !== role) {
        socket.emit(EVENT.joinError, { error: 'This connection already joined with another identity.' });
        return;
      }
      if (!isValidPublicKey(publicKey)) {
        socket.emit(EVENT.joinError, { error: 'Invalid public key.' });
        return;
      }

      const existing = peers.get(role);
      if (existing && existing.id !== socket.id && existing.connected) {
        socket.emit(EVENT.joinError, { error: `Person ${role} is already connected.` });
        return;
      }

      peers.set(role, socket);
      publicKeys.set(role, publicKey);
      socket.data.role = role;
      socket.emit(EVENT.joined, { role });

      const other = peerOf(role);
      const otherSocket = peers.get(other);
      const otherKey = publicKeys.get(other);

      if (otherSocket && otherSocket.connected && otherKey) {
        socket.emit(EVENT.peerPublicKey, { publicKey: otherKey });
        otherSocket.emit(EVENT.peerPublicKey, { publicKey });
        socket.emit(EVENT.peerStatus, { peer: other, connected: true });
        otherSocket.emit(EVENT.peerStatus, { peer: role, connected: true });
      } else {
        socket.emit(EVENT.peerStatus, { peer: other, connected: false });
      }
    });

    socket.on(EVENT.publicKey, (payload: PublicKeyPayload) => {
      const role = socket.data.role as Role | undefined;
      if (!role || !isRole(role)) {
        socket.emit(EVENT.joinError, { error: 'Join before sending a public key.' });
        return;
      }
      if (!isValidPublicKey(payload?.publicKey)) {
        socket.emit(EVENT.joinError, { error: 'Invalid public key.' });
        return;
      }
      publicKeys.set(role, payload.publicKey);
      const otherSocket = peers.get(peerOf(role));
      if (otherSocket && otherSocket.connected) {
        otherSocket.emit(EVENT.peerPublicKey, { publicKey: payload.publicKey });
      }
    });

    socket.on(EVENT.encryptedMessage, (packet: EncryptedPacket) => {
      const role = socket.data.role as Role | undefined;
      const rawId =
        packet && typeof packet.messageId === 'string' ? packet.messageId : '';
      const messageId = rawId.length >= 1 && rawId.length <= 128 ? rawId : '';

      if (!role || !isRole(role)) {
        reject(socket, messageId, 'not_joined');
        return;
      }
      if (!isValidPacket(packet)) {
        reject(socket, messageId, 'invalid_packet');
        return;
      }
      if (packet.sender !== role) {
        reject(socket, packet.messageId, 'sender_mismatch');
        return;
      }

      const other = peerOf(role);
      const otherSocket = peers.get(other);
      if (!otherSocket || !otherSocket.connected) {
        socket.emit(EVENT.peerStatus, { peer: other, connected: false });
        reject(socket, packet.messageId, 'peer_unavailable');
        return;
      }

      routes.set(packet.messageId, { from: role, to: other });
      otherSocket.emit(EVENT.encryptedMessage, packet);
      socket.emit(EVENT.deliveryStatus, { messageId: packet.messageId, status: 'sent' });
    });

    socket.on(EVENT.deliveryStatus, (payload: DeliveryStatusPayload) => {
      const role = socket.data.role as Role | undefined;
      if (!role || !isRole(role)) return;
      if (!isValidDeliveryStatus(payload)) return;

      const route = routes.get(payload.messageId);
      if (!route || route.to !== role) {
        reject(socket, payload.messageId, 'unknown_message');
        return;
      }

      const fromSocket = peers.get(route.from);
      if (fromSocket && fromSocket.connected) {
        fromSocket.emit(EVENT.deliveryStatus, {
          messageId: payload.messageId,
          status: payload.status
        });
      }
    });

    socket.on('disconnect', () => {
      const role = socket.data.role as Role | undefined;
      if (!role || !isRole(role)) return;
      if (peers.get(role)?.id !== socket.id) return;

      peers.delete(role);
      const other = peerOf(role);
      const otherSocket = peers.get(other);
      if (otherSocket && otherSocket.connected) {
        otherSocket.emit(EVENT.peerStatus, { peer: role, connected: false });
      }
    });
  });
}
