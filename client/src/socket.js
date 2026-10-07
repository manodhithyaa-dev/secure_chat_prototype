export function connectSocket(url = '/') {
  if (typeof io === 'undefined') {
    throw new Error('Socket.IO client failed to load');
  }
  return io(url, { reconnection: true, reconnectionAttempts: Infinity });
}

export function on(socket, event, handler) {
  socket.on(event, handler);
}

export function sendJoin(socket, role, publicKeyBase64) {
  socket.emit('join', { role, publicKey: publicKeyBase64 });
}

export function sendPublicKey(socket, publicKeyBase64) {
  socket.emit('public_key', { publicKey: publicKeyBase64 });
}

export function sendEncryptedMessage(socket, packet) {
  socket.emit('encrypted_message', {
    messageId: packet.messageId,
    sender: packet.sender,
    ciphertext: packet.ciphertext,
    iv: packet.iv,
    timestamp: packet.timestamp
  });
}

export function sendDeliveryStatus(socket, messageId, status) {
  socket.emit('delivery_status', { messageId, status });
}

export function disconnectSocket(socket) {
  if (socket) socket.disconnect();
}
