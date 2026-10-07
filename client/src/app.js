import {
  MAX_MESSAGE_LENGTH,
  decryptMessage,
  deriveSharedKey,
  encryptMessage,
  exportPublicKey,
  generateFingerprint,
  generateKeyPair,
  validatePacket
} from './crypto.js';
import {
  getEncryptedMessages,
  initializeDatabase,
  loadKeyPair,
  saveEncryptedMessage,
  saveKeyPair,
  updateMessageStatus
} from './storage.js';
import {
  connectSocket,
  on,
  sendDeliveryStatus,
  sendEncryptedMessage,
  sendJoin,
  sendPublicKey
} from './socket.js';
import * as ui from './ui.js';

const CONVERSATION_ID = 'A-B';

const state = {
  role: null,
  privateKey: null,
  ownPublicKeyBase64: null,
  ownFingerprint: null,
  peerPublicKeyBase64: null,
  peerFingerprint: null,
  conversationKey: null,
  socket: null,
  joined: false,
  peerSeen: false,
  receivedIds: new Set()
};

function peerRole() {
  return state.role === 'A' ? 'B' : 'A';
}

function describePeer() {
  return `Person ${peerRole()}`;
}

async function handleJoin(role) {
  if (state.role) return;
  ui.showJoinError(null);
  ui.setJoinBusy(role, true);

  try {
    await initializeDatabase();

    let keyPair = await loadKeyPair(role);
    if (!keyPair) {
      const generated = await generateKeyPair();
      const publicKeyBase64 = await exportPublicKey(generated.publicKey);
      await saveKeyPair(role, { privateKey: generated.privateKey, publicKeyBase64 });
      keyPair = { privateKey: generated.privateKey, publicKeyBase64 };
    }

    state.role = role;
    state.privateKey = keyPair.privateKey;
    state.ownPublicKeyBase64 = keyPair.publicKeyBase64;
    state.ownFingerprint = await generateFingerprint(keyPair.publicKeyBase64);

    state.socket = connectSocket();
    wireSocket(state.socket);
  } catch (error) {
    state.role = null;
    state.privateKey = null;
    ui.setJoinBusy(null, false);
    ui.showJoinError(error?.message || 'Failed to initialize secure chat.');
  }
}

function wireSocket(socket) {
  on(socket, 'connect', () => {
    if (state.role && state.ownPublicKeyBase64) {
      sendJoin(socket, state.role, state.ownPublicKeyBase64);
    }
  });

  on(socket, 'joined', async () => {
    state.joined = true;
    ui.showChatScreen();
    ui.setIdentity(state.role);
    ui.setConnectionStatus(`Connected as Person ${state.role}`, 'ok');
    ui.setEncryptionStatus('🔒 Exchanging keys…', 'wait');
    ui.setFingerprints(state.ownFingerprint, null);
    ui.setJoinBusy(null, false);
    sendPublicKey(socket, state.ownPublicKeyBase64);
    await renderHistory();
  });

  on(socket, 'join_error', ({ error } = {}) => {
    ui.showJoinError(error || 'Unable to join.');
    ui.setJoinBusy(null, false);
    state.role = null;
    state.privateKey = null;
    state.joined = false;
    ui.showJoinScreen();
    socket.disconnect();
  });

  on(socket, 'peer_public_key', async ({ publicKey } = {}) => {
    try {
      if (!publicKey || typeof publicKey !== 'string') throw new Error('Invalid public key');
      const alreadyDerived =
        state.conversationKey && state.peerPublicKeyBase64 === publicKey;
      if (alreadyDerived) return;

      state.peerPublicKeyBase64 = publicKey;
      state.peerFingerprint = await generateFingerprint(publicKey);
      state.conversationKey = await deriveSharedKey(
        state.privateKey,
        publicKey,
        CONVERSATION_ID
      );
      state.peerSeen = true;

      ui.setConnectionStatus(`Connected to ${describePeer()}`, 'ok');
      ui.setEncryptionStatus('🔒 End-to-end encrypted', 'ok');
      ui.setFingerprints(state.ownFingerprint, state.peerFingerprint);
      ui.showNotice(null);
      await renderHistory();
      await resendPending();
    } catch (error) {
      state.conversationKey = null;
      ui.setEncryptionStatus('⚠ Key exchange failed', 'bad');
      ui.showNotice(`Key exchange with ${describePeer()} failed.`);
    }
  });

  on(socket, 'peer_status', async ({ peer, connected } = {}) => {
    if (peer !== peerRole()) return;
    if (connected) {
      state.peerSeen = true;
      ui.setConnectionStatus(
        state.conversationKey ? `Connected to ${describePeer()}` : 'Connected, waiting for keys…',
        state.conversationKey ? 'ok' : 'wait'
      );
      if (!state.conversationKey) {
        ui.setEncryptionStatus('🔒 Exchanging keys…', 'wait');
      } else {
        ui.showNotice(null);
        await resendPending();
      }
    } else if (state.peerSeen) {
      ui.setConnectionStatus(`${describePeer()} is offline`, 'bad');
      ui.showNotice(`${describePeer()} is offline`);
    } else {
      ui.setConnectionStatus(`Waiting for ${describePeer()}...`, 'wait');
      ui.showNotice(null);
    }
  });

  on(socket, 'encrypted_message', async (packet) => {
    try {
      const valid = validatePacket(packet);
      if (valid.sender === state.role) return;

      if (state.receivedIds.has(valid.messageId) || ui.hasMessage(valid.messageId)) {
        sendDeliveryStatus(socket, valid.messageId, 'delivered');
        return;
      }
      if (!state.conversationKey) {
        ui.showNotice('Received a message before key exchange completed.');
        return;
      }

      const plaintext = await decryptMessage(state.conversationKey, valid);
      state.receivedIds.add(valid.messageId);
      await saveEncryptedMessage({ ...packet, status: 'delivered' });
      ui.addMessage({
        id: valid.messageId,
        sender: valid.sender,
        text: plaintext,
        status: 'delivered',
        timestamp: valid.timestamp,
        mine: false
      });
      sendDeliveryStatus(socket, valid.messageId, 'delivered');
    } catch (error) {
      ui.showNotice('A message could not be decrypted and was ignored.');
    }
  });

  on(socket, 'delivery_status', async ({ messageId, status } = {}) => {
    if (!messageId || !status) return;
    try {
      await updateMessageStatus(messageId, status);
      ui.updateMessageStatus(messageId, status);
    } catch (error) {
      ui.showNotice('Failed to update message status.');
    }
  });

  on(socket, 'message_rejected', async ({ messageId, reason } = {}) => {
    if (reason === 'peer_unavailable') {
      ui.setConnectionStatus(`${describePeer()} is offline`, 'bad');
      ui.showNotice(`${describePeer()} is offline. Message stored on this device.`);
      return;
    }
    try {
      await updateMessageStatus(messageId, 'failed');
      ui.updateMessageStatus(messageId, 'failed');
    } catch (error) {
      ui.showNotice('A message could not be sent.');
    }
    ui.showNotice('A message could not be sent.');
  });

  on(socket, 'disconnect', () => {
    state.joined = false;
    ui.setConnectionStatus('Disconnected. Reconnecting…', 'bad');
  });

  on(socket, 'connect_error', () => {
    ui.setConnectionStatus('Connection failed. Retrying…', 'bad');
  });
}

async function renderHistory() {
  let messages = [];
  try {
    messages = await getEncryptedMessages();
  } catch (error) {
    ui.showNotice('Failed to load local chat history.');
    return;
  }

  ui.clearMessages();
  for (const record of messages) {
    let plaintext = null;
    if (state.conversationKey) {
      try {
        plaintext = await decryptMessage(state.conversationKey, record);
      } catch (error) {
        plaintext = null;
      }
    }
    if (plaintext === null) continue;
    ui.addMessage({
      id: record.messageId,
      sender: record.sender,
      text: plaintext,
      status: record.status,
      timestamp: record.timestamp,
      mine: record.sender === state.role
    });
  }
}

async function resendPending() {
  if (!state.socket || !state.conversationKey) return;
  let messages = [];
  try {
    messages = await getEncryptedMessages();
  } catch (error) {
    return;
  }
  for (const record of messages) {
    if (record.sender === state.role && record.status === 'sending') {
      sendEncryptedMessage(state.socket, record);
    }
  }
}

async function handleSend(text) {
  if (!state.role || !state.joined) {
    ui.showNotice('Not connected yet.');
    return false;
  }
  if (typeof text !== 'string' || !text.trim()) {
    ui.showNotice('Message cannot be empty.');
    return false;
  }
  if (text.length > MAX_MESSAGE_LENGTH) {
    ui.showNotice(`Message exceeds ${MAX_MESSAGE_LENGTH} characters.`);
    return false;
  }
  if (!state.conversationKey) {
    ui.showNotice(`Waiting for ${describePeer()}'s key exchange to finish.`);
    return false;
  }

  try {
    const messageId = crypto.randomUUID();
    const packet = await encryptMessage(state.conversationKey, text, {
      messageId,
      sender: state.role,
      timestamp: Date.now()
    });

    await saveEncryptedMessage({ ...packet, status: 'sending' });
    ui.addMessage({
      id: packet.messageId,
      sender: packet.sender,
      text,
      status: 'sending',
      timestamp: packet.timestamp,
      mine: true
    });
    sendEncryptedMessage(state.socket, packet);
    return true;
  } catch (error) {
    ui.showNotice('Failed to encrypt the message.');
    return false;
  }
}

ui.initUI({
  onJoin: handleJoin,
  onSend: handleSend
});
