const byId = (id) => document.getElementById(id);

const STATUS_LABELS = {
  sending: 'sending',
  sent: 'sent',
  delivered: 'delivered',
  failed: 'failed'
};

function formatTime(timestamp) {
  try {
    return new Date(timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  } catch {
    return '';
  }
}

export function initUI({ onJoin, onSend }) {
  document.querySelectorAll('[data-role]').forEach((button) => {
    button.addEventListener('click', () => onJoin(button.dataset.role));
  });

  byId('composer').addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = byId('message-input');
    const text = input.value;
    if (!text.trim()) return;
    const sent = await onSend(text);
    if (sent) {
      input.value = '';
      input.focus();
    }
  });
}

export function showJoinScreen() {
  byId('join-screen').classList.add('active');
  byId('chat-screen').classList.remove('active');
}

export function showChatScreen() {
  byId('join-screen').classList.remove('active');
  byId('chat-screen').classList.add('active');
}

export function setJoinBusy(role, busy) {
  document.querySelectorAll('[data-role]').forEach((button) => {
    button.disabled = busy;
    button.classList.toggle('selected', busy && button.dataset.role === role);
  });
}

export function showJoinError(message) {
  const node = byId('join-error');
  node.textContent = message || '';
}

export function setIdentity(role) {
  byId('identity').textContent = `Person ${role}`;
}

export function setConnectionStatus(text, kind) {
  const node = byId('connection-status');
  node.textContent = text;
  node.className = `status status-${kind}`;
}

export function setEncryptionStatus(text, kind) {
  const node = byId('encryption-status');
  node.textContent = text;
  node.className = `status status-${kind}`;
}

export function setFingerprints(own, peer) {
  const ownNode = byId('own-fingerprint');
  const peerNode = byId('peer-fingerprint');
  ownNode.textContent = own ? `Your fingerprint: ${own}` : 'Your fingerprint: generating…';
  if (peer) {
    peerNode.textContent = `Peer fingerprint: ${peer}`;
    peerNode.classList.remove('hidden');
  } else {
    peerNode.textContent = 'Peer fingerprint: waiting for peer…';
    peerNode.classList.add('hidden');
  }
}

export function showNotice(text) {
  const node = byId('notice');
  node.textContent = text || '';
  node.classList.toggle('hidden', !text);
}

export function clearMessages() {
  byId('messages').textContent = '';
}

export function addMessage({ id, sender, text, status, timestamp, mine }) {
  const container = byId('messages');
  const article = document.createElement('article');
  article.className = `message ${mine ? 'mine' : 'theirs'}`;
  article.dataset.id = id;
  article.dataset.sender = sender;

  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.textContent = text;

  const meta = document.createElement('div');
  meta.className = 'meta';
  meta.textContent = mine ? STATUS_LABELS[status] || status : formatTime(timestamp);

  article.appendChild(bubble);
  article.appendChild(meta);
  container.appendChild(article);
  container.scrollTop = container.scrollHeight;
}

export function hasMessage(messageId) {
  const container = byId('messages');
  for (const article of container.children) {
    if (article.dataset.id === messageId) return true;
  }
  return false;
}

export function updateMessageStatus(messageId, status) {
  const container = byId('messages');
  for (const article of container.children) {
    if (article.dataset.id === messageId) {
      const meta = article.querySelector('.meta');
      if (meta) meta.textContent = STATUS_LABELS[status] || status;
      return;
    }
  }
}
