# 🔐 Secure Chat — Two-Person End-to-End Encrypted Chat (V1)

A minimal, runnable two-person private chat application.

- Real-time messaging with **Socket.IO**
- End-to-end encryption with **ECDH P-256 → HKDF-SHA-256 → AES-256-GCM**
- Each person has their own key pair; **private keys never leave the device**
- The server is a **ciphertext-only relay** — it can never read messages
- Chat history is stored locally in **IndexedDB, encrypted**

There are exactly two identities: **Person A** and **Person B**. No groups,
channels, registration, or multi-conversation support — by design.

---

## Architecture

```text
                    ┌─────────────────────┐
                    │    Node.js Server   │
                    │    Express +        │
                    │    Socket.IO        │
                    └──────────┬──────────┘
                               │
                    ciphertext only
                               │
              ┌────────────────┴────────────────┐
              │                                 │
       ┌──────▼──────┐                   ┌──────▼──────┐
       │   Person A  │                   │   Person B  │
       │             │                   │             │
       │ Private A   │                   │ Private B   │
       │ Public A    │                   │ Public B    │
       └──────┬──────┘                   └──────┬──────┘
              │                                 │
              └─────────────┬───────────────────┘
                            │
                       ECDH shared secret
                            │
                           HKDF
                            │
                   Conversation encryption key
                            │
                       AES-256-GCM
                            │
                     Local encrypted DB
```

The server knows only:

- that Person A and Person B are connected
- their public keys
- encrypted message packets
- message routing status (`sent` / `delivered`)

The server never knows:

- private keys
- the conversation key
- plaintext messages

### Message flow

```text
A private key
       +
B public key
       ↓
ECDH (P-256)
       ↓
shared secret
       ↓
HKDF-SHA-256
       ↓
AES-256-GCM conversation key
       ↓
encrypt message locally (fresh random IV)
       ↓
ciphertext packet
       ↓
Socket.IO  →  relay server  →  Socket.IO
       ↓
B decrypts locally
       ↓
B stores ciphertext in IndexedDB
```

---

## Project structure

```text
secure-chat/
│
├── server/
│   ├── package.json
│   ├── tsconfig.json
│   ├── src/
│   │   ├── server.ts        Express static hosting + Socket.IO bootstrap
│   │   ├── socket.ts        relay logic + packet validation
│   │   └── types.ts         shared event/payload types
│   └── tests/
│       ├── e2e.test.mjs         relay E2E (keys, messages, statuses, rejections)
│       └── browser.test.mjs     headless Chrome E2E (chat, refresh, offline)
│
├── client/
│   ├── index.html
│   ├── package.json
│   ├── src/
│   │   ├── app.js           orchestration / state
│   │   ├── crypto.js        all cryptography (Web Crypto API)
│   │   ├── storage.js       IndexedDB (keys + encrypted messages)
│   │   ├── socket.js        Socket.IO wrapper (packets only, no plaintext)
│   │   ├── ui.js            DOM rendering (textContent only)
│   │   └── styles.css       dark theme
│   └── tests/
│       ├── crypto.test.js
│       ├── storage.test.js
│       ├── security.test.js
│       └── helpers/fake-indexeddb.js
│
├── package.json             root scripts
└── README.md
```

---

## Installation

Requires **Node.js ≥ 20** (uses the built-in test runner and Web Crypto).

```bash
cd secure-chat
npm run setup        # installs server + client dependencies
```

## Running

```bash
npm run server
```

This builds the TypeScript server and starts it on **http://localhost:3000**.
The server also serves the client, so there is no separate client build step.

To use a different port:

```bash
PORT=8080 npm run server
```

## Running two users

1. Start the server: `npm run server`
2. Open **http://localhost:3000** in one browser window (or browser profile) → choose **Person A**
3. Open **http://localhost:3000** in a second browser window (or another browser/profile) → choose **Person B**
4. Wait until both show `🔒 End-to-end encrypted`
5. Compare the fingerprints shown in both headers — they must match the peer
6. Chat

> You can use two normal windows of the same browser: each window picks a
> different identity, and keys are stored per identity in IndexedDB.
> A second attempt to join an identity that is already connected is rejected
> with `Person A is already connected.`

## Running the tests

```bash
npm test             # runs client unit tests + server E2E tests
```

Or individually:

```bash
npm --prefix client test     # crypto, storage, security tests
npm --prefix server test     # relay E2E + headless-browser E2E
```

The browser E2E requires Google Chrome/Chromium (skipped automatically if not
found; override with `CHROME_BIN=/path/to/chrome`).

---

## Cryptographic design

All cryptography happens in the browser with the **Web Crypto API**
(`crypto.subtle`). No third-party crypto libraries are used.

### Key generation

Each identity generates one ECDH key pair on **P-256**:

```js
crypto.subtle.generateKey(
  { name: 'ECDH', namedCurve: 'P-256' },
  false,                                  // private key is NON-EXTRACTABLE
  ['deriveKey', 'deriveBits']
)
```

- The **private key is non-extractable** — the browser will not let the page
  export it, so it can never be printed, logged, or sent anywhere.
- The public key is exported as SPKI (`base64`) and shared over Socket.IO.
- The key pair is stored in IndexedDB **once** and reused on every page load.
  A new key pair is generated only if none exists for that identity.

### Key agreement (ECDH)

```text
Person A: privateKeyA + publicKeyB  →  shared secret
Person B: privateKeyB + publicKeyA  →  shared secret   (identical value)
```

Raw ECDH output is **never used directly** as an AES key.

### Key derivation (HKDF-SHA-256)

The shared secret is stretched with HKDF-SHA-256:

```text
salt = SHA-256("secure-chat-v1|salt|" + conversationId)
info = "secure-chat-v1|key|" + conversationId
conversationId = "A-B"

HKDF-SHA-256(sharedSecret, salt, info) → 256-bit AES-GCM key (non-extractable)
```

Both sides use the identical, deterministic `conversationId` (`"A-B"`), so both
derive the same conversation key without any key being transmitted.

### Message encryption (AES-256-GCM)

Every message:

```text
plaintext
   ↓  AES-256-GCM with a fresh random 96-bit IV (crypto.getRandomValues)
ciphertext + 128-bit authentication tag
   +
random IV
   ↓
packet: { messageId, sender, ciphertext, iv, timestamp }
```

- A **new random IV is generated for every message**; IVs are never reused.
- The authentication tag makes any tampering with ciphertext or IV fail
  decryption (`OperationError`) instead of producing garbage.
- Packet size and shape are validated on both the client and the server
  (message length limit: **4096 characters**).

### Key fingerprints

```text
SHA-256(public key SPKI bytes) → first 8 bytes → "8A:F2:19:..."
```

Both parties can read the fingerprint aloud and compare. This is a manual
check that you are talking to the expected key — it is **not** a full identity
or authentication system (see threat model).

---

## Local storage

IndexedDB database `secure-chat` with two stores:

| Store      | Key        | Contents                                                  |
|------------|------------|-----------------------------------------------------------|
| `keys`     | role       | non-extractable private `CryptoKey` + own public key (b64) |
| `messages` | messageId  | `{ messageId, sender, ciphertext, iv, timestamp, status }`  |

- The messages store is validated: any record containing a `plaintext`-like
  field or an unknown field is **rejected**.
- On startup: load messages → derive conversation key (once the peer key
  arrives) → decrypt → render.
- Only the ciphertext is ever persisted; plaintext exists in memory and in the
  rendered DOM only.

---

## Socket.IO events

| Direction         | Event               | Payload                                    |
|-------------------|---------------------|--------------------------------------------|
| client → server   | `join`              | `{ role, publicKey }`                      |
| server → client   | `joined`            | `{ role }`                                 |
| server → client   | `join_error`        | `{ error }`                                |
| client → server   | `public_key`        | `{ publicKey }`                            |
| server → client   | `peer_public_key`   | `{ publicKey }`                            |
| server → client   | `peer_status`       | `{ peer, connected }`                      |
| client → server   | `encrypted_message` | `{ messageId, sender, ciphertext, iv, timestamp }` |
| server → client   | `encrypted_message` | same (relayed verbatim)                    |
| client → server   | `delivery_status`   | `{ messageId, status }`                    |
| server → client   | `delivery_status`   | `{ messageId, status }` (`sent`/`delivered`) |
| server → client   | `message_rejected`  | `{ messageId, reason }`                    |

The server validates that:

- the sender field matches the joining role of the socket (no impersonation)
- IV decodes to exactly 12 bytes and ciphertext is well-formed base64
- messageId/timestamp are well-formed and bounded
- the peer is actually connected before relaying

Message statuses: `sending → sent → delivered` (plus `failed` on rejection).
The server acknowledges `sent` when it relays; the receiving client reports
`delivered`. No plaintext is involved in any of this.

---

## Offline behavior (known limitation)

If the other person is offline:

- you see `Person B is offline`
- the encrypted message is stored on your device with status `sending`
- when the peer connects, pending messages are re-sent automatically
- the receiver de-duplicates by `messageId`

The **server keeps no message queue and no message database**. If you close
the sender's device before the peer ever comes online, that message is only on
the sender's device. Offline delivery is not guaranteed in V1.

---

## Threat model

### What this V1 protects against

- ✓ **Server reading plaintext** — the server only ever sees ciphertext, and
  it never receives the material needed to derive the key.
- ✓ **Server seeing private keys** — private keys are non-extractable and are
  never transmitted; tests scan the sources to enforce this.
- ✓ **Network observer reading plaintext** — messages are end-to-end encrypted;
  sniffing Socket.IO traffic yields ciphertext only.
- ✓ **Local plaintext database exposure** — IndexedDB stores only ciphertext;
  an attacker reading the database files gets nothing readable without the
  keys (and the private key is stored as a non-extractable `CryptoKey`).
- ✓ **Message tampering** — AES-GCM authentication tags reject modified
  ciphertext or IVs.
- ✓ **Accidental key/IV misuse** — fresh random IV per message, keys derived
  through HKDF instead of using raw ECDH output.

### What this V1 does NOT protect against

- ✗ **Compromised device** — malware with access to the running browser can
  read messages and keys from memory.
- ✗ **Malicious browser** — a backdoored browser can exfiltrate anything.
- ✗ **XSS executing inside the application** — the UI avoids `innerHTML`, but
  a successful XSS in this origin could act with the page's privileges.
- ✗ **Stolen unlocked device** — anyone using your logged-in browser sees the
  chat and can export nothing but *can* read everything on screen.
- ✗ **Endpoint screenshots / shoulder surfing**.
- ✗ **Traffic analysis and metadata** — the server sees who is online, when
  messages are sent, and message sizes/timing.
- ✗ **Man-in-the-middle identity attacks without fingerprint verification** —
  if you never compare fingerprints, a malicious relay could perform a key
  substitution attack. Compare fingerprints out of band.
- ✗ **Key compromise** — there is no forward secrecy in V1: one long-lived
  key pair per identity. If a private key is later stolen, all recorded
  traffic encrypted to it can be decrypted.

**This is a V1 prototype. It is not equivalent to Signal, Session, or any
mature secure messenger.**

### Known limitations

- No forward secrecy (long-lived static key pairs, no ratcheting)
- No server-side persistence: offline messages live only on the sender's device
- No identity verification beyond manual fingerprint comparison
- Exactly two users, one conversation — by design
- Browser-only client (Web Crypto requires a secure context; `localhost` works)

### Future improvements

- X3DH/Double-Ratchet style session key agreement (forward secrecy)
- Trusted-fingerprint UI with change alerts
- Optional sealed-sender / metadata reduction
- Server-side *encrypted* offline queue (still opaque to the server)
- Key rotation and revocation

---

## Security engineering notes

- The crypto, storage, socket and UI concerns live in separate modules; the
  socket module has no API that accepts plaintext or private keys.
- DOM rendering uses `textContent` only — no `innerHTML` anywhere (enforced by
  a test).
- Malformed packets, oversized messages, decryption failures and database
  errors surface as notices; a single bad message never crashes the app.
- The server source contains no decryption, no key derivation, no message
  logging and no database (enforced by tests).
