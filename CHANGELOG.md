# Changelog

All notable changes to SecureChat are documented here.
Versioning follows [Semantic Versioning](https://semver.org/).

## [0.0.0] — Baseline

First working implementation of the two-person end-to-end encrypted chat.

### Added
- Express + Socket.IO ciphertext-only relay server (`server/`)
- Browser client with ECDH P-256 → HKDF-SHA-256 → AES-256-GCM
  (`client/`, modular: crypto/storage/socket/ui/app)
- Non-extractable `CryptoKey` material kept in IndexedDB
- Connection-key fingerprints, offline/reconnect resend, message dedupe
- Dark themed single-page UI (Generate Keys → Connect → Chat)
- Test suite: 17 client tests (crypto/storage/security scans) + 3 server
  tests (relay E2E, headless Chrome browser E2E) — 20/20 green

### Protocol (v0.0.0)
- Anonymous two-role protocol: `join {role: A|B}`, `peer_public_key`,
  `encrypted_message`, `delivery_status`
- No accounts, no persistence: server relays base64 ciphertext only
