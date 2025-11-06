# 🔐 Secure Chat App - Encryption Module Documentation

## 📚 Table of Contents
1. [Overview](#overview)
2. [Cryptographic Architecture](#cryptographic-architecture)
3. [Encryption Flows](#encryption-flows)
4. [API Reference](#api-reference)
5. [Security Features](#security-features)
6. [How to Run](#how-to-run)
7. [Testing Guide](#testing-guide)
8. [Integration Instructions](#integration-instructions)
9. [Security Warnings](#security-warnings)

---

## 🎯 Overview

This project implements a **complete end-to-end encryption module** for secure chat communication using:

- **AES-GCM** (Advanced Encryption Standard - Galois/Counter Mode) for symmetric encryption
- **RSA-OAEP** (RSA Optimal Asymmetric Encryption Padding) for asymmetric encryption  
- **Hybrid E2E Encryption** combining AES + RSA for optimal security and performance

### Technology Stack
- **Frontend**: Vanilla JavaScript (HTML, CSS, JS) - No frameworks required
- **Crypto**: Web Crypto API (`window.crypto.subtle`)
- **Storage**: localStorage (demo purposes only)
- **UI**: Tailwind CSS + Custom Glassmorphism theme

---

## 🏗️ Cryptographic Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HYBRID E2E ENCRYPTION                     │
└─────────────────────────────────────────────────────────────┘

SENDER SIDE:
┌──────────────┐
│   Message    │
│  (Plaintext) │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────────┐
│  Generate Random AES-256-GCM Key         │
│  (256-bit key + 96-bit IV)               │
└──────────────┬───────────────────────────┘
               │
               ▼
       ┌───────────────┐
       │  AES Encrypt  │ ─────► Ciphertext
       └───────────────┘
               │
               │ (export AES key)
               ▼
       ┌───────────────────────┐
       │  RSA-OAEP Encrypt     │ ─────► Encrypted AES Key
       │  (Recipient's Public) │
       └───────────────────────┘
               │
               ▼
   ┌────────────────────────┐
   │  Send Package:         │
   │  • encryptedKey        │
   │  • iv                  │
   │  • ciphertext          │
   └────────────────────────┘

RECEIVER SIDE:
┌────────────────────────┐
│  Receive Package       │
└──────┬─────────────────┘
       │
       ▼
┌──────────────────────────────────┐
│  RSA-OAEP Decrypt                │
│  (Your Private Key)              │
└──────┬───────────────────────────┘
       │
       ▼ (get AES key)
┌──────────────────┐
│  AES-GCM Decrypt │
└──────┬───────────┘
       │
       ▼
┌──────────────┐
│   Message    │
│  (Plaintext) │
└──────────────┘
```

---

## 🔄 Encryption Flows

### 1️⃣ AES-GCM Encryption (Symmetric)

**Purpose**: Fast encryption of message content

**Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 96 bits (12 bytes) - recommended for GCM
- **Authentication**: Built-in authentication tag (prevents tampering)

**Why AES-GCM?**
- ✅ Authenticated encryption (confidentiality + integrity)
- ✅ Fast performance for large messages
- ✅ No padding oracle attacks
- ✅ Native browser support

**Code Example**:
```javascript
// Generate AES key
const aesKey = await crypto.subtle.generateKey(
  {
    name: 'AES-GCM',
    length: 256
  },
  true,
  ['encrypt', 'decrypt']
);

// Generate random IV
const iv = crypto.getRandomValues(new Uint8Array(12));

// Encrypt
const ciphertext = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv: iv },
  aesKey,
  plaintext
);
```

### 2️⃣ RSA-OAEP Encryption (Asymmetric)

**Purpose**: Secure key exchange (wrapping AES keys)

**Algorithm**: RSA-OAEP with SHA-256
- **Key Size**: 2048 bits (minimum secure size)
- **Padding**: OAEP (Optimal Asymmetric Encryption Padding)
- **Hash**: SHA-256

**Why RSA-OAEP?**
- ✅ Industry standard for key wrapping
- ✅ Prevents padding oracle attacks
- ✅ Secure against known RSA vulnerabilities
- ✅ Web Crypto API support

**Code Example**:
```javascript
// Generate RSA keypair
const keyPair = await crypto.subtle.generateKey(
  {
    name: 'RSA-OAEP',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]), // 65537
    hash: 'SHA-256'
  },
  true,
  ['encrypt', 'decrypt']
);

// Encrypt AES key with RSA public key
const encryptedKey = await crypto.subtle.encrypt(
  { name: 'RSA-OAEP' },
  recipientPublicKey,
  aesKeyRaw
);
```

### 3️⃣ Hybrid E2E Encryption (Combined)

**Why Hybrid?**
- RSA is slow for large data → Use AES for message
- AES requires shared key → Use RSA to share AES key securely
- Best of both worlds: RSA security + AES performance

**Complete Flow**:
```javascript
// SENDER
async function encryptForRecipient(recipientPublicPem, plaintext) {
  // 1. Generate random AES-256 key
  const aesKey = await generateAESKey();
  
  // 2. Generate random IV
  const iv = generateIV();
  
  // 3. Encrypt message with AES-GCM
  const ciphertext = await encryptWithAES(aesKey, plaintext, iv);
  
  // 4. Export AES key to raw bytes
  const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
  
  // 5. Encrypt AES key with recipient's RSA public key
  const recipientPublicKey = await importPublicKeyFromPem(recipientPublicPem);
  const encryptedKey = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    recipientPublicKey,
    rawAesKey
  );
  
  // 6. Return encrypted package
  return {
    encryptedKey: base64(encryptedKey),
    iv: base64(iv),
    ciphertext: base64(ciphertext)
  };
}

// RECEIVER
async function decryptReceived(privateKeyPem, encryptedKeyB64, ivB64, ciphertextB64) {
  // 1. Import private RSA key
  const privateKey = await importPrivateKeyFromPem(privateKeyPem);
  
  // 2. Decrypt AES key with RSA private key
  const encryptedKey = base64ToBuffer(encryptedKeyB64);
  const rawAesKey = await crypto.subtle.decrypt(
    { name: 'RSA-OAEP' },
    privateKey,
    encryptedKey
  );
  
  // 3. Import AES key
  const aesKey = await crypto.subtle.importKey(
    'raw',
    rawAesKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  
  // 4. Decrypt message with AES-GCM
  const iv = base64ToBuffer(ivB64);
  const ciphertext = base64ToBuffer(ciphertextB64);
  const plaintext = await decryptWithAES(aesKey, ciphertext, iv);
  
  return plaintext;
}
```

---

## 📖 API Reference

### Core Functions

#### `generateRSAKeyPair()`
Generates a new RSA-OAEP keypair for encryption.

```javascript
const keyPair = await window.SecureChatCrypto.generateRSAKeyPair();
// Returns: { publicKey: CryptoKey, privateKey: CryptoKey }
```

#### `exportPublicKeyToPem(publicKey)`
Exports RSA public key to PEM format.

```javascript
const publicPem = await window.SecureChatCrypto.exportPublicKeyToPem(keyPair.publicKey);
// Returns: "-----BEGIN PUBLIC KEY-----\n..."
```

#### `exportPrivateKeyToPem(privateKey)`
Exports RSA private key to PEM format (keep secure!).

```javascript
const privatePem = await window.SecureChatCrypto.exportPrivateKeyToPem(keyPair.privateKey);
// Returns: "-----BEGIN PRIVATE KEY-----\n..."
```

#### `encryptForRecipient(recipientPublicPem, plaintext)`
**Main encryption function** - Encrypts message using hybrid E2E.

```javascript
const encrypted = await window.SecureChatCrypto.encryptForRecipient(
  recipientPublicKeyPem,
  "Hello, this is a secret message!"
);
// Returns: { encryptedKey: "...", iv: "...", ciphertext: "..." }
```

#### `decryptReceived(privateKeyPem, encryptedKey, iv, ciphertext)`
**Main decryption function** - Decrypts hybrid E2E encrypted message.

```javascript
const plaintext = await window.SecureChatCrypto.decryptReceived(
  myPrivateKeyPem,
  encrypted.encryptedKey,
  encrypted.iv,
  encrypted.ciphertext
);
// Returns: "Hello, this is a secret message!"
```

#### `getPublicKeyFingerprint(publicKeyPem)`
Generates SHA-256 fingerprint for key verification.

```javascript
const fingerprint = await window.SecureChatCrypto.getPublicKeyFingerprint(publicPem);
// Returns: "A1:B2:C3:D4:E5:F6:..." (hex format with colons)
```

### Utility Functions

#### `arrayBufferToBase64(buffer)` / `base64ToArrayBuffer(base64)`
Convert between ArrayBuffer and Base64 encoding.

#### `pemToArrayBuffer(pem)` / `arrayBufferToPem(buffer, type)`
Convert between PEM format and ArrayBuffer.

#### `simpleAESEncrypt(plaintext, password)` / `simpleAESDecrypt(...)`
Demo: Password-based AES encryption using PBKDF2.

---

## 🛡️ Security Features

### ✅ What's Secure

1. **Real Cryptography**
   - Uses Web Crypto API (not custom crypto!)
   - AES-256-GCM authenticated encryption
   - RSA-2048-OAEP key wrapping
   - Cryptographically secure random (crypto.getRandomValues)

2. **Private Key Protection**
   - Private keys never sent to server
   - Only public keys stored/transmitted
   - Download option for offline backup
   - Clear security warnings in UI

3. **Message Integrity**
   - AES-GCM provides authentication tag
   - Tampering detected automatically
   - No padding oracle vulnerabilities

4. **Key Verification**
   - SHA-256 fingerprints for manual verification
   - Prevents man-in-the-middle attacks (if verified)

### ⚠️ Security Limitations (Demo Project)

1. **localStorage for Private Keys**
   - ❌ NOT SECURE for production
   - ✅ Only for demo/testing purposes
   - 🔒 Production: Use secure hardware storage, password-encrypted export, or TEE

2. **No Backend**
   - ❌ No user authentication
   - ❌ No public key registry verification
   - ✅ Shows concept only

3. **No Perfect Forward Secrecy (PFS)**
   - If private key compromised, all past messages can be decrypted
   - Could add ECDH key exchange for PFS (future enhancement)

4. **No HTTPS Enforcement**
   - Must use HTTPS in production
   - Local file:// protocol okay for testing only

---

## 🚀 How to Run

### Prerequisites
- Modern web browser (Chrome, Firefox, Edge, Safari)
- No server needed (frontend-only)

### Option 1: Direct File Open
1. Open `index.html` in your browser
2. That's it! No build process needed

### Option 2: Local Server (Recommended)
```bash
# Using Python 3
cd secure-chat-app
python -m http.server 8000

# Using Node.js
npx serve .

# Using PHP
php -S localhost:8000
```

Then open: `http://localhost:8000`

### File Structure
```
secure-chat-app/
├── index.html              # Main HTML file
├── css/
│   ├── styles.css          # Main styles
│   └── glass.css           # Glassmorphism theme
├── js/
│   ├── crypto-module.js    # 🔐 Encryption module
│   └── app.js              # App logic
├── ENCRYPTION_GUIDE.md     # This file
└── README.md               # Quick start guide
```

---

## 🧪 Testing Guide

### Test 1: Key Generation
```javascript
// Open browser console (F12)
const keyPair = await window.SecureChatCrypto.generateRSAKeyPair();
const publicPem = await window.SecureChatCrypto.exportPublicKeyToPem(keyPair.publicKey);
const privatePem = await window.SecureChatCrypto.exportPrivateKeyToPem(keyPair.privateKey);

console.log('Public Key:', publicPem);
console.log('Private Key:', privatePem);
```

### Test 2: AES Encryption
```javascript
const aesKey = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  true,
  ['encrypt', 'decrypt']
);

const iv = crypto.getRandomValues(new Uint8Array(12));
const encoder = new TextEncoder();
const plaintext = encoder.encode("Test message");

const ciphertext = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv: iv },
  aesKey,
  plaintext
);

console.log('Encrypted:', new Uint8Array(ciphertext));
```

### Test 3: Complete E2E Flow
```javascript
// Generate two users
const alice = await window.SecureChatCrypto.generateRSAKeyPair();
const bob = await window.SecureChatCrypto.generateRSAKeyPair();

const alicePublic = await window.SecureChatCrypto.exportPublicKeyToPem(alice.publicKey);
const alicePrivate = await window.SecureChatCrypto.exportPrivateKeyToPem(alice.privateKey);
const bobPublic = await window.SecureChatCrypto.exportPublicKeyToPem(bob.publicKey);
const bobPrivate = await window.SecureChatCrypto.exportPrivateKeyToPem(bob.privateKey);

// Alice sends to Bob
const message = "Hello Bob, this is encrypted!";
const encrypted = await window.SecureChatCrypto.encryptForRecipient(bobPublic, message);

console.log('Encrypted package:', encrypted);

// Bob receives from Alice
const decrypted = await window.SecureChatCrypto.decryptReceived(
  bobPrivate,
  encrypted.encryptedKey,
  encrypted.iv,
  encrypted.ciphertext
);

console.log('Decrypted:', decrypted);
console.assert(decrypted === message, 'Decryption failed!');
```

### Test 4: Fingerprint Verification
```javascript
const fingerprint = await window.SecureChatCrypto.getPublicKeyFingerprint(alicePublic);
console.log('Alice fingerprint:', fingerprint);
// Share this with Bob through separate channel for verification
```

---

## 🔌 Integration Instructions

### Integrate into Any Website

**Step 1**: Include the crypto module
```html
<script src="js/crypto-module.js"></script>
```

**Step 2**: Generate keys on user registration
```javascript
// On registration
async function registerUser(username) {
  const keyPair = await window.SecureChatCrypto.generateRSAKeyPair();
  const publicPem = await window.SecureChatCrypto.exportPublicKeyToPem(keyPair.publicKey);
  const privatePem = await window.SecureChatCrypto.exportPrivateKeyToPem(keyPair.privateKey);
  
  // Store public key on server
  await fetch('/api/users', {
    method: 'POST',
    body: JSON.stringify({ username, publicKey: publicPem })
  });
  
  // Download private key to user
  downloadFile(`${username}_private.pem`, privatePem);
}
```

**Step 3**: Send encrypted message
```javascript
async function sendEncryptedMessage(recipientUsername, message) {
  // Get recipient's public key from server
  const response = await fetch(`/api/users/${recipientUsername}`);
  const { publicKey } = await response.json();
  
  // Encrypt message
  const encrypted = await window.SecureChatCrypto.encryptForRecipient(publicKey, message);
  
  // Send encrypted package
  await fetch('/api/messages', {
    method: 'POST',
    body: JSON.stringify({
      to: recipientUsername,
      encryptedKey: encrypted.encryptedKey,
      iv: encrypted.iv,
      ciphertext: encrypted.ciphertext,
      timestamp: Date.now()
    })
  });
}
```

**Step 4**: Receive and decrypt
```javascript
async function receiveMessage(encryptedMessage) {
  // Load user's private key (from secure storage)
  const privatePem = localStorage.getItem('privateKey'); // ⚠️ Use secure storage!
  
  // Decrypt
  const plaintext = await window.SecureChatCrypto.decryptReceived(
    privatePem,
    encryptedMessage.encryptedKey,
    encryptedMessage.iv,
    encryptedMessage.ciphertext
  );
  
  return plaintext;
}
```

---

## ⚠️ Security Warnings

### 🚨 CRITICAL - READ BEFORE DEPLOYMENT

#### 1. Private Key Storage
```
❌ NEVER do this in production:
   localStorage.setItem('privateKey', privatePem);

✅ Instead:
   - Use hardware security modules (HSM)
   - Use browser WebAuthn/FIDO2
   - Encrypt with user password + PBKDF2 (100k+ iterations)
   - Store in IndexedDB with encryption
   - Or don't store at all (user downloads only)
```

#### 2. HTTPS Requirement
```
⚠️ All crypto operations MUST happen over HTTPS
   - Web Crypto API requires secure context
   - Prevents man-in-the-middle attacks
   - Use Let's Encrypt for free SSL
```

#### 3. Key Verification
```
📋 Users MUST verify key fingerprints out-of-band:
   - Phone call
   - Video chat
   - QR code scan in person
   - Prevents impersonation attacks
```

#### 4. Session vs Per-Message Keys
```
🔄 Current implementation: New AES key per message
   ✅ Better security (no key reuse)
   ❌ Slightly more overhead
   
   Alternative: Session-based AES key
   ✅ Better performance
   ❌ Need proper session management
```

#### 5. Backend Security (if adding server)
```
✅ DO:
   - Store ONLY public keys
   - Use transient message relay (don't persist)
   - Implement rate limiting
   - Use prepared statements (SQL injection)
   - Validate all inputs
   
❌ DON'T:
   - Store private keys on server
   - Store plaintext messages
   - Log decrypted content
   - Trust client-side validation
```

#### 6. Browser Compatibility
```
✅ Supported: Chrome 37+, Firefox 34+, Safari 11+, Edge 79+
⚠️ Not supported: IE11 and below
```

---

## 🎓 Educational Notes

### Why This Architecture?

1. **AES-GCM over CBC**
   - GCM provides authentication (integrity check)
   - No padding = no padding oracle attacks
   - Faster than CBC for parallel processing

2. **RSA-OAEP over raw RSA**
   - OAEP prevents chosen ciphertext attacks
   - Industry standard (PKCS#1 v2.0)
   - Required by Web Crypto API

3. **Hybrid over pure RSA**
   - RSA max message size = key size - padding
   - RSA is slow for large messages
   - Hybrid: Fast AES + Secure RSA key exchange

4. **256-bit AES**
   - Future-proof against quantum computers (for now)
   - Minimal performance cost vs 128-bit
   - Industry standard for high security

5. **96-bit IV for GCM**
   - Optimal for GCM mode (recommended size)
   - Allows efficient counter management
   - Unique per message (using crypto.getRandomValues)

### Common Attack Mitigations

| Attack Type | Mitigation |
|------------|------------|
| Man-in-the-Middle | HTTPS + Key fingerprint verification |
| Padding Oracle | Use GCM (no padding) |
| Replay Attack | Include timestamp in messages |
| Key Reuse | Generate new AES key per message |
| Weak Random | Use crypto.getRandomValues() |
| Tampering | GCM authentication tag |

---

## 📞 Support & Contact

For college A6 project evaluation:
- **Demo**: Open `index.html` and create two users
- **Code Review**: Check `js/crypto-module.js` (well-commented)
- **Architecture**: See diagrams in this document

---

## 📄 License

Educational project for college submission.
Crypto module can be used in other projects with attribution.

---

**Last Updated**: November 2024  
**Version**: 1.0.0  
**Project**: College A6 Submission - Secure Chat Application
