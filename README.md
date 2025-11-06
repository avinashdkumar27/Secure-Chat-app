# 🔐 Secure Chat App - Complete E2E Encryption Module

> **College A6 Project** - End-to-End Encrypted Chat Application with AES, RSA, and Hybrid Encryption

[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-blue)](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
[![RSA](https://img.shields.io/badge/RSA-2048--OAEP-green)](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto)
[![Web Crypto API](https://img.shields.io/badge/Web%20Crypto-API-orange)](https://www.w3.org/TR/WebCryptoAPI/)

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [File Structure](#file-structure)
- [How It Works](#how-it-works)
- [Testing](#testing)
- [Documentation](#documentation)
- [Security](#security)
- [Tech Stack](#tech-stack)

---

## 🎯 Overview

This project demonstrates a **complete end-to-end encryption system** for secure chat messaging using modern Web Crypto APIs. Built for educational purposes, it implements industry-standard cryptographic algorithms in a clean, well-documented manner.

### What You Get

✅ **AES-256-GCM** encryption for message content  
✅ **RSA-2048-OAEP** for secure key exchange  
✅ **Hybrid E2E encryption** combining both  
✅ **Frontend-only** implementation (no backend required for demo)  
✅ **Professional glassmorphism UI**  
✅ **Complete documentation** with code examples  
✅ **Test console** for verification  
✅ **Integration snippets** for other projects  

---

## ✨ Features

### 🔒 Cryptographic Features

- **AES-GCM Symmetric Encryption**
  - 256-bit key length
  - 96-bit IV (recommended for GCM)
  - Authenticated encryption (integrity + confidentiality)
  
- **RSA Asymmetric Encryption**
  - 2048-bit modulus
  - OAEP padding with SHA-256
  - Public/private keypair generation
  
- **Hybrid E2E Encryption**
  - Random AES key per message
  - AES key wrapped with RSA
  - Optimal performance + security

### 🎨 UI Features

- Modern glassmorphism design
- Dark theme with subtle neon accents
- Responsive layout
- Real-time message simulation
- Key fingerprint display
- Private key download (.pem format)
- Encryption status indicators

### 🔐 Security Features

- Private keys never leave client
- Web Crypto API (not custom crypto!)
- Cryptographically secure random
- SHA-256 key fingerprints
- Clear security warnings
- No plaintext storage

---

## 🚀 Quick Start

### Option 1: Direct Open (Simplest)

1. **Download/Clone** the project
2. **Open** `index.html` in your browser
3. **Done!** No installation needed

### Option 2: Local Server (Recommended)

```bash
# Navigate to project folder
cd secure-chat-app

# Start local server (choose one):

# Python 3
python -m http.server 8000

# Node.js
npx serve .

# PHP
php -S localhost:8000
```

Then open: **`http://localhost:8000`**

### First Steps

1. **Register** a new account (generates RSA keys automatically)
2. **Download** your private key (⚠️ Keep it safe!)
3. **Copy** your Public ID
4. **Start chatting** (messages are encrypted with E2E)

---

## 📁 File Structure

```
secure-chat-app/
│
├── index.html                    # Main application
├── test-console.html             # Testing & demos
│
├── js/
│   ├── crypto-module.js          # 🔐 Core encryption module
│   └── app.js                    # Application logic
│
├── css/
│   ├── styles.css                # Main styles
│   └── glass.css                 # Glassmorphism theme
│
├── README.md                     # This file
├── ENCRYPTION_GUIDE.md           # Complete technical documentation
└── INTEGRATION_SNIPPET.js        # Copy-paste integration code
```

---

## 🔄 How It Works

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                   SENDER (Alice)                        │
├─────────────────────────────────────────────────────────┤
│ 1. Generate random AES-256 key                          │
│ 2. Encrypt message with AES-GCM → Ciphertext           │
│ 3. Encrypt AES key with Bob's RSA public key           │
│ 4. Send: {encryptedKey, iv, ciphertext}                │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  RECEIVER (Bob)                         │
├─────────────────────────────────────────────────────────┤
│ 1. Decrypt AES key with Bob's RSA private key          │
│ 2. Decrypt ciphertext with AES key → Plaintext         │
│ 3. Display message                                      │
└─────────────────────────────────────────────────────────┘
```

### Code Example

```javascript
// SEND MESSAGE
const encrypted = await window.SecureChatCrypto.encryptForRecipient(
  recipientPublicKey,
  "Hello, this is secret!"
);
// Returns: { encryptedKey, iv, ciphertext }

// RECEIVE MESSAGE
const plaintext = await window.SecureChatCrypto.decryptReceived(
  myPrivateKey,
  encrypted.encryptedKey,
  encrypted.iv,
  encrypted.ciphertext
);
// Returns: "Hello, this is secret!"
```

---

## 🧪 Testing

### Built-in Test Console

Open `test-console.html` for interactive testing:

- **Test 1**: RSA key generation
- **Test 2**: AES encryption/decryption
- **Test 3**: Complete E2E flow (Alice → Bob)
- **Test 4**: Key fingerprint generation
- **Test 5**: Performance benchmarks

### Browser Console Tests

```javascript
// Generate keys
const keyPair = await window.SecureChatCrypto.generateRSAKeyPair();

// Test encryption
const encrypted = await window.SecureChatCrypto.encryptForRecipient(
  publicKeyPem, 
  "Test message"
);

// Test decryption
const decrypted = await window.SecureChatCrypto.decryptReceived(
  privateKeyPem,
  encrypted.encryptedKey,
  encrypted.iv,
  encrypted.ciphertext
);

console.assert(decrypted === "Test message", "E2E test failed!");
```

---

## 📚 Documentation

### Core Files

| File | Description |
|------|-------------|
| `ENCRYPTION_GUIDE.md` | Complete technical documentation (680+ lines) |
| `INTEGRATION_SNIPPET.js` | Ready-to-use code for integration |
| `crypto-module.js` | Well-commented encryption module |
| `test-console.html` | Interactive testing interface |

### API Reference

See [`ENCRYPTION_GUIDE.md`](ENCRYPTION_GUIDE.md) for:

- Complete API documentation
- Cryptographic flow explanations
- Security best practices
- Integration instructions
- Code examples

### Key Functions

```javascript
// Key Management
generateRSAKeyPair()
exportPublicKeyToPem(publicKey)
exportPrivateKeyToPem(privateKey)
importPublicKeyFromPem(pem)
importPrivateKeyFromPem(pem)
getPublicKeyFingerprint(publicKeyPem)

// Encryption/Decryption
encryptForRecipient(recipientPublicPem, plaintext)
decryptReceived(privateKeyPem, encryptedKey, iv, ciphertext)
```

---

## 🛡️ Security

### ✅ What's Secure

- Real Web Crypto API (industry-standard)
- AES-256-GCM authenticated encryption
- RSA-2048-OAEP key wrapping
- Cryptographically secure random
- Private keys never sent to server
- No plaintext message storage

### ⚠️ Demo Limitations

This is an **educational project**. For production:

1. **Don't use localStorage for private keys**
   - Use hardware security (WebAuthn/FIDO2)
   - Or encrypt with strong password + PBKDF2

2. **Require HTTPS**
   - Web Crypto API requires secure context
   - Prevents man-in-the-middle attacks

3. **Implement key verification**
   - Users must verify fingerprints out-of-band
   - QR codes, phone calls, video chat

4. **Add Perfect Forward Secrecy**
   - Use ECDH for ephemeral keys
   - Protects past messages if key compromised

5. **Backend security**
   - Never store private keys
   - Never store plaintext messages
   - Implement rate limiting

### Security Warnings in UI

The app displays clear warnings:

```
⚠️ SECURITY WARNING:
• Private key stays ONLY on your device
• Download and store it securely (not on server!)
• If lost, you cannot decrypt old messages
• Never share your private key with anyone
• Use HTTPS in production environment
```

---

## 💻 Tech Stack

| Technology | Purpose |
|-----------|---------|
| **HTML5** | Structure |
| **CSS3** | Styling + Glassmorphism |
| **Vanilla JS** | Logic (no frameworks!) |
| **Web Crypto API** | Encryption (`crypto.subtle`) |
| **Tailwind CSS** | Utility classes |
| **Font Awesome** | Icons |

### Browser Support

| Browser | Version | Status |
|---------|---------|--------|
| Chrome | 37+ | ✅ Full support |
| Firefox | 34+ | ✅ Full support |
| Safari | 11+ | ✅ Full support |
| Edge | 79+ | ✅ Full support |
| IE11 | Any | ❌ Not supported |

---

## 🎓 For College Evaluation

### Demonstrates

1. **Cryptographic Algorithms**
   - Symmetric (AES-GCM)
   - Asymmetric (RSA-OAEP)
   - Hybrid encryption

2. **Security Principles**
   - Confidentiality
   - Integrity
   - Authentication
   - Key management

3. **Modern Web Development**
   - Web Crypto API
   - Async/await patterns
   - Clean code architecture
   - Comprehensive documentation

4. **Practical Implementation**
   - Working chat application
   - Professional UI/UX
   - Real encryption (not simulation)
   - Test suite included

### Project Files for Review

- **Code**: `js/crypto-module.js` (560 lines, well-commented)
- **Demo**: `test-console.html` (interactive tests)
- **Docs**: `ENCRYPTION_GUIDE.md` (complete technical guide)
- **Integration**: `INTEGRATION_SNIPPET.js` (copy-paste ready)

---

## 📞 Support

### Testing Issues?

1. Check browser console (F12) for errors
2. Verify `crypto-module.js` is loaded
3. Use test console for debugging

### Common Questions

**Q: Why localStorage for private keys?**  
A: Demo purposes only! Production should use secure storage.

**Q: Can I use this in production?**  
A: Code is secure, but add backend validation, HTTPS, and proper key storage.

**Q: Why no backend?**  
A: Frontend-only for easy demonstration. Backend example included in docs.

**Q: Is the crypto real?**  
A: Yes! Uses Web Crypto API (same as Signal, WhatsApp Web).

---

## 📄 License

Educational project for college A6 submission.  
Crypto module free to use with attribution.

---

## 🎉 Credits

**Developed for**: College A6 Project Submission  
**Date**: November 2024  
**Tech**: Web Crypto API, Modern JavaScript, Glassmorphism UI

---

## 🚀 Next Steps

1. **Run the demo**: Open `index.html`
2. **Test encryption**: Open `test-console.html`
3. **Read docs**: Check `ENCRYPTION_GUIDE.md`
4. **Integrate**: Use `INTEGRATION_SNIPPET.js`

---

**Happy Encrypting! 🔐**
