/**
 * ============================================================
 * COPY-PASTE INTEGRATION SNIPPET
 * ============================================================
 * 
 * Use this snippet to add E2E encryption to any website.
 * Just include crypto-module.js and use these functions.
 * 
 * SETUP:
 * 1. Include: <script src="js/crypto-module.js"></script>
 * 2. Copy the functions below to your app
 * 3. Call them as needed
 * 
 * ============================================================
 */

// ============================================================
// REGISTRATION: Generate keys for new user
// ============================================================
async function registerUserWithE2E(username) {
  console.log(`🔐 Registering ${username} with E2E encryption...`);
  
  // Generate RSA keypair
  const keyPair = await window.SecureChatCrypto.generateRSAKeyPair();
  
  // Export to PEM format
  const publicKeyPem = await window.SecureChatCrypto.exportPublicKeyToPem(keyPair.publicKey);
  const privateKeyPem = await window.SecureChatCrypto.exportPrivateKeyToPem(keyPair.privateKey);
  
  // Generate fingerprint for verification
  const fingerprint = await window.SecureChatCrypto.getPublicKeyFingerprint(publicKeyPem);
  
  // ⚠️ IMPORTANT: Store public key on server, private key on client ONLY
  const userData = {
    username: username,
    publicKey: publicKeyPem,
    fingerprint: fingerprint,
    createdAt: new Date().toISOString()
  };
  
  // Send ONLY public key to server
  await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(userData)
  });
  
  // Download private key for user (DO NOT store on server!)
  downloadPrivateKey(username, privateKeyPem);
  
  // Optional: Store in localStorage (⚠️ NOT recommended for production)
  // localStorage.setItem(`privateKey_${username}`, privateKeyPem);
  
  console.log('✅ User registered with E2E encryption');
  return { publicKey: publicKeyPem, privateKey: privateKeyPem, fingerprint };
}

// ============================================================
// SEND MESSAGE: Encrypt and send
// ============================================================
async function sendEncryptedMessage(recipientUsername, messageText) {
  console.log(`📤 Sending encrypted message to ${recipientUsername}...`);
  
  // 1. Fetch recipient's public key from server
  const response = await fetch(`/api/users/${recipientUsername}`);
  const recipientData = await response.json();
  
  if (!recipientData || !recipientData.publicKey) {
    throw new Error('Recipient not found or has no public key');
  }
  
  // 2. Encrypt message using hybrid E2E
  const encrypted = await window.SecureChatCrypto.encryptForRecipient(
    recipientData.publicKey,
    messageText
  );
  
  // 3. Prepare message package
  const messagePackage = {
    from: getCurrentUsername(), // Your implementation
    to: recipientUsername,
    encryptedKey: encrypted.encryptedKey,
    iv: encrypted.iv,
    ciphertext: encrypted.ciphertext,
    timestamp: Date.now()
  };
  
  // 4. Send encrypted package to server (transient relay only)
  await fetch('/api/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(messagePackage)
  });
  
  console.log('✅ Encrypted message sent');
  return messagePackage;
}

// ============================================================
// RECEIVE MESSAGE: Decrypt received message
// ============================================================
async function receiveAndDecryptMessage(encryptedPackage) {
  console.log('📥 Receiving encrypted message...');
  
  // 1. Load user's private key (from secure storage)
  const privateKeyPem = getUserPrivateKey(); // Your implementation
  
  if (!privateKeyPem) {
    throw new Error('Private key not found! Cannot decrypt.');
  }
  
  // 2. Decrypt using hybrid E2E
  const plaintext = await window.SecureChatCrypto.decryptReceived(
    privateKeyPem,
    encryptedPackage.encryptedKey,
    encryptedPackage.iv,
    encryptedPackage.ciphertext
  );
  
  console.log('✅ Message decrypted');
  
  // 3. Return decrypted message
  return {
    from: encryptedPackage.from,
    text: plaintext,
    timestamp: encryptedPackage.timestamp
  };
}

// ============================================================
// UTILITY: Download private key as .pem file
// ============================================================
function downloadPrivateKey(username, privateKeyPem) {
  const blob = new Blob([privateKeyPem], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${username}_private_key.pem`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  alert('⚠️ IMPORTANT: Save this private key safely! You cannot decrypt messages without it.');
}

// ============================================================
// UTILITY: Verify recipient's public key fingerprint
// ============================================================
async function verifyPublicKeyFingerprint(recipientUsername) {
  // Fetch recipient's public key
  const response = await fetch(`/api/users/${recipientUsername}`);
  const recipientData = await response.json();
  
  // Calculate fingerprint
  const fingerprint = await window.SecureChatCrypto.getPublicKeyFingerprint(
    recipientData.publicKey
  );
  
  // Display for manual verification
  console.log(`🔍 ${recipientUsername}'s fingerprint:`);
  console.log(fingerprint);
  
  // User should verify this with recipient via separate channel
  // (phone call, video chat, in person, etc.)
  const verified = confirm(
    `Verify ${recipientUsername}'s fingerprint:\n\n${fingerprint}\n\n` +
    'Does this match what they shared with you through another channel?'
  );
  
  return verified;
}

// ============================================================
// HELPER: Get current user's private key
// ============================================================
function getUserPrivateKey() {
  // Option 1: From localStorage (NOT secure for production!)
  const username = getCurrentUsername();
  return localStorage.getItem(`privateKey_${username}`);
  
  // Option 2: Prompt user to upload .pem file
  // return await loadPrivateKeyFromFile();
  
  // Option 3: Decrypt from IndexedDB using password
  // return await loadEncryptedPrivateKey(password);
}

// ============================================================
// HELPER: Get current username
// ============================================================
function getCurrentUsername() {
  // Your implementation - e.g.:
  const user = JSON.parse(localStorage.getItem('currentUser'));
  return user ? user.username : null;
}

// ============================================================
// EXAMPLE USAGE
// ============================================================

/*

// 1. REGISTRATION
const keys = await registerUserWithE2E('alice');
console.log('Alice registered:', keys);

// 2. SEND MESSAGE
const messagePackage = await sendEncryptedMessage('bob', 'Hello Bob!');
console.log('Sent:', messagePackage);

// 3. RECEIVE MESSAGE (on Bob's side)
const decrypted = await receiveAndDecryptMessage(messagePackage);
console.log('Received:', decrypted);

// 4. VERIFY KEY
const verified = await verifyPublicKeyFingerprint('bob');
if (verified) {
  console.log('✅ Bob\'s key verified');
} else {
  console.warn('⚠️ Key verification failed!');
}

*/

// ============================================================
// BACKEND API ENDPOINTS (Example with Express.js)
// ============================================================

/*

// === Node.js Express Backend Example ===

const express = require('express');
const app = express();
app.use(express.json());

// In-memory storage (use MongoDB/PostgreSQL in production)
const users = new Map();
const pendingMessages = new Map();

// 1. Register user (store ONLY public key)
app.post('/api/register', (req, res) => {
  const { username, publicKey, fingerprint } = req.body;
  
  if (users.has(username)) {
    return res.status(400).json({ error: 'Username exists' });
  }
  
  users.set(username, {
    username,
    publicKey,      // ✅ Store this
    fingerprint,    // ✅ Store this
    createdAt: new Date()
    // ❌ NEVER store: privateKey, password plaintext
  });
  
  res.json({ success: true, username });
});

// 2. Get user's public key
app.get('/api/users/:username', (req, res) => {
  const user = users.get(req.params.username);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  res.json({
    username: user.username,
    publicKey: user.publicKey,
    fingerprint: user.fingerprint
  });
});

// 3. Send message (transient relay - DO NOT persist)
app.post('/api/messages', (req, res) => {
  const { from, to, encryptedKey, iv, ciphertext, timestamp } = req.body;
  
  // Check recipient exists
  if (!users.has(to)) {
    return res.status(404).json({ error: 'Recipient not found' });
  }
  
  // Store temporarily (or use Socket.io for real-time)
  if (!pendingMessages.has(to)) {
    pendingMessages.set(to, []);
  }
  
  pendingMessages.get(to).push({
    from,
    encryptedKey,  // ✅ Encrypted AES key
    iv,            // ✅ IV for AES
    ciphertext,    // ✅ Encrypted message
    timestamp
    // ❌ NO plaintext stored!
  });
  
  // In production: use Socket.io to emit to recipient immediately
  // io.to(to).emit('new_message', { from, encryptedKey, iv, ciphertext });
  
  res.json({ success: true });
});

// 4. Get pending messages
app.get('/api/messages/:username', (req, res) => {
  const messages = pendingMessages.get(req.params.username) || [];
  
  // Clear after retrieval (transient)
  pendingMessages.delete(req.params.username);
  
  res.json({ messages });
});

// 5. Verify public key fingerprint
app.post('/api/verify-public-key', async (req, res) => {
  const { username, fingerprint } = req.body;
  const user = users.get(username);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  const match = user.fingerprint === fingerprint;
  res.json({ match, fingerprint: user.fingerprint });
});

app.listen(3000, () => {
  console.log('🔐 Secure Chat API running on port 3000');
});

*/

// ============================================================
// SECURITY CHECKLIST
// ============================================================

/*

✅ DO:
- Use HTTPS in production
- Store ONLY public keys on server
- Generate new AES key per message
- Verify key fingerprints out-of-band
- Use secure random (crypto.getRandomValues)
- Implement rate limiting
- Validate all inputs
- Use prepared statements for DB
- Log security events

❌ DON'T:
- Store private keys on server
- Store plaintext messages
- Reuse AES keys
- Trust client-side validation alone
- Log decrypted content
- Use HTTP (must be HTTPS)
- Store passwords in plaintext

*/
