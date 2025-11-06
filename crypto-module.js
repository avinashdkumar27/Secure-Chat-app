/**
 * SECURE CHAT ENCRYPTION MODULE
 * 
 * Implements AES-GCM (symmetric), RSA-OAEP (asymmetric), and Hybrid E2E encryption
 * Uses Web Crypto API for all cryptographic operations
 * 
 * Security Features:
 * - AES-GCM 256-bit with 96-bit IV for authenticated encryption
 * - RSA-OAEP 2048-bit with SHA-256 for key wrapping
 * - Hybrid encryption: AES for message + RSA for AES key
 * - Private keys never leave client
 */

// ============= CONSTANTS =============
const CRYPTO_CONFIG = {
  AES: {
    name: 'AES-GCM',
    length: 256,        // 256-bit key
    ivLength: 12        // 96-bit IV (12 bytes) for GCM
  },
  RSA: {
    name: 'RSA-OAEP',
    modulusLength: 2048,  // 2048-bit key
    publicExponent: new Uint8Array([1, 0, 1]), // 65537
    hash: 'SHA-256'
  }
};

// ============= UTILITY FUNCTIONS =============

/**
 * Convert ArrayBuffer to Base64 string
 * @param {ArrayBuffer} buffer 
 * @returns {string}
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 * @param {string} base64 
 * @returns {ArrayBuffer}
 */
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert PEM string to ArrayBuffer
 * @param {string} pem - PEM formatted key
 * @returns {ArrayBuffer}
 */
function pemToArrayBuffer(pem) {
  // Remove PEM header/footer and newlines
  const b64 = pem
    .replace(/-----BEGIN.*?-----/g, '')
    .replace(/-----END.*?-----/g, '')
    .replace(/\s/g, '');
  return base64ToArrayBuffer(b64);
}

/**
 * Convert ArrayBuffer to PEM string
 * @param {ArrayBuffer} buffer 
 * @param {string} type - 'PUBLIC' or 'PRIVATE'
 * @returns {string}
 */
function arrayBufferToPem(buffer, type = 'PUBLIC') {
  const b64 = arrayBufferToBase64(buffer);
  const label = type === 'PRIVATE' ? 'PRIVATE KEY' : 'PUBLIC KEY';
  
  // Format with line breaks every 64 characters
  let pem = `-----BEGIN ${label}-----\n`;
  for (let i = 0; i < b64.length; i += 64) {
    pem += b64.substring(i, i + 64) + '\n';
  }
  pem += `-----END ${label}-----`;
  return pem;
}

/**
 * Generate SHA-256 fingerprint of public key
 * @param {string} publicKeyPem 
 * @returns {Promise<string>} - Hex fingerprint
 */
async function getPublicKeyFingerprint(publicKeyPem) {
  const keyBuffer = pemToArrayBuffer(publicKeyPem);
  const hashBuffer = await crypto.subtle.digest('SHA-256', keyBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join(':').toUpperCase();
}

// ============= RSA KEY MANAGEMENT =============

/**
 * Generate RSA-OAEP keypair
 * @returns {Promise<{publicKey: CryptoKey, privateKey: CryptoKey}>}
 */
async function generateRSAKeyPair() {
  console.log('🔑 Generating RSA-OAEP 2048-bit keypair...');
  
  const keyPair = await crypto.subtle.generateKey(
    {
      name: CRYPTO_CONFIG.RSA.name,
      modulusLength: CRYPTO_CONFIG.RSA.modulusLength,
      publicExponent: CRYPTO_CONFIG.RSA.publicExponent,
      hash: CRYPTO_CONFIG.RSA.hash
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );
  
  console.log('✅ RSA keypair generated');
  return keyPair;
}

/**
 * Export RSA public key to PEM format
 * @param {CryptoKey} publicKey 
 * @returns {Promise<string>}
 */
async function exportPublicKeyToPem(publicKey) {
  const exported = await crypto.subtle.exportKey('spki', publicKey);
  return arrayBufferToPem(exported, 'PUBLIC');
}

/**
 * Export RSA private key to PEM format
 * @param {CryptoKey} privateKey 
 * @returns {Promise<string>}
 */
async function exportPrivateKeyToPem(privateKey) {
  const exported = await crypto.subtle.exportKey('pkcs8', privateKey);
  return arrayBufferToPem(exported, 'PRIVATE');
}

/**
 * Import RSA public key from PEM
 * @param {string} pem 
 * @returns {Promise<CryptoKey>}
 */
async function importPublicKeyFromPem(pem) {
  const keyBuffer = pemToArrayBuffer(pem);
  
  return await crypto.subtle.importKey(
    'spki',
    keyBuffer,
    {
      name: CRYPTO_CONFIG.RSA.name,
      hash: CRYPTO_CONFIG.RSA.hash
    },
    true,
    ['encrypt']
  );
}

/**
 * Import RSA private key from PEM
 * @param {string} pem 
 * @returns {Promise<CryptoKey>}
 */
async function importPrivateKeyFromPem(pem) {
  const keyBuffer = pemToArrayBuffer(pem);
  
  return await crypto.subtle.importKey(
    'pkcs8',
    keyBuffer,
    {
      name: CRYPTO_CONFIG.RSA.name,
      hash: CRYPTO_CONFIG.RSA.hash
    },
    true,
    ['decrypt']
  );
}

// ============= AES-GCM ENCRYPTION =============

/**
 * Generate random AES-GCM 256-bit key
 * @returns {Promise<CryptoKey>}
 */
async function generateAESKey() {
  return await crypto.subtle.generateKey(
    {
      name: CRYPTO_CONFIG.AES.name,
      length: CRYPTO_CONFIG.AES.length
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Generate random IV (Initialization Vector) for AES-GCM
 * Uses 96-bit (12 bytes) as recommended for GCM
 * @returns {Uint8Array}
 */
function generateIV() {
  return crypto.getRandomValues(new Uint8Array(CRYPTO_CONFIG.AES.ivLength));
}

/**
 * Encrypt plaintext using AES-GCM
 * @param {CryptoKey} aesKey 
 * @param {string} plaintext 
 * @param {Uint8Array} iv 
 * @returns {Promise<ArrayBuffer>}
 */
async function encryptWithAES(aesKey, plaintext, iv) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: CRYPTO_CONFIG.AES.name,
      iv: iv
    },
    aesKey,
    data
  );
  
  return ciphertext;
}

/**
 * Decrypt ciphertext using AES-GCM
 * @param {CryptoKey} aesKey 
 * @param {ArrayBuffer} ciphertext 
 * @param {Uint8Array} iv 
 * @returns {Promise<string>}
 */
async function decryptWithAES(aesKey, ciphertext, iv) {
  const plainBuffer = await crypto.subtle.decrypt(
    {
      name: CRYPTO_CONFIG.AES.name,
      iv: iv
    },
    aesKey,
    ciphertext
  );
  
  const decoder = new TextDecoder();
  return decoder.decode(plainBuffer);
}

// ============= HYBRID E2E ENCRYPTION =============

/**
 * Encrypt message for recipient using hybrid encryption
 * 
 * Flow:
 * 1. Generate random AES-GCM key
 * 2. Encrypt message with AES-GCM
 * 3. Wrap AES key with recipient's RSA public key
 * 4. Return encrypted package
 * 
 * @param {string} recipientPublicPem - Recipient's RSA public key (PEM)
 * @param {string} plaintext - Message to encrypt
 * @returns {Promise<{encryptedKey: string, iv: string, ciphertext: string}>}
 */
async function encryptForRecipient(recipientPublicPem, plaintext) {
  console.log('🔒 Starting hybrid E2E encryption...');
  
  // Step 1: Generate random AES-GCM key for this message
  console.log('  → Generating AES-256-GCM key...');
  const aesKey = await generateAESKey();
  
  // Step 2: Generate random IV
  const iv = generateIV();
  console.log('  → Generated 96-bit IV');
  
  // Step 3: Encrypt message with AES-GCM
  console.log('  → Encrypting message with AES-GCM...');
  const ciphertext = await encryptWithAES(aesKey, plaintext, iv);
  
  // Step 4: Export AES key to raw format
  const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
  
  // Step 5: Import recipient's RSA public key
  console.log('  → Importing recipient public key...');
  const recipientPublicKey = await importPublicKeyFromPem(recipientPublicPem);
  
  // Step 6: Encrypt AES key with RSA-OAEP (key wrapping)
  console.log('  → Wrapping AES key with RSA-OAEP...');
  const encryptedKey = await crypto.subtle.encrypt(
    {
      name: CRYPTO_CONFIG.RSA.name
    },
    recipientPublicKey,
    rawAesKey
  );
  
  console.log('✅ Encryption complete');
  
  // Return Base64-encoded components
  return {
    encryptedKey: arrayBufferToBase64(encryptedKey),
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(ciphertext)
  };
}

/**
 * Decrypt received message using hybrid decryption
 * 
 * Flow:
 * 1. Unwrap AES key using private RSA key
 * 2. Import AES key
 * 3. Decrypt message with AES-GCM
 * 
 * @param {string} privateKeyPem - Your RSA private key (PEM)
 * @param {string} encryptedKeyB64 - Base64 encrypted AES key
 * @param {string} ivB64 - Base64 IV
 * @param {string} ciphertextB64 - Base64 ciphertext
 * @returns {Promise<string>} - Decrypted plaintext
 */
async function decryptReceived(privateKeyPem, encryptedKeyB64, ivB64, ciphertextB64) {
  console.log('🔓 Starting hybrid E2E decryption...');
  
  try {
    // Step 1: Import private RSA key
    console.log('  → Importing private key...');
    const privateKey = await importPrivateKeyFromPem(privateKeyPem);
    
    // Step 2: Decrypt AES key with RSA-OAEP (key unwrapping)
    console.log('  → Unwrapping AES key with RSA-OAEP...');
    const encryptedKey = base64ToArrayBuffer(encryptedKeyB64);
    const rawAesKey = await crypto.subtle.decrypt(
      {
        name: CRYPTO_CONFIG.RSA.name
      },
      privateKey,
      encryptedKey
    );
    
    // Step 3: Import AES key
    console.log('  → Importing AES-256-GCM key...');
    const aesKey = await crypto.subtle.importKey(
      'raw',
      rawAesKey,
      {
        name: CRYPTO_CONFIG.AES.name,
        length: CRYPTO_CONFIG.AES.length
      },
      false,
      ['decrypt']
    );
    
    // Step 4: Decrypt message with AES-GCM
    console.log('  → Decrypting message with AES-GCM...');
    const iv = new Uint8Array(base64ToArrayBuffer(ivB64));
    const ciphertext = base64ToArrayBuffer(ciphertextB64);
    
    const plaintext = await decryptWithAES(aesKey, ciphertext, iv);
    
    console.log('✅ Decryption complete');
    return plaintext;
    
  } catch (error) {
    console.error('❌ Decryption failed:', error);
    throw new Error('Decryption failed. Invalid private key or corrupted message.');
  }
}

// ============= MESSAGE SIGNING (OPTIONAL) =============

/**
 * Sign message with private key (RSA-PSS)
 * @param {string} privateKeyPem 
 * @param {string} message 
 * @returns {Promise<string>} - Base64 signature
 */
async function signMessage(privateKeyPem, message) {
  const privateKey = await importPrivateKeyFromPem(privateKeyPem);
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  
  const signature = await crypto.subtle.sign(
    {
      name: 'RSA-PSS',
      saltLength: 32
    },
    privateKey,
    data
  );
  
  return arrayBufferToBase64(signature);
}

/**
 * Verify message signature
 * @param {string} publicKeyPem 
 * @param {string} message 
 * @param {string} signatureB64 
 * @returns {Promise<boolean>}
 */
async function verifySignature(publicKeyPem, message, signatureB64) {
  const publicKey = await importPublicKeyFromPem(publicKeyPem);
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  const signature = base64ToArrayBuffer(signatureB64);
  
  return await crypto.subtle.verify(
    {
      name: 'RSA-PSS',
      saltLength: 32
    },
    publicKey,
    signature,
    data
  );
}

// ============= DEMO: SIMPLE AES ENCRYPTION =============

/**
 * Simple AES encryption demo (without RSA wrapping)
 * @param {string} plaintext 
 * @param {string} password - User password (will be derived into key)
 * @returns {Promise<{iv: string, ciphertext: string, salt: string}>}
 */
async function simpleAESEncrypt(plaintext, password) {
  // Derive key from password using PBKDF2
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  
  // Generate random salt
  const salt = crypto.getRandomValues(new Uint8Array(16));
  
  // Import password as key material
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  
  // Derive AES key from password
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    {
      name: CRYPTO_CONFIG.AES.name,
      length: CRYPTO_CONFIG.AES.length
    },
    false,
    ['encrypt']
  );
  
  // Encrypt with AES-GCM
  const iv = generateIV();
  const ciphertext = await encryptWithAES(aesKey, plaintext, iv);
  
  return {
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(ciphertext),
    salt: arrayBufferToBase64(salt)
  };
}

/**
 * Simple AES decryption demo
 * @param {string} ivB64 
 * @param {string} ciphertextB64 
 * @param {string} saltB64 
 * @param {string} password 
 * @returns {Promise<string>}
 */
async function simpleAESDecrypt(ivB64, ciphertextB64, saltB64, password) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  const salt = base64ToArrayBuffer(saltB64);
  
  // Import password
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  );
  
  // Derive same AES key
  const aesKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    {
      name: CRYPTO_CONFIG.AES.name,
      length: CRYPTO_CONFIG.AES.length
    },
    false,
    ['decrypt']
  );
  
  // Decrypt
  const iv = new Uint8Array(base64ToArrayBuffer(ivB64));
  const ciphertext = base64ToArrayBuffer(ciphertextB64);
  
  return await decryptWithAES(aesKey, ciphertext, iv);
}

// ============= EXPORT MODULE =============

window.SecureChatCrypto = {
  // Key management
  generateRSAKeyPair,
  exportPublicKeyToPem,
  exportPrivateKeyToPem,
  importPublicKeyFromPem,
  importPrivateKeyFromPem,
  getPublicKeyFingerprint,
  
  // Hybrid E2E encryption (main functions)
  encryptForRecipient,
  decryptReceived,
  
  // Simple AES demo
  simpleAESEncrypt,
  simpleAESDecrypt,
  
  // Message signing (optional)
  signMessage,
  verifySignature,
  
  // Utilities
  arrayBufferToBase64,
  base64ToArrayBuffer,
  pemToArrayBuffer,
  arrayBufferToPem,
  
  // Constants
  CRYPTO_CONFIG
};

console.log('✅ Secure Chat Crypto Module loaded');
console.log('📚 Available at: window.SecureChatCrypto');
