// ============= STATE MANAGEMENT =============
let currentUser = null;
let activeChats = [];
let currentChatId = null;
let messages = {};
let userKeyPairs = {}; // Store RSA keypairs
let isEncryptionEnabled = false; // Flag for real encryption

// ============= INITIALIZATION =============
document.addEventListener('DOMContentLoaded', () => {
  console.log('🔒 Secure Chat App Initialized');
  console.log('🔐 Crypto Module:', window.SecureChatCrypto ? 'Loaded' : 'Not loaded');
  
  // Check if user is already logged in
  const savedUser = localStorage.getItem('currentUser');
  if (savedUser) {
    currentUser = JSON.parse(savedUser);
    loadSavedChats();
    showPage('chatPage');
    updateProfileInfo();
    
    // Load private key if available
    const savedPrivateKey = localStorage.getItem(`privateKey_${currentUser.username}`);
    if (savedPrivateKey) {
      console.log('🔑 Private key found in storage');
    }
  }
});

// ============= PAGE NAVIGATION =============
function showPage(pageId) {
  // Hide all pages
  document.querySelectorAll('.page').forEach(page => {
    page.classList.remove('active');
  });
  
  // Show target page
  const targetPage = document.getElementById(pageId);
  if (targetPage) {
    targetPage.classList.add('active');
  }
  
  // Clear error messages
  document.querySelectorAll('.error-message').forEach(msg => {
    msg.classList.remove('show');
    msg.textContent = '';
  });
  
  // Update chat page if needed
  if (pageId === 'chatPage' && currentUser) {
    updateChatSidebar();
  }
}

// ============= KEY GENERATION =============
async function generateKeys(useRealEncryption = true) {
  if (useRealEncryption && window.SecureChatCrypto) {
    try {
      console.log('🔐 Generating real RSA-OAEP keypair...');
      const keyPair = await window.SecureChatCrypto.generateRSAKeyPair();
      
      const publicKeyPem = await window.SecureChatCrypto.exportPublicKeyToPem(keyPair.publicKey);
      const privateKeyPem = await window.SecureChatCrypto.exportPrivateKeyToPem(keyPair.privateKey);
      
      // Generate fingerprint
      const fingerprint = await window.SecureChatCrypto.getPublicKeyFingerprint(publicKeyPem);
      
      console.log('✅ Real RSA keys generated');
      console.log('🔍 Fingerprint:', fingerprint.substring(0, 47) + '...');
      
      return {
        publicKey: publicKeyPem,
        privateKey: privateKeyPem,
        fingerprint: fingerprint,
        isReal: true
      };
    } catch (error) {
      console.error('❌ Real key generation failed:', error);
      console.log('⚠️ Falling back to demo keys');
    }
  }
  
  // Fallback to demo keys
  const publicKey = 'PUB-' + generateRandomString(6).toUpperCase();
  const privateKey = 'PRV-' + generateRandomString(6).toUpperCase();
  return { publicKey, privateKey, isReal: false };
}

function generateRandomString(length) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

// ============= AUTHENTICATION =============
async function handleRegister(event) {
  event.preventDefault();
  
  const username = document.getElementById('regUsername').value.trim();
  const email = document.getElementById('regEmail').value.trim();
  const password = document.getElementById('regPassword').value;
  
  const errorDiv = document.getElementById('registerError');
  const submitBtn = event.target.querySelector('button[type="submit"]');
  
  // Check if user already exists
  const existingUsers = JSON.parse(localStorage.getItem('users') || '[]');
  const userExists = existingUsers.find(u => u.username === username || u.email === email);
  
  if (userExists) {
    errorDiv.textContent = 'Username or email already exists!';
    errorDiv.classList.add('show');
    return;
  }
  
  // Show loading state
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Generating Keys...';
  
  // Generate keys (real RSA encryption)
  const keys = await generateKeys(true);
  
  // Create user
  const newUser = {
    username,
    email,
    password, // In real app, this would be hashed
    publicKey: keys.publicKey,
    fingerprint: keys.fingerprint,
    isRealEncryption: keys.isReal,
    createdAt: new Date().toISOString()
  };
  
  // Save user (public key only)
  existingUsers.push(newUser);
  localStorage.setItem('users', JSON.stringify(existingUsers));
  
  // Save private key separately (with warning)
  if (keys.isReal) {
    localStorage.setItem(`privateKey_${username}`, keys.privateKey);
    console.warn('⚠️ SECURITY WARNING: Private key stored in localStorage for demo purposes only!');
    console.warn('⚠️ In production, use secure key storage or allow user download only!');
  }
  
  // Set current user (without private key)
  currentUser = newUser;
  localStorage.setItem('currentUser', JSON.stringify(currentUser));
  
  // Show keys modal
  showKeyModal(keys.publicKey, keys.privateKey, keys.fingerprint, keys.isReal);
  
  // Reset form
  document.getElementById('registerForm').reset();
  submitBtn.disabled = false;
  submitBtn.innerHTML = '<i class="fas fa-user-plus"></i> Create Account';
}

function handleLogin(event) {
  event.preventDefault();
  
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value;
  
  const errorDiv = document.getElementById('loginError');
  
  // Get users
  const users = JSON.parse(localStorage.getItem('users') || '[]');
  const user = users.find(u => u.username === username && u.password === password);
  
  if (!user) {
    errorDiv.textContent = 'Invalid username or password!';
    errorDiv.classList.add('show');
    return;
  }
  
  // Set current user
  currentUser = user;
  localStorage.setItem('currentUser', JSON.stringify(currentUser));
  
  // Load chats
  loadSavedChats();
  
  // Go to chat page
  showPage('chatPage');
  updateProfileInfo();
  
  // Reset form
  document.getElementById('loginForm').reset();
}

function handleLogout() {
  if (confirm('Are you sure you want to logout?')) {
    currentUser = null;
    localStorage.removeItem('currentUser');
    activeChats = [];
    currentChatId = null;
    messages = {};
    showPage('landingPage');
  }
}

// ============= KEY MODAL =============
function showKeyModal(publicKey, privateKey, fingerprint = null, isReal = false) {
  const displayPublic = document.getElementById('displayPublicKey');
  const displayPrivate = document.getElementById('displayPrivateKey');
  
  displayPublic.value = publicKey;
  displayPrivate.value = privateKey;
  
  // Update modal header if real encryption
  const modalHeader = document.querySelector('.key-gen-modal h2');
  if (isReal) {
    modalHeader.innerHTML = 'RSA-2048 Keys Generated! <i class="fas fa-shield-alt"></i>';
  }
  
  // Show fingerprint if available
  const subtitle = document.querySelector('.key-gen-subtitle');
  if (fingerprint && isReal) {
    subtitle.innerHTML = `Key Fingerprint (SHA-256):<br><code style="font-size: 0.75rem; color: var(--accent-cyan);">${fingerprint.substring(0, 50)}...</code>`;
  }
  
  const modal = document.getElementById('keyModal');
  modal.classList.add('active');
}

function closeKeyModal() {
  const modal = document.getElementById('keyModal');
  modal.classList.remove('active');
  
  // Go to chat page
  showPage('chatPage');
  updateProfileInfo();
}

function copyKey(elementId) {
  const element = document.getElementById(elementId);
  let textToCopy = '';
  
  if (element.tagName === 'INPUT') {
    textToCopy = element.value;
  } else if (element.tagName === 'SPAN') {
    // For sidebar private key, get full version from localStorage
    if (elementId === 'sidebarPrivateKey' && currentUser) {
      textToCopy = localStorage.getItem(`privateKey_${currentUser.username}`) || element.textContent;
    } else if (elementId === 'sidebarPublicKey' && currentUser) {
      textToCopy = currentUser.publicKey;
    } else {
      textToCopy = element.textContent;
    }
  }
  
  if (!textToCopy || textToCopy === 'Not available') {
    alert('⚠️ Private key not available!');
    return;
  }
  
  navigator.clipboard.writeText(textToCopy).then(() => {
    // Show copied feedback
    const btn = event.target.closest('button');
    const originalHTML = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-check"></i> Copied!';
    btn.style.background = 'var(--success)';
    
    setTimeout(() => {
      btn.innerHTML = originalHTML;
      btn.style.background = '';
    }, 2000);
  }).catch(err => {
    alert('Failed to copy: ' + err.message);
  });
}

function downloadPrivateKey() {
  const privateKey = document.getElementById('displayPrivateKey').value;
  
  // Create blob and download
  const blob = new Blob([privateKey], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${currentUser.username}_private_key.pem`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  
  // Show feedback
  const btn = event.target;
  const originalHTML = btn.innerHTML;
  btn.innerHTML = '<i class="fas fa-check"></i> Downloaded!';
  btn.style.background = 'var(--success)';
  
  setTimeout(() => {
    btn.innerHTML = originalHTML;
    btn.style.background = '';
  }, 2000);
}

// ============= CHAT SIDEBAR =============
function updateChatSidebar() {
  if (!currentUser) return;
  
  // Update public key in sidebar
  const publicKeyElement = document.getElementById('sidebarPublicKey');
  if (currentUser.publicKey.startsWith('-----BEGIN')) {
    // For real RSA keys (PEM format), show truncated version
    publicKeyElement.textContent = currentUser.publicKey.substring(27, 60) + '...';
    publicKeyElement.title = 'Click to copy full public key';
  } else {
    publicKeyElement.textContent = currentUser.publicKey;
  }
  
  // Get private key from localStorage (stored separately for security)
  const privateKeyElement = document.getElementById('sidebarPrivateKey');
  const privateKey = localStorage.getItem(`privateKey_${currentUser.username}`);
  
  if (privateKey) {
    // For real RSA keys (PEM format), show truncated version
    if (privateKey.startsWith('-----BEGIN')) {
      privateKeyElement.textContent = privateKey.substring(28, 61) + '...';
      privateKeyElement.title = 'Click to copy full private key';
    } else {
      privateKeyElement.textContent = privateKey;
    }
  } else {
    privateKeyElement.textContent = 'Not available';
    privateKeyElement.title = 'Private key not found in storage';
  }
  
  // Update chat list
  renderChatList();
}

function renderChatList() {
  const chatListDiv = document.getElementById('chatList');
  
  if (activeChats.length === 0) {
    chatListDiv.innerHTML = '<p class="no-chats">No active chats yet</p>';
    return;
  }
  
  chatListDiv.innerHTML = activeChats.map(chat => `
    <div class="chat-item ${currentChatId === chat.id ? 'active' : ''}" onclick="openChat('${chat.id}')">
      <i class="fas fa-user-circle"></i>
      <div class="chat-item-info">
        <h5>${chat.name}</h5>
        <p>${chat.publicKey}</p>
      </div>
    </div>
  `).join('');
}

function startNewChat() {
  const friendKeyInput = document.getElementById('friendPublicKey');
  const friendKey = friendKeyInput.value.trim();
  
  if (!friendKey) {
    alert('Please enter a friend\'s Public ID');
    return;
  }
  
  if (!friendKey.startsWith('PUB-')) {
    alert('Invalid Public ID format! Should start with PUB-');
    return;
  }
  
  if (friendKey === currentUser.publicKey) {
    alert('You cannot chat with yourself!');
    return;
  }
  
  // Check if chat already exists
  const existingChat = activeChats.find(c => c.publicKey === friendKey);
  if (existingChat) {
    openChat(existingChat.id);
    friendKeyInput.value = '';
    return;
  }
  
  // Create new chat
  const chatId = 'chat_' + Date.now();
  const newChat = {
    id: chatId,
    name: 'User ' + friendKey.substring(4),
    publicKey: friendKey,
    createdAt: new Date().toISOString()
  };
  
  activeChats.push(newChat);
  messages[chatId] = [];
  
  // Save to localStorage
  saveChats();
  
  // Open chat
  openChat(chatId);
  
  // Clear input
  friendKeyInput.value = '';
  
  // Update list
  renderChatList();
}

function openChat(chatId) {
  const chat = activeChats.find(c => c.id === chatId);
  if (!chat) return;
  
  currentChatId = chatId;
  
  // Hide no chat message
  document.getElementById('noChatSelected').style.display = 'none';
  
  // Show chat window
  const chatWindow = document.getElementById('chatWindow');
  chatWindow.style.display = 'flex';
  
  // Update chat header
  document.getElementById('chatUsername').textContent = chat.name;
  document.getElementById('chatUserKey').textContent = chat.publicKey;
  
  // Render messages
  renderMessages();
  
  // Update chat list
  renderChatList();
  
  // Focus on input
  document.getElementById('messageInput').focus();
}

function closeChat() {
  currentChatId = null;
  document.getElementById('noChatSelected').style.display = 'flex';
  document.getElementById('chatWindow').style.display = 'none';
}

// ============= MESSAGING =============
async function sendMessage() {
  if (!currentChatId) return;
  
  const input = document.getElementById('messageInput');
  const messageText = input.value.trim();
  
  if (!messageText) return;
  
  const chat = activeChats.find(c => c.id === currentChatId);
  if (!chat) return;
  
  // Show encryption indicator
  const sendBtn = document.querySelector('.message-input-area button');
  sendBtn.disabled = true;
  sendBtn.innerHTML = '<i class="fas fa-lock fa-spin"></i>';
  
  let encryptedData = null;
  let isEncrypted = false;
  
  // Try real E2E encryption if available
  if (window.SecureChatCrypto && currentUser.isRealEncryption) {
    try {
      console.log('🔒 Encrypting message with E2E hybrid encryption...');
      encryptedData = await window.SecureChatCrypto.encryptForRecipient(
        chat.publicKey,
        messageText
      );
      isEncrypted = true;
      console.log('✅ Message encrypted successfully');
    } catch (error) {
      console.error('❌ Encryption failed:', error);
      console.log('⚠️ Sending unencrypted (demo mode)');
    }
  }
  
  const message = {
    id: 'msg_' + Date.now(),
    chatId: currentChatId,
    text: messageText,
    type: 'sent',
    timestamp: new Date().toISOString(),
    isEncrypted: isEncrypted,
    encryptedData: encryptedData,
    encrypted: encryptMessage(messageText) // Fallback display
  };
  
  // Add to messages
  if (!messages[currentChatId]) {
    messages[currentChatId] = [];
  }
  messages[currentChatId].push(message);
  
  // Save
  saveChats();
  
  // Render
  renderMessages();
  
  // Clear input
  input.value = '';
  
  // Reset button
  sendBtn.disabled = false;
  sendBtn.innerHTML = '<i class="fas fa-paper-plane"></i>';
  
  // Simulate typing indicator and response
  simulateTypingAndResponse();
}

function handleMessageKeyPress(event) {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    sendMessage();
  }
}

function renderMessages() {
  if (!currentChatId) return;
  
  const container = document.getElementById('messagesContainer');
  const chatMessages = messages[currentChatId] || [];
  
  if (chatMessages.length === 0) {
    container.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 2rem;">No messages yet. Start the conversation!</p>';
    return;
  }
  
  container.innerHTML = chatMessages.map(msg => {
    const time = new Date(msg.timestamp).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit'
    });
    
    const encryptionBadge = msg.isEncrypted ? 
      '<span class="encryption-badge" title="E2E Encrypted"><i class="fas fa-shield-alt"></i> E2E</span>' : '';
    
    // Check if this is a file message
    if (msg.isFile && msg.fileData) {
      return renderFileMessage(msg, time, encryptionBadge);
    }
    
    // Regular text message
    return `
      <div class="message ${msg.type}">
        <div class="message-bubble">
          <div class="message-text">${msg.text}</div>
          <div class="message-time">${time} ${encryptionBadge}</div>
        </div>
      </div>
    `;
  }).join('');
  
  // Scroll to bottom
  container.scrollTop = container.scrollHeight;
}

function renderFileMessage(msg, time, encryptionBadge) {
  const fileData = msg.fileData;
  const isImage = msg.fileType === 'image' || msg.fileType === 'camera';
  const isVideo = fileData.type.startsWith('video/');
  const isDocument = msg.fileType === 'document';
  
  let fileIcon = 'fa-file';
  if (isImage && !isVideo) fileIcon = 'fa-image';
  else if (isVideo) fileIcon = 'fa-video';
  else if (isDocument) fileIcon = 'fa-file-alt';
  
  let preview = '';
  
  if (isImage && !isVideo) {
    // Image preview
    preview = `
      <div class="file-preview">
        <img src="${fileData.dataUrl}" alt="${fileData.name}" class="file-image" onclick="openImagePreview('${fileData.dataUrl}', '${fileData.name}')">
      </div>
    `;
  } else if (isVideo) {
    // Video preview
    preview = `
      <div class="file-preview">
        <video src="${fileData.dataUrl}" controls class="file-video"></video>
      </div>
    `;
  }
  
  return `
    <div class="message ${msg.type}">
      <div class="message-bubble file-message">
        ${preview}
        <div class="file-info">
          <i class="fas ${fileIcon}"></i>
          <div class="file-details">
            <div class="file-name">${fileData.name}</div>
            <div class="file-size">${fileData.size}</div>
          </div>
          <button class="file-download-btn" onclick="downloadFile('${fileData.dataUrl}', '${fileData.name}')" title="Download">
            <i class="fas fa-download"></i>
          </button>
        </div>
        <div class="message-time">${time} ${encryptionBadge}</div>
      </div>
    </div>
  `;
}

function openImagePreview(dataUrl, fileName) {
  // Create fullscreen image preview
  const modal = document.createElement('div');
  modal.className = 'image-preview-modal';
  modal.innerHTML = `
    <div class="image-preview-content">
      <button class="image-preview-close" onclick="this.parentElement.parentElement.remove()">
        <i class="fas fa-times"></i>
      </button>
      <img src="${dataUrl}" alt="${fileName}">
      <div class="image-preview-info">
        <span>${fileName}</span>
        <button onclick="downloadFile('${dataUrl}', '${fileName}')" class="btn btn-primary btn-sm">
          <i class="fas fa-download"></i> Download
        </button>
      </div>
    </div>
  `;
  
  document.body.appendChild(modal);
  
  // Close on background click
  modal.addEventListener('click', (e) => {
    if (e.target === modal) {
      modal.remove();
    }
  });
}

function downloadFile(dataUrl, fileName) {
  const link = document.createElement('a');
  link.href = dataUrl;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

function encryptMessage(text) {
  // Simulate encryption
  const encrypted = btoa(text).split('').reverse().join('');
  return encrypted.substring(0, 15) + '...';
}

function decryptMessage(encrypted) {
  // Simulate decryption
  return 'Decrypted: ' + encrypted;
}

// ============= SIMULATE RESPONSES =============
function simulateTypingAndResponse() {
  const indicator = document.getElementById('typingIndicator');
  indicator.style.display = 'flex';
  
  setTimeout(() => {
    indicator.style.display = 'none';
    
    // Add automated response
    const responses = [
      'Thanks for your message!',
      'Got it, will check that out.',
      'Sounds good to me!',
      'Sure, let\'s do that.',
      'I agree with you.',
      'That\'s interesting!'
    ];
    
    const randomResponse = responses[Math.floor(Math.random() * responses.length)];
    
    const message = {
      id: 'msg_' + Date.now(),
      chatId: currentChatId,
      text: randomResponse,
      type: 'received',
      timestamp: new Date().toISOString(),
      encrypted: encryptMessage(randomResponse)
    };
    
    messages[currentChatId].push(message);
    saveChats();
    renderMessages();
  }, 2000);
}

// ============= PROFILE =============
function updateProfileInfo() {
  if (!currentUser) return;
  
  document.getElementById('profileUsername').textContent = currentUser.username;
  document.getElementById('profileEmail').textContent = currentUser.email;
  document.getElementById('profilePublicKey').value = currentUser.publicKey;
  
  // Get private key from localStorage (stored separately for security)
  const privateKey = localStorage.getItem(`privateKey_${currentUser.username}`);
  const profilePrivateKeyElement = document.getElementById('profilePrivateKey');
  
  if (profilePrivateKeyElement) {
    if (privateKey) {
      profilePrivateKeyElement.value = privateKey;
    } else {
      profilePrivateKeyElement.value = 'Private key not available (may have been deleted for security)';
    }
  }
  
  // Update sidebar keys as well
  updateChatSidebar();
}

// ============= ENCRYPTION MODAL =============
function showEncryptionModal() {
  const modal = document.getElementById('encryptionModal');
  modal.classList.add('active');
  
  // Animate steps
  const steps = modal.querySelectorAll('.encryption-step');
  steps.forEach((step, index) => {
    setTimeout(() => {
      step.classList.add('active');
    }, index * 1000);
  });
}

function closeEncryptionModal() {
  const modal = document.getElementById('encryptionModal');
  modal.classList.remove('active');
  
  // Reset animations
  const steps = modal.querySelectorAll('.encryption-step');
  steps.forEach(step => {
    step.classList.remove('active');
  });
}

// ============= LOCAL STORAGE =============
function saveChats() {
  if (!currentUser) return;
  
  const chatData = {
    userId: currentUser.publicKey,
    activeChats: activeChats,
    messages: messages
  };
  
  localStorage.setItem('chatData_' + currentUser.publicKey, JSON.stringify(chatData));
}

function loadSavedChats() {
  if (!currentUser) return;
  
  const savedData = localStorage.getItem('chatData_' + currentUser.publicKey);
  if (savedData) {
    const chatData = JSON.parse(savedData);
    activeChats = chatData.activeChats || [];
    messages = chatData.messages || {};
  }
  
  updateChatSidebar();
}

// ============= CLICK OUTSIDE MODAL TO CLOSE =============
window.onclick = function(event) {
  const keyModal = document.getElementById('keyModal');
  const encModal = document.getElementById('encryptionModal');
  
  if (event.target === keyModal) {
    closeKeyModal();
  }
  if (event.target === encModal) {
    closeEncryptionModal();
  }
}

// ============= ATTACHMENT MENU =============
function toggleAttachMenu() {
  const menu = document.getElementById('attachMenu');
  const btn = document.querySelector('.btn-attach');
  
  if (menu.style.display === 'none' || !menu.style.display) {
    menu.style.display = 'block';
    btn.classList.add('active');
  } else {
    menu.style.display = 'none';
    btn.classList.remove('active');
  }
}

function handleAttachment(type) {
  const menu = document.getElementById('attachMenu');
  const btn = document.querySelector('.btn-attach');
  
  // Close menu
  menu.style.display = 'none';
  btn.classList.remove('active');
  
  // Handle different attachment types
  switch(type) {
    case 'photos':
      handlePhotosUpload();
      break;
    case 'camera':
      handleCameraCapture();
      break;
    case 'document':
      handleDocumentUpload();
      break;
    case 'contact':
      handleContactShare();
      break;
    case 'poll':
      handlePollCreation();
      break;
    case 'event':
      handleEventCreation();
      break;
    case 'drawing':
      handleDrawing();
      break;
  }
}

function handlePhotosUpload() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = 'image/*,video/*';
  input.multiple = true;
  
  input.onchange = async (e) => {
    const files = Array.from(e.target.files);
    if (files.length === 0) return;
    
    for (const file of files) {
      // Read file and create preview
      const reader = new FileReader();
      
      reader.onload = (event) => {
        const fileData = {
          name: file.name,
          size: file.size,
          type: file.type,
          dataUrl: event.target.result
        };
        
        // Send as message with preview
        sendFileMessage(fileData, 'image');
      };
      
      reader.readAsDataURL(file);
    }
  };
  
  input.click();
}

function handleCameraCapture() {
  // Open camera capture
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = 'image/*';
  input.capture = 'environment'; // Use camera
  
  input.onchange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      
      reader.onload = (event) => {
        const fileData = {
          name: file.name,
          size: file.size,
          type: file.type,
          dataUrl: event.target.result
        };
        
        sendFileMessage(fileData, 'camera');
      };
      
      reader.readAsDataURL(file);
    }
  };
  
  input.click();
}

function handleDocumentUpload() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.pdf,.doc,.docx,.txt,.xls,.xlsx,.zip,.rar';
  
  input.onchange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      
      reader.onload = (event) => {
        const fileData = {
          name: file.name,
          size: file.size,
          type: file.type,
          dataUrl: event.target.result
        };
        
        sendFileMessage(fileData, 'document');
      };
      
      reader.readAsDataURL(file);
    }
  };
  
  input.click();
}

function handleContactShare() {
  // Demo: Share current user's public key as contact
  if (currentUser) {
    const contactInfo = `Contact: ${currentUser.username}\nPublic ID: ${currentUser.publicKey.substring(0, 30)}...`;
    sendSystemMessage(`👤 ${contactInfo}`);
  }
}

function handlePollCreation() {
  const question = prompt('Enter poll question:');
  if (question) {
    const options = prompt('Enter options (comma-separated):');
    if (options) {
      sendSystemMessage(`📊 Poll: ${question}\nOptions: ${options}`);
    }
  }
}

function handleEventCreation() {
  const eventName = prompt('Enter event name:');
  if (eventName) {
    const eventDate = prompt('Enter date (e.g., Dec 25, 2024):');
    if (eventDate) {
      sendSystemMessage(`📅 Event: ${eventName}\nDate: ${eventDate}`);
    }
  }
}

function handleDrawing() {
  sendSystemMessage('🎨 Drawing feature - Would open drawing canvas');
}

function toggleEmojiPicker() {
  // Quick emoji insertion demo
  const emojis = ['😊', '😂', '❤️', '👍', '🎉', '🔥', '✨', '💯'];
  const emoji = emojis[Math.floor(Math.random() * emojis.length)];
  const input = document.getElementById('messageInput');
  input.value += emoji;
  input.focus();
}

function sendFileMessage(fileData, fileType) {
  if (!currentChatId) {
    alert('Please select a chat first');
    return;
  }
  
  // Format file size
  const sizeKB = (fileData.size / 1024).toFixed(2);
  const sizeMB = (fileData.size / (1024 * 1024)).toFixed(2);
  const sizeText = fileData.size > 1024 * 1024 ? `${sizeMB} MB` : `${sizeKB} KB`;
  
  // Create message with file data
  const message = {
    id: 'msg_' + Date.now(),
    chatId: currentChatId,
    text: fileData.name,
    type: 'sent',
    timestamp: new Date().toISOString(),
    isFile: true,
    fileType: fileType,
    fileData: {
      name: fileData.name,
      size: sizeText,
      type: fileData.type,
      dataUrl: fileData.dataUrl
    }
  };
  
  if (!messages[currentChatId]) {
    messages[currentChatId] = [];
  }
  messages[currentChatId].push(message);
  
  saveChats();
  renderMessages();
  
  // Show success notification
  console.log(`✅ File shared: ${fileData.name} (${sizeText})`);
}

function sendSystemMessage(text) {
  if (!currentChatId) {
    alert('Please select a chat first');
    return;
  }
  
  const message = {
    id: 'msg_' + Date.now(),
    chatId: currentChatId,
    text: text,
    type: 'sent',
    timestamp: new Date().toISOString(),
    isSystem: true
  };
  
  if (!messages[currentChatId]) {
    messages[currentChatId] = [];
  }
  messages[currentChatId].push(message);
  
  saveChats();
  renderMessages();
}

// Close attach menu when clicking outside
document.addEventListener('click', (e) => {
  const menu = document.getElementById('attachMenu');
  const btn = document.querySelector('.btn-attach');
  
  if (menu && btn) {
    if (!menu.contains(e.target) && !btn.contains(e.target)) {
      menu.style.display = 'none';
      btn.classList.remove('active');
    }
  }
});

// ============= INITIAL SETUP =============
console.log('✅ All functions loaded successfully (with attachment features)');
