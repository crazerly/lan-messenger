// '?' is the optional chaining operator: If the object using it is undefined or null, the expression returns undefined instead of throwing an error
// '...' is the spread operator, which expands an interable into its individual elements
// '!!' converts a value to bool by first converting it to the bool opposite and then back again

const socket = io();

// Elements
const contactsList = document.getElementById('contacts-list');
const groupsList = document.getElementById('groups-list');
const messagesElem = document.getElementById('messages');
const chatName = document.getElementById('chat-name');
const chatAvatar = document.getElementById('chat-avatar');
const chatStatus = document.getElementById('chat-status');
const headerRight = document.getElementById('header-right');

const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const attachBtn = document.getElementById('attach-btn');
const fileInput = document.getElementById('file-input');

const searchInput = document.getElementById('search-input');
const createGroupBtn = document.getElementById('group-btn');

const loginOverlay = document.getElementById('login-overlay');
const usernameInput = document.getElementById('username-input');
const passwordInput = document.getElementById('password-input');
const loginBtn = document.getElementById('login-btn');
const registerBtn = document.getElementById('register-btn');

const groupModal = document.getElementById('group-modal');
const groupNameInput = document.getElementById('group-name-input');
const groupMembersList = document.getElementById('group-members-list');
const groupCreateBtn = document.getElementById('create-group-btn');
const groupCancelBtn = document.getElementById('cancel-group-btn');

const profileBtn = document.getElementById('profile-btn');
const profileModal = document.getElementById('profile-modal');
const profileAvatar = document.getElementById('profile-avatar');
const statusInput = document.getElementById('status-input');
const avatarFile = document.getElementById('avatar-file');
const saveProfileBtn = document.getElementById('save-profile-btn');
const closeProfileBtn = document.getElementById('close-profile-btn');

const groupMembersModal = document.getElementById('group-members-modal');
const groupMembersInner = document.getElementById('group-members-inner');
const groupMembersTitle = document.getElementById('group-members-title');
const closeMembersBtn = document.getElementById('close-members-btn');

// Global vars
let CURRENT_USER = null;
let CURRENT_CHAT = null;
let CURRENT_ACTIVE_SIDEBAR = { type: null, id: null };
let contacts = [];
let groups = [];

const enc = new TextEncoder();
const dec = new TextDecoder();

// Helper functions
function createElem(tag, cls) {
  const elem = document.createElement(tag);
  if (cls) elem.className = cls;
  return elem;
}

function formatTimeDigits(n) {
  return n < 10 ? '0' + n : String(n);
}

function formatTime(ms) {
  if (!ms) return '';
  const date = new Date(ms);
  return formatTimeDigits(date.getHours()) + ':' + formatTimeDigits(date.getMinutes());
}

function formatLastSeen(ms) {
  if (!ms) return '-';
  const date = new Date(ms);
  return formatTimeDigits(date.getDate()) + '/' + formatTimeDigits(date.getMonth()+1) + '/' + date.getFullYear() + ' ' + formatTimeDigits(date.getHours()) + ':' + formatTimeDigits(date.getMinutes());
}

function abToBase64(buf) {
    var binary = '';
    var bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToAb(b64) {
  const binary = atob(b64);
  const len = binary.length;
  const arr = new Uint8Array(len);
  for (let i = 0; i < len; i++) arr[i] = binary.charCodeAt(i);
  return arr.buffer;
}

// Dark/Light Theme
function applyTheme(theme) {
  const isDark = theme == 'dark';
  if (isDark) document.body.classList.add('dark-mode');
  else document.body.classList.remove('dark-mode');
  const btn = document.getElementById('theme-toggle-btn');
  if (btn) btn.textContent = isDark ? 'Switch to Light' : 'Switch to Dark';
}

function ensureThemeToggleButton() {
  let btn = document.getElementById('theme-toggle-btn');
  btn.style.marginRight = '8px';
  btn.addEventListener('click', () => {
    const current = localStorage.getItem('theme') || 'dark';
    const next = current == 'dark' ? 'light' : 'dark';
    localStorage.setItem('theme', next);
    applyTheme(next);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  try {
    ensureThemeToggleButton();
    const theme = localStorage.getItem('theme') || 'dark';
    applyTheme(theme);
  }
  catch (e) { console.warn('Theme init failed', e); }
});

// Other functions
async function api(path, opts = {}) {
  const res = await fetch('/api' + path, opts);
  return res.json();
}

function setActiveSidebarItem(type, id) {
  if (type != 'contact' && type != 'group' && type != null) return;
  CURRENT_ACTIVE_SIDEBAR.type = type;
  CURRENT_ACTIVE_SIDEBAR.id = id != null ? id : null;
  renderContacts(searchInput.value);
  renderGroups();
}

function clearActiveSidebar() {
  CURRENT_ACTIVE_SIDEBAR.type = null;
  CURRENT_ACTIVE_SIDEBAR.id = null;
  renderContacts(searchInput.value);
  renderGroups();
}

function createMessageElement(msg) {
  const senderId = msg.sender_id;
  const isMe = CURRENT_USER.id == senderId;
  const row = createElem('div', 'msg-row ' + (isMe ? 'right' : 'left'));
  const sender = createElem('div','msg-sender');
  sender.textContent = isMe ? 'You' : (msg.sender_name || 'Unknown');
  row.appendChild(sender);

  const bubble = createElem('div','bubble ' + (isMe ? 'me' : 'other'));
  let addedMediaElement = false;
  
  const isMediaType = (type) => ['image','video','audio'].includes(type);

  if (isMediaType(msg.type) && msg.media_url) {
    addedMediaElement = true;
    if (msg.type == 'image') {
      const img = createElem('img');
      img.style.maxWidth = '320px';
      img.style.borderRadius = '8px';
      bubble.appendChild(img);
      img.alt = 'Decrypting…';
      decryptMediaAndCreateObjectUrl(msg)
        .then(({ objectUrl, caption }) => {
          img.src = objectUrl;
          if (caption) {
            const captionDiv = createElem('div');
            captionDiv.innerHTML = caption.replace(/\n/g,'<br>');
            bubble.appendChild(captionDiv);
          }
        })
        .catch(e => {
          img.alt = 'Cannot decrypt image';
          console.error('Failed to decrypt image', e);
        });
    }
    else if (msg.type == 'video') {
      const video = createElem('video');
      video.controls = true;
      video.style.maxWidth = '420px';
      bubble.appendChild(video);

      video.textContent = 'Decrypting video…';
      decryptMediaAndCreateObjectUrl(msg)
        .then(({ objectUrl, caption }) => {
          video.src = objectUrl;
          video.textContent = '';
          if (caption) {
            const captionDiv = createElem('div');
            captionDiv.innerHTML = caption.replace(/\n/g,'<br>');
            bubble.appendChild(captionDiv);
          }
        })
        .catch(e => {
          video.textContent = 'Cannot decrypt video';
          console.error('Failed to decrypt video', e);
        });
    }
    else if (msg.type == 'audio') {
      const audio = createElem('audio');
      audio.controls = true;
      bubble.appendChild(audio);

      audio.textContent = 'Decrypting audio…';
      decryptMediaAndCreateObjectUrl(msg)
        .then(({ objectUrl, caption }) => {
          audio.src = objectUrl;
          audio.textContent = '';
          if (caption) {
            const captionDiv = createElem('div');
            captionDiv.innerHTML = caption.replace(/\n/g,'<br>');
            bubble.appendChild(captionDiv);
          }
        })
        .catch(e => {
          audio.textContent = 'Cannot decrypt audio';
          console.error('Failed to decrypt audio', e);
        });
    }
  }
  if (!addedMediaElement) {
    if (msg.type == 'e2ee') {
      bubble.innerHTML = (msg.plaintext || '[Encrypted]').replace(/\n/g,'<br>');
    }
    else bubble.innerHTML = (msg.content || '').replace(/\n/g,'<br>');
  }
  
  row.appendChild(bubble);
  const meta = createElem('div','msg-meta');
  const time = msg.created_at_ms ? formatTime(msg.created_at_ms) : formatTime(new Date().getTime());
  meta.innerHTML = `<span class="time">${time}</span>`;
  row.appendChild(meta);
  return row;
}

async function loadMessages(chatId) {
  messagesElem.innerHTML = '';
  const res = await api(`/chats/${chatId}/messages`);
  const msgs = res.messages || [];
  for (const msg of msgs) {
    if (msg.type == 'e2ee') {
      try { msg.plaintext = await decryptMessageContent(msg.content); }
      catch (e) { msg.plaintext = '[Error: cannot decrypt message]'; }
    }
    messagesElem.appendChild(createMessageElement(msg));
  }
  setTimeout(()=> messagesElem.scrollTop = messagesElem.scrollHeight, 0);
}

function afterLogin() {
  loginOverlay.style.display = 'none';
  socket.emit('register', { userId: CURRENT_USER.id });
  fetchContacts();
  fetchGroups();
}

async function uploadFile(file) {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch('/api/upload', { method:'POST', body: formData });
  return res.json();
}

// E2EE functions
async function generateRSAKeyPair() {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
  return keyPair;
}

// Exports a public key in SPKI format, encoded as Base64
async function exportPublicKeySpki(publicKey) {
  const spki = await crypto.subtle.exportKey('spki', publicKey);
  return abToBase64(spki);
}

// Exports private key in PKCS#8 format, encoded as Base64
async function exportPrivateKeyPkcs8(privateKey) {
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
  return abToBase64(pkcs8);
}

// Converts Base64-encoded SPKI private key to CryptoKey
async function importPublicKeySpki(spkiBase64) {
  const ab = base64ToAb(spkiBase64);
  const key = await crypto.subtle.importKey(
    'spki',
    ab,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['encrypt']
  );
  return key;
}

// Converts Base64-encoded PKCS#8 private key to CryptoKey
async function importPrivateKeyPkcs8(pkcs8Base64) {
  const ab = base64ToAb(pkcs8Base64);
  const key = await crypto.subtle.importKey(
    'pkcs8',
    ab,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['decrypt']
  );
  return key;
}

async function encryptAndUploadFileForMembers(members, file, caption = '') {
  const arrayBuffer = await file.arrayBuffer();

  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encryptedData = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    arrayBuffer
  );

  // Wrap AES key for each member with RSA-OAEP
  const aesRaw = await crypto.subtle.exportKey('raw', aesKey);
  const keys = [];
  for (const m of members) {
    if (!m.public_key) continue;
    try {
      const publicKey = await importPublicKeySpki(m.public_key);
      const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, aesRaw);
      keys.push({ user_id: m.user_id, encrypted_key: abToBase64(wrapped) });
    }
    catch (e) { console.warn('encryptAndUploadFileForMembers: failed to wrap key for ', m.user_id, e); }
  }
  if (keys.length == 0) throw new Error('No recipient public keys available for encryption');

  const blob = new Blob([new Uint8Array(encryptedData)], {
    type: 'application/octet-stream' // binary file
  });
  const formData = new FormData();
  formData.append('file', blob, file.name + '.enc');

  const uploadRes = await fetch('/api/upload', { method: 'POST', body: formData });
  if (!uploadRes.ok) { throw new Error('Failed to upload file'); }
  const uploaded = await uploadRes.json();
  if (!uploaded || !uploaded.url) throw new Error('Upload did not return url');

  const payload = {
    version: 1,
    iv: abToBase64(iv.buffer),
    keys,
    caption: caption || ''
  };

  return { payloadJsonString: JSON.stringify(payload), uploadedUrl: uploaded.url };
}

async function decryptMediaAndCreateObjectUrl(msg) {
  let payload;
  try { payload = typeof msg.content == 'string' ? JSON.parse(msg.content) : msg.content; }
  catch (e) { throw new Error('Invalid encrypted media payload'); }
  if (!payload || !payload.keys || !payload.iv) throw new Error('Invalid encrypted payload format');

  const myId = CURRENT_USER.id;
  if (!myId) throw new Error('No current user');
  const entry = payload.keys.find(key => key.user_id == myId);
  if (!entry) throw new Error('No encrypted key for this user');
  if (!window.E2EE_PRIVATE_KEY) throw new Error('Private key is not in memory');
  
  const encryptedKeyAb = base64ToAb(entry.encrypted_key);
  const aesRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, window.E2EE_PRIVATE_KEY, encryptedKeyAb);
  const aesKey = await crypto.subtle.importKey('raw', aesRaw, { name: 'AES-GCM' }, false, ['decrypt']);

  const resp = await fetch(msg.media_url);
  if (!resp.ok) throw new Error('Failed to fetch encrypted media');
  const encBuf = await resp.arrayBuffer();

  const iv = base64ToAb(payload.iv);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, aesKey, encBuf);

  const mime = getMimeTypeFromFilename(msg.media_url) || 'application/octet-stream';
  const blob = new Blob([new Uint8Array(plainBuf)], { type: mime });
  const objectUrl = URL.createObjectURL(blob);

  return { objectUrl, caption: payload.caption || '' };
}

function getMimeTypeFromFilename(url) {
  try {
    const parts = url.split('?')[0].split('/');
    const name = parts[parts.length - 1] || ''; // Extracts file name from URL
    const ext = name.split('.').pop().toLowerCase(); // Extracts file extension
    if (!ext) return null;
    const map = {
      'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'png': 'image/png', 'gif': 'image/gif',
      'webp': 'image/webp', 'mp4': 'video/mp4', 'webm': 'video/webm', 'ogg': 'audio/ogg', 'mp3': 'audio/mpeg'
    };
    return map[ext] || null;
  }
  catch (e) { return null; }
}

async function sendEncryptedMedia({ chatId, file, type, caption = '' }) {
  if (!CURRENT_USER) throw new Error('Not signed in');
  const res = await api(`/chats/${chatId}/members_public_keys`);
  const members = res.members || [];
  const membersWithKeys = members.filter(m => m.public_key);
  if (membersWithKeys.length == 0) throw new Error('No member public keys available');

  const { payloadJsonString, uploadedUrl } = await encryptAndUploadFileForMembers(membersWithKeys, file, caption);

  socket.emit('send_message', {
    chatId,
    senderId: CURRENT_USER.id,
    content: payloadJsonString,
    media_url: uploadedUrl,
    type
  }, () => {});
}

async function deriveKeyFromPassword(password, salt, usages = ['encrypt','decrypt']) {
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: 150000,
      hash: 'SHA-256'
    },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
  return key;
}

async function encryptAndStorePrivateKey(pkcs8Base64, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const symKey = await deriveKeyFromPassword(password, salt, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    symKey,
    base64ToAb(pkcs8Base64)
  );
  const payload = {
    salt: abToBase64(salt.buffer),
    iv: abToBase64(iv.buffer),
    ciphertext: abToBase64(ciphertext)
  };
  localStorage.setItem('e2ee_private', JSON.stringify(payload));
}

async function loadPrivateKeyFromStorage(password) {
  const raw = localStorage.getItem('e2ee_private');
  if (!raw) return null;
  const payload = JSON.parse(raw);
  const salt = base64ToAb(payload.salt);
  const iv = base64ToAb(payload.iv);
  const cipher = base64ToAb(payload.ciphertext);
  const symKey = await deriveKeyFromPassword(password, new Uint8Array(salt), ['decrypt']);
  try {
    const pkcs8ab = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, symKey, cipher);
    const pkcs8b64 = abToBase64(pkcs8ab);
    const privateKey = await importPrivateKeyPkcs8(pkcs8b64);
    window.E2EE_PRIVATE_KEY = privateKey; // Avoids reprompting for password
    return privateKey;
  }
  catch (e) {
    console.error('Failed to decrypt private key: ', e);
    throw new Error('Invalid password or corrupted key material');
  }
}

async function encryptMessageForMembers(members, plaintext) {
  // Generate an ephemeral AES-GCM key
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ptBuf = enc.encode(plaintext);
  const ciphertextBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, ptBuf);
  const exportedAesRaw = await crypto.subtle.exportKey('raw', aesKey);

  // Import each member's public key and encrypt the AES key for them
  const keys = [];
  for (const m of members) {
    if (!m.public_key) continue;
    try {
      const publicKey = await importPublicKeySpki(m.public_key);
      const encryptedAes = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, exportedAesRaw);
      keys.push({
        user_id: m.user_id,
        encrypted_key: abToBase64(encryptedAes)
      });
    }
    catch (e) { console.warn('Failed to encrypt AES key for member ', m.user_id, e); }
  }

  const payload = {
    version: 1,
    iv: abToBase64(iv.buffer),
    ciphertext: abToBase64(ciphertextBuf),
    keys
  };
  return JSON.stringify(payload);
}

async function decryptMessageContent(contentString) {
  let payload;
  try { payload = JSON.parse(contentString); } 
  catch (e) { throw new Error('Payload is not encrypted'); }
  if (!payload || !payload.keys || !payload.ciphertext || !payload.iv) { throw new Error('Invalid encrypted payload format'); }
  
  const myId = CURRENT_USER.id;
  if (!myId) throw new Error('No current user');
  const entry = payload.keys.find(key => key.user_id == myId);
  if (!entry) throw new Error('User does not have encrypted key');
  if (!window.E2EE_PRIVATE_KEY) { throw new Error('Private key not loaded in memory (user must decrypt it on login)'); }

  const encryptedKeyAb = base64ToAb(entry.encrypted_key);
  const aesRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, window.E2EE_PRIVATE_KEY, encryptedKeyAb);

  // Import AES key and decrypt ciphertext
  const aesKey = await crypto.subtle.importKey('raw', aesRaw, { name: 'AES-GCM' }, false, ['decrypt']);
  const iv = base64ToAb(payload.iv);
  const cipher = base64ToAb(payload.ciphertext);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, aesKey, cipher);
  return dec.decode(plainBuf); // Converts bytes to UTF-8 string
}

// Contacts
async function findOrCreateChat(otherId) {
  const res = await api('/chats/find_or_create', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ userId: CURRENT_USER.id, otherId })
  });
  return res.chat;
}

function clearUnreadForContact(contactId) {
  const contact = contacts.find(contact => contact.id == contactId);
  if (contact) {
    contact.unread = false;
    if (contact.status == 'New message') contact.status = '';
  }
}

function renderContacts(filter = '') {
  const query = (filter || '').trim().toLowerCase();
  contactsList.innerHTML = '';
  // Query gets substring instead of first chars to query for last names, etc.
  const shown = contacts.filter(contact => !query || (contact.username || '').toLowerCase().includes(query));
  shown.forEach(contact => {
    const item = createElem('div', 'contact');
    item.dataset.id = contact.id;
    
    const avatar = createElem('div', 'avatar');
    if (contact.profile_pic) {
      avatar.style.backgroundImage = `url(${contact.profile_pic})`; 
      avatar.style.backgroundSize = 'cover';
      avatar.textContent = '';
    }
    else avatar.textContent = (contact.username && contact.username[0]) ? contact.username[0].toUpperCase() : 'U';
    item.appendChild(avatar);

    const meta = createElem('div', 'meta');
    let extraStatus = '';
    if (contact.status && String(contact.status).trim().length) extraStatus = contact.status;
    const presence = contact.online ? 'Online' : ('Last seen: ' + (contact.last_seen_ms ? formatLastSeen(contact.last_seen_ms) : '-'));
    meta.innerHTML = `<div class="name">${contact.username || 'User'}${extraStatus ? `<span class="inline-status"> — ${extraStatus}</span>` : ''}</div><div class="sub">${presence}</div>`;
    item.appendChild(meta);

    item.addEventListener('click', () => {
      openChatWith(contact.id);
    });

    if (CURRENT_ACTIVE_SIDEBAR.type == 'contact' && CURRENT_ACTIVE_SIDEBAR.id == contact.id) { item.classList.add('active'); }
    else { item.classList.remove('active'); }

    if (contact.unread) {
      const badge = createElem('div', 'unread-badge');
      badge.textContent = 'New';
      item.appendChild(badge);
    }
    else {
      const existing = item.querySelector('.unread-badge');
      if (existing) existing.remove();
    }

    contactsList.appendChild(item);
  });
}

async function fetchContacts() {
  if (!CURRENT_USER) return;
  const res = await api('/contacts?exclude=' + (CURRENT_USER.id || 0));
  contacts = (res.contacts || []).map(contact => ({ ...contact, online: !!contact.online }));
  renderContacts(searchInput.value);
}

async function openChatWith(otherId) {
  setActiveSidebarItem('contact', otherId); 
  clearUnreadForContact(otherId);
  renderContacts(searchInput.value);
  const chat = await findOrCreateChat(otherId);
  CURRENT_CHAT = chat;
  headerRight.innerHTML = '';
  const other = contacts.find(contact => contact.id == otherId) || {};

  chatName.innerHTML = `${other.username || 'Chat'}${other.status ? `<span class="inline-status"> — ${other.status}</span>` : ''}`;
  chatAvatar.textContent = (other.username?.[0] || '#').toUpperCase();
  chatStatus.textContent = other.online ? 'Online' : ('Last seen: ' + (other.last_seen_ms ? formatLastSeen(other.last_seen_ms) : '-'));
  socket.emit('join_chat', { chatId: chat.id });
  await loadMessages(chat.id);
}

// Groups
function renderGroups() {
  groupsList.innerHTML = '';
  const seen = new Set();
  const dedup = [];
  groups.forEach(group => {
    if (!seen.has(String(group.id))) {
      seen.add(String(group.id));
      dedup.push(group);
    }
  });
  groups = dedup;
  groups.forEach(group => {
    const item = createElem('div', 'contact');
    item.dataset.id = group.id;
    const avatar = createElem('div', 'avatar');
    avatar.textContent = (group.name && group.name[0]) ? group.name[0].toUpperCase() : '#';
    item.appendChild(avatar);
    const meta = createElem('div', 'meta');
    meta.innerHTML = `<div class="name">${group.name || 'Group'}</div><div class="sub">Group chat</div>`;
    item.appendChild(meta);
    item.addEventListener('click', () => {
      openGroupChat(group.id, group.name);
    });

    if (CURRENT_ACTIVE_SIDEBAR.type == 'group' && CURRENT_ACTIVE_SIDEBAR.id == group.id) {
      item.classList.add('active');
    }
    else { item.classList.remove('active'); }

    if (group.unread) {
      const badge = createElem('div', 'unread-badge');
      badge.textContent = 'New';
      item.appendChild(badge);
    }
    else {
      const existing = item.querySelector('.unread-badge');
      if (existing) existing.remove();
    }

    groupsList.appendChild(item);
  });
}

async function fetchGroups() {
  if (!CURRENT_USER) return;
  const res = await api('/groups?userId=' + CURRENT_USER.id);
  groups = (res.groups || []).map(group => ({ ...group, creator_id: group.creator_id ? group.creator_id : null }));
  renderGroups();
}

async function openGroupChat(chatId, name) {
  setActiveSidebarItem('group', chatId);
  clearUnreadForChat(chatId); 
  CURRENT_CHAT = { id: chatId, name, is_group: 1 };
  chatName.textContent = name || 'Group';
  chatAvatar.textContent = (name?.[0] || '#').toUpperCase();
  chatStatus.textContent = 'Group chat';
  socket.emit('join_chat', { chatId });
  createHeaderForChat();
  renderGroups();
  await loadMessages(chatId);
}

function createHeaderForChat() {
  headerRight.innerHTML = '';
  if (CURRENT_CHAT && CURRENT_CHAT.is_group) {
    const membersBtn = createElem('button');
    membersBtn.textContent = 'Members';
    membersBtn.style.padding = '6px';
    membersBtn.style.borderRadius = '8px';
    membersBtn.style.background = 'var(--accent)';
    membersBtn.style.color = 'white';
    membersBtn.style.cursor = 'pointer';
    membersBtn.addEventListener('click', () => openGroupMembers(CURRENT_CHAT.id));
    headerRight.appendChild(membersBtn);
  }
}

async function openGroupMembers(chatId) {
  groupMembersInner.innerHTML = '';
  const res = await api(`/chats/${chatId}/members`);
  const members = res.members || [];
  groupMembersTitle.textContent = 'Members';

  // Find creator id from group list
  const chatObj = groups.find(group => group.id == chatId);
  const creatorId = chatObj ? chatObj.creator_id : null;

  // Build member rows
  members.forEach(member => {
    const row = createElem('div');
    row.style.display = 'flex';
    row.style.alignItems = 'center';
    row.style.justifyContent = 'space-between';
    row.style.gap = '8px';
    row.style.marginBottom = '6px';

    const left = createElem('div');
    left.style.display = 'flex';
    left.style.alignItems = 'center';
    left.style.gap='8px';
    const avatar = createElem('div','avatar');

    if (member.profile_pic) {
      avatar.style.backgroundImage = `url(${member.profile_pic})`;
      avatar.style.backgroundSize = 'cover';
      avatar.textContent = '';
      avatar.style.width = '36px';
      avatar.style.height = '36px';
      avatar.style.borderRadius = '6px';
    }
    else {
      avatar.textContent = (member.username && member.username[0]) ? member.username[0].toUpperCase() : 'U';
      avatar.style.width = '36px';
      avatar.style.height = '36px';
      avatar.style.borderRadius = '6px';
    }

    left.appendChild(avatar);
    const nameBlock = createElem('div');
    const nameElem = createElem('div');
    nameElem.textContent = member.username;
    const statusElem = createElem('div');
    statusElem.style.fontSize = '12px';
    statusElem.style.color = 'var(--muted)';
    if (member.status && String(member.status).trim().length) statusElem.textContent = member.status;
    else statusElem.textContent = member.last_seen_ms ? `Last seen: ${formatLastSeen(member.last_seen_ms)}` : 'Last seen: -';
    nameBlock.appendChild(nameElem);
    nameBlock.appendChild(statusElem);
    left.appendChild(nameBlock);
    row.appendChild(left);

    const right = createElem('div');

    // Leave group
    if (member.id == CURRENT_USER.id) {
      const leaveBtn = createElem('button');
      leaveBtn.textContent = 'Leave';
      leaveBtn.style.background = '#ef4444';
      leaveBtn.style.color = 'white';
      leaveBtn.style.border = 'none';
      leaveBtn.style.padding = '6px 8px';
      leaveBtn.style.borderRadius = '6px';
      leaveBtn.addEventListener('click', async () => {
        if (!confirm('Leave this group?')) return;
        const res = await api(`/chats/${chatId}/leave`, {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ userId: CURRENT_USER.id })
        });
        if (res.ok) {
          groupMembersModal.style.display = 'none';
          if (CURRENT_CHAT && CURRENT_CHAT.id == chatId) {
            CURRENT_CHAT = null;
            chatAvatar.textContent = "#";
            messagesElem.innerHTML = '';
            chatName.textContent = 'Select a contact';
            chatStatus.textContent = 'Offline';
            headerRight.innerHTML = '';
          }
          await fetchGroups();
        }
        else {
          alert(res.error || 'Leave failed');
        }
      });
      right.appendChild(leaveBtn);
    }

    // If user is creator, allow them to kick member
    else {
      if (creatorId && creatorId == CURRENT_USER.id) {
        const kickBtn = createElem('button');
        kickBtn.textContent = 'Kick';
        kickBtn.style.background = '#ef4444';
        kickBtn.style.color = 'white';
        kickBtn.style.border = 'none';
        kickBtn.style.padding = '6px 8px';
        kickBtn.style.borderRadius = '6px';
        kickBtn.addEventListener('click', async () => {
          if (!confirm(`Kick ${member.username}?`)) return;
          const res = await api(`/chats/${chatId}/kick`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ userId: CURRENT_USER.id, targetId: member.id })
          });
          if (res.ok) {
            await fetchGroups();
            await openGroupMembers(chatId);
          }
          else alert(res.error || 'Kick failed');
        });
        right.appendChild(kickBtn);
      }
    }

    row.appendChild(right);
    groupMembersInner.appendChild(row);
  });

  // Show "Add members" area if user is creator
  if (chatObj && chatObj.creator_id == CURRENT_USER.id) {
    const sep = createElem('div');
    sep.style.marginTop = '8px';
    sep.style.marginBottom = '8px';
    sep.innerHTML = '<strong>Add members</strong>';
    groupMembersInner.appendChild(sep);

    const notInGroup = contacts.filter(contact => !members.find(member => member.id == contact.id) && contact.id != CURRENT_USER.id);
    const addContainer = createElem('div');
    addContainer.style.maxHeight = '160px';
    addContainer.style.overflow = 'auto';
    notInGroup.forEach(contact => {
      const row = createElem('div');
      row.style.display = 'flex';
      row.style.alignItems = 'center';
      row.style.gap = '8px';
      row.style.marginBottom = '6px';

      const checkbox = createElem('input');
      checkbox.type = 'checkbox';
      checkbox.value = contact.id;
      checkbox.id = 'add_cb_' + contact.id;

      const label = createElem('label');
      label.htmlFor = checkbox.id; 
      label.textContent = contact.username;
      row.appendChild(checkbox);
      row.appendChild(label);
      addContainer.appendChild(row);
    });
    groupMembersInner.appendChild(addContainer);

    const addBtnRow = createElem('div');
    addBtnRow.style.display = 'flex'; 
    addBtnRow.style.justifyContent = 'flex-end';
    addBtnRow.style.marginTop = '8px';
    const addBtn = createElem('button');
    addBtn.textContent = 'Add selected';
    addBtn.style.background = '#10b981';
    addBtn.style.color = 'white';
    addBtn.style.border = 'none';
    addBtn.style.padding = '6px 8px';
    addBtn.style.borderRadius = '6px';
    addBtn.addEventListener('click', async () => {
      const checked = Array.from(groupMembersInner.querySelectorAll('input[type=checkbox]:checked')).map(i => i.value);
      if (!checked.length) return alert('Select at least one user to add');
      const res = await api(`/chats/${chatId}/add_members`, {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ memberIds: checked })
      });
      if (res.ok) {
        alert('Members added');
        await fetchGroups();
        await openGroupMembers(chatId);
      }
      else alert(res.error || 'Failed to add members');
    });
    addBtnRow.appendChild(addBtn);
    groupMembersInner.appendChild(addBtnRow);
  }

  groupMembersModal.style.display = 'flex';
}

function clearUnreadForChat(chatId) {
  const group = groups.find(group => group.id == chatId);
  if (group) group.unread = false;
}

// Button functions
sendBtn.addEventListener('click', async () => {
  if (!CURRENT_USER) return alert('Sign in first.');
  if (!CURRENT_CHAT) return alert('Open a chat first.');
  const text = messageInput.value.trim();
  if (!text) return;
  try {
    const res = await api(`/chats/${CURRENT_CHAT.id}/members_public_keys`);
    const members = res.members || [];
    const membersWithKeys = members.filter(m => m.public_key);
    if (membersWithKeys.length == 0) return alert('No member public keys available. Cannot send encrypted message.');

    const encryptedContent = await encryptMessageForMembers(membersWithKeys, text);

    socket.emit('send_message', {
      chatId: CURRENT_CHAT.id,
      senderId: CURRENT_USER.id, 
      content: encryptedContent, 
      type: 'e2ee'
    }, () => {});
    messageInput.value = '';
  }
  catch (e) {
    console.error('Encryption/send failed', e);
    alert('Failed to encrypt/send message: ' + e.message);
  }
});
messageInput.addEventListener('keydown', e => { if (e.key == 'Enter') sendBtn.click(); });
attachBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (!CURRENT_USER || !CURRENT_CHAT) return alert('Sign in and open a chat first.');
  try {
    let msgType = 'image';
    if (file.type.startsWith('video/')) msgType = 'video';
    else if (file.type.startsWith('audio/')) msgType = 'audio';
    await sendEncryptedMedia({ chatId: CURRENT_CHAT.id, file: file, type: msgType, caption: '' });
  }
  catch (err) {
    console.error('sendEncryptedMedia failed', err);
    alert('Upload failed: ' + (err.message || err));
  }
  fileInput.value = '';
});

searchInput.addEventListener('input', () => {
  renderContacts(searchInput.value);
  renderGroups();
});
profileBtn.addEventListener('click', () => {
  if (!CURRENT_USER) return alert('Sign in first.');
  profileAvatar.textContent = (CURRENT_USER.username?.[0] || 'X').toUpperCase();
  if (CURRENT_USER.profile_pic) {
    profileAvatar.style.backgroundImage = `url(${CURRENT_USER.profile_pic})`;
    profileAvatar.style.backgroundSize = 'cover';
    profileAvatar.textContent = '';
  }
  else profileAvatar.style.backgroundImage = '';
  statusInput.value = CURRENT_USER.status || '';
  profileModal.style.display = 'flex';
});

closeProfileBtn.addEventListener('click', () => profileModal.style.display = 'none');
saveProfileBtn.addEventListener('click', async () => {
  if (!CURRENT_USER) return;
  if (avatarFile.files && avatarFile.files[0]) {
    const formData = new FormData();
    formData.append('avatar', avatarFile.files[0]);
    const res = await fetch(`/api/users/${CURRENT_USER.id}/avatar`, { method:'POST', body: formData });
    const avatar_update = await res.json();
    if (avatar_update.user) CURRENT_USER = avatar_update.user;
  }
  const status_update = await api(`/users/${CURRENT_USER.id}/status`, {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ status: statusInput.value.trim() })
  });
  if (status_update.user) CURRENT_USER = status_update.user;
  await fetchContacts();
  profileModal.style.display = 'none';
});

registerBtn.addEventListener('click', async () => {
  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();
  if (!username || !password) return alert('Username & password required.');
  const registerRes = await api('/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  if (!registerRes.user) {
    return alert(registerRes.error || 'Register failed.');
  }

  CURRENT_USER = registerRes.user;

  const kp = await generateRSAKeyPair();
  const pubB64 = await exportPublicKeySpki(kp.publicKey);
  const privPkcs8B64 = await exportPrivateKeyPkcs8(kp.privateKey);

  await encryptAndStorePrivateKey(privPkcs8B64, password);
  window.E2EE_PRIVATE_KEY = kp.privateKey;

  await api(`/users/${CURRENT_USER.id}/public_key`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey: pubB64 })
  });
  afterLogin();
});
loginBtn.addEventListener('click', async () => {
  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();
  if (!username || !password) return alert('Username & password required.');
  const res = await api('/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username, password }) });
  if (res.user) {
    try {
      await loadPrivateKeyFromStorage(password);
      CURRENT_USER = res.user;
      afterLogin();
    }
    catch (e) { alert('Logged in but failed to load private key: ' + e.message); }
  }
  else alert(res.error || 'Login failed.');
});

closeMembersBtn.addEventListener('click', () => groupMembersModal.style.display = 'none');
createGroupBtn.addEventListener('click', async () => {
  groupMembersList.innerHTML = '';
  contacts.forEach(contact => {
    const row = createElem('div');
    row.style.display='flex';
    row.style.alignItems='center';
    row.style.gap='8px';
    
    const checkbox = createElem('input');
    checkbox.type='checkbox';
    checkbox.value = contact.id;
    checkbox.id = 'gcb_' + contact.id;
    
    const label = createElem('label');
    label.htmlFor = checkbox.id;
    label.textContent = contact.username;
    
    row.appendChild(checkbox);
    row.appendChild(label);
    groupMembersList.appendChild(row);
  });
  groupModal.style.display = 'flex';
});
groupCancelBtn.addEventListener('click', () => {
  groupNameInput.value = '';
  groupModal.style.display = 'none'; 
});
groupCreateBtn.addEventListener('click', async () => {
  const name = groupNameInput.value.trim();
  if (!name) return alert('Enter group name');
  const checked = Array.from(groupMembersList.querySelectorAll('input[type=checkbox]:checked')).map(i => i.value);
  if (!checked.length) return alert('Select at least one member');
  const res = await api('/groups', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ name, memberIds: checked, creatorId: CURRENT_USER.id })});
  if (res.chat) {
    await fetchGroups();
    groupModal.style.display = 'none';
    groupNameInput.value = '';
    alert('Group created');
  }
  else alert(res.error || 'Failed to create group.');
});

// Server requests
socket.on('receive_message', async (msg) => {
  if (msg.type == 'e2ee') {
    try { msg.plaintext = await decryptMessageContent(msg.content); }
    catch (e) {
      console.warn('Could not decrypt message', e);
      msg.plaintext = '[Encrypted message — cannot decrypt]';
    }
  }

  if (CURRENT_CHAT && msg.chat_id == CURRENT_CHAT.id) {
    messagesElem.appendChild(createMessageElement(msg));
    messagesElem.scrollTop = messagesElem.scrollHeight;
    return;
  }

  const group = groups.find(g => g.id == msg.chat_id);
  if (group) {
    group.unread = true;
    renderGroups();
  }
  else {
    const contact = contacts.find(contact => contact.id == msg.sender_id);
    if (contact) {
      contact.unread = true;
      renderContacts(searchInput.value);
    }
  }
});

socket.on('new_user', (user) => {
  if (!user) return;
  if (user.id == CURRENT_USER.id) return;
  if (!contacts.find(contact => contact.id == user.id)) {
    contacts.push({ ...user, online: false });
    renderContacts(searchInput.value);
  }
});

socket.on('user_status', (payload) => {
  if (!payload) return;
  const idx = contacts.findIndex(contact => contact.id == payload.id);
  if (idx >= 0) {
    contacts[idx].online = payload.online;
    contacts[idx].last_seen_ms = payload.last_seen_ms || contacts[idx].last_seen_ms;
    renderContacts(searchInput.value);
  }
  else if (payload.id != CURRENT_USER?.id) {
    contacts.push({ id: payload.id, username: payload.username || 'User', online: payload.online, last_seen_ms: payload.last_seen_ms || null });
    renderContacts(searchInput.value);
  }
});

socket.on('user_updated', (user) => {
  if (!user) return;
  if (user.id == CURRENT_USER.id) CURRENT_USER = user;
  const idx = contacts.findIndex(contact => contact.id == user.id);
  if (idx >= 0) {
    contacts[idx] = { ...contacts[idx], ...user };
    renderContacts(searchInput.value);
  }
});

socket.on('group_created', (chat) => {
  if (!chat) return;
  if (!groups.find(group => group.id == chat.id)) {
    groups.unshift({ ...chat, creator_id: chat.creator_id ? chat.creator_id : null });
    renderGroups();
  }
  else fetchGroups();
});

socket.on('chat_updated', async (payload) => {
  await fetchGroups();
  if (CURRENT_CHAT && payload && payload.chat && payload.chat.id == CURRENT_CHAT.id) {
    createHeaderForChat();
  }
});

socket.on('chat_deleted', payload => {
  if (!payload || !payload.chatId) return;
  const chatId = payload.chatId;
  groups = groups.filter(group => group.id) != chatId;
  renderGroups();
  if (CURRENT_CHAT && CURRENT_CHAT.id == chatId) {
    CURRENT_CHAT = null;
    messagesElem.innerHTML = '';
    chatName.textContent = 'Select a contact';
    chatStatus.textContent = 'Offline';
    headerRight.innerHTML = '';
    alert('This group was removed because it has no members left.');
  }
});

socket.on('removed_from_chat', async (data) => {
  try {
    const chatId = data.chatId;
    console.info('Removed from chat', chatId, data);
    const name = data.chat_name || 'a group';
    alert(`You were removed from "${name}".`);
    // Clear the UI if user was kicked from currently opened chat
    if (CURRENT_CHAT && CURRENT_CHAT.id == chatId) {
      CURRENT_CHAT = null;
      chatAvatar.textContent = "#";
      messagesElem.innerHTML = '';
      chatName.textContent = 'Select a contact';
      chatStatus.textContent = 'Offline';
      headerRight.innerHTML = '';
    }

    if (typeof fetchGroups == 'function') await fetchGroups();
  }
  catch (e) { console.error('Error handling removed_from_chat', e); }
});

socket.on('added_to_chat', async (data) => {
  try {
    const chat = data.chat;
    if (!chat || !chat.id) return;

    // Avoid duplicate entries
    if (!groups.find(g => g.id == chat.id)) groups.push(chat);
    else groups = groups.map(g => g.id == chat.id ? chat : g);
    renderGroups();
  }
  catch (e) { console.error('Error handling added_to_chat', e); }
});



usernameInput.focus();
