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

let CURRENT_USER = null;
let CURRENT_CHAT = null;
let CURRENT_ACTIVE_SIDEBAR = { type: null, id: null };
let contacts = [];
let groups = [];

// Helper functions
function createElem(tag, cls) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  return e;
}

function formatTimeDigits(n) {
  return n < 10 ? '0' + n : String(n);
}

function formatTime(ms) {
  if (!ms) return '';
  const date = new Date(Number(ms));
  return formatTimeDigits(date.getHours()) + ':' + formatTimeDigits(date.getMinutes());
}

function formatLastSeen(ms) {
  if (!ms) return '-';
  const date = new Date(Number(ms));
  return formatTimeDigits(date.getDate()) + '/' + formatTimeDigits(date.getMonth()+1) + '/' + date.getFullYear() + ' ' + formatTimeDigits(date.getHours()) + ':' + formatTimeDigits(date.getMinutes());
}

async function api(path, opts = {}) {
  const res = await fetch('/api' + path, opts);
  return res.json();
}

function setActiveSidebarItem(type, id) {
  if (type != 'contact' && type != 'group' && type != null) return;
  CURRENT_ACTIVE_SIDEBAR.type = type;
  CURRENT_ACTIVE_SIDEBAR.id = id != null ? Number(id) : null;
  renderContacts(searchInput.value);
  renderGroups();
}

function clearActiveSidebar() {
  CURRENT_ACTIVE_SIDEBAR.type = null;
  CURRENT_ACTIVE_SIDEBAR.id = null;
  renderContacts(searchInput.value);
  renderGroups();
}

function clearUnreadForContact(contactId) {
  const contact = contacts.find(contact => Number(contact.id) == Number(contactId));
  if (contact) {
    contact.unread = false;
    if (contact.status == 'New message') contact.status = '';
  }
}

function clearUnreadForChat(chatId) {
  const group = groups.find(group => Number(group.id) == Number(chatId));
  if (group) group.unread = false;
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

    if (CURRENT_ACTIVE_SIDEBAR.type == 'contact' && Number(CURRENT_ACTIVE_SIDEBAR.id) == Number(contact.id)) { item.classList.add('active'); }
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

    if (CURRENT_ACTIVE_SIDEBAR.type == 'group' && Number(CURRENT_ACTIVE_SIDEBAR.id) == Number(group.id)) { item.classList.add('active'); }
    else { item.classList.remove('active'); }

    groupsList.appendChild(item);
  });
}

async function fetchContacts() {
  if (!CURRENT_USER) return;
  const res = await api('/contacts?exclude=' + (CURRENT_USER.id || 0));
  contacts = (res.contacts || []).map(contact => ({ ...contact, online: !!contact.online }));
  renderContacts(searchInput.value);
}

async function fetchGroups() {
  if (!CURRENT_USER) return;
  const res = await api('/groups?userId=' + CURRENT_USER.id);
  groups = (res.groups || []).map(group => ({ ...group, creator_id: group.creator_id ? Number(group.creator_id) : null }));
  renderGroups();
}

function createMessageElement(msg) {
  const senderId = Number(msg.sender_id);
  const isMe = CURRENT_USER && Number(CURRENT_USER.id) == senderId;
  const row = createElem('div', 'msg-row ' + (isMe ? 'right' : 'left'));
  const sender = createElem('div','msg-sender');
  sender.textContent = isMe ? 'You' : (msg.sender_name || 'Unknown');
  row.appendChild(sender);

  const bubble = createElem('div','bubble ' + (isMe ? 'me' : 'other'));
  if (msg.type == 'image' && msg.media_url) {
    const img = createElem('img');
    img.src = msg.media_url;
    img.style.maxWidth = '320px';
    img.style.borderRadius = '8px';
    bubble.appendChild(img);
    if (msg.content) bubble.appendChild(createElem('div')).innerHTML = msg.content.replace(/\n/g,'<br>');
  }
  else if (msg.type == 'video' && msg.media_url) {
    const video = createElem('video');
    video.controls = true
    video.src = msg.media_url;
    video.style.maxWidth = '420px';
    bubble.appendChild(video);
    if (msg.content) bubble.appendChild(createElem('div')).innerHTML = msg.content.replace(/\n/g,'<br>');
  }
  else if (msg.type == 'audio' && msg.media_url) {
    const audio = createElem('audio');
    audio.controls = true;
    audio.src = msg.media_url;
    bubble.appendChild(audio);
    if (msg.content) bubble.appendChild(createElem('div')).innerHTML = msg.content.replace(/\n/g,'<br>');
  }
  else {
    bubble.innerHTML = (msg.content || '').replace(/\n/g,'<br>');
  }
  row.appendChild(bubble);
  const meta = createElem('div','msg-meta');
  const time = msg.created_at_ms ? formatTime(msg.created_at_ms) : formatTime(new Date().getTime());
  meta.innerHTML = `<span class="time">${time}</span>`;
  row.appendChild(meta);
  return row;
}

async function findOrCreateChat(otherId) {
  const res = await api('/chats/find_or_create', {
    method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ userId: CURRENT_USER.id, otherId })
  });
  return res.chat;
}

async function loadMessages(chatId) {
  messagesElem.innerHTML = '';
  const res = await api(`/chats/${chatId}/messages`);
  (res.messages || []).forEach(msg => messagesElem.appendChild(createMessageElement(msg)));
  setTimeout(()=> messagesElem.scrollTop = messagesElem.scrollHeight, 0);
}

async function openChatWith(otherId) {
  setActiveSidebarItem('contact', otherId);
  clearUnreadForContact(otherId); 
  const chat = await findOrCreateChat(otherId);
  CURRENT_CHAT = chat;
  headerRight.innerHTML = '';
  const other = contacts.find(contact => Number(contact.id) == Number(otherId)) || {};

  chatName.innerHTML = `${other.username || 'Chat'}${other.status ? `<span class="inline-status"> — ${other.status}</span>` : ''}`;
  chatAvatar.textContent = (other.username?.[0] || 'U').toUpperCase();
  chatStatus.textContent = other.online ? 'Online' : ('Last seen: ' + (other.last_seen_ms ? formatLastSeen(other.last_seen_ms) : '-'));
  socket.emit('join_chat', { chatId: chat.id });
  await loadMessages(chat.id);
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
  const chatObj = groups.find(group => Number(group.id) == Number(chatId));
  const creatorId = chatObj ? Number(chatObj.creator_id) : null;

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
    if (Number(member.id) == Number(CURRENT_USER.id)) {
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
          if (CURRENT_CHAT && Number(CURRENT_CHAT.id) == Number(chatId)) {
            CURRENT_CHAT = null;
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
      if (creatorId && Number(creatorId) == Number(CURRENT_USER.id)) {
        const kickBtn = createElem('button');
        kickBtn.textContent = 'Kick';
        kickBtn.style.background = '#ef4444';
        kickBtn.style.color='white';
        kickBtn.style.border='none';
        kickBtn.style.padding='6px 8px';
        kickBtn.style.borderRadius='6px';
        kickBtn.addEventListener('click', async () => {
          if (!confirm(`Kick ${member.username}?`)) return;
          const res = await api(`/chats/${chatId}/kick`, {
            method: 'POST', headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ userId: CURRENT_USER.id, targetId: member.id })
          });
          if (res.ok) {
            await fetchGroups();
            await openGroupMembers(chatId);
          } else alert(res.error || 'Kick failed');
        });
        right.appendChild(kickBtn);
      }
    }

    row.appendChild(right);
    groupMembersInner.appendChild(row);
  });

  // Show "Add members" area if user is creator
  if (chatObj && Number(chatObj.creator_id) == Number(CURRENT_USER.id)) {
    const sep = createElem('div');
    sep.style.marginTop = '8px';
    sep.style.marginBottom = '8px';
    sep.innerHTML = '<strong>Add members</strong>';
    groupMembersInner.appendChild(sep);

    const notInGroup = contacts.filter(contact => !members.find(member => Number(member.id) == Number(contact.id)) && Number(contact.id) != Number(CURRENT_USER.id));
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
      const checked = Array.from(groupMembersInner.querySelectorAll('input[type=checkbox]:checked')).map(i => Number(i.value));
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
  const checked = Array.from(groupMembersList.querySelectorAll('input[type=checkbox]:checked')).map(i => Number(i.value));
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


registerBtn.addEventListener('click', async () => {
  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();
  if (!username || !password) return alert('Username & password required.');
  const res = await api('/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username, password }) });
  if (res.user) {
    CURRENT_USER = res.user;
    afterLogin();
  }
  else alert(res.error || 'Register failed.');
});

loginBtn.addEventListener('click', async () => {
  const username = usernameInput.value.trim();
  const password = passwordInput.value.trim();
  if (!username || !password) return alert('Username & password required.');
  const res = await api('/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username, password }) });
  if (res.user) {
    CURRENT_USER = res.user;
    afterLogin();
  }
  else alert(res.error || 'Login failed.');
});

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

sendBtn.addEventListener('click', async () => {
  if (!CURRENT_USER) return alert('Sign in first.');
  if (!CURRENT_CHAT) return alert('Open a chat first.');
  const text = messageInput.value.trim();
  if (!text) return;
  socket.emit('send_message', {
    chatId: CURRENT_CHAT.id,
    senderId: CURRENT_USER.id, 
    content: text, 
    type: 'text'
  }, () => {});
  messageInput.value = '';
});

messageInput.addEventListener('keydown', e => { if (e.key == 'Enter') sendBtn.click(); });
attachBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (!CURRENT_USER || !CURRENT_CHAT) return alert('Sign in and open a chat first.');
  const upload = await uploadFile(file);
  if (upload && upload.url) {
    socket.emit('send_message', { chatId: CURRENT_CHAT.id, senderId: CURRENT_USER.id, content: '', media_url: upload.url, type: upload.type }, () => {});
  }
  else alert('Upload failed.');
  fileInput.value = '';
});

socket.on('receive_message', (msg) => {
  if (CURRENT_CHAT && Number(msg.chat_id) == Number(CURRENT_CHAT.id)) {
    messagesElem.appendChild(createMessageElement(msg));
    messagesElem.scrollTop = messagesElem.scrollHeight;
  }
  else {
    const contact = contacts.find(contact => Number(contact.id) == Number(msg.sender_id));
    if (contact) {
      contact.unread = true;
      renderContacts(searchInput.value);
    }
  }
});

socket.on('new_user', (user) => {
  if (!user) return;
  if (CURRENT_USER && Number(user.id) == Number(CURRENT_USER.id)) return;
  if (!contacts.find(contact => Number(contact.id) == Number(user.id))) {
    contacts.push({ ...user, online: false });
    renderContacts(searchInput.value);
  }
});

socket.on('user_status', (payload) => {
  if (!payload) return;
  const idx = contacts.findIndex(contact => Number(contact.id) == Number(payload.id));
  if (idx >= 0) {
    contacts[idx].online = payload.online;
    contacts[idx].last_seen_ms = payload.last_seen_ms || contacts[idx].last_seen_ms;
    renderContacts(searchInput.value);
  }
  else if (Number(payload.id) != Number(CURRENT_USER?.id)) {
    contacts.push({ id: payload.id, username: payload.username || 'User', online: payload.online, last_seen_ms: payload.last_seen_ms || null });
    renderContacts(searchInput.value);
  }
});

socket.on('user_updated', (user) => {
  if (!user) return;
  if (CURRENT_USER && Number(user.id) == Number(CURRENT_USER.id)) CURRENT_USER = user;
  const idx = contacts.findIndex(contact => Number(contact.id) == Number(user.id));
  if (idx >= 0) {
    contacts[idx] = { ...contacts[idx], ...user };
    renderContacts(searchInput.value);
  }
});

socket.on('group_created', (chat) => {
  if (!chat) return;
  if (!groups.find(group => Number(group.id) == Number(chat.id))) {
    groups.unshift({ ...chat, creator_id: chat.creator_id ? Number(chat.creator_id) : null });
    renderGroups();
  }
  else fetchGroups();
});

socket.on('chat_updated', async (payload) => {
  await fetchGroups();
  if (CURRENT_CHAT && payload && payload.chat && Number(payload.chat.id) == Number(CURRENT_CHAT.id)) {
    createHeaderForChat();
  }
});

socket.on('chat_deleted', payload => {
  if (!payload || !payload.chatId) return;
  const chatId = Number(payload.chatId);
  groups = groups.filter(group => Number(group.id) != chatId);
  renderGroups();
  if (CURRENT_CHAT && Number(CURRENT_CHAT.id) == chatId) {
    CURRENT_CHAT = null;
    messagesElem.innerHTML = '';
    chatName.textContent = 'Select a contact';
    chatStatus.textContent = 'Offline';
    headerRight.innerHTML = '';
    alert('This group was removed because it has no members left.');
  }
});

searchInput.addEventListener('input', () => {
  renderContacts(searchInput.value);
  renderGroups();
});
closeMembersBtn.addEventListener('click', () => groupMembersModal.style.display = 'none');

usernameInput.focus();
