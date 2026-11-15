const form = document.querySelector('#chatForm');
const input = document.querySelector('#messageInput');
const messages = document.querySelector('#messages');
const sendButton = document.querySelector('#sendButton');
const resetButton = document.querySelector('#resetButton');
const statusDot = document.querySelector('#statusDot');
const statusText = document.querySelector('#statusText');
const modelText = document.querySelector('#modelText');
let sessionId = localStorage.getItem('llmid-session') || crypto.randomUUID();

function addMessage(role, text, pending = false) {
  const element = document.createElement('div');
  element.className = `message ${role}${pending ? ' thinking' : ''}`;
  if (role === 'assistant') {
    const avatar = document.createElement('div');
    avatar.className = 'avatar';
    avatar.textContent = 'ID';
    element.appendChild(avatar);
  }
  const bubble = document.createElement('div');
  bubble.className = 'bubble';
  bubble.textContent = text;
  element.appendChild(bubble);
  messages.appendChild(element);
  messages.scrollTop = messages.scrollHeight;
  return element;
}

async function checkHealth() {
  try {
    const response = await fetch('/api/health', {cache: 'no-store'});
    const data = await response.json();
    statusDot.className = `status-dot ${data.ollama_ready ? 'ready' : 'error'}`;
    statusText.textContent = data.ollama_ready ? 'Engines online' : 'Ollama unavailable';
    modelText.textContent = data.model || 'Unknown model';
  } catch {
    statusDot.className = 'status-dot error';
    statusText.textContent = 'Backend unavailable';
  }
}

async function sendMessage(text) {
  addMessage('user', text);
  const pending = addMessage('assistant', 'Investigating', true);
  sendButton.disabled = true;
  input.disabled = true;
  try {
    const response = await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({session_id: sessionId, message: text}),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    sessionId = data.session_id;
    localStorage.setItem('llmid-session', sessionId);
    pending.remove();
    addMessage('assistant', data.answer);
  } catch (error) {
    pending.remove();
    addMessage('assistant', `Request failed: ${error.message}`);
  } finally {
    sendButton.disabled = false;
    input.disabled = false;
    input.focus();
  }
}

form.addEventListener('submit', event => {
  event.preventDefault();
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  sendMessage(text);
});

input.addEventListener('keydown', event => {
  if (event.key === 'Enter' && !event.shiftKey) {
    event.preventDefault();
    form.requestSubmit();
  }
});

document.querySelectorAll('.prompt').forEach(button => {
  button.addEventListener('click', () => sendMessage(button.dataset.prompt));
});

resetButton.addEventListener('click', async () => {
  await fetch('/api/reset', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({session_id: sessionId}),
  });
  messages.innerHTML = '';
  addMessage('assistant', 'New investigation session started.');
});

checkHealth();
setInterval(checkHealth, 15000);
