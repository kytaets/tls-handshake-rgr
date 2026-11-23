// Спільні функції для клієнта і сервера: протокол обміну, генерація сеансового ключа, симетричне шифрування
const crypto = require('crypto');

// Повідомлення передаються як JSON, по одному на рядок
function send(socket, msg) {
  socket.write(JSON.stringify(msg) + '\n');
}

// Розбиває TCP-потік на окремі JSON-повідомлення
function onMessages(socket, handler) {
  let buf = '';
  socket.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i);
      buf = buf.slice(i + 1);
      if (line.trim()) handler(JSON.parse(line));
    }
  });
}

// Крок 5. Сеансовий ключ: HKDF-SHA256 з premaster, сіль = client_random || server_random
function deriveSessionKey(premaster, clientRandom, serverRandom) {
  const salt = Buffer.concat([Buffer.from(clientRandom, 'hex'), Buffer.from(serverRandom, 'hex')]);
  return Buffer.from(crypto.hkdfSync('sha256', premaster, salt, Buffer.from('session key'), 32));
}

// Симетричне шифрування AES-256-GCM. Номер повідомлення йде в AAD, щоб не можна було повторити чи переставити пакет
function encrypt(key, seq, text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(String(seq)));
  const ct = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return { seq, iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ct: ct.toString('base64') };
}

function decrypt(key, msg) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(msg.iv, 'base64'));
  decipher.setAAD(Buffer.from(String(msg.seq)));
  decipher.setAuthTag(Buffer.from(msg.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(msg.ct, 'base64')), decipher.final()]).toString('utf8');
}

const short = (s, n = 32) => (s.length > n ? s.slice(0, n) + '...' : s);
const fingerprint = (key) => crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);

module.exports = { send, onMessages, deriveSessionKey, encrypt, decrypt, short, fingerprint };
