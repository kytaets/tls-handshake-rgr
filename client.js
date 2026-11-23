// Клієнт: ініціює імітацію TLS-рукостискання (базовий варіант) і працює в захищеному чаті
const net = require('net');
const crypto = require('crypto');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const { send, onMessages, deriveSessionKey, encrypt, decrypt, short, fingerprint } = require('./common');

const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT) || 4000;
const st = { step: 'wait_server_hello', sendSeq: 0, recvSeq: 0 };

const socket = net.connect(PORT, HOST, () => {
  console.log(`Підключено до ${HOST}:${PORT}\n`);
  // Крок 1. "Привіт" клієнта з випадковим рядком
  st.clientRandom = crypto.randomBytes(32).toString('hex');
  send(socket, { type: 'client_hello', random: st.clientRandom });
  console.log('[1] -> client_hello, client_random =', short(st.clientRandom));
});

onMessages(socket, (msg) => {
  try {
    handle(msg);
  } catch (err) {
    console.log('Помилка:', err.message);
    socket.destroy();
  }
});
socket.on('close', () => { console.log('З\'єднання закрито'); process.exit(0); });
socket.on('error', (e) => { console.log('Не вдалося підключитися:', e.message); process.exit(1); });

function handle(msg) {
  if (st.step === 'wait_server_hello' && msg.type === 'server_hello') {
    // Крок 2. Отримали "привіт сервера" і публічний ключ
    st.serverRandom = msg.random;
    console.log('[2] <- server_hello, server_random =', short(msg.random));
    console.log('    отримано публічний ключ сервера:', msg.publicKey.split('\n')[1].slice(0, 40) + '...');

    // Крок 3. Автентифікація сертифіката: у базовому варіанті пропускаємо
    console.log('[3] перевірку сертифіката в центрі сертифікації пропущено (базовий варіант)');

    // Крок 4. Premaster: 48 випадкових байтів, шифруємо публічним ключем сервера
    const premaster = crypto.randomBytes(48);
    const encrypted = crypto.publicEncrypt(
      { key: msg.publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      premaster
    );
    send(socket, { type: 'premaster', data: encrypted.toString('base64') });
    console.log('[4] -> premaster =', short(premaster.toString('hex')));
    console.log('    відправлено зашифрованим публічним ключем сервера (RSA-OAEP)');

    // Крок 5. Сеансовий ключ
    st.key = deriveSessionKey(premaster, st.clientRandom, st.serverRandom);
    console.log('[5] сеансовий ключ згенеровано, відбиток =', fingerprint(st.key));

    // Крок 6. "Готовий", зашифрований сеансовим ключем
    send(socket, { type: 'finished', ...encrypt(st.key, st.sendSeq++, 'готовий') });
    console.log('[6] -> finished клієнта, зашифровано сеансовим ключем');
    st.step = 'wait_finished';
    return;
  }

  if (st.step === 'wait_finished' && msg.type === 'finished') {
    const text = decrypt(st.key, msg);
    st.recvSeq = msg.seq + 1;
    if (text !== 'готовий') throw new Error('неправильне повідомлення finished');
    console.log('[6] <- finished від сервера розшифровано:', JSON.stringify(text));
    // Крок 7
    console.log('[7] Рукостискання завершено, далі зв\'язок шифрується AES-256-GCM сеансовим ключем\n');
    st.step = 'secure';
    startChat();
    return;
  }

  if (st.step === 'secure' && msg.type === 'data') {
    if (msg.seq !== st.recvSeq) throw new Error('неочікуваний номер повідомлення (повтор або підміна)');
    st.recvSeq++;
    console.log(`  зашифровано: ${short(msg.ct, 40)}`);
    const data = JSON.parse(decrypt(st.key, msg));
    console.log(`  Сервер: ${data.text}`);
    return;
  }

  throw new Error(`неочікуване повідомлення ${msg.type} на кроці ${st.step}`);
}

function startChat() {
  console.log('Захищений чат. Пишіть повідомлення і натискайте Enter');
  console.log('Щоб надіслати файл: /file <шлях до файлу>');
  console.log('Перевірка цілісності: /tamper <текст> (пошкоджує зашифрований пакет)');
  const rl = readline.createInterface({ input: process.stdin });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    if (line.startsWith('/tamper ')) {
      // Демонстрація: змінюємо один байт шифротексту, сервер має відхилити пакет (GCM tag не збігається)
      const pkt = encrypt(st.key, st.sendSeq++, JSON.stringify({ kind: 'text', text: line.slice(8) }));
      const ct = Buffer.from(pkt.ct, 'base64'); ct[0] ^= 0xff; pkt.ct = ct.toString('base64');
      console.log('  відправлено пакет з пошкодженим шифротекстом');
      return send(socket, { type: 'data', ...pkt });
    }
    let payload;
    if (line.startsWith('/file ')) {
      const file = line.slice(6).trim();
      if (!fs.existsSync(file)) return console.log('Файл не знайдено:', file);
      const content = fs.readFileSync(file);
      payload = { kind: 'file', name: path.basename(file), size: content.length, content: content.toString('base64') };
      console.log(`  файл ${payload.name} (${payload.size} байт) зашифровано і відправлено`);
    } else {
      payload = { kind: 'text', text: line };
    }
    send(socket, { type: 'data', ...encrypt(st.key, st.sendSeq++, JSON.stringify(payload)) });
  });
}
