// Сервер: імітація TLS-рукостискання (базовий варіант) і захищений чат
const net = require('net');
const crypto = require('crypto');
const readline = require('readline');
const fs = require('fs');
const path = require('path');
const { send, onMessages, deriveSessionKey, encrypt, decrypt, short, fingerprint } = require('./common');

const PORT = Number(process.env.PORT) || 4000;

const server = net.createServer((socket) => {
  console.log(`\nКлієнт підключився: ${socket.remoteAddress}:${socket.remotePort}`);
  const st = { step: 'wait_hello', sendSeq: 0, recvSeq: 0 };

  onMessages(socket, (msg) => {
    try {
      handle(socket, st, msg);
    } catch (err) {
      console.log('Помилка:', err.message);
      socket.destroy();
    }
  });
  socket.on('close', () => console.log('Клієнт відключився'));
  socket.on('error', () => {});
});

function handle(socket, st, msg) {
  if (st.step === 'wait_hello' && msg.type === 'client_hello') {
    // Крок 1. Отримали "привіт" клієнта
    st.clientRandom = msg.random;
    console.log('[1] <- client_hello, client_random =', short(msg.random));

    // Крок 2. "Привіт сервера": власний випадковий рядок + публічний ключ (базовий варіант замість сертифіката)
    st.serverRandom = crypto.randomBytes(32).toString('hex');
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    st.privateKey = privateKey;
    const pem = publicKey.export({ type: 'spki', format: 'pem' });
    send(socket, { type: 'server_hello', random: st.serverRandom, publicKey: pem });
    console.log('[2] -> server_hello, server_random =', short(st.serverRandom));
    console.log('    згенеровано пару ключів RSA-2048, публічний ключ відправлено клієнту');
    st.step = 'wait_premaster';
    return;
  }

  if (st.step === 'wait_premaster' && msg.type === 'premaster') {
    // Крок 4. Розшифровуємо premaster приватним ключем
    const encrypted = Buffer.from(msg.data, 'base64');
    console.log('[4] <- premaster (зашифрований RSA-OAEP) =', short(msg.data));
    const premaster = crypto.privateDecrypt(
      { key: st.privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
      encrypted
    );
    console.log('    розшифровано premaster =', short(premaster.toString('hex')));

    // Крок 5. Сеансовий ключ з client_random, server_random і premaster
    st.key = deriveSessionKey(premaster, st.clientRandom, st.serverRandom);
    console.log('[5] сеансовий ключ згенеровано, відбиток =', fingerprint(st.key));
    st.step = 'wait_finished';
    return;
  }

  if (st.step === 'wait_finished' && msg.type === 'finished') {
    // Крок 6. Перевіряємо "готовий" клієнта і відповідаємо своїм
    const text = decrypt(st.key, msg);
    st.recvSeq = msg.seq + 1;
    if (text !== 'готовий') throw new Error('неправильне повідомлення finished');
    console.log('[6] <- finished від клієнта розшифровано:', JSON.stringify(text));
    send(socket, { type: 'finished', ...encrypt(st.key, st.sendSeq++, 'готовий') });
    console.log('[6] -> finished сервера, зашифровано сеансовим ключем');

    // Крок 7. Рукостискання завершене
    console.log('[7] Рукостискання завершено, далі зв\'язок шифрується AES-256-GCM сеансовим ключем\n');
    st.step = 'secure';
    startChat(socket, st);
    return;
  }

  if (st.step === 'secure' && msg.type === 'data') {
    if (msg.seq !== st.recvSeq) throw new Error('неочікуваний номер повідомлення (повтор або підміна)');
    st.recvSeq++;
    console.log(`  зашифровано: ${short(msg.ct, 40)}`);
    let text;
    try {
      text = decrypt(st.key, msg);
    } catch {
      throw new Error('пакет не пройшов перевірку цілісності (AES-GCM auth tag), з\'єднання розірвано');
    }
    const data = JSON.parse(text);
    if (data.kind === 'file') {
      const out = path.join(__dirname, 'received_' + path.basename(data.name));
      fs.writeFileSync(out, Buffer.from(data.content, 'base64'));
      console.log(`  Клієнт надіслав файл ${data.name} (${data.size} байт), збережено як ${path.basename(out)}`);
    } else {
      console.log(`  Клієнт: ${data.text}`);
    }
    return;
  }

  throw new Error(`неочікуване повідомлення ${msg.type} на кроці ${st.step}`);
}

function startChat(socket, st) {
  console.log('Захищений чат. Пишіть повідомлення і натискайте Enter');
  const rl = readline.createInterface({ input: process.stdin });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    send(socket, { type: 'data', ...encrypt(st.key, st.sendSeq++, JSON.stringify({ kind: 'text', text: line })) });
  });
  socket.on('close', () => rl.close());
}

server.listen(PORT, () => console.log(`Сервер слухає порт ${PORT}`));
