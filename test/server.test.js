const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { cleanDomain, validDomain, server } = require('../server');
test('cleans friendly domain input without changing the host', () => assert.equal(cleanDomain('https://www.Example.com/path'), 'www.example.com'));
test('accepts public domains and rejects unsafe or private names', () => { assert.equal(validDomain('example.com'), true); assert.equal(validDomain('../etc/passwd'), false); assert.equal(validDomain('service.railway.internal'), false); });
test('accepts an email address and keeps its exact domain', () => assert.equal(cleanDomain('Hello@news.Example.com'), 'news.example.com'));
test('a malformed request returns 400 without crashing the server', async t => {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const response = await new Promise((resolve, reject) => {
    const socket = net.connect(server.address().port, '127.0.0.1', () => socket.write('GET http://[ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n'));
    let data = '';
    socket.setEncoding('utf8');
    socket.on('data', chunk => { data += chunk; });
    socket.on('end', () => resolve(data));
    socket.on('error', reject);
  });
  assert.match(response, /400 Bad Request/);
  assert.equal(server.listening, true);
});
