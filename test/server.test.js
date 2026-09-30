const test = require('node:test');
const assert = require('node:assert/strict');
const { cleanDomain, validDomain } = require('../server');
test('cleans friendly domain input without changing the host', () => assert.equal(cleanDomain('https://www.Example.com/path'), 'www.example.com'));
test('accepts domains and rejects unsafe input', () => { assert.equal(validDomain('example.com'), true); assert.equal(validDomain('../etc/passwd'), false); });
test('accepts an email address and keeps its exact domain', () => assert.equal(cleanDomain('Hello@news.Example.com'), 'news.example.com'));
