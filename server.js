const http = require('node:http');
const { promises: dns } = require('node:dns');
const fs = require('node:fs');
const path = require('node:path');
const { domainToASCII } = require('node:url');

const publicDir = path.join(__dirname, 'public');
const port = Number(process.env.PORT || 3000);
const resultCache = new Map();
const cacheMs = 60_000;
let activeChecks = 0;

function cleanDomain(value = '') {
  const input = String(value ?? '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split('@').pop().replace(/:\d+$/, '').replace(/\.$/, '');
  return domainToASCII(input);
}

function validDomain(domain) {
  const privateSuffix = /\.(?:internal|local|localhost|invalid|test|example|home|lan)$/i;
  return Boolean(domain) && domain.length <= 253 && !privateSuffix.test(domain) && /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/i.test(domain);
}

function validSelector(selector) {
  return Boolean(selector) && selector.length <= 253 && selector.split('.').every(label => /^(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?)$/i.test(label));
}

async function safeResolve(kind, hostname) {
  let timer;
  try {
    const value = await Promise.race([
      dns[kind](hostname),
      new Promise((_, reject) => { timer = setTimeout(() => reject(Object.assign(new Error('DNS lookup timed out'), { code: 'ETIMEOUT' })), 6000); })
    ]);
    return { value, status: 'found' };
  }
  catch (error) {
    if (['ENODATA', 'ENOTFOUND'].includes(error.code)) return { value: [], status: 'missing' };
    return { value: [], status: 'unavailable' };
  }
  finally {
    if (timer) clearTimeout(timer);
  }
}

function dmarcRows(answer) {
  return answer.map(parts => parts.join('')).filter(row => /^v\s*=\s*DMARC1\s*;/.test(row));
}

async function discoverDmarc(domain) {
  const labels = domain.split('.');
  const targets = [domain];
  const parentLabels = labels.length > 8 ? labels.slice(-7) : labels.slice(1);
  for (let i = 0; i < parentLabels.length; i += 1) targets.push(parentLabels.slice(i).join('.'));
  const checked = [];
  for (const target of targets.slice(0, 8)) {
    const answer = await safeResolve('resolveTxt', `_dmarc.${target}`);
    const records = dmarcRows(answer.value);
    checked.push({ domain: target, status: answer.status, records });
    if (target === domain && records.length > 1) return { status: 'invalid', records, policyDomain: domain, inherited: false, checked };
    if (records.length === 1) return { status: 'found', records, policyDomain: target, inherited: target !== domain, checked };
    if (answer.status === 'unavailable') return { status: 'unavailable', records: [], policyDomain: null, inherited: false, checked };
  }
  return { status: 'missing', records: [], policyDomain: null, inherited: false, checked };
}

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, {
    'Content-Type': type,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer'
  });
  res.end(type.startsWith('application/json') ? JSON.stringify(body) : body);
}

const server = http.createServer(async (req, res) => {
  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  }
  catch {
    return send(res, 400, { error: 'That request could not be read.' });
  }
  if (url.pathname === '/api/check') {
    const domain = cleanDomain(url.searchParams.get('domain'));
    if (!validDomain(domain)) return send(res, 400, { error: 'Please enter a domain like example.com.' });
    const selector = (url.searchParams.get('selector') || '').trim().toLowerCase().replace(/\._domainkey.*$/, '');
    if (selector && !validSelector(selector)) return send(res, 400, { error: 'That DKIM selector does not look valid. Enter only the part before ._domainkey.' });
    const cacheKey = `${domain}|${selector}`;
    const cached = resultCache.get(cacheKey);
    if (cached && Date.now() - cached.savedAt < cacheMs) return send(res, 200, cached.payload);
    if (activeChecks >= 20) return send(res, 503, { error: 'The checker is busy. Please try again in a moment.' });
    activeChecks += 1;
    try {
      const [mx, dmarcResult, rootTxt] = await Promise.all([safeResolve('resolveMx', domain), discoverDmarc(domain), safeResolve('resolveTxt', domain)]);
      const spf = rootTxt.value.map(parts => parts.join('')).filter(row => /^v=spf1\s+/i.test(row));
      let dkim = null;
      if (selector) {
        const host = `${selector}._domainkey.${domain}`;
        const [dkimTxt, dkimCname] = await Promise.all([safeResolve('resolveTxt', host), safeResolve('resolveCname', host)]);
        const txtRecords = dkimTxt.value.map(parts => parts.join('')).filter(row => /^v\s*=\s*DKIM1\s*;/i.test(row) && /(?:^|;)\s*p\s*=\s*[^;\s]+/i.test(row));
        dkim = { selector, host, txt: txtRecords, cname: dkimCname.value, status: txtRecords.length || dkimCname.value.length ? 'found' : (dkimTxt.status === 'unavailable' || dkimCname.status === 'unavailable' ? 'unavailable' : 'missing') };
      }
      const payload = {
        domain,
        mx: mx.value.sort((a, b) => a.priority - b.priority),
        mxStatus: mx.status,
        mxNull: mx.value.length === 1 && mx.value[0].priority === 0 && (!mx.value[0].exchange || mx.value[0].exchange === '.'),
        dmarc: dmarcResult.records,
        dmarcStatus: dmarcResult.status,
        dmarcPolicyDomain: dmarcResult.policyDomain,
        dmarcInherited: dmarcResult.inherited,
        spf,
        spfStatus: rootTxt.status,
        dkim,
        checkedAt: new Date().toISOString()
      };
      resultCache.set(cacheKey, { savedAt: Date.now(), payload });
      if (resultCache.size > 500) resultCache.delete(resultCache.keys().next().value);
      return send(res, 200, payload);
    }
    finally {
      activeChecks -= 1;
    }
  }
  if (url.pathname === '/health') return send(res, 200, { ok: true });
  const relative = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
  const file = path.normalize(path.join(publicDir, relative));
  if (!file.startsWith(publicDir) || !fs.existsSync(file) || fs.statSync(file).isDirectory()) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
  const ext = path.extname(file);
  const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml' };
  res.writeHead(200, {
    'Content-Type': types[ext] || 'application/octet-stream',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()'
  });
  fs.createReadStream(file).pipe(res);
});

server.on('clientError', (_error, socket) => {
  if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
});

if (require.main === module) server.listen(port, () => console.log(`Mail Safe Guide is ready on http://localhost:${port}`));
module.exports = { cleanDomain, validDomain, server };
