// Renew an Apple shopping session in an isolated Chromium-based browser process.
// The candidate is promoted by the Go monitor only after a successful standalone API check.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import {chromium} from 'playwright-core';

const root = path.dirname(fileURLToPath(import.meta.url));
const arg = (key, fallback) => { const i = process.argv.indexOf(key); return i < 0 ? fallback : process.argv[i + 1]; };
const diagnostic = process.argv.includes('--diagnostic');
const seeded = process.argv.includes('--seeded');
const persistent = process.argv.includes('--persistent');
const checkCount = Math.max(1, Math.min(3, Number(arg('--checks', '1')) || 1));
let stage = 'starting';
const route = arg('--route', 'direct');
const output = path.resolve(arg('--output', path.join(root, '.apple-cookies.candidate.txt')));
const config = JSON.parse(fs.readFileSync(path.join(root, 'config.json'), 'utf8'));
const shop = `https://www.apple.com/${config.country || 'uk'}/shop`;
const productPage = config.product_page || (!config.country || config.country === 'uk'
  ? `${shop}/buy-iphone/iphone-duo/7.6-inch-display-256gb-star-white` : `${shop}/buy-iphone/iphone-duo`);
const storeName = store => String(store.storeName || '').replace(/^Apple /, '').toLowerCase();
const isTarget = store => config.stores.some(name => name.toLowerCase() === storeName(store));
const defaultBrowser = process.platform === 'darwin'
  ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' : 'google-chrome';
const progress = value => { stage = value; if (diagnostic) console.error(JSON.stringify({stage})); };
const params = new URLSearchParams({fae: 'true', pl: 'true', 'mts.0': 'regular', location: config.postcode});
Object.keys(config.products).forEach((part, i) => params.set(`parts.${i}`, part));
let browser, child, profile;
const events = [];
const pendingEvents = [];
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function close() {
  try { await Promise.race([browser?.close(), sleep(2500)]); } catch {}
  if (child && child.exitCode === null) {
    child.kill('SIGTERM');
    await Promise.race([once(child, 'exit').catch(() => {}), sleep(2000)]);
    if (child.exitCode === null) child.kill('SIGKILL');
  }
  if (profile && !persistent) { try { fs.rmSync(profile, {recursive: true, force: true}); } catch {} }
}
const deadline = setTimeout(() => {
  console.log(JSON.stringify({ok: false, error: 'RenewalTimeout', stage, route}));
  close().finally(() => process.exit(1));
}, 90000 + (checkCount - 1) * 65000);
deadline.unref();
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.once(signal, () => {
    clearTimeout(deadline);
    close().finally(() => process.exit(signal === 'SIGTERM' ? 143 : 130));
  });
}

try {
  if (!['direct', 'proxy'].includes(route)) throw new Error('InvalidRoute');
  const socket = net.createServer();
  await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  await new Promise(resolve => socket.close(resolve));
  if (persistent && route !== 'direct') throw new Error('PersistentProxyUnsupported');
  profile = persistent ? path.join(root, '.apple-browser-profile') : fs.mkdtempSync(path.join(os.tmpdir(), 'apple-session-browser-'));
  fs.mkdirSync(profile, {recursive: true, mode: 0o700});
  fs.chmodSync(profile, 0o700);
  // Normal browser defaults, with debugging restricted to loopback and this
  // dedicated profile. No personal profile, fingerprint patches or disabled sandbox.
  const browserExecutable = process.env.APPLE_MONITOR_BROWSER || defaultBrowser;
  child = spawn(browserExecutable, [
    // The Linux service owns an Xvfb display. The user manager can inherit
    // Wayland desktop variables; never let Chrome select that other session.
    ...(process.platform === 'linux' ? ['--ozone-platform=x11'] : []),
    `--user-data-dir=${profile}`, `--remote-debugging-port=${port}`,
    '--remote-debugging-address=127.0.0.1', '--no-first-run',
    '--no-default-browser-check', 'about:blank'
  ], {stdio: 'ignore'});
  child.on('error', () => {});
  progress('waiting-for-browser');
  let ready = false;
  for (let attempt = 0; attempt < 80; attempt++) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`, {signal: AbortSignal.timeout(1000)});
      if (response.ok) { ready = true; break; }
    } catch {}
    await sleep(150);
  }
  if (!ready) throw new Error('BrowserNotReady');
  browser = await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
  let context = browser.contexts()[0];
  if (route === 'proxy') {
    const proxyFile = arg('--proxy-file', null);
    if (!proxyFile) throw new Error('MissingProxyFile');
    const proxy = JSON.parse(fs.readFileSync(path.resolve(root, proxyFile), 'utf8'));
    context = await browser.newContext({proxy});
  }
  progress('browser-launched');
  if (seeded) {
    const seedPath = path.join(root, route === 'direct' ? '.apple-cookies.txt' : '.apple-cookies.proxy.txt');
    const cookies = (fs.existsSync(seedPath) ? fs.readFileSync(seedPath, 'utf8') : '').split('\n').flatMap(line => {
      if (!line || (line.startsWith('#') && !line.startsWith('#HttpOnly_'))) return [];
      const f = line.split('\t'); if (f.length !== 7 || (Number(f[4]) > 0 && Number(f[4]) * 1000 <= Date.now())) return [];
      return [{name: f[5], value: f[6], domain: f[0].replace(/^#HttpOnly_/, ''), path: f[2],
        secure: f[3] === 'TRUE', httpOnly: f[0].startsWith('#HttpOnly_'),
        ...(Number(f[4]) > 0 ? {expires: Number(f[4])} : {})}];
    });
    if (process.argv.includes('--refresh')) {
      await context.clearCookies({name: /^shld_/});
    }
    await context.addCookies(process.argv.includes('--refresh') ? cookies.filter(c => !c.name.startsWith('shld_')) : cookies);
  }
  const page = await context.newPage();
  let capturedReport = null;
  const reportPath = arg('--capture-verification-profile', null);
  if (reportPath) page.on('request', request => {
    if (new URL(request.url()).pathname === '/shop/shld/work/s3/q' && request.method() === 'POST') {
      try { const payload = JSON.parse(request.postData()); if (payload.jsa) capturedReport = payload.jsa; } catch {}
    }
  });
  page.on('requestfailed', request => {
    const url = new URL(request.url());
    if (url.hostname === 'www.apple.com') events.push({path: url.pathname, method: request.method(), status: 0, error: request.failure()?.errorText});
  });
  page.on('response', response => {
    const url = new URL(response.url());
    if (url.hostname !== 'www.apple.com') return;
    const record = (async () => {
      const headers = await response.headersArray();
      const setCookies = headers.filter(h => h.name.toLowerCase() === 'set-cookie').map(h => h.value.split('=', 1)[0]);
      if (url.pathname.includes('/shld/') || setCookies.length || response.status() >= 400) {
        events.push({path: url.pathname, method: response.request().method(), status: response.status(), setCookies});
      }
    })().catch(() => {});
    pendingEvents.push(record);
  });
  const verified = page.waitForResponse(response => response.url().includes('/shop/shld/') && response.request().method() === 'POST', {timeout: 20000}).catch(() => null);
  await page.goto(productPage, {waitUntil: 'domcontentloaded', timeout: 35000});
  progress('page-loaded');
  if (await verified) {
    await page.waitForFunction(() => document.cookie.split(';').some(x => x.trim().startsWith('shld_bt_ck=')), null, {timeout: 10000});
    progress('verification-cookie-ready');
    // Set-Cookie is already applied; a second product-page navigation is
    // unnecessary. Keep the old path as an explicit diagnostic option.
    if (process.argv.includes('--reload-after-verification')) {
      await page.reload({waitUntil: 'domcontentloaded', timeout: 35000});
    }
  }
  await page.waitForLoadState('networkidle', {timeout: 8000}).catch(() => {});
  progress('checking-stock');
  const checkStock = () => page.evaluate(async endpoint => {
    const response = await fetch(endpoint, {signal: AbortSignal.timeout(20000)});
    const retry = response.headers.get('retry-after');
    const retryAfterSeconds = retry ? Math.max(0, /^\d+$/.test(retry) ? Number(retry) : (Date.parse(retry) - Date.now()) / 1000) || 0 : 0;
    if (!response.ok) return {status: response.status, retryAfterSeconds};
    try { return {status: response.status, data: await response.json()}; }
    catch { return {status: response.status, invalidJson: true}; }
  }, `${new URL(shop).pathname}/fulfillment-messages?` + params);
  const checks = [];
  let result;
  for (let i = 0; i < checkCount; i++) {
    if (i) await sleep(60000);
    result = await checkStock();
    const targetStores = result.data?.body?.content?.pickupMessage?.stores?.filter(isTarget);
    const complete = targetStores?.length === config.stores.length && targetStores.every(store => Object.keys(config.products).every(part => ['available', 'unavailable'].includes(store.partsAvailability?.[part]?.pickupDisplay)));
    checks.push({at: new Date().toISOString(), status: result.status, complete: !!complete});
    if (diagnostic) console.error(JSON.stringify({check: i + 1, status: result.status}));
    if (result.status !== 200 || !complete) break;
  }
  const browserEnvironment = await page.evaluate(() => ({
    userAgent: navigator.userAgent, platform: navigator.platform,
    language: navigator.language, timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: {width: screen.width, height: screen.height, pixelRatio: devicePixelRatio}
  }));
  const stores = result.data?.body?.content?.pickupMessage?.stores;
  const targets = Array.isArray(stores) ? stores.filter(isTarget) : [];
  const valid = result.status === 200 && targets.length === config.stores.length && targets.every(store =>
    Object.keys(config.products).every(part => ['available', 'unavailable'].includes(store.partsAvailability?.[part]?.pickupDisplay)));
  const cookies = await context.cookies(`${shop}/fulfillment-messages`);
  const userAgent = await page.evaluate(() => navigator.userAgent);
  await Promise.allSettled(pendingEvents);
  if (reportPath && valid && capturedReport) {
    fs.writeFileSync(reportPath, JSON.stringify({jsa: capturedReport, userAgent, capturedAt: new Date().toISOString()}), {mode: 0o600});
    fs.chmodSync(reportPath, 0o600);
  }
  if (valid && !diagnostic) {
    const lines = ['# Netscape HTTP Cookie File', '# Private Apple session; candidate awaiting standalone validation.'];
    for (const cookie of cookies) {
      if (/[\r\n\t]/.test(cookie.name + cookie.value)) throw new Error('InvalidCookie');
      lines.push([`${cookie.httpOnly ? '#HttpOnly_' : ''}${cookie.domain}`,
        cookie.domain.startsWith('.') ? 'TRUE' : 'FALSE', cookie.path,
        cookie.secure ? 'TRUE' : 'FALSE', cookie.expires > 0 ? Math.floor(cookie.expires) : 0,
        cookie.name, cookie.value].join('\t'));
    }
    fs.writeFileSync(output, lines.join('\n') + '\n', {mode: 0o600});
    fs.chmodSync(output, 0o600);
    fs.writeFileSync(output + '.json', JSON.stringify({userAgent, renewedAt: new Date().toISOString(), route, verificationExpiry: cookies.find(c => c.name === 'shld_bt_ck')?.expires}), {mode: 0o600});
  }
  console.log(JSON.stringify({ok: valid, stage, persistent, mode: seeded ? 'seeded' : 'cold', route, status: result.status,
    events, checks, browserEnvironment, retryAfterSeconds: result.retryAfterSeconds || 0,
    networkSummary: {recordedResponses: events.length, verificationPosts: events.filter(e => e.path.includes('/shld/') && e.method === 'POST' && e.status >= 200 && e.status < 300).length,
      failures: events.filter(e => e.status === 0 || e.status >= 400).map(e => ({path: e.path, status: e.status, error: e.error}))},
    cookieCount: cookies.length,
    verificationExpiry: cookies.find(cookie => cookie.name === 'shld_bt_ck')?.expires,
    stores: targets.map(store => ({id: store.storeNumber, parts: Object.fromEntries(Object.entries(store.partsAvailability).map(([part, value]) => [part, value.pickupDisplay]))}))}));
  if (!valid) process.exitCode = 1;
} catch (error) {
  const known = ['InvalidRoute', 'MissingProxyFile', 'PersistentProxyUnsupported', 'BrowserNotReady', 'InvalidCookie'];
  console.log(JSON.stringify({ok: false, stage, route,
    error: known.includes(error.message) ? error.message : error.name || 'Error',
    browserExitCode: child?.exitCode ?? null}));
  process.exitCode = 1;
} finally {
  clearTimeout(deadline);
  await close();
}
