#!/usr/bin/env node
/**
 * Browser smoke test (Playwright/Chromium): the admin forms must work in a
 * real browser, which sends Origin/Referer headers according to the page's
 * Referrer-Policy (the Python e2e test cannot catch that).
 *
 * Needs a hub with a fresh admin and no TOTP yet:
 *   FLEET=http://localhost:8787 FLEET_USER=… FLEET_PASS=… node test/browser.cjs
 */
const { chromium } = require('playwright');
const crypto = require('node:crypto');

const FLEET = process.env.FLEET || 'http://localhost:8787';
const USER = process.env.FLEET_USER;
const PASS = process.env.FLEET_PASS;
let fails = 0;
const check = (name, ok, info = '') => {
  console.log((ok ? 'PASS ' : 'FAIL ') + name + (ok ? '' : '  -> ' + String(info).slice(0, 300)));
  if (!ok) fails++;
};

function totp(secret, t = Date.now()) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secret.replace(/\s+/g, '')) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = crypto.createHmac('sha1', key).update(msg).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const origins = [];
  page.on('request', (r) => {
    if (r.method() === 'POST' && r.url().startsWith(FLEET)) origins.push(r.headers()['origin']);
  });
  const submit = (sel = 'form button[type=submit]') => Promise.all([page.waitForLoadState(), page.locator(sel).first().click()]);

  await page.goto(FLEET + '/login');
  await page.fill('input[name=username]', USER);
  await page.fill('input[name=password]', PASS);
  await submit();
  check('password login leads to TOTP setup', page.url().includes('/totp'), page.url());

  const secret = (await page.textContent('p.muted code')).trim();
  await page.fill('input[name=code]', totp(secret));
  await submit();
  check('TOTP activated, admin page shown', page.url().endsWith('/admin') && (await page.content()).includes('Add a site'), page.url());

  await page.fill('input[name=url]', 'https://does-not-exist.invalid');
  await submit('form[action="/admin/sites"] button[type=submit]');
  const body = await page.textContent('body');
  check('admin form accepted (error comes from the site check, not CSRF/Origin)', page.url().endsWith('/admin') && !body.includes('form has expired'), body.slice(0, 200));

  await submit('form[action="/logout"] button[type=submit]');
  check('logout', page.url().includes('/login'), page.url());

  // Next 30 s window, so the code differs from the one used for enrolment.
  await new Promise((r) => setTimeout(r, 31000));
  await page.fill('input[name=username]', USER);
  await page.fill('input[name=password]', PASS);
  await page.fill('input[name=code]', totp(secret));
  await submit();
  check('login with password + TOTP', page.url().endsWith('/admin'), page.url());

  check('every POST carried the real Origin', origins.length >= 4 && origins.every((o) => o === FLEET), JSON.stringify(origins));
  await browser.close();
  console.log('\nFAILS:', fails);
  process.exit(fails ? 1 : 0);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
