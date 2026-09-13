// The wallet. Everything here works with the radio off except "bank it".

import { newDevice, importDevice, publicKeyOf, sign, verify, pack, unpack,
         encodeAddress, decodeAddress, hex, unhex } from './lastmile.js';

const $ = (id) => document.getElementById(id);
const STORE = 'lastmile.device.v1';
const QUEUE = 'lastmile.accepted.v1';

let device = null;

// ---- storage. localStorage can throw in private windows, so never assume it.
const load = (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } };
const save = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} };

// ---- money. Stroops are integers; never let a float near them.
const toStroops = (s) => {
  const m = String(s).trim().match(/^(\d+)(?:\.(\d{1,7}))?$/);
  if (!m) throw new Error('Enter an amount like 2.5');
  return (BigInt(m[1]) * 10000000n + BigInt((m[2] ?? '').padEnd(7, '0'))).toString();
};
const toXLM = (stroops) => {
  const n = BigInt(stroops), whole = n / 10000000n, frac = (n % 10000000n).toString().padStart(7, '0');
  return `${whole}.${frac}`.replace(/0+$/, '').replace(/\.$/, '');
};

// ---- online indicator
function net() {
  const on = navigator.onLine;
  $('net').textContent = on ? 'online · testnet' : 'no signal — still works';
  $('net').classList.toggle('off', !on);
}
addEventListener('online', net); addEventListener('offline', net); net();

// ---- device key
async function restore() {
  const saved = load(STORE, null);
  if (!saved) return;
  const seed = unhex(saved.seed);
  device = { seed, key: await importDevice(seed), publicKey: unhex(saved.pub) };
  showDevice();
}

function showDevice() {
  const g = encodeAddress(device.publicKey);
  $('devline').textContent = 'Signing key ready on this device.';
  $('mkdev').classList.add('hide');
  $('payform').classList.remove('hide');
  $('devkey').textContent = g;
  $('payee').value ||= '';
}

$('mkdev').onclick = async () => {
  try {
    device = await newDevice();
    save(STORE, { seed: hex(device.seed), pub: hex(device.publicKey) });
    showDevice();
  } catch (e) {
    $('devline').textContent = `This browser cannot make an Ed25519 key (${e.message}). Try Chrome or Safari 17+.`;
  }
};

$('forget').onclick = () => {
  if (!confirm('Forget this key? Any voucher you signed that nobody has banked yet becomes worthless.')) return;
  try { localStorage.removeItem(STORE); } catch {}
  location.reload();
};

// ---- paying
$('signbtn').onclick = async () => {
  const out = $('payout'), summary = $('paysummary');
  try {
    const payee = $('payee').value.trim().toUpperCase();
    decodeAddress(payee); // throws on a typo, which is the point
    const amount = toStroops($('amount').value);
    if (BigInt(amount) <= 0n) throw new Error('Amount must be more than zero');

    const auth = {
      payer: encodeAddress(device.publicKey),
      payee,
      amount,
      // Milliseconds since the epoch: unique per device without needing to ask
      // the chain what we have already spent, which we cannot do offline.
      nonce: String(Date.now()),
      expires: String(Math.floor(Date.now() / 1000) + 7 * 86400),
    };
    const code = pack(await sign(auth, device));
    $('code').value = code;
    out.classList.remove('hide');
    summary.textContent = `${toXLM(amount)} XLM · expires in 7 days · ${code.length} characters`;
  } catch (e) {
    out.classList.remove('hide');
    $('code').value = '';
    summary.textContent = e.message;
  }
};

$('copy').onclick = async () => {
  try { await navigator.clipboard.writeText($('code').value); $('copy').textContent = 'Copied'; }
  catch { $('code').select(); }
  setTimeout(() => ($('copy').textContent = 'Copy'), 1500);
};

// Web NFC is Android Chrome only. Say so rather than failing silently.
$('nfc').onclick = async () => {
  if (!('NDEFReader' in window)) return alert('This phone cannot send by tap. Copy the code instead.');
  try {
    await new NDEFReader().write({ records: [{ recordType: 'text', data: $('code').value }] });
    alert('Hold the phones together.');
  } catch (e) { alert(`Tap failed: ${e.message}`); }
};

// ---- accepting
$('check').onclick = async () => {
  const box = $('result');
  box.innerHTML = '';
  try {
    const v = unpack($('inp').value);
    const good = await verify(v);
    const when = Number(v.auth.expires) * 1000;
    const expired = Date.now() > when;

    if (!good) {
      box.innerHTML = `<div class="msg bad">This voucher has been altered. Do not accept it.</div>`;
      return;
    }
    box.innerHTML = `
      <div class="msg ${expired ? 'bad' : 'ok'}">
        <div class="big">${toXLM(v.auth.amount)} XLM</div>
        <div class="sub">signature checks out${expired ? ' — but it expired ' + new Date(when).toLocaleDateString() : ''}</div>
      </div>
      <p class="note mono">from ${v.auth.payer.slice(0, 8)}…${v.auth.payer.slice(-6)}<br>
      to ${v.auth.payee.slice(0, 8)}…${v.auth.payee.slice(-6)}</p>`;
    if (!expired) {
      const b = document.createElement('button');
      b.textContent = 'Accept it';
      b.onclick = () => {
        const q = load(QUEUE, []);
        if (q.some((x) => x.code === $('inp').value.trim())) return alert('Already accepted.');
        q.push({ code: $('inp').value.trim(), amount: v.auth.amount, at: Date.now() });
        save(QUEUE, q);
        $('inp').value = ''; box.innerHTML = '';
        renderQueue();
        document.querySelector('nav button[data-v=wallet]').click();
      };
      box.append(b);
    }
  } catch (e) {
    box.innerHTML = `<div class="msg bad">${e.message}</div>`;
  }
};

$('nfcread').onclick = async () => {
  if (!('NDEFReader' in window)) return alert('This phone cannot receive by tap. Paste the code instead.');
  try {
    const r = new NDEFReader();
    await r.scan();
    r.onreading = (e) => {
      for (const rec of e.message.records) {
        if (rec.recordType === 'text') {
          $('inp').value = new TextDecoder(rec.encoding || 'utf-8').decode(rec.data);
          $('check').click();
        }
      }
    };
    alert('Hold the phones together.');
  } catch (e) { alert(`Tap failed: ${e.message}`); }
};

// ---- accepted queue
function renderQueue() {
  const q = load(QUEUE, []);
  const el = $('pending');
  if (!q.length) { el.innerHTML = '<p class="sub">Nothing accepted yet.</p>'; return; }
  const total = q.reduce((a, x) => a + BigInt(x.amount), 0n);
  el.innerHTML = `<div class="big">${toXLM(total)} XLM</div>
    <div class="sub">${q.length} voucher${q.length > 1 ? 's' : ''} held on this phone, not yet banked</div>
    <p class="note">Banking them needs a connection and is not wired up yet — the SDK does it,
    the button does not. Until then these are safe here: the code is the money.</p>`;
}

// ---- views
for (const b of document.querySelectorAll('nav button')) {
  b.onclick = () => {
    for (const o of document.querySelectorAll('nav button')) o.removeAttribute('aria-current');
    b.setAttribute('aria-current', 'page');
    for (const v of ['pay', 'recv', 'wallet']) $(`v-${v}`).classList.toggle('hide', v !== b.dataset.v);
    if (b.dataset.v === 'wallet') renderQueue();
  };
}

if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
restore();
renderQueue();
