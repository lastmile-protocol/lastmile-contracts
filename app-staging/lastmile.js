// Lastmile, with nothing underneath it.
//
// This file deliberately has no dependencies. The Stellar JS SDK is over a
// megabyte, and an app whose whole premise is "your connection is bad" cannot
// ask you to download a megabyte before it will sign anything. So the few things
// we actually need -- strkey, the XDR encoding of one struct, sha256, ed25519 --
// are done here against Web Crypto, which every modern phone browser has.
//
// Everything in here is checked byte-for-byte against @stellar/stellar-sdk,
// which is itself checked against the deployed contract. Hand-rolled crypto that
// nobody compared to a reference is how people lose money.

const DOMAIN = new TextEncoder().encode('lastmile.v1.authorization');

// ---------------------------------------------------------------- strkey

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** CRC16-XMODEM, the checksum Stellar puts on the end of every address. */
function crc16(bytes) {
  let crc = 0;
  for (const b of bytes) {
    crc ^= b << 8;
    for (let i = 0; i < 8; i++) crc = (crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1) & 0xffff;
  }
  return crc;
}

function b32decode(s) {
  let bits = 0, value = 0;
  const out = [];
  for (const c of s) {
    const idx = B32.indexOf(c);
    if (idx === -1) throw new Error(`not a Stellar address: bad character "${c}"`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Uint8Array.from(out);
}

function b32encode(bytes) {
  let bits = 0, value = 0, out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += '=';
  return out;
}

/** G... address -> the 32 raw ed25519 bytes, checksum verified. */
export function decodeAddress(g) {
  if (typeof g !== 'string' || g[0] !== 'G' || g.length !== 56) {
    throw new Error(`not a Stellar account address: ${g}`);
  }
  const raw = b32decode(g);
  const body = raw.subarray(0, raw.length - 2);
  const want = (raw[raw.length - 2] | (raw[raw.length - 1] << 8)) & 0xffff;
  if (crc16(body) !== want) throw new Error('that address has a typo in it');
  if (body[0] !== 6 << 3) throw new Error('not an account address');
  return body.subarray(1);
}

/** 32 raw ed25519 bytes -> a G... address. */
export function encodeAddress(key) {
  const body = new Uint8Array(33);
  body[0] = 6 << 3;
  body.set(key, 1);
  const c = crc16(body);
  const full = new Uint8Array(35);
  full.set(body);
  full[33] = c & 0xff;
  full[34] = (c >>> 8) & 0xff;
  return b32encode(full).replace(/=+$/, '');
}

// ---------------------------------------------------------------- xdr

// ScVal discriminants we need. Getting one of these wrong changes the hash and
// nothing else, which is why they are checked against the reference SDK.
const SCV_U64 = 5, SCV_I128 = 10, SCV_SYMBOL = 15, SCV_MAP = 17, SCV_ADDRESS = 18;

class Writer {
  constructor() { this.parts = []; }
  u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0); this.parts.push(b); return this; }
  u64(v) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v)); this.parts.push(b); return this; }
  i64(v) { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(v)); this.parts.push(b); return this; }
  bytes(b) { this.parts.push(b); return this; }
  /** XDR pads every variable-length field out to a multiple of four. */
  padded(b) {
    this.u32(b.length).bytes(b);
    const pad = (4 - (b.length % 4)) % 4;
    if (pad) this.bytes(new Uint8Array(pad));
    return this;
  }
  done() {
    const n = this.parts.reduce((a, p) => a + p.length, 0);
    const out = new Uint8Array(n);
    let o = 0;
    for (const p of this.parts) { out.set(p, o); o += p.length; }
    return out;
  }
}

function writeSymbol(w, s) { w.u32(SCV_SYMBOL).padded(new TextEncoder().encode(s)); }
function writeU64(w, v) { w.u32(SCV_U64).u64(v); }

function writeI128(w, v) {
  // Int128Parts is { hi: int64, lo: uint64 } -- high half first.
  const x = BigInt(v);
  const lo = x & 0xffffffffffffffffn;
  const hi = x >> 64n;
  w.u32(SCV_I128).i64(hi).u64(lo);
}

function writeAddress(w, g) {
  // ScAddress::Account(AccountId::PublicKeyTypeEd25519(...)): two zero
  // discriminants, then the raw key.
  w.u32(SCV_ADDRESS).u32(0).u32(0).bytes(decodeAddress(g));
}

/** Refuse numbers JavaScript has already rounded, rather than sign a wrong hash. */
function exact(v, field) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'string') {
    if (!/^-?\d+$/.test(v.trim())) throw new TypeError(`${field}: "${v}" is not an integer`);
    return BigInt(v.trim());
  }
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) {
      throw new RangeError(`${field}: ${v} is past JavaScript's exact integer range; pass a string`);
    }
    return BigInt(v);
  }
  throw new TypeError(`${field}: expected string, number or bigint`);
}

/** Encode an Authorization exactly as the contract sees it: a map, keys sorted. */
export function encode(auth) {
  const w = new Writer();
  w.u32(SCV_MAP).u32(1).u32(5); // map, present, five entries
  writeSymbol(w, 'amount');  writeI128(w, exact(auth.amount, 'amount'));
  writeSymbol(w, 'expires'); writeU64(w, exact(auth.expires, 'expires'));
  writeSymbol(w, 'nonce');   writeU64(w, exact(auth.nonce, 'nonce'));
  writeSymbol(w, 'payee');   writeAddress(w, auth.payee);
  writeSymbol(w, 'payer');   writeAddress(w, auth.payer);
  return w.done();
}

/** The 32 bytes a device signs. */
export async function payload(auth) {
  const body = encode(auth);
  const msg = new Uint8Array(DOMAIN.length + body.length);
  msg.set(DOMAIN);
  msg.set(body, DOMAIN.length);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', msg));
}

// ---------------------------------------------------------------- keys

// A raw ed25519 seed wrapped as PKCS#8, which is the only private format Web
// Crypto will import. The prefix is fixed; only the 32 seed bytes change.
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
  0x04, 0x22, 0x04, 0x20,
]);

/** Import a 32-byte seed as a signing key. */
export async function importDevice(seed) {
  if (seed.length !== 32) throw new Error('a device seed is 32 bytes');
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + 32);
  pkcs8.set(PKCS8_PREFIX);
  pkcs8.set(seed, PKCS8_PREFIX.length);
  return crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
}

/**
 * Make a new device key.
 *
 * This is the key that signs while you have no signal. It is deliberately not
 * your Stellar account key: if the phone is stolen you revoke a device, you do
 * not lose an account.
 */
export async function newDevice() {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  return { seed, key: await importDevice(seed), publicKey: await publicKeyOf(seed) };
}

/**
 * The 32-byte public key for a seed.
 *
 * Web Crypto has no seed-to-public shortcut, but exporting an imported private
 * key as a JWK yields both halves, so import a throwaway extractable copy and
 * read `x` off it. The key actually used for signing stays non-extractable.
 */
export async function publicKeyOf(seed) {
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + 32);
  pkcs8.set(PKCS8_PREFIX);
  pkcs8.set(seed, PKCS8_PREFIX.length);
  const tmp = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', tmp);
  if (!jwk.x) throw new Error('this browser cannot derive an Ed25519 public key');
  return unb64url(jwk.x);
}

function b64url(u8) {
  return btoa(String.fromCharCode(...u8)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function unb64url(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

// ---------------------------------------------------------------- signing

/** Sign an authorization. Nothing here touches the network. */
export async function sign(auth, device) {
  const sig = new Uint8Array(await crypto.subtle.sign('Ed25519', device.key, await payload(auth)));
  return { auth, device: hex(device.publicKey), sig: hex(sig) };
}

/** Check a voucher's signature. Also offline -- the payee can check before handing over goods. */
export async function verify(v) {
  try {
    const pub = await crypto.subtle.importKey('raw', unhex(v.device), { name: 'Ed25519' }, false, ['verify']);
    return crypto.subtle.verify('Ed25519', pub, unhex(v.sig), await payload(v.auth));
  } catch {
    return false;
  }
}

export const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
export const unhex = (s) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));

// ---------------------------------------------------------------- transport

// 184 bytes: payer 32, payee 32, amount 8, nonce 8, expires 8, device 32, sig 64.
const OFF = { payer: 0, payee: 32, amount: 64, nonce: 72, expires: 80, device: 88, sig: 120 };
export const PACKED_BYTES = 184;
const MAX_AMOUNT = (1n << 63n) - 1n;

/** Pack a voucher small enough to carry: 246 base64url characters. */
export function pack(v) {
  const amount = exact(v.auth.amount, 'amount');
  if (amount < 0n || amount > MAX_AMOUNT) throw new RangeError(`amount ${amount} does not fit`);
  const b = new Uint8Array(PACKED_BYTES);
  const dv = new DataView(b.buffer);
  b.set(decodeAddress(v.auth.payer), OFF.payer);
  b.set(decodeAddress(v.auth.payee), OFF.payee);
  dv.setBigInt64(OFF.amount, amount);
  dv.setBigUint64(OFF.nonce, exact(v.auth.nonce, 'nonce'));
  dv.setBigUint64(OFF.expires, exact(v.auth.expires, 'expires'));
  const dev = unhex(v.device), sig = unhex(v.sig);
  if (dev.length !== 32) throw new TypeError(`device key should be 32 bytes, got ${dev.length}`);
  if (sig.length !== 64) throw new TypeError(`signature should be 64 bytes, got ${sig.length}`);
  b.set(dev, OFF.device);
  b.set(sig, OFF.sig);
  return b64url(b);
}

/** Recover a voucher from its packed form. */
export function unpack(s) {
  let b;
  // Whoever is holding this phone did not mistype base64url; they pasted the
  // wrong thing, or half of it. Say that, not "InvalidCharacterError".
  try { b = unb64url(String(s).trim()); }
  catch { throw new TypeError('That does not look like a voucher code.'); }
  if (b.length !== PACKED_BYTES) {
    throw new TypeError(
      b.length < PACKED_BYTES
        ? 'That voucher code is incomplete — some of it is missing.'
        : 'That does not look like a voucher code.',
    );
  }
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  return {
    auth: {
      payer: encodeAddress(b.subarray(OFF.payer, OFF.payer + 32)),
      payee: encodeAddress(b.subarray(OFF.payee, OFF.payee + 32)),
      amount: dv.getBigInt64(OFF.amount).toString(),
      nonce: dv.getBigUint64(OFF.nonce).toString(),
      expires: dv.getBigUint64(OFF.expires).toString(),
    },
    device: hex(b.subarray(OFF.device, OFF.device + 32)),
    sig: hex(b.subarray(OFF.sig, OFF.sig + 64)),
  };
}
