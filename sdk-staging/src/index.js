// Lastmile — offline-authorised payments on Stellar.
//
// The whole library exists to let a phone with no signal produce a payment that
// a contract will honour later. That splits into three jobs:
//
//   1. compute the exact bytes the contract will hash   (payload)
//   2. sign them without touching the network            (sign)
//   3. carry the result to someone, somehow              (pack / unpack)
//
// Only the fourth job -- redeeming -- needs connectivity, and whoever has it can
// do it: the payee, the payer, or a shopkeeper with a data bundle. The signature
// is the authority, not the sender.

import { Address, Keypair, StrKey, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { createHash } from 'node:crypto';

export const TESTNET = {
  rpc: 'https://soroban-testnet.stellar.org',
  passphrase: 'Test SDF Network ; September 2015',
};

/** Mixed into every signed payload so a Lastmile signature is only ever that. */
const DOMAIN = Buffer.from('lastmile.v1.authorization');

/** Contract error codes, so callers can branch on meaning rather than parse strings. */
export const ERRORS = {
  1: 'no vault for that payer',
  2: 'that payer already has a vault',
  3: 'the signing device is unknown or has been revoked',
  4: 'the signature does not verify',
  5: 'this voucher has expired',
  6: 'this nonce has already been redeemed',
  7: 'the vault does not have enough float left',
  8: 'amounts must be positive',
  9: 'those two authorizations are not a double-sign',
  10: 'there is no bond left to slash',
  11: 'that device key is already registered',
};

export class LastmileError extends Error {
  constructor(code, detail) {
    super(ERRORS[code] ?? detail ?? `contract error ${code}`);
    this.name = 'LastmileError';
    this.code = code;
  }
}

// ---------------------------------------------------------------- numbers

/**
 * Coerce to BigInt, refusing anything a JS number has already corrupted.
 *
 * A u64 nonce reaches 18446744073709551615; a JS number is only exact to
 * 9007199254740991. Past that, `JSON.parse` rounds silently and you sign a hash
 * for an authorization nobody wrote -- no error, nothing to see, just a
 * signature that verifies against nothing. So refuse rather than encode.
 */
function exact(v, field) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'string') {
    if (!/^-?\d+$/.test(v.trim())) throw new TypeError(`${field}: "${v}" is not an integer`);
    return BigInt(v.trim());
  }
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) {
      throw new RangeError(
        `${field}: ${v} is past JavaScript's exact integer range, so it may already ` +
          `be wrong. Pass it as a string or BigInt.`,
      );
    }
    return BigInt(v);
  }
  throw new TypeError(`${field}: expected string, number or bigint`);
}

// ---------------------------------------------------------------- payload

/**
 * Encode an Authorization exactly as the contract sees it.
 *
 * A Soroban contracttype struct is an ScVal map whose symbol keys are sorted.
 * The sort order is load-bearing: get it wrong and the hash differs silently.
 */
export function encode(auth) {
  const entries = [
    ['amount', nativeToScVal(exact(auth.amount, 'amount'), { type: 'i128' })],
    ['expires', nativeToScVal(exact(auth.expires, 'expires'), { type: 'u64' })],
    ['nonce', nativeToScVal(exact(auth.nonce, 'nonce'), { type: 'u64' })],
    ['payee', new Address(auth.payee).toScVal()],
    ['payer', new Address(auth.payer).toScVal()],
  ].map(([k, v]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: v }));
  return xdr.ScVal.scvMap(entries).toXDR();
}

/** The 32 bytes a device signs. Verified byte-for-byte against the deployed contract. */
export function payload(auth) {
  return createHash('sha256').update(Buffer.concat([DOMAIN, encode(auth)])).digest();
}

// ---------------------------------------------------------------- signing

/**
 * Sign an authorization offline.
 *
 * `device` is a Stellar secret seed, which is an ed25519 key -- the same kind the
 * contract stores. It is deliberately not the payer's account key: a stolen phone
 * should mean a revoked device, not a drained account.
 */
export function sign(auth, device) {
  const kp = typeof device === 'string' ? Keypair.fromSecret(device) : device;
  return {
    auth,
    // Buffer.from matters: sign() returns a Uint8Array, whose toString('hex')
    // quietly yields comma-separated decimals instead of hex.
    device: Buffer.from(kp.rawPublicKey()).toString('hex'),
    sig: Buffer.from(kp.sign(payload(auth))).toString('hex'),
  };
}

/** Check a voucher's signature locally, with no network. */
export function verify(voucher) {
  const kp = Keypair.fromPublicKey(
    StrKey.encodeEd25519PublicKey(Buffer.from(voucher.device, 'hex')),
  );
  return kp.verify(payload(voucher.auth), Buffer.from(voucher.sig, 'hex'));
}

// ---------------------------------------------------------------- transport

// Wire layout, 184 bytes:
//   0   payer      32   raw ed25519
//   32  payee      32
//   64  amount      8   stroops, big-endian signed
//   72  nonce       8
//   80  expires     8
//   88  device     32   the key that signed
//   120 signature  64
const OFF = { payer: 0, payee: 32, amount: 64, nonce: 72, expires: 80, device: 88, sig: 120 };
export const PACKED_BYTES = 184;

/** Largest amount the wire format carries: ~922 billion XLM, in stroops. */
const MAX_AMOUNT = (1n << 63n) - 1n;

/**
 * Pack a voucher into bytes small enough to carry.
 *
 * 184 bytes, so about 246 characters of base64url: comfortable in a QR code, one
 * NFC tap, or two SMS. Not small enough to read aloud -- a spoken code needs a
 * scheme that looks the payee up rather than carrying them, which is not built
 * yet and would be dishonest to claim.
 *
 * The contract's `amount` is an i128; this format carries 64 bits of it. That is
 * ~922 billion XLM, far past any offline float, and an amount above it is
 * rejected here rather than silently truncated on its way to a signature.
 */
export function pack(v) {
  const amount = exact(v.auth.amount, 'amount');
  if (amount < 0n || amount > MAX_AMOUNT) {
    throw new RangeError(`amount ${amount} does not fit the wire format (max ${MAX_AMOUNT})`);
  }
  const b = Buffer.alloc(PACKED_BYTES);
  Buffer.from(StrKey.decodeEd25519PublicKey(v.auth.payer)).copy(b, OFF.payer);
  Buffer.from(StrKey.decodeEd25519PublicKey(v.auth.payee)).copy(b, OFF.payee);
  b.writeBigInt64BE(amount, OFF.amount);
  b.writeBigUInt64BE(exact(v.auth.nonce, 'nonce'), OFF.nonce);
  b.writeBigUInt64BE(exact(v.auth.expires, 'expires'), OFF.expires);

  const dev = Buffer.from(v.device, 'hex');
  const sig = Buffer.from(v.sig, 'hex');
  if (dev.length !== 32) throw new TypeError(`device key should be 32 bytes, got ${dev.length}`);
  if (sig.length !== 64) throw new TypeError(`signature should be 64 bytes, got ${sig.length}`);
  dev.copy(b, OFF.device);
  sig.copy(b, OFF.sig);
  return b.toString('base64url');
}

/** Recover a voucher from its packed form. */
export function unpack(s) {
  const b = Buffer.from(s, 'base64url');
  if (b.length !== PACKED_BYTES) {
    throw new TypeError(`voucher should be ${PACKED_BYTES} bytes, got ${b.length}`);
  }
  return {
    auth: {
      payer: StrKey.encodeEd25519PublicKey(b.subarray(OFF.payer, OFF.payer + 32)),
      payee: StrKey.encodeEd25519PublicKey(b.subarray(OFF.payee, OFF.payee + 32)),
      amount: b.readBigInt64BE(OFF.amount).toString(),
      nonce: b.readBigUInt64BE(OFF.nonce).toString(),
      expires: b.readBigUInt64BE(OFF.expires).toString(),
    },
    device: b.subarray(OFF.device, OFF.device + 32).toString('hex'),
    sig: b.subarray(OFF.sig, OFF.sig + 64).toString('hex'),
  };
}
