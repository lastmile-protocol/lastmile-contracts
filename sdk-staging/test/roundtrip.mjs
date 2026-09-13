// What a voucher has to survive.
//
// Between signing and redeeming, a voucher gets squeezed into a QR code,
// photographed, maybe retyped, and carried around for a day. These check that it
// comes out the other side meaning exactly what it meant going in -- and that a
// voucher somebody has edited does not.

import assert from 'node:assert/strict';
import test from 'node:test';
import { Keypair } from '@stellar/stellar-sdk';
import { sign, verify, pack, unpack, payload, encode, PACKED_BYTES } from '../src/index.js';

const payer = Keypair.random();
const payee = Keypair.random();
const device = Keypair.random();

const auth = () => ({
  payer: payer.publicKey(),
  payee: payee.publicKey(),
  amount: '25000000',
  // Deliberately the u64 maximum: this is the value that rounds silently if it
  // ever passes through a JavaScript number.
  nonce: '18446744073709551615',
  expires: '1789393424',
});

test('a signed voucher verifies', () => {
  assert.ok(verify(sign(auth(), device.secret())));
});

test('packing is exactly the size we claim', () => {
  const s = pack(sign(auth(), device.secret()));
  assert.equal(Buffer.from(s, 'base64url').length, PACKED_BYTES);
  assert.ok(s.length < 260, `base64url should stay QR-sized, got ${s.length}`);
});

test('every field survives the round trip', () => {
  const v = sign(auth(), device.secret());
  const back = unpack(pack(v));
  assert.deepEqual(back.auth, auth());
  assert.equal(back.device, v.device);
  assert.equal(back.sig, v.sig);
});

test('the maximum nonce is not rounded away', () => {
  const back = unpack(pack(sign(auth(), device.secret())));
  assert.equal(back.auth.nonce, '18446744073709551615');
});

test('a voucher still verifies after being packed and unpacked', () => {
  assert.ok(verify(unpack(pack(sign(auth(), device.secret())))));
});

test('the payload is identical before and after transport', () => {
  const v = sign(auth(), device.secret());
  assert.ok(payload(unpack(pack(v)).auth).equals(payload(v.auth)));
});

test('editing the amount breaks the signature', () => {
  const v = unpack(pack(sign(auth(), device.secret())));
  v.auth.amount = '25000001';
  assert.equal(verify(v), false);
});

test('redirecting the payee breaks the signature', () => {
  const v = unpack(pack(sign(auth(), device.secret())));
  v.auth.payee = payer.publicKey();
  assert.equal(verify(v), false);
});

test('another device cannot pass off a voucher as its own', () => {
  const v = sign(auth(), device.secret());
  v.device = Buffer.from(Keypair.random().rawPublicKey()).toString('hex');
  assert.equal(verify(v), false);
});

test('a number past JavaScript precision is refused, not encoded', () => {
  assert.throws(
    () => encode({ ...auth(), nonce: 18446744073709551615 }),
    /exact integer range/,
    'a lossy number must fail loudly rather than produce a wrong hash',
  );
});

test('malformed vouchers are rejected', () => {
  const v = sign(auth(), device.secret());
  assert.throws(() => pack({ ...v, device: 'aabb' }), /32 bytes/);
  assert.throws(() => pack({ ...v, sig: 'aabb' }), /64 bytes/);
  assert.throws(() => unpack('tooshort'), /184 bytes/);
  assert.throws(
    () => pack({ ...v, auth: { ...auth(), amount: '99999999999999999999' } }),
    /does not fit the wire format/,
  );
});
