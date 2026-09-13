// The one thing the SDK must get exactly right.
//
// A device with no connectivity has to compute the same 32 bytes the contract
// computes, or its signature verifies against nothing. The contract does:
//
//     sha256( b"lastmile.v1.authorization" || xdr(Authorization) )
//
// so this reimplements Soroban's XDR encoding of that struct in JavaScript.
// A contracttype struct encodes as an ScVal map whose keys are symbols in
// sorted order -- get the order wrong and the hash silently differs.
//
// # Why the fuss about numbers
//
// A u64 nonce goes up to 18446744073709551615. A JavaScript number stops being
// exact at 9007199254740991. Feed a big nonce through `JSON.parse` and it is
// silently rounded -- 18446744073709551615 becomes ...551616 -- and you sign a
// hash for an authorization nobody asked for. There is no error and no wrong
// answer to look at, just a signature that verifies against nothing.
//
// So: numeric fields are accepted as strings or BigInt, and a plain `number`
// that has already lost precision is rejected loudly rather than encoded.

import { Address, nativeToScVal, xdr } from '@stellar/stellar-sdk';
import { createHash } from 'node:crypto';

const DOMAIN = Buffer.from('lastmile.v1.authorization');

/** Coerce to BigInt, refusing values a JS number has already corrupted. */
function exact(v, field) {
  if (typeof v === 'bigint') return v;
  if (typeof v === 'string') {
    if (!/^-?\d+$/.test(v.trim())) {
      throw new TypeError(`${field}: "${v}" is not an integer`);
    }
    return BigInt(v.trim());
  }
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) {
      throw new RangeError(
        `${field}: ${v} is past JavaScript's exact integer range, so it may ` +
          `already be wrong. Pass it as a string or BigInt.`,
      );
    }
    return BigInt(v);
  }
  throw new TypeError(`${field}: expected string, number or bigint`);
}

/** Encode an Authorization exactly as the contract sees it. */
export function encode(auth) {
  // Sorted by key, because that is what Soroban does and the hash depends on it.
  const entries = [
    ['amount', nativeToScVal(exact(auth.amount, 'amount'), { type: 'i128' })],
    ['expires', nativeToScVal(exact(auth.expires, 'expires'), { type: 'u64' })],
    ['nonce', nativeToScVal(exact(auth.nonce, 'nonce'), { type: 'u64' })],
    ['payee', new Address(auth.payee).toScVal()],
    ['payer', new Address(auth.payer).toScVal()],
  ].map(([k, v]) => new xdr.ScMapEntry({ key: xdr.ScVal.scvSymbol(k), val: v }));

  return xdr.ScVal.scvMap(entries).toXDR();
}

/** The 32 bytes a device signs. */
export function payload(auth) {
  return createHash('sha256')
    .update(Buffer.concat([DOMAIN, encode(auth)]))
    .digest();
}

/**
 * Parse an Authorization from JSON *text*.
 *
 * Deliberately not `JSON.parse` for the numbers: they are lifted straight out of
 * the source text as digit strings, so a u64 near its maximum survives the trip.
 */
export function fromJson(text) {
  const digits = (name) => {
    const m = text.match(new RegExp(`"${name}"\\s*:\\s*"?(-?\\d+)"?`));
    if (!m) throw new TypeError(`missing field ${name}`);
    return m[1];
  };
  const str = (name) => {
    const m = text.match(new RegExp(`"${name}"\\s*:\\s*"([^"]+)"`));
    if (!m) throw new TypeError(`missing field ${name}`);
    return m[1];
  };
  return {
    payer: str('payer'),
    payee: str('payee'),
    amount: digits('amount'),
    nonce: digits('nonce'),
    expires: digits('expires'),
  };
}

// Run directly to print the payload for an auth passed as JSON.
if (process.argv[2]) {
  process.stdout.write(payload(fromJson(process.argv[2])).toString('hex'));
}
