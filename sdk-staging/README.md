# lastmile-sdk

Sign a Stellar payment with no connectivity. Redeem it when signal returns.

Every Stellar payment product assumes both parties are online. Stellar's best
markets are the places where that is least true. Lastmile splits **authorisation**
from **settlement**: a phone with no signal signs a voucher, it travels by QR,
NFC or SMS, and whoever reaches a network first submits it.

```js
import { sign, pack, unpack, verify } from '@lastmile/sdk';

// On a phone with no signal. Nothing here touches the network.
const voucher = sign({
  payer:   'GDHY…',        // whose float this is drawn from
  payee:   'GB6Y…',        // who may redeem it
  amount:  '25000000',     // stroops
  nonce:   '7',            // unique per payer; reusing one is provable fraud
  expires: '1789393424',   // unix seconds
}, deviceSecret);

const code = pack(voucher);   // 246 characters -> a QR code

// On the other side, still offline: the payee can check the signature before
// accepting the goods.
verify(unpack(code));         // true
```

## What it does and does not promise

**Offline double-spend cannot be prevented in software.** That is not a gap in
this design; it is why serious offline CBDC work uses secure hardware. Two people
with no connectivity cannot agree on who spent what. Lastmile bounds and
attributes it instead:

- a voucher **names its payee**, so a photographed QR is worthless to a thief
- the payer's **float caps** what can ever be at risk
- signing two vouchers on one nonce is a **signed confession** anyone can submit
  to slash the payer's bond and revoke the key

A payer can still overspend across *distinct* nonces. Signatures cannot tell that
from ordinary overdraft, so those redemptions fail first-come-first-served. That
is the risk a shopkeeper takes on a cheque, and it is bounded by the float and the
bond. We would rather write that down than claim a guarantee the mathematics does
not support.

## Two things this library exists to get right

**The payload.** A device must compute the same 32 bytes the contract hashes, or
its signature verifies against nothing. `payload()` reimplements Soroban's XDR
encoding of the `Authorization` struct — an ScVal map with sorted symbol keys —
and is checked byte-for-byte against the deployed contract across ordinary values,
zeros, and the i128 and u64 maximums.

**Integer precision.** A u64 nonce reaches 18446744073709551615; a JavaScript
number is exact only to 9007199254740991. Put a big nonce through `JSON.parse` and
it silently becomes …551616, and the device signs a hash for an authorization
nobody wrote — no error, nothing to look at. So numeric fields are taken as
strings or BigInt, and a `number` that has already lost precision is **refused**
rather than encoded.

## Wire format

184 bytes: payer (32), payee (32), amount (8), nonce (8), expires (8), device
key (32), signature (64). That is 246 characters of base64url — comfortable in a
QR code, one NFC tap, or two SMS.

Not small enough to read aloud. A spoken code needs a scheme that looks the payee
up rather than carrying them, and that is not built yet.

## Status

Testnet. Unaudited. No mainnet deployment and no real money has moved through it.

- contract `CB5ZYVSQY2XF3BSCD4KMCQY2IJI23LQMTNBT3DO7Q4RKUDGTWDORWVPS`
- contracts and tests: https://github.com/lastmile-protocol/lastmile-contracts

`npm test` — 11 tests covering the round trip, tampering, and the precision trap.

Apache-2.0.
