# lastmile-contracts

Offline-authorised payments on Stellar. Sign a voucher with no connectivity; redeem it
when signal returns.

Every Stellar payment product assumes both parties are online. Stellar's best markets
are the places where that is least true. This splits **authorisation** from
**settlement**: a device with no signal signs an `Authorization`, it travels by QR, NFC
or SMS, and whoever reaches a network first submits it. The contract verifies the
ed25519 signature on chain before moving anything.

## Live on testnet

| | |
|---|---|
| vault | `CB5ZYVSQY2XF3BSCD4KMCQY2IJI23LQMTNBT3DO7Q4RKUDGTWDORWVPS` |
| wasm sha256 | `ac98db4da11e1f4639fd83e8e2596ec8156f0d8c83e22bc30f452f0d50b2bea4` |

[On stellar.expert](https://stellar.expert/explorer/testnet/contract/CB5ZYVSQY2XF3BSCD4KMCQY2IJI23LQMTNBT3DO7Q4RKUDGTWDORWVPS)

`live.sh` runs the whole path against that deployment: it opens a vault, registers a
device key, signs a voucher **with no transaction**, redeems it, checks the payee's
balance moved by exactly the signed amount, and confirms a replay is refused.
`live-output.txt` is the recorded run.

## Device keys

A payer opens a vault, deposits a float, and registers one or more **device keys** --
ed25519 keys held by the phone or card that will sign while offline. A device key is
deliberately *not* the payer's Stellar account key: a lost phone should mean a revoked
device, not a drained account.

## The honest part: offline double-spend

**It cannot be prevented in software.** That is not a gap in this design; it is why
every serious offline CBDC design uses secure hardware. Two parties with no
connectivity cannot agree on who spent what. So this contract *bounds* and *attributes*
it instead:

- **Payee-bound** -- an authorization names its payee, so a photographed QR code or an
  overheard code is worthless to anyone else.
- **Bounded** -- a payer can never put more at risk than the float they locked.
  Redemption beyond the remaining float fails; it cannot overdraw.
- **Provable** -- signing two different authorizations under one nonce is something an
  honest device never does. Both signatures together are a proof anyone can submit to
  `report_double_sign`, which slashes the payer's bond to the reporter and revokes the
  key.

**The residual risk, stated plainly:** a payer may also spend beyond their float using
*distinct* nonces. Signatures alone cannot tell that from ordinary overdraft, so those
redemptions fail first-come-first-served and the late payee is not paid. That is the
risk a shopkeeper takes accepting a cheque, bounded by the bond and the float. We would
rather write that sentence than claim a guarantee the mathematics does not support.

## Parallel execution

Storage keys are parameterised by payer -- `Vault(payer)`, `Device(payer, key)`,
`Spent(payer, nonce)` -- so two redemptions against different payers touch disjoint keys
and do not serialise under CAP-0063. The shared point is the token contract's own
balance entries, which is inherent to custody and not something this contract can avoid.

## Build

```
cargo test                                                      # 21 tests
cargo build -p lastmile-vault --target wasm32v1-none --release
```

Soroban SDK 23. Note that `ed25519-dalek` must be pinned to 2.x -- 3.0.0 breaks
soroban-env-host's test utilities across SDK versions.

## The rest

- sdk -- https://github.com/lastmile-protocol/lastmile-sdk
- app -- https://github.com/lastmile-protocol/lastmile-app

## Status

Testnet. Unaudited. No mainnet deployment and no real money has moved through it.

Apache-2.0.
