#!/usr/bin/env bash
# Prove the whole offline path against live Stellar testnet.
#
# Nothing here is mocked: a real ed25519 device key signs a real Authorization
# with no transaction, and the deployed contract verifies that signature on chain
# before moving real testnet XLM.
set -uo pipefail
export PATH="$HOME/bin:$PATH"

V=$(grep '^vault:' DEPLOYED.txt | cut -d' ' -f2)
N="--network testnet"
NATIVE=$(stellar contract id asset --asset native $N)
say() { printf '\n=== %s\n' "$1"; }

say "setting up three parties"
for k in payee device; do
  stellar keys generate "$k" $N --fund --overwrite >/dev/null 2>&1 || true
done
PAYER=$(stellar keys address deployer)
PAYEE=$(stellar keys address payee)
DEVG=$(stellar keys address device)
DEVS=$(stellar keys show device)

# A Stellar key IS an ed25519 key, so the device key is just a keypair whose raw
# 32 bytes the contract stores. That is the whole trick: no special hardware.
DEV=$(node -e 'const{StrKey}=require("@stellar/stellar-sdk");process.stdout.write(Buffer.from(StrKey.decodeEd25519PublicKey(process.argv[1])).toString("hex"))' "$DEVG")
echo "payer  $PAYER"
echo "payee  $PAYEE"
echo "device $DEV"

say "opening a vault: 10 XLM of float, 5 XLM of bond"
stellar contract invoke --id "$V" --source deployer $N -- \
  open --payer "$PAYER" --token "$NATIVE" --float 100000000 --bond 50000000 >/dev/null
stellar contract invoke --id "$V" --source deployer $N --send=no -- vault_of --payer "$PAYER"

say "registering the device key"
stellar contract invoke --id "$V" --source deployer $N -- \
  add_device --payer "$PAYER" --device "$DEV" >/dev/null
stellar contract invoke --id "$V" --source deployer $N --send=no -- \
  is_device --payer "$PAYER" --device "$DEV"

stellar contract invoke --id "$V" --source deployer $N -- top_up --payer "$PAYER" --amount 100000000 >/dev/null 2>&1 || true
EXP=$(( $(date +%s) + 86400 ))
AUTH="{\"payer\":\"$PAYER\",\"payee\":\"$PAYEE\",\"amount\":\"25000000\",\"nonce\":${NONCE},\"expires\":$EXP}"

say "the offline step: signing 2.5 XLM to the payee"
PAYLOAD=$(stellar contract invoke --id "$V" --source deployer $N --send=no -- \
  signing_payload --auth "$AUTH" | tr -d '"')
echo "payload $PAYLOAD"
SIG=$(node -e '
const {Keypair} = require("@stellar/stellar-sdk");
const kp = Keypair.fromSecret(process.argv[1]);
process.stdout.write(Buffer.from(kp.sign(Buffer.from(process.argv[2],"hex"))).toString("hex"));
' "$DEVS" "$PAYLOAD")
echo "signature $SIG"

say "balances before"
BEFORE=$(stellar contract invoke --id "$NATIVE" --source deployer $N --send=no -- balance --id "$PAYEE" | tr -d '"')
echo "payee $BEFORE"

say "redeeming — submitted by the payer, but the signature is the authority"
stellar contract invoke --id "$V" --source deployer $N -- \
  redeem --auth "$AUTH" --device "$DEV" --sig "$SIG" >/dev/null

say "balances after"
AFTER=$(stellar contract invoke --id "$NATIVE" --source deployer $N --send=no -- balance --id "$PAYEE" | tr -d '"')
echo "payee $AFTER"
echo "delta $(( AFTER - BEFORE )) stroops (expected 25000000)"
test $(( AFTER - BEFORE )) -eq 25000000 || { echo "PAYEE NOT PAID CORRECTLY"; exit 1; }

say "the nonce is burnt and the float has fallen"
stellar contract invoke --id "$V" --source deployer $N --send=no -- is_spent --payer "$PAYER" --nonce $NONCE
stellar contract invoke --id "$V" --source deployer $N --send=no -- vault_of --payer "$PAYER"

say "replaying the same voucher must fail"
if stellar contract invoke --id "$V" --source deployer $N -- \
     redeem --auth "$AUTH" --device "$DEV" --sig "$SIG" >/dev/null 2>&1; then
  echo "REPLAY SUCCEEDED - THIS IS A BUG"; exit 1
else
  echo "refused, as it must be"
fi

say "ALL LIVE CHECKS PASSED"
echo "contract https://stellar.expert/explorer/testnet/contract/$V"
