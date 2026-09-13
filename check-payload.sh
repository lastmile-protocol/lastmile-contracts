#!/usr/bin/env bash
# Does the JavaScript payload match what the contract computes?
#
# If these ever disagree, every voucher signed offline is worthless, so this
# checks several shapes rather than one happy case.
set -uo pipefail
export PATH="$HOME/bin:$PATH"
V=$(grep '^vault:' DEPLOYED.txt | cut -d' ' -f2)
N="--network testnet"
P=$(stellar keys address deployer)
Q=$(stellar keys address payee)

fail=0
try() {
  local auth="$1" label="$2"
  local chain js
  chain=$(stellar contract invoke --id "$V" --source deployer $N --send=no -- \
            signing_payload --auth "$auth" 2>/dev/null | tr -d '"')
  js=$(node payload.mjs "$auth")
  if [ -z "$chain" ]; then
    echo "  $label: CONTRACT CALL FAILED"; fail=1; return
  fi
  if [ "$chain" = "$js" ]; then
    echo "  $label: match  ${chain:0:16}..."
  else
    echo "  $label: MISMATCH"
    echo "    chain $chain"
    echo "    js    $js"
    fail=1
  fi
}

echo "comparing local encoding against the deployed contract"
try "{\"payer\":\"$P\",\"payee\":\"$Q\",\"amount\":\"25000000\",\"nonce\":1,\"expires\":1789393424}" "ordinary"
try "{\"payer\":\"$P\",\"payee\":\"$Q\",\"amount\":\"1\",\"nonce\":0,\"expires\":0}" "minimums"
try "{\"payer\":\"$P\",\"payee\":\"$Q\",\"amount\":\"170141183460469231731687303715884105727\",\"nonce\":18446744073709551615,\"expires\":18446744073709551615}" "maximums"
try "{\"payer\":\"$P\",\"payee\":\"$P\",\"amount\":\"999999999999\",\"nonce\":4294967296,\"expires\":2000000000}" "self-pay, big nonce"

if [ $fail -eq 0 ]; then echo "ALL PAYLOADS MATCH"; else echo "PAYLOAD MISMATCH - THE SDK WOULD BE BROKEN"; fi
exit $fail
