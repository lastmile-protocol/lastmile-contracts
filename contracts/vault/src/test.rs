#![cfg(test)]

// The contract is no_std; its tests are not. Pulling std in here buys Vec and
// format! for the harness without any of it reaching the wasm.
extern crate std;

use std::vec::Vec;

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger as _},
    token::{StellarAssetClient, TokenClient},
    Env,
};

// ed25519 signing for the tests. The contract only ever sees a public key and a
// signature, so the tests need to produce real ones — a stub would prove nothing.
use ed25519_dalek::{Signer, SigningKey};

const DAY: u64 = 86_400;

struct Fix {
    env: Env,
    vault: ContractClient<'static>,
    token: TokenClient<'static>,
    mint: StellarAssetClient<'static>,
    token_id: Address,
}

fn setup() -> Fix {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000_000);

    let issuer = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(issuer);
    let token_id = sac.address();

    let vault_id = env.register(Contract, ());
    Fix {
        vault: ContractClient::new(&env, &vault_id),
        token: TokenClient::new(&env, &token_id),
        mint: StellarAssetClient::new(&env, &token_id),
        token_id,
        env,
    }
}

/// A device: an ed25519 keypair that will sign while offline.
fn device(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey(env: &Env, k: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &k.verifying_key().to_bytes())
}

/// Sign an authorization the way an offline device would: compute the payload,
/// sign it, and never touch the network.
fn sign(env: &Env, k: &SigningKey, payload: &BytesN<32>) -> BytesN<64> {
    let sig = k.sign(&payload.to_array());
    BytesN::from_array(env, &sig.to_bytes())
}

fn auth(f: &Fix, payer: &Address, payee: &Address, amount: i128, nonce: u64) -> Authorization {
    Authorization {
        payer: payer.clone(),
        payee: payee.clone(),
        amount,
        nonce,
        expires: f.env.ledger().timestamp() + 7 * DAY,
    }
}

/// Open a funded vault with one registered device.
fn funded(f: &Fix, float: i128, bond: i128) -> (Address, SigningKey) {
    let payer = Address::generate(&f.env);
    f.mint.mint(&payer, &(float + bond + 10_000));
    f.vault.open(&payer, &f.token_id, &float, &bond);
    let dev = device(7);
    f.vault.add_device(&payer, &pubkey(&f.env, &dev));
    (payer, dev)
}

// ---------------------------------------------------------------- happy path

#[test]
fn a_voucher_signed_offline_pays_out_when_it_reaches_the_network() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 2_000);
    let payee = Address::generate(&f.env);

    // Offline: the device signs. Nothing below this line touches the network.
    let a = auth(&f, &payer, &payee, 2_500, 1);
    let payload = f.vault.signing_payload(&a);
    let sig = sign(&f.env, &dev, &payload);

    // Later, somewhere with signal.
    f.vault.redeem(&a, &pubkey(&f.env, &dev), &sig);

    assert_eq!(
        f.token.balance(&payee),
        2_500,
        "the payee should be paid in full"
    );
    assert_eq!(
        f.vault.vault_of(&payer).float,
        7_500,
        "float should fall by exactly the amount"
    );
    assert!(f.vault.is_spent(&payer, &1), "the nonce should be burnt");
}

#[test]
fn anyone_may_submit_a_voucher_not_only_the_payee() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 0);
    let payee = Address::generate(&f.env);

    let a = auth(&f, &payer, &payee, 1_000, 1);
    let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));

    // No `require_auth` anywhere in redeem: the signature is the authority. This
    // matters because the payee may never get online at all — a passing agent,
    // a bus driver, a shopkeeper with a data bundle can carry it in for them.
    f.vault.redeem(&a, &pubkey(&f.env, &dev), &sig);
    assert_eq!(f.token.balance(&payee), 1_000);
}

#[test]
fn a_payee_can_spend_their_whole_float_across_many_vouchers() {
    let f = setup();
    let (payer, dev) = funded(&f, 3_000, 0);
    let pk = pubkey(&f.env, &dev);

    for n in 1..=3u64 {
        let payee = Address::generate(&f.env);
        let a = auth(&f, &payer, &payee, 1_000, n);
        let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));
        f.vault.redeem(&a, &pk, &sig);
        assert_eq!(f.token.balance(&payee), 1_000);
    }
    assert_eq!(
        f.vault.vault_of(&payer).float,
        0,
        "the float should be exactly exhausted"
    );
}

// ------------------------------------------------------------------ refusals

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn the_same_nonce_cannot_be_redeemed_twice() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 0);
    let payee = Address::generate(&f.env);
    let pk = pubkey(&f.env, &dev);

    let a = auth(&f, &payer, &payee, 1_000, 1);
    let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));
    f.vault.redeem(&a, &pk, &sig);
    f.vault.redeem(&a, &pk, &sig);
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn a_voucher_cannot_overdraw_the_float() {
    let f = setup();
    let (payer, dev) = funded(&f, 1_000, 0);
    let payee = Address::generate(&f.env);
    let a = auth(&f, &payer, &payee, 1_001, 1);
    let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));
    f.vault.redeem(&a, &pubkey(&f.env, &dev), &sig);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn an_expired_voucher_is_refused() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 0);
    let payee = Address::generate(&f.env);
    let a = auth(&f, &payer, &payee, 1_000, 1);
    let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));

    f.env
        .ledger()
        .set_timestamp(f.env.ledger().timestamp() + 8 * DAY);
    f.vault.redeem(&a, &pubkey(&f.env, &dev), &sig);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn a_revoked_device_cannot_spend() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 0);
    let payee = Address::generate(&f.env);
    let pk = pubkey(&f.env, &dev);

    let a = auth(&f, &payer, &payee, 1_000, 1);
    let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));

    // The phone is stolen. Vouchers it signed but nobody redeemed die with it.
    f.vault.revoke_device(&payer, &pk);
    f.vault.redeem(&a, &pk, &sig);
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn an_unregistered_key_cannot_spend() {
    let f = setup();
    let (payer, _dev) = funded(&f, 10_000, 0);
    let payee = Address::generate(&f.env);
    let stranger = device(99);

    let a = auth(&f, &payer, &payee, 1_000, 1);
    let sig = sign(&f.env, &stranger, &f.vault.signing_payload(&a));
    f.vault.redeem(&a, &pubkey(&f.env, &stranger), &sig);
}

#[test]
#[should_panic]
fn a_tampered_amount_breaks_the_signature() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 0);
    let payee = Address::generate(&f.env);

    let honest = auth(&f, &payer, &payee, 1_000, 1);
    let sig = sign(&f.env, &dev, &f.vault.signing_payload(&honest));

    // A payee who inflates the amount after the fact holds a signature over the
    // old payload. This is why the amount is inside the signed object.
    let greedy = Authorization {
        amount: 9_000,
        ..honest
    };
    f.vault.redeem(&greedy, &pubkey(&f.env, &dev), &sig);
}

#[test]
#[should_panic]
fn a_voucher_cannot_be_redirected_to_another_payee() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 0);
    let payee = Address::generate(&f.env);
    let thief = Address::generate(&f.env);

    let a = auth(&f, &payer, &payee, 1_000, 1);
    let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));

    // Someone photographs the QR code off a market stall counter. Naming the
    // payee inside the signed object is what makes that worthless.
    let stolen = Authorization { payee: thief, ..a };
    f.vault.redeem(&stolen, &pubkey(&f.env, &dev), &sig);
}

// -------------------------------------------------------------- double-sign

#[test]
fn double_signing_one_nonce_slashes_the_bond_to_whoever_proves_it() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 2_000);
    let pk = pubkey(&f.env, &dev);

    let first = Address::generate(&f.env);
    let second = Address::generate(&f.env);

    // The payer walks between two stalls with no signal and signs the same nonce
    // to both. Only one of these can ever be paid.
    let a = auth(&f, &payer, &first, 1_000, 42);
    let b = auth(&f, &payer, &second, 1_000, 42);
    let sig_a = sign(&f.env, &dev, &f.vault.signing_payload(&a));
    let sig_b = sign(&f.env, &dev, &f.vault.signing_payload(&b));

    // First to town wins.
    f.vault.redeem(&a, &pk, &sig_a);
    assert_eq!(f.token.balance(&first), 1_000);

    // The second vendor is out of pocket — but holds a signed confession.
    f.vault
        .report_double_sign(&pk, &a, &sig_a, &b, &sig_b, &second);

    assert_eq!(
        f.token.balance(&second),
        2_000,
        "the bond should go to the reporter"
    );
    assert_eq!(f.vault.vault_of(&payer).bond, 0, "the bond should be spent");
    assert!(
        !f.vault.is_device(&payer, &pk),
        "a device that double-signs should never sign again"
    );
}

#[test]
fn a_double_sign_can_be_proven_before_either_voucher_is_redeemed() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 1_500);
    let pk = pubkey(&f.env, &dev);
    let watcher = Address::generate(&f.env);

    let a = auth(&f, &payer, &Address::generate(&f.env), 500, 9);
    let b = auth(&f, &payer, &Address::generate(&f.env), 500, 9);
    let sig_a = sign(&f.env, &dev, &f.vault.signing_payload(&a));
    let sig_b = sign(&f.env, &dev, &f.vault.signing_payload(&b));

    // No redemption first: the proof stands on the signatures alone.
    f.vault
        .report_double_sign(&pk, &a, &sig_a, &b, &sig_b, &watcher);
    assert_eq!(f.token.balance(&watcher), 1_500);
}

#[test]
#[should_panic(expected = "Error(Contract, #9)")]
fn submitting_the_same_voucher_twice_is_not_a_double_sign() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 1_000);
    let pk = pubkey(&f.env, &dev);
    let payee = Address::generate(&f.env);

    let a = auth(&f, &payer, &payee, 500, 3);
    let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));

    // An identical pair proves nothing and must not be a way to grab a bond.
    f.vault.report_double_sign(&pk, &a, &sig, &a, &sig, &payee);
}

#[test]
#[should_panic(expected = "Error(Contract, #9)")]
fn two_honest_vouchers_on_different_nonces_are_not_a_double_sign() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 1_000);
    let pk = pubkey(&f.env, &dev);
    let payee = Address::generate(&f.env);

    let a = auth(&f, &payer, &payee, 500, 1);
    let b = auth(&f, &payer, &payee, 500, 2);
    let sig_a = sign(&f.env, &dev, &f.vault.signing_payload(&a));
    let sig_b = sign(&f.env, &dev, &f.vault.signing_payload(&b));

    f.vault
        .report_double_sign(&pk, &a, &sig_a, &b, &sig_b, &payee);
}

// ------------------------------------------------------ the accounting holds

#[test]
fn the_contract_never_holds_more_or_less_than_it_owes() {
    let f = setup();
    let (payer, dev) = funded(&f, 5_000, 1_000);
    let pk = pubkey(&f.env, &dev);
    let id = f.vault.address.clone();

    assert_eq!(
        f.token.balance(&id),
        6_000,
        "float plus bond, and nothing else"
    );

    let payee = Address::generate(&f.env);
    let a = auth(&f, &payer, &payee, 2_000, 1);
    let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));
    f.vault.redeem(&a, &pk, &sig);

    let v = f.vault.vault_of(&payer);
    assert_eq!(
        f.token.balance(&id),
        v.float + v.bond,
        "held balance must always equal the sum of what the vault says it owes"
    );

    f.vault.close(&payer);
    assert_eq!(
        f.token.balance(&id),
        0,
        "closing should leave nothing behind"
    );
    assert_eq!(
        f.token.balance(&payee),
        2_000,
        "and the payee keeps what they were paid"
    );
}

#[test]
fn top_up_and_withdraw_move_only_the_float() {
    let f = setup();
    let (payer, _dev) = funded(&f, 1_000, 500);

    f.vault.top_up(&payer, &2_000);
    assert_eq!(f.vault.vault_of(&payer).float, 3_000);
    assert_eq!(
        f.vault.vault_of(&payer).bond,
        500,
        "top-up must not touch the bond"
    );

    f.vault.withdraw(&payer, &1_200);
    assert_eq!(f.vault.vault_of(&payer).float, 1_800);
    assert_eq!(
        f.vault.vault_of(&payer).bond,
        500,
        "withdrawal must not touch the bond"
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn the_bond_cannot_be_withdrawn_as_float() {
    let f = setup();
    let (payer, _dev) = funded(&f, 1_000, 500);
    // 1_500 is in the contract, but only 1_000 of it is spendable float.
    f.vault.withdraw(&payer, &1_500);
}

#[test]
fn a_second_device_can_sign_for_the_same_vault() {
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 0);
    let phone = device(21);
    f.vault.add_device(&payer, &pubkey(&f.env, &phone));

    let payee = Address::generate(&f.env);
    let a = auth(&f, &payer, &payee, 400, 1);
    f.vault.redeem(
        &a,
        &pubkey(&f.env, &phone),
        &sign(&f.env, &phone, &f.vault.signing_payload(&a)),
    );

    let b = auth(&f, &payer, &payee, 600, 2);
    f.vault.redeem(
        &b,
        &pubkey(&f.env, &dev),
        &sign(&f.env, &dev, &f.vault.signing_payload(&b)),
    );

    assert_eq!(
        f.token.balance(&payee),
        1_000,
        "both devices draw on one float"
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn a_payer_cannot_open_two_vaults() {
    let f = setup();
    let (payer, _) = funded(&f, 1_000, 0);
    f.vault.open(&payer, &f.token_id, &1_000, &0);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn spending_from_a_vault_that_does_not_exist_fails() {
    let f = setup();
    let stranger = Address::generate(&f.env);
    f.vault.vault_of(&stranger);
}

#[test]
fn signing_payload_is_stable_and_domain_separated() {
    let f = setup();
    let payer = Address::generate(&f.env);
    let payee = Address::generate(&f.env);
    let a = auth(&f, &payer, &payee, 1_000, 1);

    // Same input, same payload — an offline device and the chain must agree, or
    // nothing works.
    assert_eq!(f.vault.signing_payload(&a), f.vault.signing_payload(&a));

    // Any field change must change the payload.
    let b = Authorization {
        nonce: 2,
        ..a.clone()
    };
    assert_ne!(f.vault.signing_payload(&a), f.vault.signing_payload(&b));
    let c = Authorization {
        amount: 1_001,
        ..a.clone()
    };
    assert_ne!(f.vault.signing_payload(&a), f.vault.signing_payload(&c));
}

// ------------------------------------------------- the bond belongs to the payer

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn a_stranger_cannot_slash_a_bond_with_a_keypair_they_made_themselves() {
    // The attack this closes: `report_double_sign` verifies two signatures over
    // conflicting authorizations sharing a nonce. Both signatures here are
    // perfectly valid — they just belong to a key the payer never registered.
    // Without the ownership check, anyone could generate a keypair, sign two
    // vouchers naming a stranger as payer, and walk off with that stranger's
    // bond. The signatures prove somebody signed twice, not that the payer did.
    let f = setup();
    let (victim, _) = funded(&f, 10_000, 5_000);
    let attacker = Address::generate(&f.env);

    let theirs = device(200); // never registered to anyone
    let pk = pubkey(&f.env, &theirs);

    let a = auth(&f, &victim, &attacker, 1, 99);
    let b = auth(&f, &victim, &attacker, 2, 99);
    let sa = sign(&f.env, &theirs, &f.vault.signing_payload(&a));
    let sb = sign(&f.env, &theirs, &f.vault.signing_payload(&b));

    f.vault.report_double_sign(&pk, &a, &sa, &b, &sb, &attacker);
}

#[test]
fn the_victims_bond_survives_a_forged_report() {
    let f = setup();
    let (victim, _) = funded(&f, 10_000, 5_000);
    let attacker = Address::generate(&f.env);
    let theirs = device(201);
    let pk = pubkey(&f.env, &theirs);

    let a = auth(&f, &victim, &attacker, 1, 99);
    let b = auth(&f, &victim, &attacker, 2, 99);
    let sa = sign(&f.env, &theirs, &f.vault.signing_payload(&a));
    let sb = sign(&f.env, &theirs, &f.vault.signing_payload(&b));

    assert!(f
        .vault
        .try_report_double_sign(&pk, &a, &sa, &b, &sb, &attacker)
        .is_err());
    assert_eq!(f.vault.vault_of(&victim).bond, 5_000, "bond untouched");
    assert_eq!(f.token.balance(&attacker), 0, "attacker paid nothing");
}

#[test]
fn revoking_a_device_does_not_escape_the_proof() {
    // A payer who could erase a device could sign two vouchers on one nonce,
    // revoke the key the moment the first was redeemed, and leave the second
    // payee with a worthless confession. Revocation marks, it does not forget.
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 4_000);
    let pk = pubkey(&f.env, &dev);
    let first = Address::generate(&f.env);
    let second = Address::generate(&f.env);

    let a = auth(&f, &payer, &first, 3_000, 42);
    let b = auth(&f, &payer, &second, 3_000, 42);
    let sa = sign(&f.env, &dev, &f.vault.signing_payload(&a));
    let sb = sign(&f.env, &dev, &f.vault.signing_payload(&b));

    f.vault.redeem(&a, &pk, &sa); // first payee gets there first
    f.vault.revoke_device(&payer, &pk); // payer tries to bury the evidence
    assert!(!f.vault.is_device(&payer, &pk), "key can no longer sign");
    assert!(f.vault.was_device(&payer, &pk), "but is still on record");

    f.vault.report_double_sign(&pk, &a, &sa, &b, &sb, &second);
    assert_eq!(
        f.token.balance(&second),
        4_000,
        "bond paid to the unpaid payee"
    );
    assert_eq!(f.vault.vault_of(&payer).bond, 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn a_bond_cannot_be_claimed_twice() {
    // Once slashed there is nothing left. A second reporter, however honest,
    // gets an error rather than a payout from someone else's float — the bond
    // caps what a payer can lose, and that cap has to mean something.
    let f = setup();
    let (payer, dev) = funded(&f, 10_000, 4_000);
    let pk = pubkey(&f.env, &dev);
    let one = Address::generate(&f.env);
    let two = Address::generate(&f.env);

    let a = auth(&f, &payer, &one, 1_000, 7);
    let b = auth(&f, &payer, &two, 2_000, 7);
    let sa = sign(&f.env, &dev, &f.vault.signing_payload(&a));
    let sb = sign(&f.env, &dev, &f.vault.signing_payload(&b));

    f.vault.report_double_sign(&pk, &a, &sa, &b, &sb, &one);
    f.vault.report_double_sign(&pk, &a, &sa, &b, &sb, &two);
}

// ------------------------------------------------------- the accounting invariant

/// A small deterministic generator. Not cryptography — just a reproducible walk
/// through the state machine, so a failure can be replayed from the seed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn upto(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Whatever sequence of calls arrives, the contract holds exactly what it owes.
///
/// This is the one property that must never bend. Everything else is a rule about
/// who may do what; this is the promise that the money is all still there. The
/// walk below fires every state-changing entry point in an arbitrary order,
/// including plenty of calls that fail, and checks the books after each one.
#[test]
fn the_books_balance_after_any_sequence_of_calls() {
    let f = setup();
    let vault_addr = f.vault.address.clone();

    const PAYERS: usize = 4;
    const KEYS: usize = 3;
    // Several keys each: a slash revokes one key for good, and a payer with only
    // one key would be inert for the rest of the walk.
    let mut payers = Vec::new();
    let mut devs: Vec<Vec<SigningKey>> = Vec::new();
    for i in 0..PAYERS {
        let p = Address::generate(&f.env);
        f.mint.mint(&p, &1_000_000);
        payers.push(p);
        devs.push(
            (0..KEYS)
                .map(|j| device(30 + (i * KEYS + j) as u8))
                .collect(),
        );
    }
    let payees: Vec<Address> = (0..3).map(|_| Address::generate(&f.env)).collect();

    // Sum of float + bond over every vault that still exists.
    let owed = |f: &Fix, payers: &Vec<Address>| -> i128 {
        payers
            .iter()
            .filter_map(|p| f.vault.try_vault_of(p).ok().and_then(|r| r.ok()))
            .map(|v| v.float + v.bond)
            .sum()
    };

    let mut rng = Rng(0x5EED_1234_ABCD_0001);
    let mut nonce: u64 = 1;
    // A walk where every call happens to fail proves nothing, so count the ones
    // that landed and insist at the end that the interesting ones did.
    let (mut opened, mut redeemed, mut slashed, mut closed) = (0, 0, 0, 0);

    for step in 0..800u32 {
        let i = rng.upto(PAYERS as u64) as usize;
        let j = rng.upto(KEYS as u64) as usize;
        let payer = payers[i].clone();
        let dev = &devs[i][j];
        let pk = pubkey(&f.env, dev);

        // Weighted so the walk spends most of its time redeeming, which is the
        // path that moves money. Closing is rare, or the vaults never live long
        // enough for anything interesting to happen in them.
        match rng.upto(24) {
            0 | 1 => {
                let float = 1 + rng.upto(5_000) as i128;
                let bond = rng.upto(2_000) as i128;
                if f.vault.try_open(&payer, &f.token_id, &float, &bond).is_ok() {
                    opened += 1;
                    for k in &devs[i] {
                        let _ = f.vault.try_add_device(&payer, &pubkey(&f.env, k));
                    }
                }
            }
            2 | 3 => {
                let amount = 1 + rng.upto(1_000) as i128;
                let _ = f.vault.try_top_up(&payer, &amount);
            }
            4 => {
                let amount = 1 + rng.upto(1_500) as i128;
                let _ = f.vault.try_withdraw(&payer, &amount);
            }
            5 => {
                let _ = f.vault.try_add_device(&payer, &pk);
            }
            6 => {
                let _ = f.vault.try_revoke_device(&payer, &pk);
            }
            7..=20 => {
                let payee = payees[rng.upto(payees.len() as u64) as usize].clone();
                let amount = 1 + rng.upto(2_000) as i128;
                let a = auth(&f, &payer, &payee, amount, nonce);
                nonce += 1;
                let sig = sign(&f.env, dev, &f.vault.signing_payload(&a));
                if f.vault.try_redeem(&a, &pk, &sig).is_ok() {
                    redeemed += 1;
                }
            }
            21 | 22 => {
                // A genuine double-sign, reported by the payee left unpaid.
                let payee = payees[rng.upto(payees.len() as u64) as usize].clone();
                let n = nonce;
                nonce += 1;
                let a = auth(&f, &payer, &payee, 100, n);
                let b = auth(&f, &payer, &payee, 200, n);
                let sa = sign(&f.env, dev, &f.vault.signing_payload(&a));
                let sb = sign(&f.env, dev, &f.vault.signing_payload(&b));
                if f.vault
                    .try_report_double_sign(&pk, &a, &sa, &b, &sb, &payee)
                    .is_ok()
                {
                    slashed += 1;
                }
            }
            _ => {
                if f.vault.try_close(&payer).is_ok() {
                    closed += 1;
                }
            }
        }

        assert_eq!(
            f.token.balance(&vault_addr),
            owed(&f, &payers),
            "step {step}: the contract holds something other than what it owes"
        );
    }

    assert!(opened > 0, "the walk never opened a vault");
    assert!(redeemed > 0, "the walk never redeemed a voucher");
    assert!(slashed > 0, "the walk never slashed a bond");
    assert!(closed > 0, "the walk never closed a vault");
    std::println!(
        "walk: {opened} opens, {redeemed} redemptions, {slashed} slashes, {closed} closes"
    );
}

#[test]
fn a_vault_can_never_pay_out_more_than_was_put_in() {
    // The bound that makes offline authorisation safe to offer at all: whatever
    // happens offline, the payer's exposure stops at what they locked up.
    let f = setup();
    let (payer, dev) = funded(&f, 5_000, 1_000);
    let pk = pubkey(&f.env, &dev);
    let payee = Address::generate(&f.env);

    // Sign far more than the float, on distinct nonces, exactly as a dishonest
    // payer with no signal would.
    let mut paid = 0i128;
    for n in 1..=10u64 {
        let a = auth(&f, &payer, &payee, 2_000, n);
        let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));
        if f.vault.try_redeem(&a, &pk, &sig).is_ok() {
            paid += 2_000;
        }
    }
    assert_eq!(
        paid, 4_000,
        "redemption stops at the float, it does not overdraw"
    );
    assert_eq!(f.token.balance(&payee), 4_000);
    assert_eq!(f.vault.vault_of(&payer).float, 1_000);
    assert_eq!(
        f.vault.vault_of(&payer).bond,
        1_000,
        "the bond is not spendable"
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #11)")]
fn a_revoked_key_cannot_be_brought_back() {
    // Revocation is final. Otherwise a payer could revoke the key on a phone
    // they reported stolen, wait for the fuss to die down, and add it again.
    let f = setup();
    let (payer, dev) = funded(&f, 1_000, 0);
    let pk = pubkey(&f.env, &dev);
    f.vault.revoke_device(&payer, &pk);
    f.vault.add_device(&payer, &pk);
}

#[test]
fn every_state_change_says_so_out_loud() {
    // An indexer, a balance page, or a payer's low-float alert all need to learn
    // what happened without reading storage key by key. Each call below must
    // leave a trace attributable to this contract.
    let f = setup();
    let payer = Address::generate(&f.env);
    let payee = Address::generate(&f.env);
    let dev = device(9);
    let pk = pubkey(&f.env, &dev);
    f.mint.mint(&payer, &20_000);

    let mine = |f: &Fix| -> usize {
        f.env
            .events()
            .all()
            .iter()
            .filter(|(id, _, _)| *id == f.vault.address)
            .count()
    };

    let check = |label: &str, n: usize| {
        assert!(n > 0, "{label} published nothing");
        std::println!("{label}: {n}");
    };

    f.vault.open(&payer, &f.token_id, &10_000, &1_000);
    check("open", mine(&f));
    f.vault.add_device(&payer, &pk);
    check("add_device", mine(&f));
    f.vault.top_up(&payer, &500);
    check("top_up", mine(&f));

    let a = auth(&f, &payer, &payee, 1_000, 1);
    let sig = sign(&f.env, &dev, &f.vault.signing_payload(&a));
    f.vault.redeem(&a, &pk, &sig);
    check("redeem", mine(&f));

    f.vault.withdraw(&payer, &200);
    check("withdraw", mine(&f));
    f.vault.revoke_device(&payer, &pk);
    check("revoke_device", mine(&f));
    f.vault.close(&payer);
    check("close", mine(&f));
}
