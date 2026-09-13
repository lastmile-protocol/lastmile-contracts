#![cfg(test)]

use super::*;
use soroban_sdk::{
    testutils::{Address as _, Ledger as _},
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

    assert_eq!(f.token.balance(&payee), 2_500, "the payee should be paid in full");
    assert_eq!(f.vault.vault_of(&payer).float, 7_500, "float should fall by exactly the amount");
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
    assert_eq!(f.vault.vault_of(&payer).float, 0, "the float should be exactly exhausted");
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

    f.env.ledger().set_timestamp(f.env.ledger().timestamp() + 8 * DAY);
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
    let greedy = Authorization { amount: 9_000, ..honest };
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

    assert_eq!(f.token.balance(&second), 2_000, "the bond should go to the reporter");
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
    f.vault
        .report_double_sign(&pk, &a, &sig, &a, &sig, &payee);
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

    assert_eq!(f.token.balance(&id), 6_000, "float plus bond, and nothing else");

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
    assert_eq!(f.token.balance(&id), 0, "closing should leave nothing behind");
    assert_eq!(f.token.balance(&payee), 2_000, "and the payee keeps what they were paid");
}

#[test]
fn top_up_and_withdraw_move_only_the_float() {
    let f = setup();
    let (payer, _dev) = funded(&f, 1_000, 500);

    f.vault.top_up(&payer, &2_000);
    assert_eq!(f.vault.vault_of(&payer).float, 3_000);
    assert_eq!(f.vault.vault_of(&payer).bond, 500, "top-up must not touch the bond");

    f.vault.withdraw(&payer, &1_200);
    assert_eq!(f.vault.vault_of(&payer).float, 1_800);
    assert_eq!(f.vault.vault_of(&payer).bond, 500, "withdrawal must not touch the bond");
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

    assert_eq!(f.token.balance(&payee), 1_000, "both devices draw on one float");
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
    let b = Authorization { nonce: 2, ..a.clone() };
    assert_ne!(f.vault.signing_payload(&a), f.vault.signing_payload(&b));
    let c = Authorization { amount: 1_001, ..a.clone() };
    assert_ne!(f.vault.signing_payload(&a), f.vault.signing_payload(&c));
}
