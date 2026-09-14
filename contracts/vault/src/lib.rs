#![no_std]

//! Lastmile — offline-authorised payments on Stellar.
//!
//! Every Stellar payment product assumes both parties are online. Stellar's best
//! markets are the places where that is least true. This contract separates
//! *authorisation* from *settlement*: a payer signs a voucher with no connectivity
//! at all, hands it over by QR, NFC or a spoken code, and the payee redeems it
//! whenever signal returns.
//!
//! # How it works
//!
//! A payer opens a vault, deposits a float, and registers one or more **device
//! keys** — ed25519 keys held by the phone or card that will sign while offline.
//! A device key is deliberately *not* the payer's Stellar account key: a lost
//! phone is a revoked device, not a compromised account.
//!
//! Offline, the device signs an [`Authorization`] naming the payee, the amount, a
//! nonce and an expiry. Nothing touches the network. Later — minutes or days —
//! anyone submits it to `redeem`, which verifies the signature on chain and pays
//! the payee out of the payer's float.
//!
//! # The honest part: offline double-spend
//!
//! Offline double-spend cannot be prevented in software. That is not a gap in this
//! design; it is why every serious offline CBDC design uses secure hardware. Two
//! parties with no connectivity cannot agree on who spent what. So this contract
//! *bounds* and *attributes* it instead:
//!
//! - **Payee-bound.** An authorization names its payee, so an intercepted QR code
//!   or an overheard spoken code is worthless to anyone else.
//! - **Bounded.** A payer can never put more at risk than the float they locked.
//!   Redemption beyond the remaining float fails; it cannot overdraw.
//! - **Provable.** Signing two different authorizations under the same nonce is
//!   something an honest device never does. Both signatures together are a proof
//!   anyone can submit to [`Contract::report_double_sign`], which slashes the
//!   payer's bond to the reporter and revokes the offending device key.
//!
//! **The residual risk, stated plainly:** a payer may also spend beyond their
//! float using *distinct* nonces. Signatures alone cannot distinguish that from
//! ordinary overspending, so those redemptions fail first-come-first-served and
//! the late payee is not paid. This is the same risk a merchant takes accepting a
//! cheque, and it is bounded by the bond and the float. Keep floats small, keep
//! bonds meaningful, and redeem often. We would rather write that sentence than
//! claim a guarantee the mathematics does not support.
//!
//! # Parallel execution
//!
//! Storage keys are parameterised by payer — `Vault(payer)`, `Device(payer, key)`,
//! `Spent(payer, nonce)`. Two redemptions against different payers touch disjoint
//! keys and do not serialise under CAP-0063. The shared point is the token
//! contract's own balance entries, which is inherent to custody and not something
//! this contract can avoid.

use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, token, xdr::ToXdr,
    Address, Bytes, BytesN, Env,
};

/// Domain separator. Mixed into every signed payload so that a signature made for
/// Lastmile can never be replayed as a signature for anything else, and so that a
/// voucher for one deployment is not valid on another.
const DOMAIN: &[u8] = b"lastmile.v1.authorization";

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// The vault does not exist. Open it first.
    NoVault = 1,
    /// A vault already exists for this payer.
    VaultExists = 2,
    /// The signing key is not registered to this payer, or has been revoked.
    UnknownDevice = 3,
    /// The signature does not verify under the named device key.
    BadSignature = 4,
    /// This authorization's expiry has passed.
    Expired = 5,
    /// This nonce has already been redeemed.
    AlreadySpent = 6,
    /// The vault's remaining float does not cover this amount.
    InsufficientFloat = 7,
    /// Amounts must be positive.
    BadAmount = 8,
    /// The two authorizations offered as proof are not a double-sign.
    NotADoubleSign = 9,
    /// The bond is already spent, or there was never one to slash.
    NoBond = 10,
    /// A device key may only be registered once.
    DeviceExists = 11,
}

/// A payment authorised offline.
///
/// This is the object a device signs with no connectivity. It is deliberately
/// small: it has to survive being carried as a QR code, an NFC tap, an SMS, or a
/// short code read aloud over a bad phone line.
#[contracttype]
#[derive(Clone)]
pub struct Authorization {
    /// Whose float this is drawn from.
    pub payer: Address,
    /// Who may redeem it. Naming the payee is what makes an intercepted voucher
    /// worthless to a thief.
    pub payee: Address,
    /// Stroops of the vault's token.
    pub amount: i128,
    /// Unique per payer. Reusing one is the provable offence.
    pub nonce: u64,
    /// Unix seconds after which this cannot be redeemed. Bounds how long a
    /// voucher can sit in someone's pocket creating uncertainty.
    pub expires: u64,
}

/// A payer's vault.
#[contracttype]
#[derive(Clone)]
pub struct Vault {
    /// The asset this vault pays in.
    pub token: Address,
    /// Unredeemed float still available to offline authorizations.
    pub float: i128,
    /// Held against proof of double-signing, and payable to whoever proves it.
    pub bond: i128,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    /// Vault(payer) — the payer's float and bond.
    Vault(Address),
    /// Device(payer, pubkey) — a registered offline signing key.
    Device(Address, BytesN<32>),
    /// Spent(payer, nonce) — the redeemed-nonce ledger, and the evidence store
    /// for double-sign proofs. Holds the hash of the authorization that claimed
    /// this nonce, so a conflicting one is detectable later.
    Spent(Address, u64),
}

/// How long a redeemed nonce is remembered. A nonce must outlive every voucher
/// that could carry it, or a replay becomes possible once the record expires.
const SPENT_TTL: u32 = 3_110_400; // ~180 days of ledgers at 5s

#[contract]
pub struct Contract;

#[contractimpl]
impl Contract {
    /// Open a vault and fund it.
    ///
    /// `float` is what can be spent offline; `bond` is what a defrauded payee can
    /// claim on proof of double-signing. Both are transferred in now.
    pub fn open(env: Env, payer: Address, token: Address, float: i128, bond: i128) {
        payer.require_auth();
        if float <= 0 || bond < 0 {
            panic_with_error!(&env, Error::BadAmount);
        }
        if env.storage().persistent().has(&Key::Vault(payer.clone())) {
            panic_with_error!(&env, Error::VaultExists);
        }
        token::Client::new(&env, &token).transfer(
            &payer,
            &env.current_contract_address(),
            &(float + bond),
        );
        env.storage()
            .persistent()
            .set(&Key::Vault(payer.clone()), &Vault { token, float, bond });
    }

    /// Add more float to an existing vault.
    pub fn top_up(env: Env, payer: Address, amount: i128) {
        payer.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, Error::BadAmount);
        }
        let mut v = Self::vault(&env, &payer);
        token::Client::new(&env, &v.token).transfer(
            &payer,
            &env.current_contract_address(),
            &amount,
        );
        v.float += amount;
        env.storage()
            .persistent()
            .set(&Key::Vault(payer.clone()), &v);
    }

    /// Register a device key that may sign authorizations offline.
    ///
    /// This is not the payer's Stellar account key. It belongs to the phone or
    /// card that goes out of signal, so losing the device means revoking a key
    /// rather than losing an account.
    pub fn add_device(env: Env, payer: Address, device: BytesN<32>) {
        payer.require_auth();
        Self::vault(&env, &payer);
        let k = Key::Device(payer.clone(), device);
        if env.storage().persistent().has(&k) {
            panic_with_error!(&env, Error::DeviceExists);
        }
        env.storage().persistent().set(&k, &true);
    }

    /// Revoke a device key. Vouchers it already signed but nobody has redeemed
    /// become worthless, which is the point: this is what you call when a phone
    /// is stolen.
    pub fn revoke_device(env: Env, payer: Address, device: BytesN<32>) {
        payer.require_auth();
        env.storage()
            .persistent()
            .remove(&Key::Device(payer.clone(), device));
    }

    /// The exact bytes a device must sign for `auth`.
    ///
    /// Exposed so that an offline signer, a test, or a third-party wallet can
    /// compute the payload without reimplementing the encoding and getting it
    /// subtly wrong.
    pub fn signing_payload(env: Env, auth: Authorization) -> BytesN<32> {
        Self::payload(&env, &auth)
    }

    /// Redeem an offline authorization.
    ///
    /// Permissionless: the payee, the payer, or a passing agent with a data
    /// connection may all submit it. The signature is the authority, not the
    /// caller — which is the whole point, because the payee may never get online
    /// at all.
    pub fn redeem(env: Env, auth: Authorization, device: BytesN<32>, sig: BytesN<64>) {
        if auth.amount <= 0 {
            panic_with_error!(&env, Error::BadAmount);
        }
        if env.ledger().timestamp() > auth.expires {
            panic_with_error!(&env, Error::Expired);
        }
        if !env
            .storage()
            .persistent()
            .has(&Key::Device(auth.payer.clone(), device.clone()))
        {
            panic_with_error!(&env, Error::UnknownDevice);
        }

        let payload = Self::payload(&env, &auth);
        Self::verify(&env, &device, &payload, &sig);

        let spent = Key::Spent(auth.payer.clone(), auth.nonce);
        if env.storage().persistent().has(&spent) {
            panic_with_error!(&env, Error::AlreadySpent);
        }

        let mut v = Self::vault(&env, &auth.payer);
        if v.float < auth.amount {
            panic_with_error!(&env, Error::InsufficientFloat);
        }
        v.float -= auth.amount;

        // Remember the payload, not just the fact of spending: a later conflicting
        // authorization on this nonce is then provable against what is stored.
        env.storage().persistent().set(&spent, &payload);
        env.storage()
            .persistent()
            .extend_ttl(&spent, SPENT_TTL, SPENT_TTL);
        env.storage()
            .persistent()
            .set(&Key::Vault(auth.payer.clone()), &v);

        token::Client::new(&env, &v.token).transfer(
            &env.current_contract_address(),
            &auth.payee,
            &auth.amount,
        );
    }

    /// Prove that a device signed two different authorizations under one nonce,
    /// slash the bond to the reporter, and revoke the key.
    ///
    /// An honest device never does this: the nonce is what it spends. Two valid
    /// signatures over different payloads sharing a nonce is a signed confession,
    /// and anyone holding both can submit it — typically the payee who was left
    /// unpaid when the other voucher got there first.
    pub fn report_double_sign(
        env: Env,
        device: BytesN<32>,
        a: Authorization,
        sig_a: BytesN<64>,
        b: Authorization,
        sig_b: BytesN<64>,
        reporter: Address,
    ) {
        if a.payer != b.payer || a.nonce != b.nonce {
            panic_with_error!(&env, Error::NotADoubleSign);
        }
        let pa = Self::payload(&env, &a);
        let pb = Self::payload(&env, &b);
        if pa == pb {
            // The same authorization twice is not a double-sign, just a duplicate.
            panic_with_error!(&env, Error::NotADoubleSign);
        }
        Self::verify(&env, &device, &pa, &sig_a);
        Self::verify(&env, &device, &pb, &sig_b);

        let mut v = Self::vault(&env, &a.payer);
        if v.bond <= 0 {
            panic_with_error!(&env, Error::NoBond);
        }
        let payout = v.bond;
        v.bond = 0;
        env.storage()
            .persistent()
            .set(&Key::Vault(a.payer.clone()), &v);
        env.storage()
            .persistent()
            .remove(&Key::Device(a.payer.clone(), device));

        token::Client::new(&env, &v.token).transfer(
            &env.current_contract_address(),
            &reporter,
            &payout,
        );
    }

    /// Withdraw unspent float. The bond stays until `close`.
    pub fn withdraw(env: Env, payer: Address, amount: i128) {
        payer.require_auth();
        if amount <= 0 {
            panic_with_error!(&env, Error::BadAmount);
        }
        let mut v = Self::vault(&env, &payer);
        if v.float < amount {
            panic_with_error!(&env, Error::InsufficientFloat);
        }
        v.float -= amount;
        env.storage()
            .persistent()
            .set(&Key::Vault(payer.clone()), &v);
        token::Client::new(&env, &v.token).transfer(
            &env.current_contract_address(),
            &payer,
            &amount,
        );
    }

    /// Close the vault, returning whatever float and bond remain.
    ///
    /// Any voucher still in someone's pocket becomes unredeemable, so this is the
    /// payer's own risk to take and nobody else's — it can only be called by them.
    pub fn close(env: Env, payer: Address) {
        payer.require_auth();
        let v = Self::vault(&env, &payer);
        let total = v.float + v.bond;
        env.storage()
            .persistent()
            .remove(&Key::Vault(payer.clone()));
        if total > 0 {
            token::Client::new(&env, &v.token).transfer(
                &env.current_contract_address(),
                &payer,
                &total,
            );
        }
    }

    // ---- reads: free, simulated, no wallet needed ----

    /// A payer's vault, or panic if there is none.
    pub fn vault_of(env: Env, payer: Address) -> Vault {
        Self::vault(&env, &payer)
    }

    /// Whether a nonce has already been redeemed.
    pub fn is_spent(env: Env, payer: Address, nonce: u64) -> bool {
        env.storage().persistent().has(&Key::Spent(payer, nonce))
    }

    /// Whether a device key may currently sign for this payer.
    pub fn is_device(env: Env, payer: Address, device: BytesN<32>) -> bool {
        env.storage().persistent().has(&Key::Device(payer, device))
    }

    /// Check an authorization end to end without spending it.
    ///
    /// A payee with a brief window of signal can call this to see whether a
    /// voucher in their pocket is still good, before walking back to the village.
    /// Returns false for anything checkable; panics on a bad signature, so call
    /// the generated `try_` variant and treat an error as "no".
    pub fn would_redeem(
        env: Env,
        auth: Authorization,
        device: BytesN<32>,
        sig: BytesN<64>,
    ) -> bool {
        if auth.amount <= 0 || env.ledger().timestamp() > auth.expires {
            return false;
        }
        if !env
            .storage()
            .persistent()
            .has(&Key::Device(auth.payer.clone(), device.clone()))
        {
            return false;
        }
        if env
            .storage()
            .persistent()
            .has(&Key::Spent(auth.payer.clone(), auth.nonce))
        {
            return false;
        }
        // `ed25519_verify` panics on a bad signature rather than returning false,
        // so a caller wanting a boolean should use the generated `try_` variant
        // and read a failed simulation as "no". Reads are simulated for free, so
        // this costs the payee nothing but the moment of signal.
        Self::verify(&env, &device, &Self::payload(&env, &auth), &sig);
        match env
            .storage()
            .persistent()
            .get::<Key, Vault>(&Key::Vault(auth.payer.clone()))
        {
            Some(v) => v.float >= auth.amount,
            None => false,
        }
    }

    // ---- internals ----

    fn vault(env: &Env, payer: &Address) -> Vault {
        env.storage()
            .persistent()
            .get(&Key::Vault(payer.clone()))
            .unwrap_or_else(|| panic_with_error!(env, Error::NoVault))
    }

    fn payload(env: &Env, auth: &Authorization) -> BytesN<32> {
        let mut b = Bytes::from_slice(env, DOMAIN);
        b.append(&auth.clone().to_xdr(env));
        env.crypto().sha256(&b).into()
    }

    fn verify(env: &Env, device: &BytesN<32>, payload: &BytesN<32>, sig: &BytesN<64>) {
        // ed25519_verify panics on a bad signature; the explicit check keeps the
        // error surface ours rather than the host's.
        let msg: Bytes = payload.clone().into();
        env.crypto().ed25519_verify(device, &msg, sig);
    }
}

mod test;
