// Copyright (c) 2022 Octavian Oncescu
// Copyright (c) 2022 The Purplecoin Core developers
// Licensed under the Apache License, Version 2.0 see LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0 or the MIT license, see
// LICENSE-MIT or http://opensource.org/licenses/MIT

use crate::primitives::{Address, PublicKey};
use bincode::{Decode, Encode};
use schnorrkel_purplecoin::derive::{ChainCode, ExtendedKey};
use schnorrkel_purplecoin::keys::{ExpansionMode, MiniSecretKey};
use schnorrkel_purplecoin::SecretKey as SchnorrSecretKey;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::prelude::*;
use std::marker::PhantomData;
use std::fmt;
use zeroize::Zeroize;

/// Generates simple wallets consisting of an Address and encrypted private key.
/// 
/// Returns them as a tuple of two strings.
pub fn gen_encrypted_simple_wallet(passphrase: &str, batch_size: u64) -> Vec<(String, String)> {
    let pass_hash = argon2rs::argon2d_simple(passphrase, "purplecoin.default.salt");

    // Transform argon2 hash into a 512bit output
    let mut pass_hash512 = [0; 64];
    let mut hasher = blake3::Hasher::new();
    hasher.update(&pass_hash);
    let mut out = hasher.finalize_xof();
    out.fill(&mut pass_hash512);

    let chain_code = &pass_hash512[32..];
    let mut master_priv_key = [0; 32];
    master_priv_key.copy_from_slice(&pass_hash512[..32]);

    // Calculate external and internal priv keys by transforming
    // the master priv key to a 512 bit output.
    let mut master_priv_hash512 = [0; 64];
    let mut hasher = blake3::Hasher::new();
    hasher.update(&master_priv_key);
    hasher.update(&[0x00]);
    let mut out = hasher.finalize_xof();
    out.fill(&mut master_priv_hash512);

    let master_internal_priv_key = &master_priv_hash512[..32];

    let mut master_keypair_internal = XKeypair::new_master(
        master_internal_priv_key,
        chain_code,
        [0, 0, 0, 0],
        0x00,
        0x000000,
    );

    let batch = (0..batch_size)
        .into_iter()
        .map(|_| {
            let mut next_internal = master_keypair_internal.derive_next();
            master_keypair_internal = next_internal.clone();
            let mut buf = vec![];
            let pubkey = next_internal.pub_key();
            let address = pubkey.to_address().to_bech32("pu");
            let encrypted_entry = EncryptedEntry::xchacha20poly1305(&pass_hash, next_internal.secret_key.secret_key).unwrap();
            buf.extend(pubkey.to_pubkey_bytes());
            buf.extend(encrypted_entry.to_bytes());
            
            let encrypted_key = hex::encode(buf);

            next_internal.zeroize();
            (address, encrypted_key)
        }).collect();

    pass_hash512.zeroize();
    master_priv_hash512.zeroize();
    master_keypair_internal.zeroize();

    batch

}

#[derive(Encode, Decode, Zeroize, Clone, PartialEq)]
pub struct XPub {
    version: u32,
    depth: u8,
    fingerprint: [u8; 4],
    child_number: u32,
    chain_code: [u8; 32],
    pub_key: PublicKey,
}

impl XPub {
    pub fn derive_next(&self) -> Self {
        let address = self.to_address();
        let mut fingerprint = [0; 4];
        fingerprint.copy_from_slice(&address.as_bytes()[..4]);

        let extended_key = ExtendedKey {
            chaincode: ChainCode(self.chain_code),
            key: self.pub_key.0.clone(),
        };
        let child_number = self.child_number + 1;

        XPub {
            version: 0x0488B21E,
            chain_code: self.chain_code,
            fingerprint,
            child_number,
            depth: 0x01,
            pub_key: PublicKey(
                extended_key
                    .derived_key_simple(format!("{}", child_number))
                    .key,
            ),
        }
    }

    pub fn to_address(&self) -> Address {
        self.pub_key.to_address()
    }

    pub fn to_pubkey_bytes(&self) -> [u8; 32] {
        self.pub_key.to_bytes()
    }
}

impl fmt::Debug for XPub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XPub")
            .field("version", &format!("0x{:x}", self.version))
            .field("chain_code", &hex::encode(&self.chain_code))
            .field("fingerprint", &hex::encode(&self.fingerprint))
            .field("child_number", &self.child_number)
            .field("depth", &self.depth)
            .field("pub_key", &hex::encode(&self.pub_key.0))
            .finish()
    }
}

impl XPriv {
    pub fn derive_next(&self) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.secret_key);
        let mut out = hasher.finalize_xof();
        let mut fingerprint = [0; 4];
        out.fill(&mut fingerprint);

        let extended_key = ExtendedKey {
            chaincode: ChainCode(self.chain_code),
            key: SchnorrSecretKey::from_bytes(&self.secret_key).unwrap(),
        };
        let child_number = self.child_number + 1;

        XPriv {
            version: 0x0488ADE4,
            chain_code: self.chain_code,
            fingerprint,
            child_number,
            depth: 0x01,
            secret_key: extended_key
                .derived_key_simple(format!("{}", child_number))
                .key
                .to_bytes(),
        }
    }
}

#[derive(Encode, Decode, Zeroize, Clone, Debug, PartialEq)]
#[zeroize(drop)]
pub struct XPriv {
    version: u32,
    depth: u8,
    fingerprint: [u8; 4],
    child_number: u32,
    chain_code: [u8; 32],
    secret_key: [u8; 64],
}

#[derive(Encode, Decode, Zeroize, Debug, Clone)]
pub struct XKeypair {
    pub pub_key: XPub,
    pub secret_key: XPriv,
}

impl XKeypair {
    pub fn new_master(
        secret: &[u8],
        chain_code: &[u8],
        fingerprint: [u8; 4],
        depth: u8,
        child_number: u32,
    ) -> Self {
        let mut chain_code_fixed = [0; 32];
        chain_code_fixed.copy_from_slice(&chain_code);
        let mut mini_secret = MiniSecretKey::from_bytes(secret).unwrap();
        let mut keypair = mini_secret.expand_to_keypair(ExpansionMode::Uniform);

        let xkeypair = XKeypair {
            pub_key: XPub {
                version: 0x0488B21E,
                chain_code: chain_code_fixed,
                fingerprint,
                child_number,
                depth,
                pub_key: PublicKey::from_bytes(&keypair.public.to_bytes()).unwrap(),
            },
            secret_key: XPriv {
                version: 0x0488ADE4,
                chain_code: chain_code_fixed,
                fingerprint,
                child_number,
                depth,
                secret_key: keypair.secret.to_bytes(),
            },
        };

        keypair.zeroize();
        mini_secret.zeroize();

        xkeypair
    }

    pub fn derive_next(&self) -> Self {
        XKeypair {
            pub_key: self.pub_key.derive_next(),
            secret_key: self.secret_key.derive_next(),
        }
    }

    pub fn pub_key(&self) -> &XPub {
        &self.pub_key
    }

    pub fn secret_key(&self) -> &XPriv {
        &self.secret_key
    }
}


#[derive(Encode, Decode, Debug, PartialEq)]
pub enum EncryptionAlgo {
    XChaCha20Poly1305,
    AES256GCM,
}

#[derive(Encode, Decode, PartialEq)]
/// Encrypted entry that can be serialized to bytes
pub struct EncryptedEntry<T: Encode + Decode> {
    /// Encryption algorithm
    algo: EncryptionAlgo,

    /// Nonce
    nonce: Vec<u8>,
    
    /// Ciphertext
    ciphertext: Vec<u8>,

    /// Phantom
    phantom: PhantomData<T>,
}

impl<T: Encode + Decode> fmt::Debug for EncryptedEntry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XPub")
            .field("algo", &self.algo)
            .field("nonce", &hex::encode(&self.nonce))
            .field("data", &"[ENCRYPTED]")
            .finish()
    }
}

impl<T: Encode + Decode> EncryptedEntry<T> {
    /// Creates an encrypted entry from data with key using XChacha20Poly1305
    pub fn xchacha20poly1305(key: &[u8], data: T) -> Result<Self, &'static str> {
        let config = bincode::config::standard()
            .with_little_endian()
            .with_variable_int_encoding()
            .skip_fixed_array_length();
        let mut data = bincode::encode_to_vec(data, config).unwrap();
        let mut rng = rand::rngs::OsRng;
        let key = Key::from_slice(key);
        let cipher = XChaCha20Poly1305::new(key);
        let nonce_bytes: [u8; 24] = rng.gen();
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, data.as_ref())
            .map_err(|_| "encryption failure!")?;

        data.zeroize();

        Ok(EncryptedEntry {
            algo: EncryptionAlgo::XChaCha20Poly1305,
            nonce: nonce_bytes.to_vec(),
            ciphertext,
            phantom: PhantomData,
        })
    }

    /// Creates an encrypted entry from data with key using AES256GCM
    pub fn aes256gcm(key: &[u8], data: T) -> Result<Self, &'static str> {
        unimplemented!();
    }

    /// Decrypts the ciphertext using the provided key
    pub fn decrypt(&self, key: &[u8]) -> Result<T, &'static str> {
        let config = bincode::config::standard()
            .with_little_endian()
            .with_variable_int_encoding()
            .skip_fixed_array_length();

        match self.algo {
            EncryptionAlgo::XChaCha20Poly1305 => {
                unimplemented!();
            }

            EncryptionAlgo::AES256GCM => {
                unimplemented!();
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let config = bincode::config::standard()
            .with_little_endian()
            .with_variable_int_encoding()
            .skip_fixed_array_length();
        bincode::encode_to_vec(self, config).unwrap()
    }
}