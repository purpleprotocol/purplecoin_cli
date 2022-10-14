// Copyright (c) 2022 Octavian Oncescu
// Copyright (c) 2022 The Purplecoin Core developers
// Licensed under the Apache License, Version 2.0 see LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0 or the MIT license, see
// LICENSE-MIT or http://opensource.org/licenses/MIT

use bech32::{self, FromBase32, ToBase32, Variant};
use bincode::{Decode, Encode};
use lazy_static::*;
use schnorrkel::PublicKey as SchnorrPubKey;
use schnorrkel::Signature as SchnorrSignature;
use std::convert::From;
use std::fmt;
use std::hash::Hash as HashTrait;
use std::hash::Hasher;
use std::str;
use zeroize::Zeroize;

pub const ADDRESS_BYTES: usize = 20;
pub const COLOURED_ADDRESS_BYTES: usize = 40;

const HASH_KEY_PREFIX: &'static str = "purplecoin.hash.";

lazy_static! {
    static ref HASH_KEY160_OWNED: String = format!("{}", 20);
    static ref HASH_KEY160: &'static str = &HASH_KEY160_OWNED;
    static ref HASH_KEY256_OWNED: String = format!("{}", 32);
    static ref HASH_KEY256: &'static str = &HASH_KEY256_OWNED;
    static ref HASH_KEY512_OWNED: String = format!("{}", 64);
    static ref HASH_KEY512: &'static str = &HASH_KEY512_OWNED;
}

#[derive(Clone, PartialEq, Eq, HashTrait, Encode, Decode)]
pub struct ColouredAddress(pub [u8; COLOURED_ADDRESS_BYTES]);

impl ColouredAddress {
    pub fn zero() -> Self {
        Self([0; COLOURED_ADDRESS_BYTES])
    }

    pub fn to_bech32(&self, hrp: &str) -> String {
        bech32::encode(hrp, self.0.to_base32(), Variant::Bech32m).unwrap()
    }

    /// Validate against public key
    pub fn validate(&self, public_key: &PublicKey, colour_hash: &Hash160) -> bool {
        self == &public_key.to_coloured_address(colour_hash)
    }
}

impl fmt::Debug for ColouredAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ColouredAddress")
            .field(&self.to_bech32("pu"))
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, HashTrait, Encode, Decode)]
pub struct Address(pub [u8; ADDRESS_BYTES]);

impl Address {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn zero() -> Self {
        Self([0; ADDRESS_BYTES])
    }

    pub fn to_bech32(&self, hrp: &str) -> String {
        bech32::encode(hrp, self.0.to_base32(), Variant::Bech32m).unwrap()
    }

    pub fn from_bech32(encoded: &str) -> Result<Self, &'static str> {
        let (_hrp, data, _variant) = bech32::decode(encoded).map_err(|_| "invalid address")?;
        let data: Vec<u8> = Vec::<u8>::from_base32(&data).map_err(|_| "invalid address")?;
        let mut out = Self([0; ADDRESS_BYTES]);
        out.0.copy_from_slice(&data);
        Ok(out)
    }

    /// Validate against public key
    pub fn validate(&self, public_key: &PublicKey) -> bool {
        self == &public_key.to_address()
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Address")
            .field(&self.to_bech32("pu"))
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PublicKey(pub SchnorrPubKey);

impl Zeroize for PublicKey {
    fn zeroize(&mut self) {}
}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 32 {
            return Err("invalid slice length! expected 32");
        }

        Ok(Self(
            SchnorrPubKey::from_bytes(bytes).map_err(|_| "could not decode public key")?,
        ))
    }

    pub fn zero() -> Self {
        let bytes = vec![0; 32];
        Self::from_bytes(&bytes).unwrap()
    }

    #[inline]
    pub fn to_address(&self) -> Address {
        let mut address = Address([0; ADDRESS_BYTES]);
        let mut hash1 = [0; 32];
        let pub_bytes = self.0.to_bytes();
        let mut hasher = blake3::Hasher::new_derive_key(&HASH_KEY256);
        hasher.update(&pub_bytes);
        let mut out = hasher.finalize_xof();
        out.fill(&mut hash1);
        let mut hasher = blake3::Hasher::new_derive_key(&HASH_KEY160);
        hasher.update(&hash1);
        let mut out = hasher.finalize_xof();
        out.fill(&mut address.0);
        address
    }

    #[inline]
    pub fn to_coloured_address(&self, colour_hash: &Hash160) -> ColouredAddress {
        let mut out_bytes = [0; COLOURED_ADDRESS_BYTES];
        let mut hash1 = [0; 32];
        let pub_bytes = self.0.to_bytes();
        let mut hasher = blake3::Hasher::new_derive_key(&HASH_KEY256);
        hasher.update(&pub_bytes);
        let mut out = hasher.finalize_xof();
        out.fill(&mut hash1);
        let mut hasher = blake3::Hasher::new_derive_key(&HASH_KEY160);
        hasher.update(&hash1);
        let mut out = hasher.finalize_xof();
        let mut hash_bytes = [0; 20];
        out.fill(&mut hash_bytes);
        out_bytes.copy_from_slice(&[hash_bytes.as_slice(), colour_hash.as_bytes()].concat());

        ColouredAddress(out_bytes)
    }
}

impl Encode for PublicKey {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> core::result::Result<(), bincode::error::EncodeError> {
        bincode::Encode::encode(&self.0.to_bytes(), encoder)?;
        Ok(())
    }
}

impl Decode for PublicKey {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        let pk_bytes: [u8; schnorrkel::PUBLIC_KEY_LENGTH] = bincode::Decode::decode(decoder)?;
        let result = SchnorrPubKey::from_bytes(&pk_bytes).map_err(|_| {
            bincode::error::DecodeError::OtherString("invalid public key format".to_owned())
        })?;
        Ok(Self(result))
    }
}

#[derive(Clone, PartialEq)]
pub struct Signature(pub SchnorrSignature);

impl Encode for Signature {
    fn encode<E: bincode::enc::Encoder>(
        &self,
        encoder: &mut E,
    ) -> core::result::Result<(), bincode::error::EncodeError> {
        bincode::Encode::encode(&self.0.to_bytes(), encoder)?;
        Ok(())
    }
}

impl Decode for Signature {
    fn decode<D: bincode::de::Decoder>(
        decoder: &mut D,
    ) -> core::result::Result<Self, bincode::error::DecodeError> {
        let pk_bytes: [u8; schnorrkel::SIGNATURE_LENGTH] = bincode::Decode::decode(decoder)?;
        let result = SchnorrSignature::from_bytes(&pk_bytes).map_err(|_| {
            bincode::error::DecodeError::OtherString("invalid signature format".to_owned())
        })?;
        Ok(Self(result))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Signature")
            .field(&hex::encode(self.0.to_bytes()))
            .finish()
    }
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, HashTrait, Zeroize)]
pub struct Hash160(pub [u8; 20]);

impl Hash160 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn zero() -> Self {
        Self([0; 20])
    }

    pub fn to_address(&self) -> Address {
        Address(self.0)
    }

    #[inline]
    pub fn hash_from_slice<T: AsRef<[u8]>>(slice: T, key: &str) -> Self {
        let mut out_hash = Hash160([0; 20]);
        let mut hash1 = [0; 32];
        let key1 = &[
            HASH_KEY_PREFIX.as_bytes(),
            HASH_KEY256.as_bytes(),
            ".".as_bytes(),
            key.as_bytes(),
        ]
        .concat();
        let key1 = unsafe { str::from_utf8_unchecked(key1) };
        let mut hasher = blake3::Hasher::new_derive_key(key1);
        hasher.update(slice.as_ref());
        let mut out = hasher.finalize_xof();
        out.fill(&mut hash1);
        let key = &[
            HASH_KEY_PREFIX.as_bytes(),
            HASH_KEY160.as_bytes(),
            ".".as_bytes(),
            key.as_bytes(),
        ]
        .concat();
        let key = unsafe { str::from_utf8_unchecked(key) };
        let mut hasher = blake3::Hasher::new_derive_key(key);
        hasher.update(&hash1);
        let mut out = hasher.finalize_xof();
        out.fill(&mut out_hash.0);
        out_hash
    }
}

impl fmt::Debug for Hash160 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hash160")
            .field(&hex::encode(self.0))
            .finish()
    }
}

#[derive(
    PartialEq, Eq, Encode, Decode, Clone, HashTrait, Zeroize, PartialOrd, Ord, Default, Copy,
)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn zero() -> Self {
        Self([0; 32])
    }

    #[inline]
    pub fn hash_from_slice<T: AsRef<[u8]>>(slice: T, key: &str) -> Self {
        let mut out_hash = Hash256([0; 32]);
        let key = &[
            HASH_KEY_PREFIX.as_bytes(),
            HASH_KEY256.as_bytes(),
            ".".as_bytes(),
            key.as_bytes(),
        ]
        .concat();
        let key = unsafe { str::from_utf8_unchecked(key) };
        let mut hasher = blake3::Hasher::new_derive_key(key);
        hasher.update(slice.as_ref());
        let mut out = hasher.finalize_xof();
        out.fill(&mut out_hash.0);
        out_hash
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hash256")
            .field(&hex::encode(self.0))
            .finish()
    }
}

#[derive(PartialEq, Eq, Encode, Decode, Clone, HashTrait)]
pub struct Hash512(pub [u8; 64]);

impl Hash512 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn zero() -> Self {
        Self([0; 64])
    }

    pub fn hash_from_slice<T: AsRef<[u8]>>(slice: T, key: &str) -> Self {
        let mut out_hash = Hash512([0; 64]);
        let key = &[
            HASH_KEY_PREFIX.as_bytes(),
            HASH_KEY512.as_bytes(),
            ".".as_bytes(),
            key.as_bytes(),
        ]
        .concat();
        let key = unsafe { str::from_utf8_unchecked(key) };
        let mut hasher = blake3::Hasher::new_derive_key(key);
        hasher.update(slice.as_ref());
        let mut out = hasher.finalize_xof();
        out.fill(&mut out_hash.0);
        out_hash
    }
}

impl fmt::Debug for Hash512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hash512")
            .field(&hex::encode(self.0))
            .finish()
    }
}
