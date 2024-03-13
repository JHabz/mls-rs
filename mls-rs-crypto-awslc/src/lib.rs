// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// Copyright by contributors to this project.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)

mod aead;
mod ec;
mod ecdsa;
mod kdf;
mod kem;

pub mod x509;

use std::{ffi::c_int, marker::PhantomData, mem::MaybeUninit};

use aead::AwsLcAead;
use aws_lc_rs::{
    error::{KeyRejected, Unspecified},
    hmac,
};

use aws_lc_sys::SHA256;
use kem::kyber::KyberKem;
use mls_rs_core::{
    crypto::{
        CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePublicKey,
        HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
    },
    error::{AnyError, IntoAnyError},
};

use ecdsa::AwsLcEcdsa;
use kdf::{AwsLcHash, AwsLcHkdf, AwsLcShake128, Sha3};
use kem::ecdh::Ecdh;
use mls_rs_crypto_hpke::{
    context::{ContextR, ContextS},
    dhkem::DhKem,
    hpke::{Hpke, HpkeError},
    kem_combiner::{CombinedKem, XWingSharedSecretHashInput},
};
use mls_rs_crypto_traits::{AeadType, Hash, KdfType, KemId, KemType};
use thiserror::Error;
use zeroize::Zeroizing;

#[derive(Clone)]
pub struct AwsLcCipherSuite<KEM> {
    cipher_suite: CipherSuite,
    signing: AwsLcEcdsa,
    aead: AwsLcAead,
    kdf: AwsLcHkdf,
    kem: KEM,
    mac_algo: hmac::Algorithm,
    hash: AwsLcHash,
}

impl<KEM: KemType + Clone> AwsLcCipherSuite<KEM> {
    pub fn import_ec_der_private_key(
        &self,
        bytes: &[u8],
    ) -> Result<SignatureSecretKey, AwsLcCryptoError> {
        self.signing.import_ec_der_private_key(bytes)
    }

    pub fn import_ec_der_public_key(
        &self,
        bytes: &[u8],
    ) -> Result<SignaturePublicKey, AwsLcCryptoError> {
        self.signing.import_ec_der_public_key(bytes)
    }

    fn hpke(&self) -> Hpke<KEM, AwsLcHkdf, AwsLcAead> {
        Hpke::new(self.kem.clone(), self.kdf, Some(self.aead))
    }
}

#[derive(Clone, Debug)]
pub struct AwsLcCryptoProvider<KEM: Clone> {
    pub enabled_cipher_suites: Vec<CipherSuite>,
    _phantom: PhantomData<KEM>,
}

pub type AwsLcCryptoClassicalProvider = AwsLcCryptoProvider<DhKem<Ecdh, AwsLcHkdf>>;

pub type CombinedEcdhKyberKem = CombinedKem<
    KyberKem,
    DhKem<Ecdh, AwsLcHkdf>,
    AwsLcHash,
    AwsLcShake128,
    XWingSharedSecretHashInput,
>;

pub type AwsLcCryptoPqProvider = AwsLcCryptoProvider<CombinedEcdhKyberKem>;

impl AwsLcCryptoPqProvider {
    pub fn new_pq() -> Self {
        Self {
            enabled_cipher_suites: Self::all_supported_cipher_suites(),
            _phantom: PhantomData,
        }
    }

    pub fn all_supported_cipher_suites() -> Vec<CipherSuite> {
        vec![
            CipherSuite::KYBER768_X25519, // We don't have numbers for others
        ]
    }
}
impl AwsLcCryptoClassicalProvider {
    pub fn new() -> Self {
        Self {
            enabled_cipher_suites: Self::all_supported_cipher_suites(),
            _phantom: PhantomData,
        }
    }

    pub fn all_supported_cipher_suites() -> Vec<CipherSuite> {
        vec![
            CipherSuite::CURVE25519_AES128,
            CipherSuite::CURVE25519_CHACHA,
            CipherSuite::P256_AES128,
            CipherSuite::P384_AES256,
            CipherSuite::P521_AES256,
        ]
    }

    fn kem(cipher_suite: CipherSuite) -> Option<DhKem<Ecdh, AwsLcHkdf>> {
        Self::dhkem(cipher_suite)
    }
}

impl<KEM: Clone> AwsLcCryptoProvider<KEM> {
    pub fn with_enabled_cipher_suites(enabled_cipher_suites: Vec<CipherSuite>) -> Self {
        Self {
            enabled_cipher_suites,
            _phantom: PhantomData,
        }
    }

    fn cipher_suite_provider_internal(
        &self,
        classical_cipher_suite: CipherSuite,
        kem: KEM,
        cipher_suite: CipherSuite,
    ) -> Option<AwsLcCipherSuite<KEM>> {
        let kdf = AwsLcHkdf::new(classical_cipher_suite)?;
        let aead = AwsLcAead::new(classical_cipher_suite)?;

        let mac_algo = match classical_cipher_suite {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::CURVE25519_CHACHA
            | CipherSuite::P256_AES128 => hmac::HMAC_SHA256,
            CipherSuite::P384_AES256 => hmac::HMAC_SHA384,
            CipherSuite::P521_AES256 => hmac::HMAC_SHA512,
            _ => return None,
        };

        Some(AwsLcCipherSuite {
            cipher_suite,
            kem,
            aead,
            kdf,
            signing: AwsLcEcdsa::new(classical_cipher_suite)?,
            mac_algo,
            hash: AwsLcHash::new(classical_cipher_suite)?,
        })
    }

    fn dhkem(cipher_suite: CipherSuite) -> Option<DhKem<Ecdh, AwsLcHkdf>> {
        let kem_id = KemId::new(cipher_suite)?;
        let dh = Ecdh::new(cipher_suite)?;
        let kdf = AwsLcHkdf::new(cipher_suite)?;

        Some(DhKem::new(dh, kdf, kem_id as u16, kem_id.n_secret()))
    }
}

impl CryptoProvider for AwsLcCryptoProvider<CombinedEcdhKyberKem> {
    type CipherSuiteProvider = AwsLcCipherSuite<CombinedEcdhKyberKem>;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.enabled_cipher_suites.clone()
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        let classical_cs = match cipher_suite {
            CipherSuite::KYBER1024 => CipherSuite::P384_AES256,
            _ => CipherSuite::CURVE25519_AES128,
        };

        let pq_cs = match cipher_suite {
            CipherSuite::KYBER768_X25519 => CipherSuite::KYBER768,
            _ => return None,
        };

        let kem = CombinedKem::new_xwing(
            KyberKem::new(pq_cs)?,
            Self::dhkem(classical_cs)?,
            AwsLcHash::new_sha3(Sha3::SHA3_256)?,
            AwsLcShake128,
        );

        self.cipher_suite_provider_internal(classical_cs, kem, cipher_suite)
    }
}

impl Default for AwsLcCryptoPqProvider {
    fn default() -> Self {
        Self::new_pq()
    }
}

impl CryptoProvider for AwsLcCryptoProvider<DhKem<Ecdh, AwsLcHkdf>> {
    type CipherSuiteProvider = AwsLcCipherSuite<DhKem<Ecdh, AwsLcHkdf>>;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        self.enabled_cipher_suites.clone()
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        self.cipher_suite_provider_internal(cipher_suite, Self::kem(cipher_suite)?, cipher_suite)
    }
}

#[derive(Debug, Error)]
pub enum AwsLcCryptoError {
    #[error("Invalid key data")]
    InvalidKeyData,
    #[error("Underlying crypto error")]
    CryptoError,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error(transparent)]
    HpkeError(#[from] HpkeError),
    #[error("Unsupported ciphersuite")]
    UnsupportedCipherSuite,
    #[error("Cert validation error: {0}")]
    CertValidationFailure(String),
    #[error(transparent)]
    KeyRejected(#[from] KeyRejected),
    #[error(transparent)]
    CombinedKemError(AnyError),
    #[error(transparent)]
    MlsCodecError(#[from] mls_rs_core::mls_rs_codec::Error),
}

impl From<Unspecified> for AwsLcCryptoError {
    fn from(_value: Unspecified) -> Self {
        AwsLcCryptoError::CryptoError
    }
}

impl IntoAnyError for AwsLcCryptoError {}

#[cfg_attr(not(mls_build_async), maybe_async::must_be_sync)]
#[cfg_attr(all(target_arch = "wasm32", mls_build_async), maybe_async::must_be_async(?Send))]
#[cfg_attr(
    all(not(target_arch = "wasm32"), mls_build_async),
    maybe_async::must_be_async
)]
impl<KEM: KemType + Clone> CipherSuiteProvider for AwsLcCipherSuite<KEM> {
    type Error = AwsLcCryptoError;

    type HpkeContextS = ContextS<AwsLcHkdf, AwsLcAead>;
    type HpkeContextR = ContextR<AwsLcHkdf, AwsLcAead>;

    fn cipher_suite(&self) -> mls_rs_core::crypto::CipherSuite {
        self.cipher_suite
    }

    async fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.hash.hash(data)
    }

    async fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let key = hmac::Key::new(self.mac_algo, key);
        Ok(hmac::sign(&key, data).as_ref().to_vec())
    }

    async fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead.seal(key, data, aad, nonce).await
    }

    async fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead
            .open(key, ciphertext, aad, nonce)
            .await
            .map(Into::into)
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    async fn kdf_extract(
        &self,
        salt: &[u8],
        ikm: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf.extract(salt, ikm).await.map(Into::into)
    }

    async fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.kdf.expand(prk, info, len).await.map(Into::into)
    }

    fn kdf_extract_size(&self) -> usize {
        self.kdf.extract_size()
    }

    async fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        self.hpke()
            .seal(remote_key, info, None, aad, pt)
            .await
            .map_err(Into::into)
    }

    async fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, Self::Error> {
        self.hpke()
            .open(ciphertext, local_secret, local_public, info, None, aad)
            .await
            .map_err(Into::into)
    }

    async fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        self.hpke()
            .setup_sender(remote_key, info, None)
            .await
            .map_err(Into::into)
    }

    async fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,

        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        self.hpke()
            .setup_receiver(kem_output, local_secret, local_public, info, None)
            .await
            .map_err(Into::into)
    }

    async fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.hpke().derive(ikm).await.map_err(Into::into)
    }

    async fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        self.hpke().generate().await.map_err(Into::into)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        self.hpke().public_key_validate(key).map_err(Into::into)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        random_bytes(out)
    }

    async fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        self.signing.signature_key_generate()
    }

    async fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        self.signing.signature_key_derive_public(secret_key)
    }

    async fn sign(
        &self,
        secret_key: &SignatureSecretKey,
        data: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.signing.sign(secret_key, data)
    }

    async fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        self.signing.verify(public_key, signature, data)
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    unsafe {
        let mut out = MaybeUninit::<[u8; 32]>::uninit();
        SHA256(data.as_ptr(), data.len(), out.as_mut_ptr() as *mut u8);
        out.assume_init()
    }
}

fn check_res(r: c_int) -> Result<(), AwsLcCryptoError> {
    check_int_return(r).map(|_| ())
}

fn check_int_return(r: c_int) -> Result<c_int, AwsLcCryptoError> {
    if r <= 0 {
        Err(AwsLcCryptoError::CryptoError)
    } else {
        Ok(r)
    }
}

fn check_non_null<T>(r: *mut T) -> Result<*mut T, AwsLcCryptoError> {
    if r.is_null() {
        return Err(AwsLcCryptoError::CryptoError);
    }

    Ok(r)
}

fn check_non_null_const<T>(r: *const T) -> Result<*const T, AwsLcCryptoError> {
    if r.is_null() {
        return Err(AwsLcCryptoError::CryptoError);
    }

    Ok(r)
}

pub(crate) fn random_bytes(out: &mut [u8]) -> Result<(), AwsLcCryptoError> {
    unsafe {
        if 1 != aws_lc_sys::RAND_bytes(out.as_mut_ptr(), out.len()) {
            return Err(Unspecified.into());
        }
    }

    Ok(())
}

#[cfg(not(mls_build_async))]
#[test]
fn mls_core_tests() {
    mls_rs_core::crypto::test_suite::verify_tests(&AwsLcCryptoProvider::new(), true);

    for cs in AwsLcCryptoProvider::new().supported_cipher_suites() {
        let mut hpke = AwsLcCryptoProvider::new()
            .cipher_suite_provider(cs)
            .unwrap()
            .hpke();

        mls_rs_core::crypto::test_suite::verify_hpke_context_tests(&hpke, cs);
        mls_rs_core::crypto::test_suite::verify_hpke_encap_tests(&mut hpke, cs);
    }
}
