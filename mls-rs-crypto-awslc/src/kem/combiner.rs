use aws_lc_rs::{digest, hmac};
use mls_rs_core::{
    crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey},
    error::IntoAnyError,
    mls_rs_codec::{self, MlsDecode, MlsEncode, MlsSize},
};
use mls_rs_crypto_traits::{KdfType, KemResult, KemType};
use zeroize::Zeroize;

use crate::{random_bytes, AwsLcCryptoError};

pub trait Hash: Send + Sync {
    type Error: IntoAnyError + Send + Sync;

    fn hash(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[derive(Clone)]
pub struct CombinedKem<KEM1, KEM2, H> {
    kem1: KEM1,
    kem2: KEM2,
    hash: H,
}

impl<KEM1, KEM2, H> CombinedKem<KEM1, KEM2, H> {
    pub fn new(kem1: KEM1, kem2: KEM2, hash: H) -> Self {
        Self { kem1, kem2, hash }
    }
}

impl<KEM1: KemType, KEM2: KemType, H: Hash> KemType for CombinedKem<KEM1, KEM2, H> {
    type Error = AwsLcCryptoError;

    fn kem_id(&self) -> u16 {
        // TODO not set by any RFC
        15
    }

    fn derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        (ikm.len() == self.seed_length_for_derive())
            .then_some(())
            .ok_or(AwsLcCryptoError::InvalidKeyData)?;

        let (ikm1, ikm2) = ikm.split_at(self.kem1.seed_length_for_derive());

        let (sk1, pk1) = self
            .kem1
            .derive(ikm1)
            .map_err(|e| AwsLcCryptoError::CombinedKemError(e.into_any_error()))?;

        let (sk2, pk2) = self
            .kem2
            .derive(ikm2)
            .map_err(|e| AwsLcCryptoError::CombinedKemError(e.into_any_error()))?;

        let sk = (sk1, sk2).mls_encode_to_vec()?;
        let pk = (pk1, pk2).mls_encode_to_vec()?;

        Ok((sk.into(), pk.into()))
    }

    fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        let (pk1, pk2) = <(HpkePublicKey, HpkePublicKey)>::mls_decode(&mut remote_key.as_ref())?;

        let ct1 = self
            .kem1
            .encap(&pk1)
            .map_err(|e| AwsLcCryptoError::CombinedKemError(e.into_any_error()))?;

        let ct2 = self
            .kem2
            .encap(&pk2)
            .map_err(|e| AwsLcCryptoError::CombinedKemError(e.into_any_error()))?;

        let enc = (ct1.enc, ct2.enc)
            .mls_encode_to_vec()
            .map_err(|e| AwsLcCryptoError::CombinedKemError(e.into_any_error()))?;

        let mut shared_secret_input =
            [ct1.shared_secret.as_slice(), &ct2.shared_secret, &enc].concat();

        let shared_secret = self
            .hash
            .hash(&shared_secret_input)
            .map_err(|e| AwsLcCryptoError::CombinedKemError(e.into_any_error()))?;

        shared_secret_input.zeroize();

        Ok(KemResult { shared_secret, enc })
    }

    fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        let (enc1, enc2) = <(Vec<u8>, Vec<u8>)>::mls_decode(&mut &*enc)?;
        let (sk1, sk2) = <(HpkeSecretKey, HpkeSecretKey)>::mls_decode(&mut secret_key.as_ref())?;
        let (pk1, pk2) = <(HpkePublicKey, HpkePublicKey)>::mls_decode(&mut local_public.as_ref())?;

        let shared_secret1 = self
            .kem1
            .decap(&enc1, &sk1, &pk1)
            .map_err(|e| AwsLcCryptoError::CombinedKemError(e.into_any_error()))?;

        let shared_secret2 = self
            .kem2
            .decap(&enc2, &sk2, &pk2)
            .map_err(|e| AwsLcCryptoError::CombinedKemError(e.into_any_error()))?;

        let mut shared_secret_input = [shared_secret1.as_slice(), &shared_secret2, &enc].concat();

        let shared_secret = self
            .hash
            .hash(&shared_secret_input)
            .map_err(|e| AwsLcCryptoError::CombinedKemError(e.into_any_error()))?;

        shared_secret_input.zeroize();

        Ok(shared_secret)
    }

    fn public_key_validate(&self, _key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(())
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let mut seed = vec![0u8; self.seed_length_for_derive()];
        random_bytes(&mut seed)?;

        let out = self.derive(&seed);

        seed.zeroize();

        out
    }

    fn seed_length_for_derive(&self) -> usize {
        self.kem1.seed_length_for_derive() + self.kem2.seed_length_for_derive()
    }
}

pub struct AwsLcHash(&'static digest::Algorithm);

impl AwsLcHash {
    pub fn new(cs: CipherSuite) -> Option<Self> {
        match cs {
            CipherSuite::CURVE25519_AES128
            | CipherSuite::CURVE25519_CHACHA
            | CipherSuite::P256_AES128 => Some(hmac::HMAC_SHA256.digest_algorithm()),
            CipherSuite::P384_AES256 => Some(hmac::HMAC_SHA384.digest_algorithm()),
            CipherSuite::P521_AES256 => Some(hmac::HMAC_SHA512.digest_algorithm()),
            _ => return None,
        }
        .map(Self)
    }
}

impl Hash for AwsLcHash {
    type Error = AwsLcCryptoError;

    fn hash(&self, input: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(digest::digest(self.0, input).as_ref().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use mls_rs_core::crypto::CipherSuite;
    use mls_rs_crypto_hpke::dhkem::DhKem;
    use mls_rs_crypto_traits::{KemId, KemType};

    use crate::{
        kdf::AwsLcHkdf,
        kem::{ecdh::Ecdh, kyber::KyberKem},
    };

    use super::{AwsLcHash, CombinedKem};

    #[test]
    fn x() {
        let kem1 = KyberKem::new(CipherSuite::CUSTOM_KYBER768).unwrap();

        let dh_cs = CipherSuite::CURVE25519_AES128;
        let kem_id = KemId::new(dh_cs).unwrap();
        let dh = Ecdh::new(dh_cs).unwrap();
        let kdf = AwsLcHkdf::new(dh_cs).unwrap();
        let kem2 = DhKem::new(dh, kdf, kem_id as u16, kem_id.n_secret());

        let hash = AwsLcHash::new(dh_cs).unwrap();

        let kem = CombinedKem::new(kem1, kem2, hash);

        let (sk, pk) = kem.generate().unwrap();
        let ct = kem.encap(&pk).unwrap();
        let pt = kem.decap(&ct.enc, &sk, &pk).unwrap();
        assert_eq!(pt, ct.shared_secret)
    }
}
