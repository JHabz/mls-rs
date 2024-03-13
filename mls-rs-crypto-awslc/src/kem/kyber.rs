use std::ptr::null_mut;

use aws_lc_rs::{
    error::Unspecified,
    kem::{Algorithm, AlgorithmIdentifier, EncapsulationKey},
    unstable::kem::{get_algorithm, AlgorithmId},
};
use aws_lc_sys::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new, EVP_PKEY_decapsulate, EVP_PKEY_free,
    EVP_PKEY_kem_new_raw_secret_key,
};
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024, MlKem512, MlKem768, B32};
use mls_rs_core::crypto::{CipherSuite, HpkePublicKey, HpkeSecretKey};
use mls_rs_crypto_traits::{KdfType, KemResult, KemType};

use crate::{check_non_null, kdf::AwsLcHkdf, random_bytes, AwsLcCryptoError};

#[derive(Clone)]
pub struct KyberKem {
    kdf: AwsLcHkdf,
    kyber: Kyber,
}

impl KyberKem {
    pub fn new(cipher_suite: CipherSuite) -> Option<Self> {
        let kdf = match cipher_suite {
            CipherSuite::KYBER512 | CipherSuite::KYBER768 => {
                AwsLcHkdf::new(CipherSuite::CURVE25519_AES128)?
            }
            CipherSuite::KYBER1024 => AwsLcHkdf::new(CipherSuite::P384_AES256)?,
            _ => return None,
        };

        Some(Self {
            kdf,
            kyber: Kyber::new(cipher_suite)?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum Kyber {
    KYBER512,
    KYBER768,
    KYBER1024,
}

impl Kyber {
    fn new(cipher_suite: CipherSuite) -> Option<Self> {
        match cipher_suite {
            CipherSuite::KYBER512 => Some(Self::KYBER512),
            CipherSuite::KYBER768 => Some(Self::KYBER768),
            CipherSuite::KYBER1024 => Some(Self::KYBER1024),
            _ => None,
        }
    }

    fn algorithm(&self) -> Result<&'static Algorithm<AlgorithmId>, AwsLcCryptoError> {
        let algorithm_id = match self {
            Kyber::KYBER512 => AlgorithmId::Kyber512_R3,
            Kyber::KYBER768 => AlgorithmId::Kyber768_R3,
            Kyber::KYBER1024 => AlgorithmId::Kyber1024_R3,
        };

        get_algorithm(algorithm_id).ok_or(AwsLcCryptoError::UnsupportedCipherSuite)
    }

    fn secret_key_size(&self) -> usize {
        match self {
            Kyber::KYBER512 => 1632,
            Kyber::KYBER768 => 2400,
            Kyber::KYBER1024 => 3168,
        }
    }
}

impl KemType for KyberKem {
    type Error = AwsLcCryptoError;

    fn kem_id(&self) -> u16 {
        // TODO not set by any RFC
        15
    }

    fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        let remote_key = EncapsulationKey::new(self.kyber.algorithm()?, &remote_key)?;
        let (enc, shared_secret) = remote_key.encapsulate()?;

        Ok(KemResult {
            enc: enc.as_ref().to_vec(),
            shared_secret: shared_secret.as_ref().to_vec(),
        })
    }

    fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        _local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        let nid = self.kyber.algorithm()?.id().nid();
        let len = self.kyber.secret_key_size();
        let mut shared_secret = vec![0u8; 32];

        let res = unsafe {
            let pkey = check_non_null(EVP_PKEY_kem_new_raw_secret_key(
                nid,
                secret_key.as_ptr(),
                len,
            ))?;

            let ctx = EVP_PKEY_CTX_new(pkey, null_mut());

            let res = EVP_PKEY_decapsulate(
                ctx,
                shared_secret.as_mut_ptr(),
                &mut 32,
                enc.as_ptr() as *mut u8,
                enc.len(),
            );

            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);

            res
        };

        (res == 1)
            .then_some(shared_secret)
            .ok_or(Unspecified.into())
    }

    fn derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let ikm = self.kdf.expand(ikm, &[], 64)?;
        let ikm1 = try_to_b32(&ikm[0..32])?;
        let ikm2 = try_to_b32(&ikm[32..64])?;

        let (secret, public) = match self.kyber {
            Kyber::KYBER512 => {
                let (secret, public) = MlKem512::generate_deterministic(ikm1, ikm2);
                (secret.as_bytes().to_vec(), public.as_bytes().to_vec())
            }
            Kyber::KYBER768 => {
                let (secret, public) = MlKem768::generate_deterministic(ikm1, ikm2);
                (secret.as_bytes().to_vec(), public.as_bytes().to_vec())
            }
            Kyber::KYBER1024 => {
                let (secret, public) = MlKem1024::generate_deterministic(ikm1, ikm2);
                (secret.as_bytes().to_vec(), public.as_bytes().to_vec())
            }
        };

        Ok((secret.into(), public.into()))
    }

    fn public_key_validate(&self, _key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(())
    }

    fn seed_length_for_derive(&self) -> usize {
        64
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let mut out = vec![0u8; self.seed_length_for_derive()];
        random_bytes(&mut out)?;

        self.derive(&out)
    }
}

fn try_to_b32(bytes: &[u8]) -> Result<&B32, AwsLcCryptoError> {
    bytes.try_into().map_err(|_| AwsLcCryptoError::CryptoError)
}

#[cfg(test)]
mod test {
    use mls_rs_core::crypto::{CipherSuite, CryptoProvider};
    use mls_rs_crypto_traits::KemType;

    use crate::AwsLcCryptoProvider;

    #[test]
    fn round_trip() {
        let kem = AwsLcCryptoProvider::new_pq()
            .cipher_suite_provider(CipherSuite::KYBER768_X25519)
            .unwrap()
            .kem;

        let (secret, public) = kem.derive(&[0u8; 96]).unwrap();
        let ct = kem.encap(&public).unwrap();
        let ss = kem.decap(&ct.enc, &secret, &public).unwrap();

        assert_eq!(ss, ct.shared_secret)
    }
}
