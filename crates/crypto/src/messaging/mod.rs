use pqcrypto_falcon::ffi::{
    PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
    PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES,
};
use pqcrypto_mlkem::{
    ffi::{
        PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES, PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
        PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES,
        PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES,
    },
    mlkem1024::{self, SharedSecret},
};
use pqcrypto_traits::kem::{Ciphertext, PublicKey};

use crate::{
    errors::CryptoError,
    exchange::{
        encryptor,
        exchange_pair::{self, b2ss, ss2b},
    },
    signatures::keypair::{SignerPair, VerifierPair, ViewOperations},
};

pub struct MessageSession {
    kem_pair: exchange_pair::KeyPair,
    ds_pair: SignerPair,
    shared_secret: SharedSecret,
    target_verifier: VerifierPair,
    current_nonce: [u8; 24], // 0..16 session id, 16..24 counter (u64, 8 bytes)
}

pub struct CraftedMessage {
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

impl CraftedMessage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.message.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&self.message);
        bytes.extend_from_slice(&self.signature);

        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let message = bytes[4..4 + len].to_vec();
        let signature = bytes[4 + len..].to_vec();

        Ok((message, signature))
    }
}

impl MessageSession {
    pub fn to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut bytes = Vec::new();

        // PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
        bytes.extend_from_slice(self.kem_pair.to_bytes_uniform().as_slice());

        // PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES
        bytes.extend_from_slice(self.ds_pair.to_bytes_uniform().as_slice());

        // PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
        bytes.extend_from_slice(&ss2b(&self.shared_secret));

        // Target verifier
        bytes.extend_from_slice(&self.target_verifier.to_bytes());

        // Current nonce
        bytes.extend_from_slice(&self.current_nonce[..]);
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len()
            != PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + 24
        {
            return Err(CryptoError::IncongruentLength(
                PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                    + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES
                    + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                    + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES
                    + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES
                    + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                    + 24,
                bytes.len(),
            ));
        }

        let mut idx = 0;

        let kem_pair = exchange_pair::KeyPair::from_bytes_uniform(
            &bytes[idx..idx
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES],
        )?;

        idx += PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES
            + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES;

        let ds_pair = SignerPair::from_bytes_uniform(
            &bytes[idx..idx
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
                + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES],
        )?;

        idx += PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES
            + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_SECRETKEYBYTES;

        let ss_bytes = &bytes[idx..idx + PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES];
        let shared_secret = b2ss(parse_ss(ss_bytes)?);
        idx += PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES;

        let target_verifier = VerifierPair::from_bytes(
            &bytes[idx..idx + PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES],
        )?;
        idx += PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES;

        let current_nonce = bytes[idx..idx + 24].try_into().unwrap();
        idx += 24;

        if idx != bytes.len() {
            return Err(CryptoError::IncongruentLength(bytes.len(), idx));
        }

        Ok(Self {
            kem_pair,
            ds_pair,
            shared_secret,
            target_verifier,
            current_nonce,
        })
    }

    pub fn new_initiator(
        &self,
        my_keypair: exchange_pair::KeyPair, // This the your own keypair
        my_signer: SignerPair,              // This is your own signer pair
        base_nonce: [u8; 24], // 0..16 session id, 16..24 counter (u64, 8 bytes), provided by server
        target_pubkey: &[u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES], // KEM public key of the target
        target_verifier: &[u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES], // Falcon verifier containing the falcon public key of the target
    ) -> Result<(Self, [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES]), CryptoError> {
        let pubkey = mlkem1024::PublicKey::from_bytes(target_pubkey)?;

        // We are the initiator, we need to encapsulate a shared secret for the receiver
        let (shared_secret, ciphertext) = my_keypair.encapsulate(&pubkey);

        // This contains the falcon public key of the target we are trying to reach
        // We will need this to verify his/her messages (signatures)
        let target_verifier = VerifierPair::from_bytes(target_verifier)?;

        // Return the ciphertext and shared secret
        Ok((
            Self {
                kem_pair: my_keypair,
                ds_pair: my_signer,
                shared_secret,
                target_verifier,
                current_nonce: base_nonce,
            },
            ct2b(&ciphertext)?,
        ))
    }

    pub fn new_responder(
        &self,
        my_keypair: exchange_pair::KeyPair, // This the your own keypair
        my_signer: SignerPair,              // This is your own signer pair
        base_nonce: [u8; 24], // 0..16 session id, 16..24 counter (u64, 8 bytes), provided by server
        ciphertext_bytes: &[u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES], // KEM ciphertext semt tp us by the initiator
        sender_verifier: &[u8; PQCLEAN_FALCONPADDED1024_CLEAN_CRYPTO_PUBLICKEYBYTES], // Falcon verifier containing the falcon public key of the initiator
    ) -> Result<Self, CryptoError> {
        // We just have someone that attempts to establish a shared secret with us

        // Compute the shared secret using our private key
        let ciphertext = Ciphertext::from_bytes(ciphertext_bytes)?;
        let shared_secret = self.kem_pair.decapsulate(&ciphertext)?;

        // This contains the verifier pubkey of the sender that is trying to reach us
        let target_verifier = VerifierPair::from_bytes(sender_verifier)?;

        Ok(Self {
            kem_pair: my_keypair,
            ds_pair: my_signer,
            shared_secret,
            target_verifier,
            current_nonce: base_nonce,
        })
    }

    pub fn craft_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig = self.ds_pair.sign(message);
        let crafted_message = CraftedMessage {
            message: message.to_vec(),
            signature: sig,
        };

        self.increment_nonce();

        let cm_bytes = crafted_message.to_bytes()?;

        encryptor::Encryptor::new(self.shared_secret)
            .encrypt(cm_bytes.as_slice(), &self.current_nonce)
    }

    pub fn parse_message(&mut self, ciphertext: &[u8]) -> Result<CraftedMessage, CryptoError> {
        let decrypted_bytes = encryptor::Encryptor::new(self.shared_secret)
            .decrypt(ciphertext, &self.current_nonce)?;

        let (message, signature) = CraftedMessage::from_bytes(&decrypted_bytes)?;

        if !self.target_verifier.verify(&message, &signature)? {
            return Err(CryptoError::SignatureVerificationFailed);
        }

        self.increment_nonce();
        Ok(CraftedMessage { message, signature })
    }

    fn increment_nonce(&mut self) {
        let mut counter = u64::from_le_bytes(self.current_nonce[16..24].try_into().unwrap());
        counter += 1;
        self.current_nonce[16..24].copy_from_slice(&counter.to_le_bytes());
    }
    fn rollback_nonce(&mut self, n: u64) {
        let mut counter = u64::from_le_bytes(self.current_nonce[16..24].try_into().unwrap());
        counter -= n;
        self.current_nonce[16..24].copy_from_slice(&counter.to_le_bytes());
    }
}

fn ct2b(
    ct: &mlkem1024::Ciphertext,
) -> Result<[u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES], CryptoError> {
    let slice = ct.as_bytes();

    if slice.len() == PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES {
        let ptr = slice.as_ptr() as *const [u8; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES];
        unsafe { Ok(*ptr) }
    } else {
        Err(CryptoError::IncongruentLength(
            PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES,
            slice.len(),
        ))
    }
}

pub fn parse_ss<T>(slice: &[T]) -> Result<&[T; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES], CryptoError> {
    if slice.len() == PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES {
        let ptr = slice.as_ptr() as *const [T; PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES];
        unsafe { Ok(&*ptr) }
    } else {
        Err(CryptoError::IncongruentLength(
            PQCLEAN_MLKEM1024_CLEAN_CRYPTO_BYTES,
            slice.len(),
        ))
    }
}

// [u8] to [u8; 24]
