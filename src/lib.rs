use leansig::signature::SignatureScheme;
use leansig::MESSAGE_LENGTH;
use leansig::signature::generalized_xmss::instantiations_poseidon_top_level::lifetime_2_to_the_32::hashing_optimized::SIGTopLevelTargetSumLifetime32Dim64Base8;
use rand::{SeedableRng, rngs::StdRng, Rng};
use thiserror::Error;
use std::ptr;
use std::slice;
use ssz::Decode;

pub type LeanSignatureScheme = SIGTopLevelTargetSumLifetime32Dim64Base8;
pub type LeanPublicKey = <LeanSignatureScheme as SignatureScheme>::PublicKey;
pub type LeanSecretKey = <LeanSignatureScheme as SignatureScheme>::SecretKey;
pub type LeanSignature = <LeanSignatureScheme as SignatureScheme>::Signature;

#[repr(C)]
pub struct SecretKey {
    pub inner: LeanSecretKey,
}

#[repr(C)]
pub struct PublicKey {
    pub inner: LeanPublicKey,
}

#[repr(C)]
pub struct Signature {
    pub inner: LeanSignature,
}

// Keypair sturcture
pub struct Keypair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Signing failed")]
    SigningFailed(leansig::signature::SigningError),
}

#[derive(Debug, Error)]
pub enum SignatureVerificationError {
    #[error("Verification failed")]
    VerificationFailed,
}

impl SecretKey {
    pub fn new(inner: LeanSecretKey) -> Self { 
        Self { inner }
    }

    pub fn generate_keys<R: Rng>(
        rng: &mut R,
        activation_epoch: usize,
        num_active_epochs: usize,
    ) -> (PublicKey, SecretKey) {
        let (public_key, secret_key) = <LeanSignatureScheme as SignatureScheme>::key_gen(
            rng,
            activation_epoch,
            num_active_epochs,
        );

        (PublicKey::new(public_key), Self::new(secret_key))
    }

    pub fn sign_message(
        &self,
        message: &[u8; MESSAGE_LENGTH],
        epoch: u32,
    ) -> Result<Signature, SigningError> {
        Ok(Signature::new(
            <LeanSignatureScheme as SignatureScheme>::sign(&self.inner, epoch, message)
                .map_err(SigningError::SigningFailed)?,
        ))
    }
}

impl PublicKey {
    pub fn new(inner: LeanPublicKey) -> Self {
        Self { inner }
    }
}

impl Signature {
    pub fn new(inner: LeanSignature) -> Self {
        Self { inner }
    }

    pub fn verify(
        &self,
        message: &[u8; MESSAGE_LENGTH],
        public_key: &PublicKey,
        epoch: u32,
    ) -> bool {
        <LeanSignatureScheme as SignatureScheme>::verify(
            &public_key.inner,
            epoch,
            message,
            &self.inner,
        )
    }
}

// FFI functions for Golang interop
//
// Returns a pointer to the keypair
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_generate(
    seed: u64,
    activation_epoch: usize,
    num_active_epochs: usize,
) -> *mut Keypair {
    let mut rng = StdRng::seed_from_u64(seed);

    let (public_key, secret_key) =
        SecretKey::generate_keys(&mut rng, activation_epoch, num_active_epochs);

    let keypair = Box::new(Keypair {
        public_key,
        secret_key,
    });

    Box::into_raw(keypair)
}

// Reconstruct a key pair from SSZ-encoded secret and public keys
// Returns a pointer to the KeyPair or null on error
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_from_ssz(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    public_key_ptr: *const u8,
    public_key_len: usize
) -> *mut Keypair {
    if secret_key_ptr.is_null() || public_key_ptr.is_null() {
        return ptr::null_mut();
    }
    
    unsafe {
        let sk_slice = slice::from_raw_parts(secret_key_ptr, secret_key_len);
        let pk_slice = slice::from_raw_parts(public_key_ptr, public_key_len);
        
        let secret_key: LeanSecretKey = match LeanSecretKey::from_ssz_bytes(sk_slice) {
            Ok(key) => key,
            Err(_) => return ptr::null_mut()
        };
        
        let public_key: LeanPublicKey = match LeanPublicKey::from_ssz_bytes(pk_slice) {
            Ok(key) => key,
            Err(_) => return ptr::null_mut()
        };
        
        let keypair = Box::new(Keypair {
            public_key: PublicKey::new(public_key),
            secret_key: SecretKey::new(secret_key),
        });
        
        Box::into_raw(keypair)
            
        
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_free(keypair: *mut Keypair) {
    if !keypair.is_null() {
        unsafe {
            let _ = Box::from_raw(keypair);
        }
    }
}

// Get a pointer to the public key from a keypair
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_get_public_key(keypair: *const Keypair) -> *const PublicKey {
    if keypair.is_null() {
           return ptr::null();
    }
    
    unsafe {
         &(*keypair).public_key
    }
}

// Get a pointer to the private key from a keypair
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_keypair_get_private_key(keypair: *const Keypair) -> *const SecretKey {
    if keypair.is_null() {
           return ptr::null();
    }
    
    unsafe {
         &(*keypair).secret_key
    }
}


// Construct a standalone public key from SSZ-encoded bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_public_key_from_ssz(public_key_ptr: *const u8, public_key_len: usize) -> *const PublicKey {
    if public_key_ptr.is_null() {
        return ptr::null_mut();
    }
    
    unsafe {
        let pk_slice = slice::from_raw_parts(public_key_ptr, public_key_len);
        let public_key: LeanPublicKey = match LeanPublicKey::from_ssz_bytes(pk_slice) {
            Ok(key) => key,
            Err(_) => return ptr::null_mut(),
        };
        
        Box::into_raw(Box::new(PublicKey::new(public_key)))
    }
}


// Free a public key created via hashsig_public_key_from_ssz.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_public_key_free(public_key: *mut PublicKey) {
    if !public_key.is_null() {
        unsafe {
            let _ = Box::from_raw(public_key);
        }
    }
}


#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_sign(secret_key: *const SecretKey, message_ptr: *const u8, epoch: u32) -> *mut Signature {
    if secret_key.is_null() || message_ptr.is_null() {
        return ptr::null_mut();
    }
    
    unsafe {
        let secret_key_ref = &*secret_key;
        let message_slice = slice::from_raw_parts(message_ptr, MESSAGE_LENGTH);
        
        let message_data: &[u8; MESSAGE_LENGTH] =  match message_slice.try_into() {
            Ok(arr) => arr,
            Err(_) => return ptr::null_mut(),
        };
        
        let signature = match secret_key_ref.sign_message(message_data, epoch) {
            Ok(sig) => sig,
            Err(_) => return ptr::null_mut(),
        };
        
        Box::into_raw(Box::new(signature))
        
    }
}


// free signature
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_signature_free(signature: *mut Signature) {
    if !signature.is_null() {
        unsafe {
            let _ = Box::from_raw(signature);
        }
    }
}

// Construct a signature from SSZ-encoded bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn leansig_signature_from_ssz(signature_ptr: *const u8, signature_len: usize) -> *mut Signature {
    if signature_ptr.is_null() || signature_len == 0 {
        return ptr::null_mut();
    }
    
    unsafe {
        let signature_slice = slice::from_raw_parts(signature_ptr, signature_len);
        let signature: LeanSignature = match LeanSignature::from_ssz_bytes(signature_slice) {
            Ok(sig) => sig,
            Err(_) => return ptr::null_mut(),
        };
        
        Box::into_raw(Box::new(Signature { inner: signature }))
    }
}

#[cfg(test)]
mod ffi_tests {
    use super::*;
    use ssz::Encode;

    #[test]
    fn test_keypair_generate() {
        unsafe {
            let keypair = leansig_keypair_generate(42, 0, 10);
            assert!(!keypair.is_null());
            leansig_keypair_free(keypair);
        }
    }

    #[test]
    fn test_keypair_get_public_key() {
        unsafe {
            let keypair = leansig_keypair_generate(42, 0, 10);
            let public_key = leansig_keypair_get_public_key(keypair);
            assert!(!public_key.is_null());
            leansig_keypair_free(keypair);
        }
    }

    #[test]
    fn test_keypair_get_public_key_null() {
        unsafe {
            let public_key = leansig_keypair_get_public_key(ptr::null());
            assert!(public_key.is_null());
        }
    }

    #[test]
    fn test_keypair_get_private_key() {
        unsafe {
            let keypair = leansig_keypair_generate(42, 0, 10);
            let secret_key = leansig_keypair_get_private_key(keypair);
            assert!(!secret_key.is_null());
            leansig_keypair_free(keypair);
        }
    }

    #[test]
    fn test_keypair_get_private_key_null() {
        unsafe {
            let secret_key = leansig_keypair_get_private_key(ptr::null());
            assert!(secret_key.is_null());
        }
    }

    #[test]
    fn test_keypair_from_ssz_roundtrip() {
        unsafe {
            let keypair = leansig_keypair_generate(42, 0, 10);
            let sk = &(*keypair).secret_key.inner;
            let pk = &(*keypair).public_key.inner;
            
            let sk_bytes = sk.as_ssz_bytes();
            let pk_bytes = pk.as_ssz_bytes();
            
            let reconstructed = leansig_keypair_from_ssz(
                sk_bytes.as_ptr(),
                sk_bytes.len(),
                pk_bytes.as_ptr(),
                pk_bytes.len()
            );
            
            assert!(!reconstructed.is_null());
            leansig_keypair_free(keypair);
            leansig_keypair_free(reconstructed);
        }
    }

    #[test]
    fn test_keypair_from_ssz_null_secret_key() {
        unsafe {
            let pk_bytes = vec![0u8; 32];
            let result = leansig_keypair_from_ssz(
                ptr::null(),
                0,
                pk_bytes.as_ptr(),
                pk_bytes.len()
            );
            assert!(result.is_null());
        }
    }

    #[test]
    fn test_keypair_from_ssz_null_public_key() {
        unsafe {
            let sk_bytes = vec![0u8; 32];
            let result = leansig_keypair_from_ssz(
                sk_bytes.as_ptr(),
                sk_bytes.len(),
                ptr::null(),
                0
            );
            assert!(result.is_null());
        }
    }

    #[test]
    fn test_keypair_from_ssz_invalid_data() {
        unsafe {
            let invalid_bytes = vec![0u8; 10];
            let result = leansig_keypair_from_ssz(
                invalid_bytes.as_ptr(),
                invalid_bytes.len(),
                invalid_bytes.as_ptr(),
                invalid_bytes.len()
            );
            assert!(result.is_null());
        }
    }

    #[test]
    fn test_keypair_free_null() {
        unsafe {
            leansig_keypair_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_public_key_from_ssz() {
        unsafe {
            let keypair = leansig_keypair_generate(42, 0, 10);
            let pk = &(*keypair).public_key.inner;
            let pk_bytes = pk.as_ssz_bytes();
            
            let public_key = leansig_public_key_from_ssz(pk_bytes.as_ptr(), pk_bytes.len());
            assert!(!public_key.is_null());
            
            leansig_keypair_free(keypair);
            leansig_public_key_free(public_key as *mut PublicKey);
        }
    }

    #[test]
    fn test_public_key_from_ssz_null() {
        unsafe {
            let public_key = leansig_public_key_from_ssz(ptr::null(), 0);
            assert!(public_key.is_null());
        }
    }

    #[test]
    fn test_public_key_from_ssz_invalid() {
        unsafe {
            let invalid_bytes = vec![0u8; 10];
            let public_key = leansig_public_key_from_ssz(invalid_bytes.as_ptr(), invalid_bytes.len());
            assert!(public_key.is_null());
        }
    }

    #[test]
    fn test_public_key_free_null() {
        unsafe {
            leansig_public_key_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_sign_and_verify() {
        unsafe {
            let keypair = leansig_keypair_generate(42, 0, 10);
            let secret_key = leansig_keypair_get_private_key(keypair);
            let public_key = leansig_keypair_get_public_key(keypair);
            
            let message = [1u8; MESSAGE_LENGTH];
            let epoch = 5u32;
            
            let signature = leansig_sign(secret_key, message.as_ptr(), epoch);
            assert!(!signature.is_null());
            
            let is_valid = (*signature).verify(&message, &*public_key, epoch);
            assert!(is_valid);
            
            leansig_signature_free(signature);
            leansig_keypair_free(keypair);
        }
    }

    #[test]
    fn test_sign_null_secret_key() {
        unsafe {
            let message = [1u8; MESSAGE_LENGTH];
            let signature = leansig_sign(ptr::null(), message.as_ptr(), 0);
            assert!(signature.is_null());
        }
    }

    #[test]
    fn test_sign_null_message() {
        unsafe {
            let keypair = leansig_keypair_generate(42, 0, 10);
            let secret_key = leansig_keypair_get_private_key(keypair);
            
            let signature = leansig_sign(secret_key, ptr::null(), 0);
            assert!(signature.is_null());
            
            leansig_keypair_free(keypair);
        }
    }

    #[test]
    fn test_signature_free_null() {
        unsafe {
            leansig_signature_free(ptr::null_mut());
        }
    }

    #[test]
    fn test_signature_from_ssz_roundtrip() {
        unsafe {
            let keypair = leansig_keypair_generate(42, 0, 10);
            let secret_key = leansig_keypair_get_private_key(keypair);
            let message = [1u8; MESSAGE_LENGTH];
            
            let signature = leansig_sign(secret_key, message.as_ptr(), 5);
            let sig_bytes = (*signature).inner.as_ssz_bytes();
            
            let reconstructed = leansig_signature_from_ssz(sig_bytes.as_ptr(), sig_bytes.len());
            assert!(!reconstructed.is_null());
            
            leansig_signature_free(signature);
            leansig_signature_free(reconstructed);
            leansig_keypair_free(keypair);
        }
    }

    #[test]
    fn test_signature_from_ssz_null() {
        unsafe {
            let signature = leansig_signature_from_ssz(ptr::null(), 0);
            assert!(signature.is_null());
        }
    }

    #[test]
    fn test_signature_from_ssz_zero_length() {
        unsafe {
            let bytes = vec![1u8; 10];
            let signature = leansig_signature_from_ssz(bytes.as_ptr(), 0);
            assert!(signature.is_null());
        }
    }

    #[test]
    fn test_signature_from_ssz_invalid() {
        unsafe {
            let invalid_bytes = vec![0u8; 10];
            let signature = leansig_signature_from_ssz(invalid_bytes.as_ptr(), invalid_bytes.len());
            assert!(signature.is_null());
        }
    }

    #[test]
    fn test_sign_wrong_epoch_fails_verification() {
        unsafe {
            let keypair = leansig_keypair_generate(42, 0, 10);
            let secret_key = leansig_keypair_get_private_key(keypair);
            let public_key = leansig_keypair_get_public_key(keypair);
            
            let message = [1u8; MESSAGE_LENGTH];
            let sign_epoch = 5u32;
            let verify_epoch = 6u32;
            
            let signature = leansig_sign(secret_key, message.as_ptr(), sign_epoch);
            let is_valid = (*signature).verify(&message, &*public_key, verify_epoch);
            assert!(!is_valid);
            
            leansig_signature_free(signature);
            leansig_keypair_free(keypair);
        }
    }

    #[test]
    fn test_sign_different_message_fails_verification() {
        unsafe {
            let keypair = leansig_keypair_generate(42, 0, 10);
            let secret_key = leansig_keypair_get_private_key(keypair);
            let public_key = leansig_keypair_get_public_key(keypair);
            
            let message1 = [1u8; MESSAGE_LENGTH];
            let message2 = [2u8; MESSAGE_LENGTH];
            let epoch = 5u32;
            
            let signature = leansig_sign(secret_key, message1.as_ptr(), epoch);
            let is_valid = (*signature).verify(&message2, &*public_key, epoch);
            assert!(!is_valid);
            
            leansig_signature_free(signature);
            leansig_keypair_free(keypair);
        }
    }
}
