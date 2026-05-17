//! Raw FFI declarations matching the Swift `ck_*` bridge exports.

#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    missing_docs
)]

use libc::{c_char, c_void};

pub mod status {
    pub const OK: i32 = 0;
    pub const INVALID_ARGUMENT: i32 = -1;
    pub const ENCRYPTION_FAILED: i32 = -2;
    pub const DECRYPTION_FAILED: i32 = -3;
    pub const HASHING_FAILED: i32 = -4;
    pub const HMAC_FAILED: i32 = -5;
    pub const HKDF_FAILED: i32 = -6;
    pub const KEY_FAILED: i32 = -7;
    pub const SIGNATURE_FAILED: i32 = -8;
    pub const AGREEMENT_FAILED: i32 = -9;
    pub const UNKNOWN: i32 = -99;
}

pub mod hash_algorithm {
    pub const SHA256: i32 = 1;
    pub const SHA384: i32 = 2;
    pub const SHA512: i32 = 3;
    pub const MD5: i32 = 4;
    pub const SHA1: i32 = 5;
}

pub mod sha3_algorithm {
    pub const SHA3_256: i32 = 1;
    pub const SHA3_384: i32 = 2;
    pub const SHA3_512: i32 = 3;
}

pub mod hmac_algorithm {
    pub const SHA256: i32 = 1;
    pub const SHA384: i32 = 2;
    pub const SHA512: i32 = 3;
}

pub mod signing_algorithm {
    pub const P256: i32 = 1;
    pub const P384: i32 = 2;
    pub const P521: i32 = 3;
    pub const ED25519: i32 = 4;
}

pub mod key_agreement_algorithm {
    pub const P256: i32 = 1;
    pub const P384: i32 = 2;
    pub const P521: i32 = 3;
    pub const X25519: i32 = 4;
}

pub mod key_representation_format {
    pub const RAW: i32 = 1;
    pub const COMPACT: i32 = 2;
    pub const X963: i32 = 3;
    pub const COMPRESSED: i32 = 4;
    pub const DER: i32 = 5;
    pub const PEM: i32 = 6;
}

pub mod ecdsa_signature_format {
    pub const RAW: i32 = 1;
    pub const DER: i32 = 2;
}

pub mod kem_algorithm {
    pub const MLKEM768: i32 = 1;
    pub const MLKEM1024: i32 = 2;
    pub const XWING_MLKEM768_X25519: i32 = 3;
}

pub mod mldsa_algorithm {
    pub const MLDSA65: i32 = 1;
    pub const MLDSA87: i32 = 2;
}

pub mod hpke_kdf {
    pub const HKDF_SHA256: i32 = 1;
    pub const HKDF_SHA384: i32 = 2;
    pub const HKDF_SHA512: i32 = 3;
}

pub mod hpke_aead {
    pub const AES_GCM_128: i32 = 1;
    pub const AES_GCM_256: i32 = 2;
    pub const CHACHA_POLY: i32 = 3;
    pub const EXPORT_ONLY: i32 = 4;
}

pub mod hpke_kem {
    pub const P256_HKDF_SHA256: i32 = 1;
    pub const P384_HKDF_SHA384: i32 = 2;
    pub const P521_HKDF_SHA512: i32 = 3;
    pub const CURVE25519_HKDF_SHA256: i32 = 4;
    pub const XWING_MLKEM768_X25519: i32 = 5;
}

pub mod hpke_mode {
    pub const BASE: i32 = 1;
    pub const PSK: i32 = 2;
    pub const AUTH: i32 = 3;
    pub const AUTH_PSK: i32 = 4;
}

pub mod secure_enclave_accessibility {
    pub const DEFAULT: i32 = 0;
    pub const AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY: i32 = 1;
    pub const WHEN_UNLOCKED_THIS_DEVICE_ONLY: i32 = 2;
    pub const WHEN_PASSCODE_SET_THIS_DEVICE_ONLY: i32 = 3;
    pub const AFTER_FIRST_UNLOCK: i32 = 4;
    pub const WHEN_UNLOCKED: i32 = 5;
    pub const ALWAYS_THIS_DEVICE_ONLY: i32 = 6;
    pub const ALWAYS: i32 = 7;
}

extern "C" {
    pub fn ck_symmetric_key_generate(
        size_bits: i32,
        out_key: *mut *mut u8,
        out_key_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_aes_key_wrap(
        key_to_wrap_bytes: *const u8,
        key_to_wrap_len: usize,
        kek_bytes: *const u8,
        kek_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_aes_key_unwrap(
        wrapped_key_bytes: *const u8,
        wrapped_key_len: usize,
        kek_bytes: *const u8,
        kek_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_aes_gcm_seal(
        key_bytes: *const u8,
        key_len: usize,
        message_bytes: *const u8,
        message_len: usize,
        nonce_bytes: *const u8,
        nonce_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_aes_gcm_open(
        key_bytes: *const u8,
        key_len: usize,
        combined_bytes: *const u8,
        combined_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_chacha_poly_seal(
        key_bytes: *const u8,
        key_len: usize,
        message_bytes: *const u8,
        message_len: usize,
        nonce_bytes: *const u8,
        nonce_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_chacha_poly_open(
        key_bytes: *const u8,
        key_len: usize,
        combined_bytes: *const u8,
        combined_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_hash(
        algorithm: i32,
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hash_hasher_create(algorithm: i32, error_out: *mut *mut c_char) -> *mut c_void;
    pub fn ck_hash_hasher_update(
        handle: *mut c_void,
        input_bytes: *const u8,
        input_len: usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hash_hasher_finalize(
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hash_hasher_release(handle: *mut c_void);
    pub fn ck_hmac(
        algorithm: i32,
        key_bytes: *const u8,
        key_len: usize,
        message_bytes: *const u8,
        message_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hmac_hasher_create(
        algorithm: i32,
        key_bytes: *const u8,
        key_len: usize,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_hmac_hasher_update(
        handle: *mut c_void,
        message_bytes: *const u8,
        message_len: usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hmac_hasher_finalize(
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hmac_hasher_release(handle: *mut c_void);
    pub fn ck_hmac_verify(
        algorithm: i32,
        key_bytes: *const u8,
        key_len: usize,
        message_bytes: *const u8,
        message_len: usize,
        code_bytes: *const u8,
        code_len: usize,
        out_valid: *mut u8,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hkdf_sha256(
        key_bytes: *const u8,
        key_len: usize,
        salt_bytes: *const u8,
        salt_len: usize,
        info_bytes: *const u8,
        info_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hkdf_extract(
        algorithm: i32,
        key_bytes: *const u8,
        key_len: usize,
        salt_bytes: *const u8,
        salt_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hkdf_expand(
        algorithm: i32,
        prk_bytes: *const u8,
        prk_len: usize,
        info_bytes: *const u8,
        info_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_signing_private_key_generate(
        algorithm: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_signing_private_key_validate(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_signing_public_key_validate(
        algorithm: i32,
        public_key_bytes: *const u8,
        public_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_signing_public_key_from_private(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_signing_private_key_generate_with_options(
        algorithm: i32,
        compact_representable: u8,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_signing_private_key_from_representation(
        algorithm: i32,
        format: i32,
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_signing_private_key_representation(
        algorithm: i32,
        raw_private_key_bytes: *const u8,
        raw_private_key_len: usize,
        format: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_signing_public_key_from_representation(
        algorithm: i32,
        format: i32,
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_signing_public_key_representation(
        algorithm: i32,
        raw_public_key_bytes: *const u8,
        raw_public_key_len: usize,
        format: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_sign(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        message_bytes: *const u8,
        message_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_verify(
        algorithm: i32,
        public_key_bytes: *const u8,
        public_key_len: usize,
        message_bytes: *const u8,
        message_len: usize,
        signature_bytes: *const u8,
        signature_len: usize,
        out_valid: *mut u8,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_ecdsa_signature_validate(
        algorithm: i32,
        format: i32,
        signature_bytes: *const u8,
        signature_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_ecdsa_signature_representation(
        algorithm: i32,
        raw_signature_bytes: *const u8,
        raw_signature_len: usize,
        format: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_key_agreement_private_key_generate(
        algorithm: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_key_agreement_private_key_validate(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_key_agreement_public_key_validate(
        algorithm: i32,
        public_key_bytes: *const u8,
        public_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_key_agreement_public_key_from_private(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_key_agreement_private_key_generate_with_options(
        algorithm: i32,
        compact_representable: u8,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_key_agreement_private_key_from_representation(
        algorithm: i32,
        format: i32,
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_key_agreement_private_key_representation(
        algorithm: i32,
        raw_private_key_bytes: *const u8,
        raw_private_key_len: usize,
        format: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_key_agreement_public_key_from_representation(
        algorithm: i32,
        format: i32,
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_key_agreement_public_key_representation(
        algorithm: i32,
        raw_public_key_bytes: *const u8,
        raw_public_key_len: usize,
        format: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_key_agreement_shared_secret(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        public_key_bytes: *const u8,
        public_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_shared_secret_hkdf_sha256(
        secret_bytes: *const u8,
        secret_len: usize,
        salt_bytes: *const u8,
        salt_len: usize,
        info_bytes: *const u8,
        info_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_shared_secret_hkdf_sha384(
        secret_bytes: *const u8,
        secret_len: usize,
        salt_bytes: *const u8,
        salt_len: usize,
        info_bytes: *const u8,
        info_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_shared_secret_hkdf_sha512(
        secret_bytes: *const u8,
        secret_len: usize,
        salt_bytes: *const u8,
        salt_len: usize,
        info_bytes: *const u8,
        info_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_shared_secret_x963_sha256(
        secret_bytes: *const u8,
        secret_len: usize,
        shared_info_bytes: *const u8,
        shared_info_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_shared_secret_x963_sha384(
        secret_bytes: *const u8,
        secret_len: usize,
        shared_info_bytes: *const u8,
        shared_info_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_shared_secret_x963_sha512(
        secret_bytes: *const u8,
        secret_len: usize,
        shared_info_bytes: *const u8,
        shared_info_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_symmetric_key_supported_size_mask() -> i32;
    pub fn ck_aes_gcm_seal_aad(
        key_bytes: *const u8,
        key_len: usize,
        message_bytes: *const u8,
        message_len: usize,
        nonce_bytes: *const u8,
        nonce_len: usize,
        authenticated_data_bytes: *const u8,
        authenticated_data_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_aes_gcm_open_aad(
        key_bytes: *const u8,
        key_len: usize,
        combined_bytes: *const u8,
        combined_len: usize,
        authenticated_data_bytes: *const u8,
        authenticated_data_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_aes_gcm_nonce_generate(
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_aes_cbc_encrypt(
        key_bytes: *const u8,
        key_len: usize,
        iv_bytes: *const u8,
        iv_len: usize,
        plaintext_bytes: *const u8,
        plaintext_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_aes_cbc_decrypt(
        key_bytes: *const u8,
        key_len: usize,
        iv_bytes: *const u8,
        iv_len: usize,
        ciphertext_bytes: *const u8,
        ciphertext_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_chacha_poly_seal_aad(
        key_bytes: *const u8,
        key_len: usize,
        message_bytes: *const u8,
        message_len: usize,
        nonce_bytes: *const u8,
        nonce_len: usize,
        authenticated_data_bytes: *const u8,
        authenticated_data_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_chacha_poly_open_aad(
        key_bytes: *const u8,
        key_len: usize,
        combined_bytes: *const u8,
        combined_len: usize,
        authenticated_data_bytes: *const u8,
        authenticated_data_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_chacha_poly_nonce_generate(
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_sha256(
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_sha384(
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_sha512(
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_md5(
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_sha1(
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_sha3_hash(
        algorithm: i32,
        input_bytes: *const u8,
        input_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_sha3_hasher_create(
        algorithm: i32,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_sha3_hasher_update(
        handle: *mut c_void,
        input_bytes: *const u8,
        input_len: usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_sha3_hasher_finalize(
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_sha3_hasher_release(handle: *mut c_void);

    pub fn ck_hkdf_sha384(
        key_bytes: *const u8,
        key_len: usize,
        salt_bytes: *const u8,
        salt_len: usize,
        info_bytes: *const u8,
        info_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hkdf_sha512(
        key_bytes: *const u8,
        key_len: usize,
        salt_bytes: *const u8,
        salt_len: usize,
        info_bytes: *const u8,
        info_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_p256_is_supported() -> u8;
    pub fn ck_p384_is_supported() -> u8;
    pub fn ck_p521_is_supported() -> u8;
    pub fn ck_curve25519_is_supported() -> u8;
    pub fn ck_key_agreement_supported_algorithm_mask() -> i32;
    pub fn ck_nist_supported_curve_mask() -> i32;

    pub fn ck_kem_public_key_validate(
        algorithm: i32,
        public_key_bytes: *const u8,
        public_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_kem_public_key_encapsulate(
        algorithm: i32,
        public_key_bytes: *const u8,
        public_key_len: usize,
        shared_secret_out_bytes: *mut *mut u8,
        shared_secret_out_len: *mut usize,
        encapsulated_out_bytes: *mut *mut u8,
        encapsulated_out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_kem_private_key_generate(
        algorithm: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_kem_private_key_from_seed(
        algorithm: i32,
        seed_bytes: *const u8,
        seed_len: usize,
        public_key_bytes: *const u8,
        public_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_kem_private_key_validate(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_kem_private_key_seed_representation(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_kem_private_key_public_key(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_kem_private_key_decapsulate(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        encapsulated_bytes: *const u8,
        encapsulated_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_mldsa_public_key_validate(
        algorithm: i32,
        public_key_bytes: *const u8,
        public_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_mldsa_public_key_verify(
        algorithm: i32,
        public_key_bytes: *const u8,
        public_key_len: usize,
        signature_bytes: *const u8,
        signature_len: usize,
        data_bytes: *const u8,
        data_len: usize,
        context_bytes: *const u8,
        context_len: usize,
        out_valid: *mut u8,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_mldsa_private_key_generate(
        algorithm: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_mldsa_private_key_from_seed(
        algorithm: i32,
        seed_bytes: *const u8,
        seed_len: usize,
        public_key_bytes: *const u8,
        public_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_mldsa_private_key_validate(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_mldsa_private_key_seed_representation(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_mldsa_private_key_public_key(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_mldsa_private_key_sign(
        algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        data_bytes: *const u8,
        data_len: usize,
        context_bytes: *const u8,
        context_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_hpke_dh_public_key_from_serialization(
        algorithm: i32,
        kem: i32,
        serialization_bytes: *const u8,
        serialization_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hpke_dh_public_key_representation(
        algorithm: i32,
        raw_public_key_bytes: *const u8,
        raw_public_key_len: usize,
        kem: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hpke_kem_public_key_from_serialization(
        algorithm: i32,
        kem: i32,
        serialization_bytes: *const u8,
        serialization_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hpke_kem_public_key_representation(
        algorithm: i32,
        raw_public_key_bytes: *const u8,
        raw_public_key_len: usize,
        kem: i32,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hpke_sender_create_dh(
        recipient_algorithm: i32,
        recipient_public_key_bytes: *const u8,
        recipient_public_key_len: usize,
        kem: i32,
        kdf: i32,
        aead: i32,
        info_bytes: *const u8,
        info_len: usize,
        mode: i32,
        auth_private_key_bytes: *const u8,
        auth_private_key_len: usize,
        psk_bytes: *const u8,
        psk_len: usize,
        psk_id_bytes: *const u8,
        psk_id_len: usize,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_hpke_sender_create_kem(
        recipient_algorithm: i32,
        recipient_public_key_bytes: *const u8,
        recipient_public_key_len: usize,
        kem: i32,
        kdf: i32,
        aead: i32,
        info_bytes: *const u8,
        info_len: usize,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_hpke_sender_release(handle: *mut c_void);
    pub fn ck_hpke_sender_encapsulated_key(
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hpke_sender_seal(
        handle: *mut c_void,
        message_bytes: *const u8,
        message_len: usize,
        aad_bytes: *const u8,
        aad_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hpke_sender_export_secret(
        handle: *mut c_void,
        context_bytes: *const u8,
        context_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hpke_recipient_create_dh(
        private_algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        kem: i32,
        kdf: i32,
        aead: i32,
        info_bytes: *const u8,
        info_len: usize,
        encapsulated_key_bytes: *const u8,
        encapsulated_key_len: usize,
        mode: i32,
        auth_public_key_bytes: *const u8,
        auth_public_key_len: usize,
        psk_bytes: *const u8,
        psk_len: usize,
        psk_id_bytes: *const u8,
        psk_id_len: usize,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_hpke_recipient_create_kem(
        private_algorithm: i32,
        private_key_bytes: *const u8,
        private_key_len: usize,
        kem: i32,
        kdf: i32,
        aead: i32,
        info_bytes: *const u8,
        info_len: usize,
        encapsulated_key_bytes: *const u8,
        encapsulated_key_len: usize,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_hpke_recipient_release(handle: *mut c_void);
    pub fn ck_hpke_recipient_open(
        handle: *mut c_void,
        ciphertext_bytes: *const u8,
        ciphertext_len: usize,
        aad_bytes: *const u8,
        aad_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_hpke_recipient_export_secret(
        handle: *mut c_void,
        context_bytes: *const u8,
        context_len: usize,
        output_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_authentication_context_create(error_out: *mut *mut c_char) -> *mut c_void;
    pub fn ck_authentication_context_release(handle: *mut c_void);
    pub fn ck_authentication_context_set_interaction_not_allowed(
        handle: *mut c_void,
        value: u8,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_authentication_context_set_touch_id_reuse_duration(
        handle: *mut c_void,
        duration: f64,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_authentication_context_set_localized_fallback_title(
        handle: *mut c_void,
        title_bytes: *const u8,
        title_len: usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_authentication_context_set_localized_cancel_title(
        handle: *mut c_void,
        title_bytes: *const u8,
        title_len: usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_secure_enclave_is_available(
        out_available: *mut u8,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_signing_private_key_generate(
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_signing_private_key_generate_with_options(
        compact_representable: u8,
        accessibility: i32,
        access_control_flags: u64,
        authentication_context: *mut c_void,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_signing_private_key_from_data_representation(
        data_bytes: *const u8,
        data_len: usize,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_signing_private_key_from_data_representation_with_context(
        data_bytes: *const u8,
        data_len: usize,
        authentication_context: *mut c_void,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_signing_private_key_release(handle: *mut c_void);
    pub fn ck_secure_enclave_signing_private_key_public_key(
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_signing_private_key_data_representation(
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_signing_private_key_sign(
        handle: *mut c_void,
        message_bytes: *const u8,
        message_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_key_agreement_private_key_generate(
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_key_agreement_private_key_generate_with_options(
        compact_representable: u8,
        accessibility: i32,
        access_control_flags: u64,
        authentication_context: *mut c_void,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_key_agreement_private_key_from_data_representation(
        data_bytes: *const u8,
        data_len: usize,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_key_agreement_private_key_from_data_representation_with_context(
        data_bytes: *const u8,
        data_len: usize,
        authentication_context: *mut c_void,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_key_agreement_private_key_release(handle: *mut c_void);
    pub fn ck_secure_enclave_key_agreement_private_key_public_key(
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_key_agreement_private_key_data_representation(
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_key_agreement_private_key_shared_secret(
        handle: *mut c_void,
        public_key_bytes: *const u8,
        public_key_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_secure_enclave_mldsa_private_key_generate(
        algorithm: i32,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_mldsa_private_key_generate_with_options(
        algorithm: i32,
        accessibility: i32,
        access_control_flags: u64,
        authentication_context: *mut c_void,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_mldsa_private_key_from_data_representation(
        algorithm: i32,
        data_bytes: *const u8,
        data_len: usize,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_mldsa_private_key_from_data_representation_with_context(
        algorithm: i32,
        data_bytes: *const u8,
        data_len: usize,
        authentication_context: *mut c_void,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_mldsa_private_key_release(algorithm: i32, handle: *mut c_void);
    pub fn ck_secure_enclave_mldsa_private_key_public_key(
        algorithm: i32,
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_mldsa_private_key_data_representation(
        algorithm: i32,
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_mldsa_private_key_sign(
        algorithm: i32,
        handle: *mut c_void,
        data_bytes: *const u8,
        data_len: usize,
        context_bytes: *const u8,
        context_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;

    pub fn ck_secure_enclave_kem_private_key_generate(
        algorithm: i32,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_kem_private_key_generate_with_options(
        algorithm: i32,
        accessibility: i32,
        access_control_flags: u64,
        authentication_context: *mut c_void,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_kem_private_key_from_data_representation(
        algorithm: i32,
        data_bytes: *const u8,
        data_len: usize,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_kem_private_key_from_data_representation_with_context(
        algorithm: i32,
        data_bytes: *const u8,
        data_len: usize,
        authentication_context: *mut c_void,
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_kem_private_key_release(algorithm: i32, handle: *mut c_void);
    pub fn ck_secure_enclave_kem_private_key_public_key(
        algorithm: i32,
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_kem_private_key_data_representation(
        algorithm: i32,
        handle: *mut c_void,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_kem_private_key_decapsulate(
        algorithm: i32,
        handle: *mut c_void,
        encapsulated_bytes: *const u8,
        encapsulated_len: usize,
        out_bytes: *mut *mut u8,
        out_len: *mut usize,
        error_out: *mut *mut c_char,
    ) -> i32;
}
