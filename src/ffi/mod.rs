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

extern "C" {
    pub fn ck_symmetric_key_generate(
        size_bits: i32,
        out_key: *mut *mut u8,
        out_key_len: *mut usize,
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

    pub fn ck_secure_enclave_is_available(
        out_available: *mut u8,
        error_out: *mut *mut c_char,
    ) -> i32;
    pub fn ck_secure_enclave_signing_private_key_generate(
        error_out: *mut *mut c_char,
    ) -> *mut c_void;
    pub fn ck_secure_enclave_signing_private_key_release(handle: *mut c_void);
    pub fn ck_secure_enclave_signing_private_key_public_key(
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
    pub fn ck_secure_enclave_key_agreement_private_key_release(handle: *mut c_void);
    pub fn ck_secure_enclave_key_agreement_private_key_public_key(
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
}
