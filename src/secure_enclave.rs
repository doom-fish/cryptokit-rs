//! Secure Enclave-backed P-256 keys.

use core::ffi::{c_char, c_void};
use core::ops::{BitOr, BitOrAssign};
use std::ptr;
use std::ptr::NonNull;

use crate::error::{from_swift, Result};
use crate::ffi;
use crate::kem::{KemAlgorithm, Mlkem1024PublicKey, Mlkem768PublicKey};
use crate::key_agreement::DiffieHellmanKeyAgreement;
use crate::mldsa::{Mldsa65PublicKey, Mldsa87PublicKey, MldsaAlgorithm};
use crate::p256::{P256EcdsaSignature, P256KeyAgreementPublicKey, P256SigningPublicKey};
use crate::private::{bridge_bytes, bridge_flag, bridge_status};
use crate::public_key::SharedSecret;
use crate::symmetric::SymmetricKey;

/// Query whether the current machine reports Secure Enclave availability.
///
/// # Errors
///
/// Returns an error if the Swift bridge rejects the query.
pub fn is_available() -> Result<bool> {
    bridge_flag(|out_available, error_out| unsafe {
        ffi::ck_secure_enclave_is_available(out_available, error_out)
    })
}

fn bridge_secure_enclave_handle<F>(call: F) -> Result<NonNull<c_void>>
where
    F: FnOnce(*mut *mut c_char) -> *mut c_void,
{
    let mut error: *mut c_char = ptr::null_mut();
    let handle = call(&mut error);
    NonNull::new(handle).ok_or_else(|| from_swift(ffi::status::KEY_FAILED, error))
}

#[allow(clippy::missing_const_for_fn)]
fn secure_enclave_access_control_parts(
    access_control: Option<&SecureEnclaveAccessControl>,
) -> (i32, u64) {
    access_control.map_or(
        (ffi::secure_enclave_accessibility::DEFAULT, 0),
        |access_control| {
            (
                access_control.accessibility.as_ffi(),
                access_control.flags.bits(),
            )
        },
    )
}

fn authentication_context_handle(
    authentication_context: Option<&SecureEnclaveAuthenticationContext>,
) -> *mut c_void {
    authentication_context.map_or(ptr::null_mut(), |context| context.handle.as_ptr())
}

/// The Keychain accessibility class used for Secure Enclave key creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SecureEnclaveAccessibility {
    AfterFirstUnlockThisDeviceOnly,
    WhenUnlockedThisDeviceOnly,
    WhenPasscodeSetThisDeviceOnly,
    AfterFirstUnlock,
    WhenUnlocked,
    AlwaysThisDeviceOnly,
    Always,
}

impl SecureEnclaveAccessibility {
    const fn as_ffi(self) -> i32 {
        match self {
            Self::AfterFirstUnlockThisDeviceOnly => {
                ffi::secure_enclave_accessibility::AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY
            }
            Self::WhenUnlockedThisDeviceOnly => {
                ffi::secure_enclave_accessibility::WHEN_UNLOCKED_THIS_DEVICE_ONLY
            }
            Self::WhenPasscodeSetThisDeviceOnly => {
                ffi::secure_enclave_accessibility::WHEN_PASSCODE_SET_THIS_DEVICE_ONLY
            }
            Self::AfterFirstUnlock => ffi::secure_enclave_accessibility::AFTER_FIRST_UNLOCK,
            Self::WhenUnlocked => ffi::secure_enclave_accessibility::WHEN_UNLOCKED,
            Self::AlwaysThisDeviceOnly => {
                ffi::secure_enclave_accessibility::ALWAYS_THIS_DEVICE_ONLY
            }
            Self::Always => ffi::secure_enclave_accessibility::ALWAYS,
        }
    }
}

/// Bitflags applied when creating a Secure Enclave `SecAccessControl` object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SecureEnclaveAccessControlFlags(u64);

impl SecureEnclaveAccessControlFlags {
    pub const USER_PRESENCE: Self = Self(1_u64 << 0);
    pub const BIOMETRY_ANY: Self = Self(1_u64 << 1);
    pub const BIOMETRY_CURRENT_SET: Self = Self(1_u64 << 3);
    pub const DEVICE_PASSCODE: Self = Self(1_u64 << 4);
    pub const COMPANION: Self = Self(1_u64 << 5);
    pub const OR: Self = Self(1_u64 << 14);
    pub const AND: Self = Self(1_u64 << 15);
    pub const PRIVATE_KEY_USAGE: Self = Self(1_u64 << 30);
    pub const APPLICATION_PASSWORD: Self = Self(1_u64 << 31);

    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }
}

impl BitOr for SecureEnclaveAccessControlFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for SecureEnclaveAccessControlFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// A Rust-friendly description of the `SecAccessControl` policy used for a new key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecureEnclaveAccessControl {
    accessibility: SecureEnclaveAccessibility,
    flags: SecureEnclaveAccessControlFlags,
}

impl SecureEnclaveAccessControl {
    #[must_use]
    pub const fn new(
        accessibility: SecureEnclaveAccessibility,
        flags: SecureEnclaveAccessControlFlags,
    ) -> Self {
        Self {
            accessibility,
            flags,
        }
    }

    #[must_use]
    pub const fn accessibility(self) -> SecureEnclaveAccessibility {
        self.accessibility
    }

    #[must_use]
    pub const fn flags(self) -> SecureEnclaveAccessControlFlags {
        self.flags
    }
}

impl Default for SecureEnclaveAccessControl {
    fn default() -> Self {
        Self::new(
            SecureEnclaveAccessibility::AfterFirstUnlockThisDeviceOnly,
            SecureEnclaveAccessControlFlags::empty(),
        )
    }
}

/// A configurable `LocalAuthentication` context for Secure Enclave operations.
#[derive(Debug)]
pub struct SecureEnclaveAuthenticationContext {
    handle: NonNull<c_void>,
}

impl SecureEnclaveAuthenticationContext {
    /// Create a new authentication context.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn new() -> Result<Self> {
        let handle = bridge_secure_enclave_handle(|error_out| unsafe {
            ffi::ck_authentication_context_create(error_out)
        })?;
        Ok(Self { handle })
    }

    /// Set whether evaluation UI interaction is allowed.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn set_interaction_not_allowed(&mut self, value: bool) -> Result<&mut Self> {
        bridge_status(|error_out| unsafe {
            ffi::ck_authentication_context_set_interaction_not_allowed(
                self.handle.as_ptr(),
                u8::from(value),
                error_out,
            )
        })?;
        Ok(self)
    }

    /// Set the Touch ID reuse duration in seconds.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn set_touch_id_authentication_allowable_reuse_duration(
        &mut self,
        duration_seconds: f64,
    ) -> Result<&mut Self> {
        bridge_status(|error_out| unsafe {
            ffi::ck_authentication_context_set_touch_id_reuse_duration(
                self.handle.as_ptr(),
                duration_seconds,
                error_out,
            )
        })?;
        Ok(self)
    }

    /// Set or clear the localized fallback title.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn set_localized_fallback_title(&mut self, title: Option<&str>) -> Result<&mut Self> {
        let (title_bytes, title_len) = title.map_or((ptr::null(), 0), |value| {
            (value.as_bytes().as_ptr(), value.len())
        });
        bridge_status(|error_out| unsafe {
            ffi::ck_authentication_context_set_localized_fallback_title(
                self.handle.as_ptr(),
                title_bytes,
                title_len,
                error_out,
            )
        })?;
        Ok(self)
    }

    /// Set or clear the localized cancel title.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn set_localized_cancel_title(&mut self, title: Option<&str>) -> Result<&mut Self> {
        let (title_bytes, title_len) = title.map_or((ptr::null(), 0), |value| {
            (value.as_bytes().as_ptr(), value.len())
        });
        bridge_status(|error_out| unsafe {
            ffi::ck_authentication_context_set_localized_cancel_title(
                self.handle.as_ptr(),
                title_bytes,
                title_len,
                error_out,
            )
        })?;
        Ok(self)
    }
}

impl Drop for SecureEnclaveAuthenticationContext {
    fn drop(&mut self) {
        unsafe { ffi::ck_authentication_context_release(self.handle.as_ptr()) };
    }
}

/// A Secure Enclave-backed P-256 signing private key.
#[derive(Debug)]
pub struct SecureEnclaveSigningPrivateKey {
    handle: NonNull<c_void>,
}

impl SecureEnclaveSigningPrivateKey {
    /// Generate a new Secure Enclave signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or key creation fails.
    pub fn generate() -> Result<Self> {
        Self::generate_with_options(true, None, None)
    }

    /// Generate a new Secure Enclave signing key with explicit creation options.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or key creation fails.
    pub fn generate_with_options(
        compact_representable: bool,
        access_control: Option<&SecureEnclaveAccessControl>,
        authentication_context: Option<&SecureEnclaveAuthenticationContext>,
    ) -> Result<Self> {
        let (accessibility, access_control_flags) =
            secure_enclave_access_control_parts(access_control);
        let handle = bridge_secure_enclave_handle(|error_out| unsafe {
            ffi::ck_secure_enclave_signing_private_key_generate_with_options(
                u8::from(compact_representable),
                accessibility,
                access_control_flags,
                authentication_context_handle(authentication_context),
                error_out,
            )
        })?;
        Ok(Self { handle })
    }

    /// Restore a Secure Enclave signing key from its persisted data representation.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or the persisted bytes are invalid.
    pub fn from_data_representation(data_representation: &[u8]) -> Result<Self> {
        Self::from_data_representation_with_authentication_context(data_representation, None)
    }

    /// Restore a Secure Enclave signing key with an explicit authentication context.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or the persisted bytes are invalid.
    pub fn from_data_representation_with_authentication_context(
        data_representation: &[u8],
        authentication_context: Option<&SecureEnclaveAuthenticationContext>,
    ) -> Result<Self> {
        let handle = bridge_secure_enclave_handle(|error_out| unsafe {
            ffi::ck_secure_enclave_signing_private_key_from_data_representation_with_context(
                data_representation.as_ptr(),
                data_representation.len(),
                authentication_context_handle(authentication_context),
                error_out,
            )
        })?;
        Ok(Self { handle })
    }

    /// Export the persisted data representation for later restoration.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn data_representation(&self) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_signing_private_key_data_representation(
                self.handle.as_ptr(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Export the matching software-verifiable P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if public-key export fails.
    pub fn public_key(&self) -> Result<P256SigningPublicKey> {
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_signing_private_key_public_key(
                self.handle.as_ptr(),
                out,
                out_len,
                error_out,
            )
        })?;
        P256SigningPublicKey::from_raw_representation(raw)
    }

    /// Sign a message with the Secure Enclave key.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_signing_private_key_sign(
                self.handle.as_ptr(),
                message.as_ptr(),
                message.len(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Sign a message and return a typed P-256 ECDSA signature.
    ///
    /// # Errors
    ///
    /// Returns an error if signing fails.
    pub fn sign_signature(&self, message: &[u8]) -> Result<P256EcdsaSignature> {
        P256EcdsaSignature::from_raw_representation(self.sign(message)?)
    }
}

impl Drop for SecureEnclaveSigningPrivateKey {
    fn drop(&mut self) {
        unsafe { ffi::ck_secure_enclave_signing_private_key_release(self.handle.as_ptr()) };
    }
}

/// A Secure Enclave-backed P-256 key-agreement private key.
#[derive(Debug)]
pub struct SecureEnclaveKeyAgreementPrivateKey {
    handle: NonNull<c_void>,
}

impl SecureEnclaveKeyAgreementPrivateKey {
    /// Generate a new Secure Enclave key-agreement key.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or key creation fails.
    pub fn generate() -> Result<Self> {
        Self::generate_with_options(true, None, None)
    }

    /// Generate a new Secure Enclave key-agreement key with explicit creation options.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or key creation fails.
    pub fn generate_with_options(
        compact_representable: bool,
        access_control: Option<&SecureEnclaveAccessControl>,
        authentication_context: Option<&SecureEnclaveAuthenticationContext>,
    ) -> Result<Self> {
        let (accessibility, access_control_flags) =
            secure_enclave_access_control_parts(access_control);
        let handle = bridge_secure_enclave_handle(|error_out| unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_generate_with_options(
                u8::from(compact_representable),
                accessibility,
                access_control_flags,
                authentication_context_handle(authentication_context),
                error_out,
            )
        })?;
        Ok(Self { handle })
    }

    /// Restore a Secure Enclave key-agreement key from its persisted data representation.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or the persisted bytes are invalid.
    pub fn from_data_representation(data_representation: &[u8]) -> Result<Self> {
        Self::from_data_representation_with_authentication_context(data_representation, None)
    }

    /// Restore a Secure Enclave key-agreement key with an explicit authentication context.
    ///
    /// # Errors
    ///
    /// Returns an error if Secure Enclave is unavailable or the persisted bytes are invalid.
    pub fn from_data_representation_with_authentication_context(
        data_representation: &[u8],
        authentication_context: Option<&SecureEnclaveAuthenticationContext>,
    ) -> Result<Self> {
        let handle = bridge_secure_enclave_handle(|error_out| unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_from_data_representation_with_context(
                data_representation.as_ptr(),
                data_representation.len(),
                authentication_context_handle(authentication_context),
                error_out,
            )
        })?;
        Ok(Self { handle })
    }

    /// Export the persisted data representation for later restoration.
    ///
    /// # Errors
    ///
    /// Returns an error if the Swift bridge rejects the request.
    pub fn data_representation(&self) -> Result<Vec<u8>> {
        bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_data_representation(
                self.handle.as_ptr(),
                out,
                out_len,
                error_out,
            )
        })
    }

    /// Export the matching software-verifiable P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if public-key export fails.
    pub fn public_key(&self) -> Result<P256KeyAgreementPublicKey> {
        let raw = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_public_key(
                self.handle.as_ptr(),
                out,
                out_len,
                error_out,
            )
        })?;
        P256KeyAgreementPublicKey::from_raw_representation(raw)
    }

    /// Derive a shared secret with a software P-256 public key.
    ///
    /// # Errors
    ///
    /// Returns an error if key agreement fails.
    pub fn shared_secret(&self, peer: &P256KeyAgreementPublicKey) -> Result<SharedSecret> {
        let bytes = bridge_bytes(|out, out_len, error_out| unsafe {
            ffi::ck_secure_enclave_key_agreement_private_key_shared_secret(
                self.handle.as_ptr(),
                peer.raw_representation().as_ptr(),
                peer.raw_representation().len(),
                out,
                out_len,
                error_out,
            )
        })?;
        Ok(SharedSecret::from_bytes(bytes))
    }
}

impl Drop for SecureEnclaveKeyAgreementPrivateKey {
    fn drop(&mut self) {
        unsafe { ffi::ck_secure_enclave_key_agreement_private_key_release(self.handle.as_ptr()) };
    }
}

impl DiffieHellmanKeyAgreement for SecureEnclaveKeyAgreementPrivateKey {
    type PublicKey = P256KeyAgreementPublicKey;

    fn public_key(&self) -> Result<Self::PublicKey> {
        Self::public_key(self)
    }

    fn shared_secret(&self, public_key: &Self::PublicKey) -> Result<SharedSecret> {
        Self::shared_secret(self, public_key)
    }
}

macro_rules! secure_enclave_mldsa_key {
    ($name:ident, $public_name:ident, $algorithm:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name {
            handle: NonNull<c_void>,
        }

        impl $name {
            /// Generate a new Secure Enclave private key.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or key creation fails.
            pub fn generate() -> Result<Self> {
                Self::generate_with_options(None, None)
            }

            /// Generate a new Secure Enclave private key with explicit creation options.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or key creation fails.
            pub fn generate_with_options(
                access_control: Option<&SecureEnclaveAccessControl>,
                authentication_context: Option<&SecureEnclaveAuthenticationContext>,
            ) -> Result<Self> {
                let (accessibility, access_control_flags) =
                    secure_enclave_access_control_parts(access_control);
                let handle = bridge_secure_enclave_handle(|error_out| unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_generate_with_options(
                        $algorithm.as_ffi(),
                        accessibility,
                        access_control_flags,
                        authentication_context_handle(authentication_context),
                        error_out,
                    )
                })?;
                Ok(Self { handle })
            }

            /// Restore a Secure Enclave private key from its persisted data representation.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or the bytes are invalid.
            pub fn from_data_representation(data_representation: &[u8]) -> Result<Self> {
                Self::from_data_representation_with_authentication_context(
                    data_representation,
                    None,
                )
            }

            /// Restore a Secure Enclave private key with an explicit authentication context.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or the bytes are invalid.
            pub fn from_data_representation_with_authentication_context(
                data_representation: &[u8],
                authentication_context: Option<&SecureEnclaveAuthenticationContext>,
            ) -> Result<Self> {
                let handle = bridge_secure_enclave_handle(|error_out| unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_from_data_representation_with_context(
                        $algorithm.as_ffi(),
                        data_representation.as_ptr(),
                        data_representation.len(),
                        authentication_context_handle(authentication_context),
                        error_out,
                    )
                })?;
                Ok(Self { handle })
            }

            /// Export the persisted data representation for later restoration.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn data_representation(&self) -> Result<Vec<u8>> {
                bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_data_representation(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                        out,
                        out_len,
                        error_out,
                    )
                })
            }

            /// Export the matching software-verifiable public key.
            ///
            /// # Errors
            ///
            /// Returns an error if public-key export fails.
            pub fn public_key(&self) -> Result<$public_name> {
                let raw = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_public_key(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                $public_name::from_raw_representation(raw)
            }

            /// Sign a message.
            ///
            /// # Errors
            ///
            /// Returns an error if signing fails.
            pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
                self.sign_with_context(message, None)
            }

            /// Sign a message with an explicit ML-DSA context.
            ///
            /// # Errors
            ///
            /// Returns an error if signing fails.
            pub fn sign_with_context(
                &self,
                message: &[u8],
                context: Option<&[u8]>,
            ) -> Result<Vec<u8>> {
                let context = context.unwrap_or(&[]);
                bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_sign(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                        message.as_ptr(),
                        message.len(),
                        context.as_ptr(),
                        context.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe {
                    ffi::ck_secure_enclave_mldsa_private_key_release(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                    )
                };
            }
        }
    };
}

macro_rules! secure_enclave_kem_key {
    ($name:ident, $public_name:ident, $algorithm:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug)]
        pub struct $name {
            handle: NonNull<c_void>,
        }

        impl $name {
            /// Generate a new Secure Enclave private key.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or key creation fails.
            pub fn generate() -> Result<Self> {
                Self::generate_with_options(None, None)
            }

            /// Generate a new Secure Enclave private key with explicit creation options.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or key creation fails.
            pub fn generate_with_options(
                access_control: Option<&SecureEnclaveAccessControl>,
                authentication_context: Option<&SecureEnclaveAuthenticationContext>,
            ) -> Result<Self> {
                let (accessibility, access_control_flags) =
                    secure_enclave_access_control_parts(access_control);
                let handle = bridge_secure_enclave_handle(|error_out| unsafe {
                    ffi::ck_secure_enclave_kem_private_key_generate_with_options(
                        $algorithm.as_ffi(),
                        accessibility,
                        access_control_flags,
                        authentication_context_handle(authentication_context),
                        error_out,
                    )
                })?;
                Ok(Self { handle })
            }

            /// Restore a Secure Enclave private key from its persisted data representation.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or the bytes are invalid.
            pub fn from_data_representation(data_representation: &[u8]) -> Result<Self> {
                Self::from_data_representation_with_authentication_context(
                    data_representation,
                    None,
                )
            }

            /// Restore a Secure Enclave private key with an explicit authentication context.
            ///
            /// # Errors
            ///
            /// Returns an error if Secure Enclave is unavailable or the bytes are invalid.
            pub fn from_data_representation_with_authentication_context(
                data_representation: &[u8],
                authentication_context: Option<&SecureEnclaveAuthenticationContext>,
            ) -> Result<Self> {
                let handle = bridge_secure_enclave_handle(|error_out| unsafe {
                    ffi::ck_secure_enclave_kem_private_key_from_data_representation_with_context(
                        $algorithm.as_ffi(),
                        data_representation.as_ptr(),
                        data_representation.len(),
                        authentication_context_handle(authentication_context),
                        error_out,
                    )
                })?;
                Ok(Self { handle })
            }

            /// Export the persisted data representation for later restoration.
            ///
            /// # Errors
            ///
            /// Returns an error if the Swift bridge rejects the request.
            pub fn data_representation(&self) -> Result<Vec<u8>> {
                bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_kem_private_key_data_representation(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                        out,
                        out_len,
                        error_out,
                    )
                })
            }

            /// Export the matching software public key.
            ///
            /// # Errors
            ///
            /// Returns an error if public-key export fails.
            pub fn public_key(&self) -> Result<$public_name> {
                let raw = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_kem_private_key_public_key(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                $public_name::from_raw_representation(raw)
            }

            /// Decapsulate an encapsulated key.
            ///
            /// # Errors
            ///
            /// Returns an error if decapsulation fails.
            pub fn decapsulate(&self, encapsulated: &[u8]) -> Result<SymmetricKey> {
                let shared_secret = bridge_bytes(|out, out_len, error_out| unsafe {
                    ffi::ck_secure_enclave_kem_private_key_decapsulate(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                        encapsulated.as_ptr(),
                        encapsulated.len(),
                        out,
                        out_len,
                        error_out,
                    )
                })?;
                Ok(SymmetricKey::from_bytes(shared_secret))
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                unsafe {
                    ffi::ck_secure_enclave_kem_private_key_release(
                        $algorithm.as_ffi(),
                        self.handle.as_ptr(),
                    )
                };
            }
        }
    };
}

secure_enclave_mldsa_key!(
    SecureEnclaveMldsa65PrivateKey,
    Mldsa65PublicKey,
    MldsaAlgorithm::Mldsa65,
    "A Secure Enclave-backed ML-DSA-65 private key."
);
secure_enclave_mldsa_key!(
    SecureEnclaveMldsa87PrivateKey,
    Mldsa87PublicKey,
    MldsaAlgorithm::Mldsa87,
    "A Secure Enclave-backed ML-DSA-87 private key."
);
secure_enclave_kem_key!(
    SecureEnclaveMlkem768PrivateKey,
    Mlkem768PublicKey,
    KemAlgorithm::Mlkem768,
    "A Secure Enclave-backed ML-KEM-768 private key."
);
secure_enclave_kem_key!(
    SecureEnclaveMlkem1024PrivateKey,
    Mlkem1024PublicKey,
    KemAlgorithm::Mlkem1024,
    "A Secure Enclave-backed ML-KEM-1024 private key."
);
