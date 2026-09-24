use std::error::Error;

use cryptokit::p256::P256KeyAgreementPrivateKey;
use cryptokit::secure_enclave::{
    self, AccessControl, AccessControlFlags, AccessControlProtection,
    SecureEnclaveAuthenticationContext, SecureEnclaveKeyAgreementPrivateKey,
    SecureEnclaveMldsa65PrivateKey, SecureEnclaveMlkem768PrivateKey,
    SecureEnclaveSigningPrivateKey,
};
use cryptokit::{CryptoKitError, Result};

#[test]
fn secure_enclave_availability_probe_is_safe() -> Result<()> {
    let _ = secure_enclave::is_available()?;
    Ok(())
}

#[test]
fn authentication_context_setters_and_access_control_flags_are_safe(
) -> std::result::Result<(), Box<dyn Error>> {
    let mut context = SecureEnclaveAuthenticationContext::new()?;
    context
        .set_interaction_not_allowed(true)?
        .set_touch_id_authentication_allowable_reuse_duration(0.0)?
        .set_localized_fallback_title(Some("Use Password"))?
        .set_localized_cancel_title(Some("Cancel"))?
        .set_localized_fallback_title(None)?
        .set_localized_cancel_title(None)?;

    let flags = AccessControlFlags::USER_PRESENCE | AccessControlFlags::PRIVATE_KEY_USAGE;
    let access_control =
        AccessControl::create(AccessControlProtection::WhenUnlockedThisDeviceOnly, flags)?;
    assert_eq!(
        access_control.protection(),
        AccessControlProtection::WhenUnlockedThisDeviceOnly
    );
    assert_eq!(access_control.flags(), flags);
    Ok(())
}

#[test]
fn default_access_control_is_usable_and_device_bound() -> Result<()> {
    let access_control = secure_enclave::default_access_control()?;
    assert_eq!(
        access_control.protection(),
        AccessControlProtection::WhenUnlockedThisDeviceOnly
    );
    assert_eq!(
        access_control.flags(),
        AccessControlFlags::PRIVATE_KEY_USAGE
    );
    assert!(!access_control.as_ptr().is_null());
    Ok(())
}

fn assert_rejected_before_key_creation(access_control: &AccessControl) {
    assert!(matches!(
        SecureEnclaveSigningPrivateKey::generate_with_options(true, Some(access_control), None),
        Err(CryptoKitError::InvalidArgument(_))
    ));
    assert!(matches!(
        SecureEnclaveKeyAgreementPrivateKey::generate_with_options(
            true,
            Some(access_control),
            None
        ),
        Err(CryptoKitError::InvalidArgument(_))
    ));
    assert!(matches!(
        SecureEnclaveMldsa65PrivateKey::generate_with_options(Some(access_control), None),
        Err(CryptoKitError::InvalidArgument(_))
    ));
    assert!(matches!(
        SecureEnclaveMlkem768PrivateKey::generate_with_options(Some(access_control), None),
        Err(CryptoKitError::InvalidArgument(_))
    ));
}

#[test]
fn access_control_without_private_key_usage_is_rejected_before_key_creation(
) -> std::result::Result<(), Box<dyn Error>> {
    let access_control = AccessControl::create(
        AccessControlProtection::WhenUnlockedThisDeviceOnly,
        AccessControlFlags::USER_PRESENCE,
    )?;
    assert_rejected_before_key_creation(&access_control);
    Ok(())
}

#[test]
fn access_control_that_could_migrate_is_rejected_before_key_creation(
) -> std::result::Result<(), Box<dyn Error>> {
    for protection in [
        AccessControlProtection::WhenUnlocked,
        AccessControlProtection::AfterFirstUnlock,
    ] {
        let access_control =
            AccessControl::create(protection, AccessControlFlags::PRIVATE_KEY_USAGE)?;
        assert_rejected_before_key_creation(&access_control);
    }
    Ok(())
}

#[test]
#[ignore = "requires Secure Enclave availability and keychain access"]
fn secure_enclave_option_initializers_round_trip_when_available() -> Result<()> {
    if !secure_enclave::is_available()? {
        return Ok(());
    }

    let access_control = secure_enclave::default_access_control()?;
    let mut context = SecureEnclaveAuthenticationContext::new()?;
    context.set_interaction_not_allowed(true)?;

    let signing = SecureEnclaveSigningPrivateKey::generate_with_options(
        true,
        Some(&access_control),
        Some(&context),
    )?;
    let restored_signing =
        SecureEnclaveSigningPrivateKey::from_data_representation_with_authentication_context(
            &signing.data_representation()?,
            Some(&context),
        )?;
    assert_eq!(
        restored_signing.public_key()?.raw_representation(),
        signing.public_key()?.raw_representation()
    );

    let agreement = SecureEnclaveKeyAgreementPrivateKey::generate_with_options(
        true,
        Some(&access_control),
        Some(&context),
    )?;
    let restored_agreement =
        SecureEnclaveKeyAgreementPrivateKey::from_data_representation_with_authentication_context(
            &agreement.data_representation()?,
            Some(&context),
        )?;
    assert_eq!(
        restored_agreement.public_key()?.raw_representation(),
        agreement.public_key()?.raw_representation()
    );
    Ok(())
}

#[test]
#[ignore = "requires Secure Enclave availability and keychain access"]
fn secure_enclave_round_trips_when_available() -> Result<()> {
    if !secure_enclave::is_available()? {
        return Ok(());
    }

    let signing = SecureEnclaveSigningPrivateKey::generate()?;
    let verifying = signing.public_key()?;
    let signature = signing.sign(b"secure enclave")?;
    assert!(verifying.verify(b"secure enclave", &signature)?);
    let typed_signature = signing.sign_signature(b"secure enclave typed")?;
    assert!(verifying.verify_signature(b"secure enclave typed", &typed_signature)?);

    let signing_restored =
        SecureEnclaveSigningPrivateKey::from_data_representation(&signing.data_representation()?)?;
    assert_eq!(
        signing_restored.public_key()?.raw_representation(),
        verifying.raw_representation()
    );

    let enclave = SecureEnclaveKeyAgreementPrivateKey::generate()?;
    let enclave_public_key = enclave.public_key()?;
    let restored_enclave = SecureEnclaveKeyAgreementPrivateKey::from_data_representation(
        &enclave.data_representation()?,
    )?;
    assert_eq!(
        restored_enclave.public_key()?.raw_representation(),
        enclave_public_key.raw_representation()
    );

    let software = P256KeyAgreementPrivateKey::generate()?;
    let enclave_secret = enclave.shared_secret(&software.public_key()?)?;
    let software_secret = software.shared_secret(&enclave_public_key)?;
    let restored_secret = restored_enclave.shared_secret(&software.public_key()?)?;
    assert_eq!(enclave_secret, software_secret);
    assert_eq!(restored_secret, software_secret);
    Ok(())
}

#[test]
#[ignore = "requires Secure Enclave post-quantum availability and keychain access"]
fn secure_enclave_post_quantum_round_trips_when_available() -> Result<()> {
    if !secure_enclave::is_available()? {
        return Ok(());
    }

    let access_control = AccessControl::create(
        AccessControlProtection::AfterFirstUnlockThisDeviceOnly,
        AccessControlFlags::PRIVATE_KEY_USAGE,
    )
    .map_err(|error| CryptoKitError::KeyOperationFailed(error.to_string()))?;
    let mut context = SecureEnclaveAuthenticationContext::new()?;
    context.set_interaction_not_allowed(true)?;

    let mldsa = SecureEnclaveMldsa65PrivateKey::generate_with_options(
        Some(&access_control),
        Some(&context),
    )?;
    let mldsa_public = mldsa.public_key()?;
    let signature = mldsa.sign_with_context(b"secure enclave mldsa", Some(b"ctx"))?;
    assert!(mldsa_public.verify_with_context(b"secure enclave mldsa", &signature, Some(b"ctx"))?);
    let restored_mldsa =
        SecureEnclaveMldsa65PrivateKey::from_data_representation_with_authentication_context(
            &mldsa.data_representation()?,
            Some(&context),
        )?;
    assert_eq!(
        restored_mldsa.public_key()?.raw_representation(),
        mldsa_public.raw_representation()
    );

    let mlkem = SecureEnclaveMlkem768PrivateKey::generate_with_options(
        Some(&access_control),
        Some(&context),
    )?;
    let mlkem_public = mlkem.public_key()?;
    let encapsulation = mlkem_public.encapsulate()?;
    let decapsulated = mlkem.decapsulate(encapsulation.encapsulated())?;
    assert_eq!(
        decapsulated.as_bytes(),
        encapsulation.shared_secret().as_bytes()
    );
    let restored_mlkem =
        SecureEnclaveMlkem768PrivateKey::from_data_representation_with_authentication_context(
            &mlkem.data_representation()?,
            Some(&context),
        )?;
    assert_eq!(
        restored_mlkem.public_key()?.raw_representation(),
        mlkem_public.raw_representation()
    );

    Ok(())
}
