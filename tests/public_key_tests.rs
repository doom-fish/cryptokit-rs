use cryptokit::public_key::{
    KeyAgreementAlgorithm, KeyAgreementPrivateKey, KeyAgreementPublicKey, SigningAlgorithm,
    SigningPrivateKey, SigningPublicKey,
};
use cryptokit::Result;

fn assert_signing_representations_round_trip(algorithm: SigningAlgorithm) -> Result<()> {
    let private = SigningPrivateKey::generate_with_compact_representable(algorithm, true)?;
    let public = private.public_key()?;

    let x963_private = private.x963_representation()?;
    let der_private = private.der_representation()?;
    let pem_private = private.pem_representation()?;
    let x963_public = public.x963_representation()?;
    let compact_public = public
        .compact_representation()?
        .expect("compact-representable key should expose a compact public key");
    let compressed_public = public.compressed_representation()?;
    let der_public = public.der_representation()?;
    let pem_public = public.pem_representation()?;

    assert!(pem_private.contains("PRIVATE KEY"));
    assert!(pem_public.contains("PUBLIC KEY"));

    assert_eq!(
        SigningPrivateKey::from_x963_representation(algorithm, x963_private)?.raw_representation(),
        private.raw_representation()
    );
    assert_eq!(
        SigningPrivateKey::from_der_representation(algorithm, der_private)?.raw_representation(),
        private.raw_representation()
    );
    assert_eq!(
        SigningPrivateKey::from_pem_representation(algorithm, pem_private)?.raw_representation(),
        private.raw_representation()
    );

    assert_eq!(
        SigningPublicKey::from_x963_representation(algorithm, x963_public)?.raw_representation(),
        public.raw_representation()
    );
    assert_eq!(
        SigningPublicKey::from_compact_representation(algorithm, compact_public)?.raw_representation(),
        public.raw_representation()
    );
    assert_eq!(
        SigningPublicKey::from_compressed_representation(algorithm, compressed_public)?
            .raw_representation(),
        public.raw_representation()
    );
    assert_eq!(
        SigningPublicKey::from_der_representation(algorithm, der_public)?.raw_representation(),
        public.raw_representation()
    );
    assert_eq!(
        SigningPublicKey::from_pem_representation(algorithm, pem_public)?.raw_representation(),
        public.raw_representation()
    );
    Ok(())
}

fn assert_key_agreement_representations_round_trip(algorithm: KeyAgreementAlgorithm) -> Result<()> {
    let private = KeyAgreementPrivateKey::generate_with_compact_representable(algorithm, true)?;
    let public = private.public_key()?;

    let x963_private = private.x963_representation()?;
    let der_private = private.der_representation()?;
    let pem_private = private.pem_representation()?;
    let x963_public = public.x963_representation()?;
    let compact_public = public
        .compact_representation()?
        .expect("compact-representable key should expose a compact public key");
    let compressed_public = public.compressed_representation()?;
    let der_public = public.der_representation()?;
    let pem_public = public.pem_representation()?;

    assert!(pem_private.contains("PRIVATE KEY"));
    assert!(pem_public.contains("PUBLIC KEY"));

    assert_eq!(
        KeyAgreementPrivateKey::from_x963_representation(algorithm, x963_private)?.raw_representation(),
        private.raw_representation()
    );
    assert_eq!(
        KeyAgreementPrivateKey::from_der_representation(algorithm, der_private)?.raw_representation(),
        private.raw_representation()
    );
    assert_eq!(
        KeyAgreementPrivateKey::from_pem_representation(algorithm, pem_private)?.raw_representation(),
        private.raw_representation()
    );

    assert_eq!(
        KeyAgreementPublicKey::from_x963_representation(algorithm, x963_public)?.raw_representation(),
        public.raw_representation()
    );
    assert_eq!(
        KeyAgreementPublicKey::from_compact_representation(algorithm, compact_public)?.raw_representation(),
        public.raw_representation()
    );
    assert_eq!(
        KeyAgreementPublicKey::from_compressed_representation(algorithm, compressed_public)?
            .raw_representation(),
        public.raw_representation()
    );
    assert_eq!(
        KeyAgreementPublicKey::from_der_representation(algorithm, der_public)?.raw_representation(),
        public.raw_representation()
    );
    assert_eq!(
        KeyAgreementPublicKey::from_pem_representation(algorithm, pem_public)?.raw_representation(),
        public.raw_representation()
    );
    Ok(())
}

#[test]
fn signing_key_representations_round_trip_for_nist_curves() -> Result<()> {
    for algorithm in [
        SigningAlgorithm::P256,
        SigningAlgorithm::P384,
        SigningAlgorithm::P521,
    ] {
        assert_signing_representations_round_trip(algorithm)?;
    }
    Ok(())
}

#[test]
fn key_agreement_representations_round_trip_for_nist_curves() -> Result<()> {
    for algorithm in [
        KeyAgreementAlgorithm::P256,
        KeyAgreementAlgorithm::P384,
        KeyAgreementAlgorithm::P521,
    ] {
        assert_key_agreement_representations_round_trip(algorithm)?;
    }
    Ok(())
}
