use cryptokit::nist::{self, NistCurve};
use cryptokit::Result;

#[test]
fn nist_curves_are_listed_and_usable() -> Result<()> {
    let curves = nist::supported_curves();
    assert_eq!(
        curves,
        vec![NistCurve::P256, NistCurve::P384, NistCurve::P521]
    );

    for curve in curves {
        let signing = nist::generate_signing_private_key(curve)?;
        let verifying = signing.public_key()?;
        let message = curve.name().as_bytes();
        let signature = signing.sign(message)?;
        assert!(verifying.verify(message, &signature)?);
    }

    Ok(())
}
