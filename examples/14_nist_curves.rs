use cryptokit::nist;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let curves = nist::supported_curves();
    assert_eq!(curves.len(), 3);
    for curve in &curves {
        let signing = nist::generate_signing_private_key(*curve)?;
        let verifying = signing.public_key()?;
        let signature = signing.sign(curve.name().as_bytes())?;
        assert!(verifying.verify(curve.name().as_bytes(), &signature)?);
        println!("nist curve: {}", curve.name());
    }
    Ok(())
}
