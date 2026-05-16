use cryptokit::symmetric_key;
use cryptokit::{SymmetricKey, SymmetricKeySize};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let supported = symmetric_key::supported_sizes();
    assert!(supported.contains(&SymmetricKeySize::Bits256));

    let key = SymmetricKey::generate(SymmetricKeySize::Bits256)?;
    assert_eq!(key.bits(), 256);
    println!("symmetric-key sizes: {supported:?}");
    Ok(())
}
