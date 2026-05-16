use cryptokit::symmetric_key;
use cryptokit::{Result, SymmetricKey, SymmetricKeySize};

#[test]
fn supported_sizes_include_all_standard_widths() {
    let supported = symmetric_key::supported_sizes();
    assert!(supported.contains(&SymmetricKeySize::Bits128));
    assert!(supported.contains(&SymmetricKeySize::Bits192));
    assert!(supported.contains(&SymmetricKeySize::Bits256));
}

#[test]
fn generated_keys_report_expected_bit_lengths() -> Result<()> {
    let key128 = SymmetricKey::generate(SymmetricKeySize::Bits128)?;
    let key256 = SymmetricKey::generate(SymmetricKeySize::Bits256)?;
    assert_eq!(key128.bits(), 128);
    assert_eq!(key256.bits(), 256);
    Ok(())
}
