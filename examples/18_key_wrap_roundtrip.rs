use cryptokit::key_wrap::AesKeyWrap;
use cryptokit::{Result, SymmetricKey};

fn main() -> Result<()> {
    let key_to_wrap = SymmetricKey::generate(cryptokit::SymmetricKeySize::Bits256)?;
    let kek = SymmetricKey::generate(cryptokit::SymmetricKeySize::Bits256)?;

    let wrapped = AesKeyWrap::wrap(&key_to_wrap, &kek)?;
    let unwrapped = AesKeyWrap::unwrap(&wrapped, &kek)?;

    println!(
        "Wrapped {} bytes into {} bytes",
        key_to_wrap.as_bytes().len(),
        wrapped.len()
    );
    println!("Unwrapped key matches: {}", unwrapped == key_to_wrap);
    Ok(())
}
