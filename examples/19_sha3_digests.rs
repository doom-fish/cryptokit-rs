use cryptokit::sha3::{sha3_256, Sha3_512};
use cryptokit::Result;

fn main() -> Result<()> {
    let digest = sha3_256(b"doom fish")?;
    println!("SHA3-256 bytes: {}", digest.as_bytes().len());

    let mut streaming = Sha3_512::new()?;
    streaming.update(b"doom ")?;
    streaming.update(b"fish")?;
    let digest = streaming.finalize()?;
    println!("SHA3-512 bytes: {}", digest.as_bytes().len());

    Ok(())
}
