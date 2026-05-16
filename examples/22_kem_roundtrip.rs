use cryptokit::kem::Mlkem768PrivateKey;
use cryptokit::Result;

fn main() -> Result<()> {
    let private_key = Mlkem768PrivateKey::generate()?;
    let public_key = private_key.public_key()?;
    let encapsulation = public_key.encapsulate()?;
    let decapsulated = private_key.decapsulate(encapsulation.encapsulated())?;

    println!(
        "ML-KEM shared secret matches: {}",
        decapsulated.as_bytes() == encapsulation.shared_secret().as_bytes()
    );
    Ok(())
}
