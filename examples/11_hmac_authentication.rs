use std::fmt::Write as _;

use cryptokit::{hmac_sha256, SymmetricKey};

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = SymmetricKey::from_bytes(vec![0x0b; 20]);
    let code = hmac_sha256(b"Hi There", &key)?;
    println!("hmac-sha256: {}", hex(&code));
    Ok(())
}
