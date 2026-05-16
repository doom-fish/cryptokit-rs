use std::fmt::Write as _;

use cryptokit::sha;

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sha256 = sha::sha256(b"hello")?;
    let sha512 = sha::sha512(b"hello")?;
    println!("sha256: {}", hex(&sha256));
    println!("sha512-bytes: {}", sha512.len());
    Ok(())
}
