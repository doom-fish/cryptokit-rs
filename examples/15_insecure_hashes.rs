use std::fmt::Write as _;

use cryptokit::insecure;

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let md5 = insecure::md5(b"hello")?;
    let sha1 = insecure::sha1(b"hello")?;
    println!("md5: {}", hex(&md5));
    println!("sha1: {}", hex(&sha1));
    Ok(())
}
