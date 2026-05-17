use cryptokit::hkdf::{hkdf_expand_sha256, hkdf_extract_sha256};
use cryptokit::hmac::{hmac_sha256_code, HmacSha256};
use cryptokit::sha::{sha256_digest, SHA2_256};
use cryptokit::{Result, SymmetricKey};

fn main() -> Result<()> {
    let digest = sha256_digest(b"stream me")?;
    let mut hasher = SHA2_256::new()?;
    hasher.update(b"stream ")?;
    hasher.update(b"me")?;
    let streamed = hasher.finalize()?;
    assert_eq!(digest, streamed);

    let key = SymmetricKey::from_bytes(vec![0xab; 32]);
    let code = hmac_sha256_code(b"payload", &key)?;
    let mut hmac = HmacSha256::new(&key)?;
    hmac.update(b"pay")?;
    hmac.update(b"load")?;
    assert_eq!(code, hmac.finalize()?);

    let pseudo_random_key = hkdf_extract_sha256(&key, Some(b"salt"))?;
    let expanded = hkdf_expand_sha256(&pseudo_random_key, Some(b"info"), 32)?;

    println!("sha256={digest}");
    println!("hmac={code}");
    println!("hkdf-bytes={}", expanded.as_bytes().len());
    Ok(())
}
