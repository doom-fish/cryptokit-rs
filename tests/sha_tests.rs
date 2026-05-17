mod common;

use cryptokit::sha::{self, SHA2_256};
use cryptokit::Result;

#[test]
fn sha_vectors_match_known_digests() -> Result<()> {
    assert_eq!(
        common::hex(&sha::sha256(b"hello")?),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
    assert_eq!(sha::sha384(b"hello")?.len(), 48);
    assert_eq!(sha::sha512(b"hello")?.len(), 64);
    Ok(())
}

#[test]
fn typed_and_streaming_sha256_match_one_shot_output() -> Result<()> {
    let typed = sha::sha256_digest(b"hello")?;

    let mut hasher = SHA2_256::new()?;
    hasher.update(b"he")?;
    hasher.update(b"llo")?;
    let streamed = hasher.finalize()?;

    assert_eq!(typed, streamed);
    assert_eq!(typed.as_bytes(), sha::sha256(b"hello")?.as_slice());
    assert_eq!(typed.to_string(), common::hex(typed.as_bytes()));
    Ok(())
}
