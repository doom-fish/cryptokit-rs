mod common;

use cryptokit::sha;
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
