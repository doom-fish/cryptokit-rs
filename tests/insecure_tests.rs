mod common;

use cryptokit::insecure;
use cryptokit::Result;

#[test]
fn insecure_hashes_match_known_digests() -> Result<()> {
    assert_eq!(
        common::hex(&insecure::md5(b"hello")?),
        "5d41402abc4b2a76b9719d911017c592"
    );
    assert_eq!(
        common::hex(&insecure::sha1(b"hello")?),
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    );
    Ok(())
}
