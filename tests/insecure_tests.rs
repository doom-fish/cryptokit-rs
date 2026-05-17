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

#[test]
fn typed_and_streaming_insecure_hashes_match_one_shot_output() -> Result<()> {
    let md5 = insecure::md5_digest(b"hello")?;
    let mut md5_hasher = insecure::Md5::new()?;
    md5_hasher.update(b"he")?;
    md5_hasher.update(b"llo")?;
    assert_eq!(md5, md5_hasher.finalize()?);

    let sha1 = insecure::sha1_digest(b"hello")?;
    let mut sha1_hasher = insecure::Sha1::new()?;
    sha1_hasher.update(b"he")?;
    sha1_hasher.update(b"llo")?;
    assert_eq!(sha1, sha1_hasher.finalize()?);
    assert_eq!(sha1.as_bytes(), insecure::sha1(b"hello")?.as_slice());
    Ok(())
}
