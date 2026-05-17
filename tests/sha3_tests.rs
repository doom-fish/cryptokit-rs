mod common;

use common::hex;
use cryptokit::sha3::{sha3_256, sha3_384, sha3_512, Sha3_256, Sha3_384, Sha3_512};
use cryptokit::Result;

#[test]
fn sha3_vectors_match_known_digests() -> Result<()> {
    assert_eq!(
        hex(sha3_256(b"abc")?.as_bytes()),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
    assert_eq!(
        hex(sha3_384(b"abc")?.as_bytes()),
        "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
    );
    assert_eq!(
        hex(sha3_512(b"abc")?.as_bytes()),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
    );
    Ok(())
}

#[test]
fn sha3_streaming_matches_one_shot() -> Result<()> {
    let mut sha3_256_state = Sha3_256::new()?;
    sha3_256_state.update(b"a")?;
    sha3_256_state.update(b"bc")?;
    assert_eq!(
        sha3_256_state.finalize()?.as_bytes(),
        sha3_256(b"abc")?.as_bytes()
    );

    let mut sha3_384_state = Sha3_384::new()?;
    sha3_384_state.update(b"ab")?;
    sha3_384_state.update(b"c")?;
    assert_eq!(
        sha3_384_state.finalize()?.as_bytes(),
        sha3_384(b"abc")?.as_bytes()
    );

    let mut sha3_512_state = Sha3_512::new()?;
    sha3_512_state.update(b"abc")?;
    assert_eq!(
        sha3_512_state.finalize()?.as_bytes(),
        sha3_512(b"abc")?.as_bytes()
    );

    Ok(())
}
