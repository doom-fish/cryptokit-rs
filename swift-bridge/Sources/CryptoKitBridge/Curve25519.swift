import CryptoKit
import Foundation

@_cdecl("ck_curve25519_is_supported")
public func ck_curve25519_is_supported() -> UInt8 {
    1
}
