import CryptoKit
import Foundation

@_cdecl("ck_p384_is_supported")
public func ck_p384_is_supported() -> UInt8 {
    1
}
