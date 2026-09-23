import CryptoKit
import Foundation

@_cdecl("ck_symmetric_key_generate")
public func ck_symmetric_key_generate(
    _ sizeBits: Int32,
    _ outKey: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outKeyLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    let key: SymmetricKey
    switch sizeBits {
    case 128:
        key = SymmetricKey(size: .bits128)
    case 192:
        key = SymmetricKey(size: .bits192)
    case 256:
        key = SymmetricKey(size: .bits256)
    default:
        return ckInvalidArgument(errorOut, "unsupported symmetric key size: \(sizeBits)")
    }

    let data = key.withUnsafeBytes(ckOwnedData)
    return ckCopyData(data, outKey, outKeyLen, errorOut)
}
