import CryptoKit
import Foundation

private func ckHashData(_ algorithm: Int32, data: Data) throws -> Data {
    switch algorithm {
    case CK_HASH_SHA256:
        return Data(Array(SHA256.hash(data: data)))
    case CK_HASH_SHA384:
        return Data(Array(SHA384.hash(data: data)))
    case CK_HASH_SHA512:
        return Data(Array(SHA512.hash(data: data)))
    case CK_HASH_MD5:
        return Data(Array(Insecure.MD5.hash(data: data)))
    case CK_HASH_SHA1:
        return Data(Array(Insecure.SHA1.hash(data: data)))
    default:
        throw CKBridgeError.invalidArgument("unsupported hash algorithm: \(algorithm)")
    }
}

@_cdecl("ck_hash")
public func ck_hash(
    _ algorithm: Int32,
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let input = try ckData(inputBytes, inputLen)
        return ckCopyData(try ckHashData(algorithm, data: input), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HASHING_FAILED, error, errorOut)
    }
}
