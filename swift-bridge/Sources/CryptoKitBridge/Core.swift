import CryptoKit
import Darwin
import Foundation

let CK_OK: Int32 = 0
let CK_INVALID_ARGUMENT: Int32 = -1
let CK_ENCRYPTION_FAILED: Int32 = -2
let CK_DECRYPTION_FAILED: Int32 = -3
let CK_HASHING_FAILED: Int32 = -4
let CK_HMAC_FAILED: Int32 = -5
let CK_HKDF_FAILED: Int32 = -6
let CK_KEY_FAILED: Int32 = -7
let CK_SIGNATURE_FAILED: Int32 = -8
let CK_AGREEMENT_FAILED: Int32 = -9
let CK_UNKNOWN: Int32 = -99

let CK_HASH_SHA256: Int32 = 1
let CK_HASH_SHA384: Int32 = 2
let CK_HASH_SHA512: Int32 = 3
let CK_HASH_MD5: Int32 = 4
let CK_HASH_SHA1: Int32 = 5

let CK_HMAC_SHA256: Int32 = 1
let CK_HMAC_SHA384: Int32 = 2
let CK_HMAC_SHA512: Int32 = 3

let CK_SIGNING_P256: Int32 = 1
let CK_SIGNING_P384: Int32 = 2
let CK_SIGNING_P521: Int32 = 3
let CK_SIGNING_ED25519: Int32 = 4

let CK_KEY_AGREEMENT_P256: Int32 = 1
let CK_KEY_AGREEMENT_P384: Int32 = 2
let CK_KEY_AGREEMENT_P521: Int32 = 3
let CK_KEY_AGREEMENT_X25519: Int32 = 4

enum CKBridgeError: LocalizedError {
    case invalidArgument(String)

    var errorDescription: String? {
        switch self {
        case .invalidArgument(let message):
            return message
        }
    }
}

@inline(__always)
func ckCString(_ string: String) -> UnsafeMutablePointer<CChar>? {
    string.withCString { strdup($0) }
}

@inline(__always)
func ckWriteError(
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ message: String
) {
    errorOut?.pointee = ckCString(message)
}

@inline(__always)
func ckInvalidArgument(
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?,
    _ message: String
) -> Int32 {
    ckWriteError(errorOut, message)
    return CK_INVALID_ARGUMENT
}

@inline(__always)
func ckFail(
    _ status: Int32,
    _ error: Error,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    ckWriteError(errorOut, error.localizedDescription)
    return status
}

@inline(__always)
func ckData(_ bytes: UnsafePointer<UInt8>?, _ count: UInt) throws -> Data {
    guard count == 0 || bytes != nil else {
        throw CKBridgeError.invalidArgument("missing byte buffer")
    }
    guard count > 0, let bytes else {
        return Data()
    }
    return Data(bytes: bytes, count: Int(count))
}

@inline(__always)
func ckOwnedData(_ rawBuffer: UnsafeRawBufferPointer) -> Data {
    guard let baseAddress = rawBuffer.baseAddress else {
        return Data()
    }
    return Data(bytes: baseAddress, count: rawBuffer.count)
}

@inline(__always)
func ckCopyData(
    _ data: Data,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let outBytes, let outLen else {
        return ckInvalidArgument(errorOut, "missing output pointers")
    }

    outLen.pointee = UInt(data.count)
    if data.isEmpty {
        outBytes.pointee = nil
        return CK_OK
    }

    guard let raw = malloc(data.count) else {
        return ckInvalidArgument(errorOut, "malloc failed")
    }
    let buffer = raw.assumingMemoryBound(to: UInt8.self)
    data.copyBytes(to: buffer, count: data.count)
    outBytes.pointee = buffer
    return CK_OK
}
