import CryptoKit
import Foundation

private let CK_HKDF_SHA256_MAX_OUTPUT_LENGTH = 255 * 32
private let CK_HKDF_SHA384_MAX_OUTPUT_LENGTH = 255 * 48
private let CK_HKDF_SHA512_MAX_OUTPUT_LENGTH = 255 * 64

private func ckHkdfDigestLength(_ algorithm: Int32) throws -> Int {
    switch algorithm {
    case CK_HASH_SHA256:
        return 32
    case CK_HASH_SHA384:
        return 48
    case CK_HASH_SHA512:
        return 64
    default:
        throw CKBridgeError.invalidArgument("unsupported HKDF algorithm: \(algorithm)")
    }
}

private func ckHkdfHmac(
    _ algorithm: Int32,
    key: Data,
    message: Data
) throws -> Data {
    let symmetricKey = SymmetricKey(data: key)
    switch algorithm {
    case CK_HASH_SHA256:
        return Data(Array(HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey)))
    case CK_HASH_SHA384:
        return Data(Array(HMAC<SHA384>.authenticationCode(for: message, using: symmetricKey)))
    case CK_HASH_SHA512:
        return Data(Array(HMAC<SHA512>.authenticationCode(for: message, using: symmetricKey)))
    default:
        throw CKBridgeError.invalidArgument("unsupported HKDF algorithm: \(algorithm)")
    }
}

func ckHkdf(
    _ algorithm: Int32,
    inputKeyMaterial: Data,
    salt: Data,
    info: Data,
    outputLen: Int
) throws -> Data {
    guard outputLen > 0 else {
        throw CKBridgeError.invalidArgument("HKDF output length must be greater than zero")
    }

    let maxOutputLength: Int
    switch algorithm {
    case CK_HASH_SHA256:
        maxOutputLength = CK_HKDF_SHA256_MAX_OUTPUT_LENGTH
    case CK_HASH_SHA384:
        maxOutputLength = CK_HKDF_SHA384_MAX_OUTPUT_LENGTH
    case CK_HASH_SHA512:
        maxOutputLength = CK_HKDF_SHA512_MAX_OUTPUT_LENGTH
    default:
        throw CKBridgeError.invalidArgument("unsupported HKDF algorithm: \(algorithm)")
    }
    guard outputLen <= maxOutputLength else {
        throw CKBridgeError.invalidArgument(
            "HKDF output length exceeds RFC 5869 maximum of \(maxOutputLength) bytes"
        )
    }

    let digestLength = try ckHkdfDigestLength(algorithm)
    let effectiveSalt = salt.isEmpty ? Data(repeating: 0, count: digestLength) : salt
    let pseudorandomKey = try ckHkdfHmac(algorithm, key: effectiveSalt, message: inputKeyMaterial)

    var output = Data()
    var previousBlock = Data()
    var counter: UInt8 = 1

    while output.count < outputLen {
        var blockInput = Data()
        blockInput.append(previousBlock)
        blockInput.append(info)
        blockInput.append(contentsOf: [counter])
        previousBlock = try ckHkdfHmac(algorithm, key: pseudorandomKey, message: blockInput)
        output.append(previousBlock)
        counter &+= 1
    }

    return output.prefix(outputLen)
}

private func ckHkdfExport(
    _ algorithm: Int32,
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ saltBytes: UnsafePointer<UInt8>?,
    _ saltLen: UInt,
    _ infoBytes: UnsafePointer<UInt8>?,
    _ infoLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let inputKeyMaterial = try ckData(keyBytes, keyLen)
        let salt = try ckData(saltBytes, saltLen)
        let info = try ckData(infoBytes, infoLen)
        return ckCopyData(
            try ckHkdf(
                algorithm,
                inputKeyMaterial: inputKeyMaterial,
                salt: salt,
                info: info,
                outputLen: Int(outputLen)
            ),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HKDF_FAILED, error, errorOut)
    }
}

@_cdecl("ck_hkdf_sha256")
public func ck_hkdf_sha256(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ saltBytes: UnsafePointer<UInt8>?,
    _ saltLen: UInt,
    _ infoBytes: UnsafePointer<UInt8>?,
    _ infoLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    ckHkdfExport(
        CK_HASH_SHA256,
        keyBytes,
        keyLen,
        saltBytes,
        saltLen,
        infoBytes,
        infoLen,
        outputLen,
        outBytes,
        outLen,
        errorOut
    )
}

@_cdecl("ck_hkdf_sha384")
public func ck_hkdf_sha384(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ saltBytes: UnsafePointer<UInt8>?,
    _ saltLen: UInt,
    _ infoBytes: UnsafePointer<UInt8>?,
    _ infoLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    ckHkdfExport(
        CK_HASH_SHA384,
        keyBytes,
        keyLen,
        saltBytes,
        saltLen,
        infoBytes,
        infoLen,
        outputLen,
        outBytes,
        outLen,
        errorOut
    )
}

@_cdecl("ck_hkdf_sha512")
public func ck_hkdf_sha512(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ saltBytes: UnsafePointer<UInt8>?,
    _ saltLen: UInt,
    _ infoBytes: UnsafePointer<UInt8>?,
    _ infoLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    ckHkdfExport(
        CK_HASH_SHA512,
        keyBytes,
        keyLen,
        saltBytes,
        saltLen,
        infoBytes,
        infoLen,
        outputLen,
        outBytes,
        outLen,
        errorOut
    )
}
