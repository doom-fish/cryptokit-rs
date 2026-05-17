import CryptoKit
import Foundation

private let CK_HKDF_SHA256_MAX_OUTPUT_LENGTH = 255 * 32
private let CK_HKDF_SHA384_MAX_OUTPUT_LENGTH = 255 * 48
private let CK_HKDF_SHA512_MAX_OUTPUT_LENGTH = 255 * 64

@available(macOS 11.0, *)
private func ckHkdfSymmetricKey(_ bytes: Data) -> SymmetricKey {
    SymmetricKey(data: bytes)
}

@available(macOS 11.0, *)
private func ckHkdfSymmetricKeyData(_ key: SymmetricKey) -> Data {
    key.withUnsafeBytes(ckOwnedData)
}

@available(macOS 11.0, *)
private func ckHkdfMaxOutputLength(_ algorithm: Int32) throws -> Int {
    switch algorithm {
    case CK_HASH_SHA256:
        return CK_HKDF_SHA256_MAX_OUTPUT_LENGTH
    case CK_HASH_SHA384:
        return CK_HKDF_SHA384_MAX_OUTPUT_LENGTH
    case CK_HASH_SHA512:
        return CK_HKDF_SHA512_MAX_OUTPUT_LENGTH
    default:
        throw CKBridgeError.invalidArgument("unsupported HKDF algorithm: \(algorithm)")
    }
}

@available(macOS 11.0, *)
private func ckOptionalData(_ bytes: UnsafePointer<UInt8>?, _ count: UInt) throws -> Data? {
    if bytes == nil, count == 0 {
        return nil
    }
    return try ckData(bytes, count)
}

@available(macOS 11.0, *)
private func ckHkdfDerive(
    _ algorithm: Int32,
    inputKeyMaterial: Data,
    salt: Data,
    info: Data,
    outputLen: Int
) throws -> Data {
    guard outputLen > 0 else {
        throw CKBridgeError.invalidArgument("HKDF output length must be greater than zero")
    }
    let maxOutputLength = try ckHkdfMaxOutputLength(algorithm)
    guard outputLen <= maxOutputLength else {
        throw CKBridgeError.invalidArgument(
            "HKDF output length exceeds RFC 5869 maximum of \(maxOutputLength) bytes"
        )
    }

    let key = ckHkdfSymmetricKey(inputKeyMaterial)
    switch algorithm {
    case CK_HASH_SHA256:
        return ckHkdfSymmetricKeyData(
            HKDF<SHA256>.deriveKey(
                inputKeyMaterial: key,
                salt: salt,
                info: info,
                outputByteCount: outputLen
            )
        )
    case CK_HASH_SHA384:
        return ckHkdfSymmetricKeyData(
            HKDF<SHA384>.deriveKey(
                inputKeyMaterial: key,
                salt: salt,
                info: info,
                outputByteCount: outputLen
            )
        )
    case CK_HASH_SHA512:
        return ckHkdfSymmetricKeyData(
            HKDF<SHA512>.deriveKey(
                inputKeyMaterial: key,
                salt: salt,
                info: info,
                outputByteCount: outputLen
            )
        )
    default:
        throw CKBridgeError.invalidArgument("unsupported HKDF algorithm: \(algorithm)")
    }
}

@available(macOS 11.0, *)
private func ckHkdfExtract(
    _ algorithm: Int32,
    inputKeyMaterial: Data,
    salt: Data?
) throws -> Data {
    let key = ckHkdfSymmetricKey(inputKeyMaterial)
    switch algorithm {
    case CK_HASH_SHA256:
        return Data(Array(HKDF<SHA256>.extract(inputKeyMaterial: key, salt: salt)))
    case CK_HASH_SHA384:
        return Data(Array(HKDF<SHA384>.extract(inputKeyMaterial: key, salt: salt)))
    case CK_HASH_SHA512:
        return Data(Array(HKDF<SHA512>.extract(inputKeyMaterial: key, salt: salt)))
    default:
        throw CKBridgeError.invalidArgument("unsupported HKDF algorithm: \(algorithm)")
    }
}

@available(macOS 11.0, *)
private func ckHkdfExpand(
    _ algorithm: Int32,
    pseudoRandomKey: Data,
    info: Data?,
    outputLen: Int
) throws -> Data {
    guard outputLen > 0 else {
        throw CKBridgeError.invalidArgument("HKDF output length must be greater than zero")
    }
    let maxOutputLength = try ckHkdfMaxOutputLength(algorithm)
    guard outputLen <= maxOutputLength else {
        throw CKBridgeError.invalidArgument(
            "HKDF output length exceeds RFC 5869 maximum of \(maxOutputLength) bytes"
        )
    }

    switch algorithm {
    case CK_HASH_SHA256:
        return ckHkdfSymmetricKeyData(
            HKDF<SHA256>.expand(
                pseudoRandomKey: pseudoRandomKey,
                info: info,
                outputByteCount: outputLen
            )
        )
    case CK_HASH_SHA384:
        return ckHkdfSymmetricKeyData(
            HKDF<SHA384>.expand(
                pseudoRandomKey: pseudoRandomKey,
                info: info,
                outputByteCount: outputLen
            )
        )
    case CK_HASH_SHA512:
        return ckHkdfSymmetricKeyData(
            HKDF<SHA512>.expand(
                pseudoRandomKey: pseudoRandomKey,
                info: info,
                outputByteCount: outputLen
            )
        )
    default:
        throw CKBridgeError.invalidArgument("unsupported HKDF algorithm: \(algorithm)")
    }
}

@available(macOS 11.0, *)
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
            try ckHkdfDerive(
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

@_cdecl("ck_hkdf_extract")
public func ck_hkdf_extract(
    _ algorithm: Int32,
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ saltBytes: UnsafePointer<UInt8>?,
    _ saltLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 11.0, *) else {
        return ckInvalidArgument(errorOut, "HKDF extract requires macOS 11.0 or newer")
    }

    do {
        let inputKeyMaterial = try ckData(keyBytes, keyLen)
        let salt = try ckOptionalData(saltBytes, saltLen)
        return ckCopyData(
            try ckHkdfExtract(algorithm, inputKeyMaterial: inputKeyMaterial, salt: salt),
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

@_cdecl("ck_hkdf_expand")
public func ck_hkdf_expand(
    _ algorithm: Int32,
    _ prkBytes: UnsafePointer<UInt8>?,
    _ prkLen: UInt,
    _ infoBytes: UnsafePointer<UInt8>?,
    _ infoLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 11.0, *) else {
        return ckInvalidArgument(errorOut, "HKDF expand requires macOS 11.0 or newer")
    }

    do {
        let pseudoRandomKey = try ckData(prkBytes, prkLen)
        let info = try ckOptionalData(infoBytes, infoLen)
        return ckCopyData(
            try ckHkdfExpand(
                algorithm,
                pseudoRandomKey: pseudoRandomKey,
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
    guard #available(macOS 11.0, *) else {
        return ckInvalidArgument(errorOut, "HKDF requires macOS 11.0 or newer")
    }

    return ckHkdfExport(
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
    guard #available(macOS 11.0, *) else {
        return ckInvalidArgument(errorOut, "HKDF requires macOS 11.0 or newer")
    }

    return ckHkdfExport(
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
    guard #available(macOS 11.0, *) else {
        return ckInvalidArgument(errorOut, "HKDF requires macOS 11.0 or newer")
    }

    return ckHkdfExport(
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
