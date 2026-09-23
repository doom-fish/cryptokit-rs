import CryptoKit
import Darwin
import Foundation

private let CK_X963_MAX_COUNTER = Int(UInt32.max)

final class CKSharedSecretHolder {
    let secret: SharedSecret

    init(_ secret: SharedSecret) {
        self.secret = secret
    }
}

func ckKeyDerivationDigestLength(_ algorithm: Int32) throws -> Int {
    switch algorithm {
    case CK_HASH_SHA256:
        return 32
    case CK_HASH_SHA384:
        return 48
    case CK_HASH_SHA512:
        return 64
    default:
        throw CKBridgeError.invalidArgument("unsupported key-derivation digest algorithm: \(algorithm)")
    }
}

func ckStoreSharedSecret(
    _ secret: SharedSecret,
    _ outHandle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let outHandle else {
        return ckInvalidArgument(errorOut, "missing shared-secret output pointer")
    }
    outHandle.pointee = Unmanaged.passRetained(CKSharedSecretHolder(secret)).toOpaque()
    return CK_OK
}

private func ckSharedSecretHolder(_ handle: UnsafeMutableRawPointer?) throws -> CKSharedSecretHolder {
    guard let handle else {
        throw CKBridgeError.invalidArgument("missing shared-secret handle")
    }
    return Unmanaged<CKSharedSecretHolder>.fromOpaque(handle).takeUnretainedValue()
}

private func ckSharedSecretHkdf(
    _ secret: SharedSecret,
    _ algorithm: Int32,
    salt: Data,
    info: Data,
    outputByteCount: Int
) throws -> SymmetricKey {
    let maximum = 255 * (try ckKeyDerivationDigestLength(algorithm))
    guard outputByteCount > 0, outputByteCount <= maximum else {
        throw CKBridgeError.invalidArgument("HKDF output length must be between 1 and \(maximum) bytes")
    }

    switch algorithm {
    case CK_HASH_SHA256:
        return secret.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
    case CK_HASH_SHA384:
        return secret.hkdfDerivedSymmetricKey(using: SHA384.self, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
    case CK_HASH_SHA512:
        return secret.hkdfDerivedSymmetricKey(using: SHA512.self, salt: salt, sharedInfo: info, outputByteCount: outputByteCount)
    default:
        throw CKBridgeError.invalidArgument("unsupported key-derivation digest algorithm: \(algorithm)")
    }
}

private func ckSharedSecretX963(
    _ secret: SharedSecret,
    _ algorithm: Int32,
    sharedInfo: Data,
    outputByteCount: Int
) throws -> SymmetricKey {
    let limit = (try ckKeyDerivationDigestLength(algorithm)) * CK_X963_MAX_COUNTER
    guard outputByteCount > 0, outputByteCount < limit else {
        throw CKBridgeError.invalidArgument("ANSI X9.63 output length must be between 1 and \(limit - 1) bytes")
    }

    switch algorithm {
    case CK_HASH_SHA256:
        return secret.x963DerivedSymmetricKey(using: SHA256.self, sharedInfo: sharedInfo, outputByteCount: outputByteCount)
    case CK_HASH_SHA384:
        return secret.x963DerivedSymmetricKey(using: SHA384.self, sharedInfo: sharedInfo, outputByteCount: outputByteCount)
    case CK_HASH_SHA512:
        return secret.x963DerivedSymmetricKey(using: SHA512.self, sharedInfo: sharedInfo, outputByteCount: outputByteCount)
    default:
        throw CKBridgeError.invalidArgument("unsupported key-derivation digest algorithm: \(algorithm)")
    }
}

@_cdecl("ck_shared_secret_release")
public func ck_shared_secret_release(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else {
        return
    }
    Unmanaged<CKSharedSecretHolder>.fromOpaque(handle).release()
}

@_cdecl("ck_shared_secret_retain")
public func ck_shared_secret_retain(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else {
        return
    }
    _ = Unmanaged<CKSharedSecretHolder>.fromOpaque(handle).retain()
}

@_cdecl("ck_shared_secret_byte_count")
public func ck_shared_secret_byte_count(_ handle: UnsafeMutableRawPointer?) -> UInt {
    guard let holder = try? ckSharedSecretHolder(handle) else {
        return 0
    }
    return holder.secret.withUnsafeBytes { UInt($0.count) }
}

@_cdecl("ck_shared_secret_copy_bytes")
public func ck_shared_secret_copy_bytes(
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UInt8>?,
    _ capacity: UInt
) -> UInt {
    guard let holder = try? ckSharedSecretHolder(handle), let outBytes else {
        return 0
    }
    return holder.secret.withUnsafeBytes { source in
        let count = min(source.count, Int(clamping: capacity))
        guard count > 0, let base = source.baseAddress else {
            return 0
        }
        memcpy(outBytes, base, count)
        return UInt(count)
    }
}

@_cdecl("ck_shared_secret_equal")
public func ck_shared_secret_equal(
    _ lhs: UnsafeMutableRawPointer?,
    _ rhs: UnsafeMutableRawPointer?
) -> UInt8 {
    guard let left = try? ckSharedSecretHolder(lhs), let right = try? ckSharedSecretHolder(rhs) else {
        return 0
    }
    return left.secret == right.secret ? 1 : 0
}

@_cdecl("ck_shared_secret_hkdf")
public func ck_shared_secret_hkdf(
    _ handle: UnsafeMutableRawPointer?,
    _ algorithm: Int32,
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
        let holder = try ckSharedSecretHolder(handle)
        let salt = try ckData(saltBytes, saltLen)
        let info = try ckData(infoBytes, infoLen)
        let key = try ckSharedSecretHkdf(
            holder.secret,
            algorithm,
            salt: salt,
            info: info,
            outputByteCount: try ckByteCount(outputLen)
        )
        return ckCopyData(key.withUnsafeBytes(ckOwnedData), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HKDF_FAILED, error, errorOut)
    }
}

@_cdecl("ck_shared_secret_x963")
public func ck_shared_secret_x963(
    _ handle: UnsafeMutableRawPointer?,
    _ algorithm: Int32,
    _ sharedInfoBytes: UnsafePointer<UInt8>?,
    _ sharedInfoLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let holder = try ckSharedSecretHolder(handle)
        let sharedInfo = try ckData(sharedInfoBytes, sharedInfoLen)
        let key = try ckSharedSecretX963(
            holder.secret,
            algorithm,
            sharedInfo: sharedInfo,
            outputByteCount: try ckByteCount(outputLen)
        )
        return ckCopyData(key.withUnsafeBytes(ckOwnedData), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HKDF_FAILED, error, errorOut)
    }
}
