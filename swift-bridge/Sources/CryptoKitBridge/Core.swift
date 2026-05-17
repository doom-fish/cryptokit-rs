import CryptoKit
import Darwin
import Foundation
import LocalAuthentication
import Security

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

let CK_SHA3_256: Int32 = 1
let CK_SHA3_384: Int32 = 2
let CK_SHA3_512: Int32 = 3

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

let CK_KEY_FORMAT_RAW: Int32 = 1
let CK_KEY_FORMAT_COMPACT: Int32 = 2
let CK_KEY_FORMAT_X963: Int32 = 3
let CK_KEY_FORMAT_COMPRESSED: Int32 = 4
let CK_KEY_FORMAT_DER: Int32 = 5
let CK_KEY_FORMAT_PEM: Int32 = 6

let CK_SECURE_ENCLAVE_ACCESSIBILITY_DEFAULT: Int32 = 0
let CK_SECURE_ENCLAVE_ACCESSIBILITY_AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY: Int32 = 1
let CK_SECURE_ENCLAVE_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY: Int32 = 2
let CK_SECURE_ENCLAVE_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY: Int32 = 3
let CK_SECURE_ENCLAVE_ACCESSIBILITY_AFTER_FIRST_UNLOCK: Int32 = 4
let CK_SECURE_ENCLAVE_ACCESSIBILITY_WHEN_UNLOCKED: Int32 = 5
let CK_SECURE_ENCLAVE_ACCESSIBILITY_ALWAYS_THIS_DEVICE_ONLY: Int32 = 6
let CK_SECURE_ENCLAVE_ACCESSIBILITY_ALWAYS: Int32 = 7

let CK_KEM_MLKEM768: Int32 = 1
let CK_KEM_MLKEM1024: Int32 = 2
let CK_KEM_XWING_MLKEM768_X25519: Int32 = 3

let CK_MLDSA_65: Int32 = 1
let CK_MLDSA_87: Int32 = 2

let CK_HPKE_KDF_SHA256: Int32 = 1
let CK_HPKE_KDF_SHA384: Int32 = 2
let CK_HPKE_KDF_SHA512: Int32 = 3

let CK_HPKE_AEAD_AES_GCM_128: Int32 = 1
let CK_HPKE_AEAD_AES_GCM_256: Int32 = 2
let CK_HPKE_AEAD_CHACHA_POLY: Int32 = 3
let CK_HPKE_AEAD_EXPORT_ONLY: Int32 = 4

let CK_HPKE_KEM_P256_HKDF_SHA256: Int32 = 1
let CK_HPKE_KEM_P384_HKDF_SHA384: Int32 = 2
let CK_HPKE_KEM_P521_HKDF_SHA512: Int32 = 3
let CK_HPKE_KEM_CURVE25519_HKDF_SHA256: Int32 = 4
let CK_HPKE_KEM_XWING_MLKEM768_X25519: Int32 = 5

let CK_HPKE_MODE_BASE: Int32 = 1
let CK_HPKE_MODE_PSK: Int32 = 2
let CK_HPKE_MODE_AUTH: Int32 = 3
let CK_HPKE_MODE_AUTH_PSK: Int32 = 4

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

@inline(__always)
func ckCopyOptionalData(
    _ data: Data?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let data else {
        guard let outBytes, let outLen else {
            return ckInvalidArgument(errorOut, "missing output pointers")
        }
        outBytes.pointee = nil
        outLen.pointee = 0
        return CK_OK
    }
    return ckCopyData(data, outBytes, outLen, errorOut)
}

final class CKAuthenticationContextHolder {
    let context: LAContext

    init() {
        self.context = LAContext()
    }
}

@inline(__always)
func ckOptionalBridgeData(_ bytes: UnsafePointer<UInt8>?, _ count: UInt) throws -> Data? {
    if count == 0, bytes == nil {
        return nil
    }
    return try ckData(bytes, count)
}

@inline(__always)
func ckOptionalBridgeString(_ bytes: UnsafePointer<UInt8>?, _ count: UInt) throws -> String? {
    guard let data = try ckOptionalBridgeData(bytes, count) else {
        return nil
    }
    guard let string = String(data: data, encoding: .utf8) else {
        throw CKBridgeError.invalidArgument("string arguments must be valid UTF-8")
    }
    return string
}

@inline(__always)
func ckAuthenticationContext(_ handle: UnsafeMutableRawPointer?) throws -> LAContext? {
    guard let handle else {
        return nil
    }
    return Unmanaged<CKAuthenticationContextHolder>.fromOpaque(handle).takeUnretainedValue().context
}

func ckSecureEnclaveAccessControl(_ accessibility: Int32, _ flags: UInt64) throws -> SecAccessControl? {
    guard accessibility != CK_SECURE_ENCLAVE_ACCESSIBILITY_DEFAULT else {
        return nil
    }

    let protection: CFString
    switch accessibility {
    case CK_SECURE_ENCLAVE_ACCESSIBILITY_AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY:
        protection = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case CK_SECURE_ENCLAVE_ACCESSIBILITY_WHEN_UNLOCKED_THIS_DEVICE_ONLY:
        protection = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    case CK_SECURE_ENCLAVE_ACCESSIBILITY_WHEN_PASSCODE_SET_THIS_DEVICE_ONLY:
        protection = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    case CK_SECURE_ENCLAVE_ACCESSIBILITY_AFTER_FIRST_UNLOCK:
        protection = kSecAttrAccessibleAfterFirstUnlock
    case CK_SECURE_ENCLAVE_ACCESSIBILITY_WHEN_UNLOCKED:
        protection = kSecAttrAccessibleWhenUnlocked
    case CK_SECURE_ENCLAVE_ACCESSIBILITY_ALWAYS_THIS_DEVICE_ONLY:
        protection = kSecAttrAccessibleAlwaysThisDeviceOnly
    case CK_SECURE_ENCLAVE_ACCESSIBILITY_ALWAYS:
        protection = kSecAttrAccessibleAlways
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave accessibility: \(accessibility)")
    }

    var error: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        nil,
        protection,
        SecAccessControlCreateFlags(rawValue: UInt(flags)),
        &error
    ) else {
        throw CKBridgeError.invalidArgument(
            error?.takeRetainedValue().localizedDescription
                ?? "failed to create Secure Enclave access-control object"
        )
    }
    return accessControl
}

@_cdecl("ck_authentication_context_create")
public func ck_authentication_context_create(
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    Unmanaged.passRetained(CKAuthenticationContextHolder()).toOpaque()
}

@_cdecl("ck_authentication_context_release")
public func ck_authentication_context_release(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else {
        return
    }
    Unmanaged<CKAuthenticationContextHolder>.fromOpaque(handle).release()
}

@_cdecl("ck_authentication_context_set_interaction_not_allowed")
public func ck_authentication_context_set_interaction_not_allowed(
    _ handle: UnsafeMutableRawPointer?,
    _ value: UInt8,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let context = try ckAuthenticationContext(handle) else {
            throw CKBridgeError.invalidArgument("missing authentication-context handle")
        }
        context.interactionNotAllowed = value != 0
        return CK_OK
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_authentication_context_set_touch_id_reuse_duration")
public func ck_authentication_context_set_touch_id_reuse_duration(
    _ handle: UnsafeMutableRawPointer?,
    _ duration: Double,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let context = try ckAuthenticationContext(handle) else {
            throw CKBridgeError.invalidArgument("missing authentication-context handle")
        }
        context.touchIDAuthenticationAllowableReuseDuration = duration
        return CK_OK
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_authentication_context_set_localized_fallback_title")
public func ck_authentication_context_set_localized_fallback_title(
    _ handle: UnsafeMutableRawPointer?,
    _ titleBytes: UnsafePointer<UInt8>?,
    _ titleLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let context = try ckAuthenticationContext(handle) else {
            throw CKBridgeError.invalidArgument("missing authentication-context handle")
        }
        context.localizedFallbackTitle = try ckOptionalBridgeString(titleBytes, titleLen)
        return CK_OK
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_authentication_context_set_localized_cancel_title")
public func ck_authentication_context_set_localized_cancel_title(
    _ handle: UnsafeMutableRawPointer?,
    _ titleBytes: UnsafePointer<UInt8>?,
    _ titleLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let context = try ckAuthenticationContext(handle) else {
            throw CKBridgeError.invalidArgument("missing authentication-context handle")
        }
        context.localizedCancelTitle = try ckOptionalBridgeString(titleBytes, titleLen)
        return CK_OK
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}
