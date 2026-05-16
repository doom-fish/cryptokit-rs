import CryptoKit
import Foundation

private func ckSymmetricKey(_ bytes: UnsafePointer<UInt8>?, _ len: UInt) throws -> SymmetricKey {
    SymmetricKey(data: try ckData(bytes, len))
}

private func ckSymmetricKeyData(_ key: SymmetricKey) -> Data {
    key.withUnsafeBytes(ckOwnedData)
}

@_cdecl("ck_aes_key_wrap")
public func ck_aes_key_wrap(
    _ keyToWrapBytes: UnsafePointer<UInt8>?,
    _ keyToWrapLen: UInt,
    _ kekBytes: UnsafePointer<UInt8>?,
    _ kekLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 12.0, *) else {
        return ckInvalidArgument(errorOut, "AES.KeyWrap requires macOS 12.0 or newer")
    }

    do {
        let keyToWrap = try ckSymmetricKey(keyToWrapBytes, keyToWrapLen)
        let kek = try ckSymmetricKey(kekBytes, kekLen)
        return ckCopyData(try AES.KeyWrap.wrap(keyToWrap, using: kek), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_aes_key_unwrap")
public func ck_aes_key_unwrap(
    _ wrappedKeyBytes: UnsafePointer<UInt8>?,
    _ wrappedKeyLen: UInt,
    _ kekBytes: UnsafePointer<UInt8>?,
    _ kekLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 12.0, *) else {
        return ckInvalidArgument(errorOut, "AES.KeyWrap requires macOS 12.0 or newer")
    }

    do {
        let wrappedKey = try ckData(wrappedKeyBytes, wrappedKeyLen)
        let kek = try ckSymmetricKey(kekBytes, kekLen)
        let unwrapped = try AES.KeyWrap.unwrap(wrappedKey, using: kek)
        return ckCopyData(ckSymmetricKeyData(unwrapped), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}
