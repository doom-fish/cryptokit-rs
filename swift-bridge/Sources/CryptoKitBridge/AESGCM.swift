import CryptoKit
import Foundation

private func ckAesGcmKey(_ keyBytes: UnsafePointer<UInt8>?, _ keyLen: UInt) throws -> SymmetricKey {
    SymmetricKey(data: try ckData(keyBytes, keyLen))
}

private func ckAesGcmNonce(
    _ nonceBytes: UnsafePointer<UInt8>?,
    _ nonceLen: UInt
) throws -> AES.GCM.Nonce? {
    guard nonceLen > 0 else {
        return nil
    }
    return try AES.GCM.Nonce(data: try ckData(nonceBytes, nonceLen))
}

@_cdecl("ck_aes_gcm_seal_aad")
public func ck_aes_gcm_seal_aad(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: UInt,
    _ nonceBytes: UnsafePointer<UInt8>?,
    _ nonceLen: UInt,
    _ authenticatedDataBytes: UnsafePointer<UInt8>?,
    _ authenticatedDataLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let key = try ckAesGcmKey(keyBytes, keyLen)
        let message = try ckData(messageBytes, messageLen)
        let authenticatedData = try ckData(authenticatedDataBytes, authenticatedDataLen)
        let sealed: AES.GCM.SealedBox
        if let nonce = try ckAesGcmNonce(nonceBytes, nonceLen) {
            sealed = try AES.GCM.seal(message, using: key, nonce: nonce, authenticating: authenticatedData)
        } else {
            sealed = try AES.GCM.seal(message, using: key, authenticating: authenticatedData)
        }
        guard let combined = sealed.combined else {
            return ckInvalidArgument(errorOut, "AES-GCM combined representation was unavailable")
        }
        return ckCopyData(combined, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_ENCRYPTION_FAILED, error, errorOut)
    }
}

@_cdecl("ck_aes_gcm_open_aad")
public func ck_aes_gcm_open_aad(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ combinedBytes: UnsafePointer<UInt8>?,
    _ combinedLen: UInt,
    _ authenticatedDataBytes: UnsafePointer<UInt8>?,
    _ authenticatedDataLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let key = try ckAesGcmKey(keyBytes, keyLen)
        let combined = try ckData(combinedBytes, combinedLen)
        let authenticatedData = try ckData(authenticatedDataBytes, authenticatedDataLen)
        let sealed = try AES.GCM.SealedBox(combined: combined)
        let opened = try AES.GCM.open(sealed, using: key, authenticating: authenticatedData)
        return ckCopyData(opened, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_DECRYPTION_FAILED, error, errorOut)
    }
}
