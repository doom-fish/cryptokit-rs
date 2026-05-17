import CryptoKit
import Foundation

private func ckChaChaPolyKey(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt
) throws -> SymmetricKey {
    SymmetricKey(data: try ckData(keyBytes, keyLen))
}

private func ckChaChaPolyNonce(
    _ nonceBytes: UnsafePointer<UInt8>?,
    _ nonceLen: UInt
) throws -> ChaChaPoly.Nonce? {
    guard nonceLen > 0 else {
        return nil
    }
    return try ChaChaPoly.Nonce(data: try ckData(nonceBytes, nonceLen))
}

@_cdecl("ck_chacha_poly_nonce_generate")
public func ck_chacha_poly_nonce_generate(
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    ckCopyData(ChaChaPoly.Nonce().withUnsafeBytes(ckOwnedData), outBytes, outLen, errorOut)
}

@_cdecl("ck_chacha_poly_seal_aad")
public func ck_chacha_poly_seal_aad(
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
        let key = try ckChaChaPolyKey(keyBytes, keyLen)
        let message = try ckData(messageBytes, messageLen)
        let authenticatedData = try ckData(authenticatedDataBytes, authenticatedDataLen)
        let sealed: ChaChaPoly.SealedBox
        if let nonce = try ckChaChaPolyNonce(nonceBytes, nonceLen) {
            sealed = try ChaChaPoly.seal(message, using: key, nonce: nonce, authenticating: authenticatedData)
        } else {
            sealed = try ChaChaPoly.seal(message, using: key, authenticating: authenticatedData)
        }
        return ckCopyData(sealed.combined, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_ENCRYPTION_FAILED, error, errorOut)
    }
}

@_cdecl("ck_chacha_poly_open_aad")
public func ck_chacha_poly_open_aad(
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
        let key = try ckChaChaPolyKey(keyBytes, keyLen)
        let combined = try ckData(combinedBytes, combinedLen)
        let authenticatedData = try ckData(authenticatedDataBytes, authenticatedDataLen)
        let sealed = try ChaChaPoly.SealedBox(combined: combined)
        let opened = try ChaChaPoly.open(sealed, using: key, authenticating: authenticatedData)
        return ckCopyData(opened, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_DECRYPTION_FAILED, error, errorOut)
    }
}
