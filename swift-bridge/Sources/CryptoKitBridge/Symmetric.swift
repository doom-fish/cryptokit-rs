import CryptoKit
import Foundation

private func ckSymmetricKey(from bytes: UnsafePointer<UInt8>?, _ count: UInt) throws -> SymmetricKey {
    SymmetricKey(data: try ckData(bytes, count))
}

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

@_cdecl("ck_aes_gcm_seal")
public func ck_aes_gcm_seal(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: UInt,
    _ nonceBytes: UnsafePointer<UInt8>?,
    _ nonceLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let key = try ckSymmetricKey(from: keyBytes, keyLen)
        let message = try ckData(messageBytes, messageLen)
        let sealed: AES.GCM.SealedBox
        if nonceLen == 0 {
            sealed = try AES.GCM.seal(message, using: key)
        } else {
            let nonce = try AES.GCM.Nonce(data: try ckData(nonceBytes, nonceLen))
            sealed = try AES.GCM.seal(message, using: key, nonce: nonce)
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

@_cdecl("ck_aes_gcm_open")
public func ck_aes_gcm_open(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ combinedBytes: UnsafePointer<UInt8>?,
    _ combinedLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let key = try ckSymmetricKey(from: keyBytes, keyLen)
        let combined = try ckData(combinedBytes, combinedLen)
        let sealed = try AES.GCM.SealedBox(combined: combined)
        let opened = try AES.GCM.open(sealed, using: key)
        return ckCopyData(opened, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_DECRYPTION_FAILED, error, errorOut)
    }
}

@_cdecl("ck_chacha_poly_seal")
public func ck_chacha_poly_seal(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: UInt,
    _ nonceBytes: UnsafePointer<UInt8>?,
    _ nonceLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let key = try ckSymmetricKey(from: keyBytes, keyLen)
        let message = try ckData(messageBytes, messageLen)
        let sealed: ChaChaPoly.SealedBox
        if nonceLen == 0 {
            sealed = try ChaChaPoly.seal(message, using: key)
        } else {
            let nonce = try ChaChaPoly.Nonce(data: try ckData(nonceBytes, nonceLen))
            sealed = try ChaChaPoly.seal(message, using: key, nonce: nonce)
        }
        return ckCopyData(sealed.combined, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_ENCRYPTION_FAILED, error, errorOut)
    }
}

@_cdecl("ck_chacha_poly_open")
public func ck_chacha_poly_open(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ combinedBytes: UnsafePointer<UInt8>?,
    _ combinedLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let key = try ckSymmetricKey(from: keyBytes, keyLen)
        let combined = try ckData(combinedBytes, combinedLen)
        let sealed = try ChaChaPoly.SealedBox(combined: combined)
        let opened = try ChaChaPoly.open(sealed, using: key)
        return ckCopyData(opened, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_DECRYPTION_FAILED, error, errorOut)
    }
}
