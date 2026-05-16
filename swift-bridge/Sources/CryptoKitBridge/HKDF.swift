import CryptoKit
import Foundation

private let CK_SHA256_DIGEST_LENGTH = 32
private let CK_HKDF_SHA256_MAX_OUTPUT_LENGTH = 255 * CK_SHA256_DIGEST_LENGTH

private func ckHmacSha256(key: Data, message: Data) -> Data {
    let code = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
    return Data(Array(code))
}

private func ckHkdfSha256(inputKeyMaterial: Data, salt: Data, info: Data, outputLen: Int) throws -> Data {
    guard outputLen > 0 else {
        throw CKBridgeError.invalidArgument("HKDF output length must be greater than zero")
    }
    guard outputLen <= CK_HKDF_SHA256_MAX_OUTPUT_LENGTH else {
        throw CKBridgeError.invalidArgument(
            "HKDF-SHA256 output length exceeds RFC 5869 maximum of \(CK_HKDF_SHA256_MAX_OUTPUT_LENGTH) bytes"
        )
    }

    let effectiveSalt = salt.isEmpty ? Data(repeating: 0, count: CK_SHA256_DIGEST_LENGTH) : salt
    let pseudorandomKey = ckHmacSha256(key: effectiveSalt, message: inputKeyMaterial)

    var output = Data()
    var previousBlock = Data()
    var counter: UInt8 = 1

    while output.count < outputLen {
        var blockInput = Data()
        blockInput.append(previousBlock)
        blockInput.append(info)
        blockInput.append(contentsOf: [counter])

        previousBlock = ckHmacSha256(key: pseudorandomKey, message: blockInput)
        output.append(previousBlock)
        counter &+= 1
    }

    return output.prefix(outputLen)
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
    do {
        let inputKeyMaterial = try ckData(keyBytes, keyLen)
        let salt = try ckData(saltBytes, saltLen)
        let info = try ckData(infoBytes, infoLen)
        return ckCopyData(
            try ckHkdfSha256(
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

@_cdecl("ck_shared_secret_hkdf_sha256")
public func ck_shared_secret_hkdf_sha256(
    _ secretBytes: UnsafePointer<UInt8>?,
    _ secretLen: UInt,
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
        let secret = try ckData(secretBytes, secretLen)
        let salt = try ckData(saltBytes, saltLen)
        let info = try ckData(infoBytes, infoLen)
        return ckCopyData(
            try ckHkdfSha256(
                inputKeyMaterial: secret,
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
