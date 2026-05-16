import CommonCrypto
import Foundation

private func ckAesCbcTransform(
    operation: CCOperation,
    key: Data,
    iv: Data,
    input: Data
) throws -> Data {
    guard [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256].contains(key.count) else {
        throw CKBridgeError.invalidArgument("AES-CBC keys must be 16, 24, or 32 bytes")
    }
    guard iv.count == kCCBlockSizeAES128 else {
        throw CKBridgeError.invalidArgument("AES-CBC IVs must be 16 bytes")
    }

    var output = Data(count: input.count + kCCBlockSizeAES128)
    let outputCapacity = output.count
    var outputCount = 0
    let status = output.withUnsafeMutableBytes { outputBytes in
        input.withUnsafeBytes { inputBytes in
            iv.withUnsafeBytes { ivBytes in
                key.withUnsafeBytes { keyBytes in
                    CCCrypt(
                        operation,
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionPKCS7Padding),
                        keyBytes.baseAddress,
                        key.count,
                        ivBytes.baseAddress,
                        inputBytes.baseAddress,
                        input.count,
                        outputBytes.baseAddress,
                        outputCapacity,
                        &outputCount
                    )
                }
            }
        }
    }

    guard status == kCCSuccess else {
        throw NSError(
            domain: "CryptoKitBridge.AESCBC",
            code: Int(status),
            userInfo: [NSLocalizedDescriptionKey: "CCCrypt failed with status \(status)"]
        )
    }

    output.removeSubrange(outputCount..<output.count)
    return output
}

@_cdecl("ck_aes_cbc_encrypt")
public func ck_aes_cbc_encrypt(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ ivBytes: UnsafePointer<UInt8>?,
    _ ivLen: UInt,
    _ plaintextBytes: UnsafePointer<UInt8>?,
    _ plaintextLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let key = try ckData(keyBytes, keyLen)
        let iv = try ckData(ivBytes, ivLen)
        let plaintext = try ckData(plaintextBytes, plaintextLen)
        let ciphertext = try ckAesCbcTransform(operation: CCOperation(kCCEncrypt), key: key, iv: iv, input: plaintext)
        return ckCopyData(ciphertext, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_ENCRYPTION_FAILED, error, errorOut)
    }
}

@_cdecl("ck_aes_cbc_decrypt")
public func ck_aes_cbc_decrypt(
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ ivBytes: UnsafePointer<UInt8>?,
    _ ivLen: UInt,
    _ ciphertextBytes: UnsafePointer<UInt8>?,
    _ ciphertextLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let key = try ckData(keyBytes, keyLen)
        let iv = try ckData(ivBytes, ivLen)
        let ciphertext = try ckData(ciphertextBytes, ciphertextLen)
        let plaintext = try ckAesCbcTransform(operation: CCOperation(kCCDecrypt), key: key, iv: iv, input: ciphertext)
        return ckCopyData(plaintext, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_DECRYPTION_FAILED, error, errorOut)
    }
}
