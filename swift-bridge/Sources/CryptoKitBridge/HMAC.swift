import CryptoKit
import Foundation

@_cdecl("ck_hmac")
public func ck_hmac(
    _ algorithm: Int32,
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let key = SymmetricKey(data: try ckData(keyBytes, keyLen))
        let message = try ckData(messageBytes, messageLen)
        let code: Data
        switch algorithm {
        case CK_HMAC_SHA256:
            code = Data(Array(HMAC<SHA256>.authenticationCode(for: message, using: key)))
        case CK_HMAC_SHA384:
            code = Data(Array(HMAC<SHA384>.authenticationCode(for: message, using: key)))
        case CK_HMAC_SHA512:
            code = Data(Array(HMAC<SHA512>.authenticationCode(for: message, using: key)))
        default:
            throw CKBridgeError.invalidArgument("unsupported HMAC algorithm: \(algorithm)")
        }
        return ckCopyData(code, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HMAC_FAILED, error, errorOut)
    }
}
