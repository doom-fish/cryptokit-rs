import CryptoKit
import Foundation

private protocol CKHmacStateProtocol: AnyObject {
    func update(_ data: Data)
    func finalize() -> Data
}

private final class CKHmacState<H: HashFunction>: CKHmacStateProtocol {
    private var state: HMAC<H>

    init(key: SymmetricKey) {
        state = HMAC<H>(key: key)
    }

    func update(_ data: Data) {
        state.update(data: data)
    }

    func finalize() -> Data {
        Data(Array(state.finalize()))
    }
}

private final class CKHmacStateHolder {
    let state: any CKHmacStateProtocol

    init(_ state: any CKHmacStateProtocol) {
        self.state = state
    }
}

private func ckHmacStateHolder(_ algorithm: Int32, key: SymmetricKey) throws -> CKHmacStateHolder {
    switch algorithm {
    case CK_HMAC_SHA256:
        return CKHmacStateHolder(CKHmacState<SHA256>(key: key))
    case CK_HMAC_SHA384:
        return CKHmacStateHolder(CKHmacState<SHA384>(key: key))
    case CK_HMAC_SHA512:
        return CKHmacStateHolder(CKHmacState<SHA512>(key: key))
    default:
        throw CKBridgeError.invalidArgument("unsupported HMAC algorithm: \(algorithm)")
    }
}

@_cdecl("ck_hmac_hasher_create")
public func ck_hmac_hasher_create(
    _ algorithm: Int32,
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        let key = SymmetricKey(data: try ckData(keyBytes, keyLen))
        return Unmanaged.passRetained(try ckHmacStateHolder(algorithm, key: key)).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_hmac_hasher_update")
public func ck_hmac_hasher_update(
    _ handle: UnsafeMutableRawPointer?,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing HMAC-state handle")
        }
        let holder = Unmanaged<CKHmacStateHolder>.fromOpaque(handle).takeUnretainedValue()
        holder.state.update(try ckData(messageBytes, messageLen))
        return CK_OK
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HMAC_FAILED, error, errorOut)
    }
}

@_cdecl("ck_hmac_hasher_finalize")
public func ck_hmac_hasher_finalize(
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing HMAC-state handle")
        }
        let holder = Unmanaged<CKHmacStateHolder>.fromOpaque(handle).takeUnretainedValue()
        return ckCopyData(holder.state.finalize(), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HMAC_FAILED, error, errorOut)
    }
}

@_cdecl("ck_hmac_hasher_release")
public func ck_hmac_hasher_release(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else {
        return
    }
    Unmanaged<CKHmacStateHolder>.fromOpaque(handle).release()
}

@_cdecl("ck_hmac_verify")
public func ck_hmac_verify(
    _ algorithm: Int32,
    _ keyBytes: UnsafePointer<UInt8>?,
    _ keyLen: UInt,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: UInt,
    _ codeBytes: UnsafePointer<UInt8>?,
    _ codeLen: UInt,
    _ outValid: UnsafeMutablePointer<UInt8>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let outValid else {
            throw CKBridgeError.invalidArgument("missing HMAC verification output pointer")
        }
        let key = SymmetricKey(data: try ckData(keyBytes, keyLen))
        let message = try ckData(messageBytes, messageLen)
        let code = try ckData(codeBytes, codeLen)
        let isValid: Bool
        switch algorithm {
        case CK_HMAC_SHA256:
            isValid = HMAC<SHA256>.isValidAuthenticationCode(code, authenticating: message, using: key)
        case CK_HMAC_SHA384:
            isValid = HMAC<SHA384>.isValidAuthenticationCode(code, authenticating: message, using: key)
        case CK_HMAC_SHA512:
            isValid = HMAC<SHA512>.isValidAuthenticationCode(code, authenticating: message, using: key)
        default:
            throw CKBridgeError.invalidArgument("unsupported HMAC algorithm: \(algorithm)")
        }
        outValid.pointee = isValid ? 1 : 0
        return CK_OK
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HMAC_FAILED, error, errorOut)
    }
}

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
