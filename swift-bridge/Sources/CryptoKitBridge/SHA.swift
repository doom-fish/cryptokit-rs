import CryptoKit
import Foundation

private func ckCopyDigest(
    _ data: Data,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    ckCopyData(data, outBytes, outLen, errorOut)
}

private protocol CKHashStateProtocol: AnyObject {
    func update(_ data: Data)
    func finalize() -> Data
}

private final class CKHashState<H: HashFunction>: CKHashStateProtocol {
    private var hasher = H()

    func update(_ data: Data) {
        hasher.update(data: data)
    }

    func finalize() -> Data {
        Data(Array(hasher.finalize()))
    }
}

private final class CKHashStateHolder {
    let state: any CKHashStateProtocol

    init(_ state: any CKHashStateProtocol) {
        self.state = state
    }
}

private func ckHashStateHolder(_ algorithm: Int32) throws -> CKHashStateHolder {
    switch algorithm {
    case CK_HASH_SHA256:
        return CKHashStateHolder(CKHashState<SHA256>())
    case CK_HASH_SHA384:
        return CKHashStateHolder(CKHashState<SHA384>())
    case CK_HASH_SHA512:
        return CKHashStateHolder(CKHashState<SHA512>())
    case CK_HASH_MD5:
        return CKHashStateHolder(CKHashState<Insecure.MD5>())
    case CK_HASH_SHA1:
        return CKHashStateHolder(CKHashState<Insecure.SHA1>())
    default:
        throw CKBridgeError.invalidArgument("unsupported hash algorithm: \(algorithm)")
    }
}

@_cdecl("ck_hash_hasher_create")
public func ck_hash_hasher_create(
    _ algorithm: Int32,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        return Unmanaged.passRetained(try ckHashStateHolder(algorithm)).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_hash_hasher_update")
public func ck_hash_hasher_update(
    _ handle: UnsafeMutableRawPointer?,
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing hash-state handle")
        }
        let holder = Unmanaged<CKHashStateHolder>.fromOpaque(handle).takeUnretainedValue()
        holder.state.update(try ckData(inputBytes, inputLen))
        return CK_OK
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HASHING_FAILED, error, errorOut)
    }
}

@_cdecl("ck_hash_hasher_finalize")
public func ck_hash_hasher_finalize(
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing hash-state handle")
        }
        let holder = Unmanaged<CKHashStateHolder>.fromOpaque(handle).takeUnretainedValue()
        return ckCopyData(holder.state.finalize(), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HASHING_FAILED, error, errorOut)
    }
}

@_cdecl("ck_hash_hasher_release")
public func ck_hash_hasher_release(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else {
        return
    }
    Unmanaged<CKHashStateHolder>.fromOpaque(handle).release()
}

@_cdecl("ck_sha256")
public func ck_sha256(
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let input = try ckData(inputBytes, inputLen)
        return ckCopyDigest(Data(Array(SHA256.hash(data: input))), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HASHING_FAILED, error, errorOut)
    }
}

@_cdecl("ck_sha384")
public func ck_sha384(
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let input = try ckData(inputBytes, inputLen)
        return ckCopyDigest(Data(Array(SHA384.hash(data: input))), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HASHING_FAILED, error, errorOut)
    }
}

@_cdecl("ck_sha512")
public func ck_sha512(
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let input = try ckData(inputBytes, inputLen)
        return ckCopyDigest(Data(Array(SHA512.hash(data: input))), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HASHING_FAILED, error, errorOut)
    }
}
