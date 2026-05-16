import CryptoKit
import Foundation

@available(macOS 26.0, *)
private protocol CKSHA3HashState: AnyObject {
    func update(_ data: Data)
    func finalize() -> Data
}

@available(macOS 26.0, *)
private final class CKSHA3_256State: CKSHA3HashState {
    private var hasher = SHA3_256()

    func update(_ data: Data) {
        data.withUnsafeBytes { hasher.update(bufferPointer: $0) }
    }

    func finalize() -> Data {
        Data(Array(hasher.finalize()))
    }
}

@available(macOS 26.0, *)
private final class CKSHA3_384State: CKSHA3HashState {
    private var hasher = SHA3_384()

    func update(_ data: Data) {
        data.withUnsafeBytes { hasher.update(bufferPointer: $0) }
    }

    func finalize() -> Data {
        Data(Array(hasher.finalize()))
    }
}

@available(macOS 26.0, *)
private final class CKSHA3_512State: CKSHA3HashState {
    private var hasher = SHA3_512()

    func update(_ data: Data) {
        data.withUnsafeBytes { hasher.update(bufferPointer: $0) }
    }

    func finalize() -> Data {
        Data(Array(hasher.finalize()))
    }
}

@available(macOS 26.0, *)
private final class CKSHA3StateHolder {
    let state: any CKSHA3HashState

    init(_ state: any CKSHA3HashState) {
        self.state = state
    }
}

@available(macOS 26.0, *)
private func ckSHA3Digest(_ algorithm: Int32, data: Data) throws -> Data {
    switch algorithm {
    case CK_SHA3_256:
        return Data(Array(SHA3_256.hash(data: data)))
    case CK_SHA3_384:
        return Data(Array(SHA3_384.hash(data: data)))
    case CK_SHA3_512:
        return Data(Array(SHA3_512.hash(data: data)))
    default:
        throw CKBridgeError.invalidArgument("unsupported SHA-3 algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSHA3StateHolder(_ algorithm: Int32) throws -> CKSHA3StateHolder {
    switch algorithm {
    case CK_SHA3_256:
        return CKSHA3StateHolder(CKSHA3_256State())
    case CK_SHA3_384:
        return CKSHA3StateHolder(CKSHA3_384State())
    case CK_SHA3_512:
        return CKSHA3StateHolder(CKSHA3_512State())
    default:
        throw CKBridgeError.invalidArgument("unsupported SHA-3 algorithm: \(algorithm)")
    }
}

@_cdecl("ck_sha3_hash")
public func ck_sha3_hash(
    _ algorithm: Int32,
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "SHA-3 requires macOS 26.0 or newer")
    }

    do {
        let input = try ckData(inputBytes, inputLen)
        return ckCopyData(try ckSHA3Digest(algorithm, data: input), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HASHING_FAILED, error, errorOut)
    }
}

@_cdecl("ck_sha3_hasher_create")
public func ck_sha3_hasher_create(
    _ algorithm: Int32,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "SHA-3 requires macOS 26.0 or newer")
        return nil
    }

    do {
        return Unmanaged.passRetained(try ckSHA3StateHolder(algorithm)).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_sha3_hasher_update")
public func ck_sha3_hasher_update(
    _ handle: UnsafeMutableRawPointer?,
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "SHA-3 requires macOS 26.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing SHA-3 state handle")
        }
        let input = try ckData(inputBytes, inputLen)
        let holder = Unmanaged<CKSHA3StateHolder>.fromOpaque(handle).takeUnretainedValue()
        holder.state.update(input)
        return CK_OK
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HASHING_FAILED, error, errorOut)
    }
}

@_cdecl("ck_sha3_hasher_finalize")
public func ck_sha3_hasher_finalize(
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "SHA-3 requires macOS 26.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing SHA-3 state handle")
        }
        let holder = Unmanaged<CKSHA3StateHolder>.fromOpaque(handle).takeUnretainedValue()
        return ckCopyData(holder.state.finalize(), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_HASHING_FAILED, error, errorOut)
    }
}

@_cdecl("ck_sha3_hasher_release")
public func ck_sha3_hasher_release(_ handle: UnsafeMutableRawPointer?) {
    guard #available(macOS 26.0, *), let handle else {
        return
    }
    Unmanaged<CKSHA3StateHolder>.fromOpaque(handle).release()
}
