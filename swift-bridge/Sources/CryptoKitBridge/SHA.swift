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
