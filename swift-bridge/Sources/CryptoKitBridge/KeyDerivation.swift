import CryptoKit
import Foundation

private func ckKeyDerivationDigestLength(_ algorithm: Int32) throws -> Int {
    switch algorithm {
    case CK_HASH_SHA256:
        return 32
    case CK_HASH_SHA384:
        return 48
    case CK_HASH_SHA512:
        return 64
    default:
        throw CKBridgeError.invalidArgument("unsupported key-derivation digest algorithm: \(algorithm)")
    }
}

private func ckKeyDerivationHmac(
    _ algorithm: Int32,
    key: Data,
    message: Data
) throws -> Data {
    let symmetricKey = SymmetricKey(data: key)
    switch algorithm {
    case CK_HASH_SHA256:
        return Data(Array(HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey)))
    case CK_HASH_SHA384:
        return Data(Array(HMAC<SHA384>.authenticationCode(for: message, using: symmetricKey)))
    case CK_HASH_SHA512:
        return Data(Array(HMAC<SHA512>.authenticationCode(for: message, using: symmetricKey)))
    default:
        throw CKBridgeError.invalidArgument("unsupported key-derivation HMAC algorithm: \(algorithm)")
    }
}

private func ckKeyDerivationDigest(
    _ algorithm: Int32,
    data: Data
) throws -> Data {
    switch algorithm {
    case CK_HASH_SHA256:
        return Data(Array(SHA256.hash(data: data)))
    case CK_HASH_SHA384:
        return Data(Array(SHA384.hash(data: data)))
    case CK_HASH_SHA512:
        return Data(Array(SHA512.hash(data: data)))
    default:
        throw CKBridgeError.invalidArgument("unsupported key-derivation digest algorithm: \(algorithm)")
    }
}

private func ckSharedSecretHkdf(
    _ algorithm: Int32,
    sharedSecret: Data,
    salt: Data,
    info: Data,
    outputLen: Int
) throws -> Data {
    guard outputLen > 0 else {
        throw CKBridgeError.invalidArgument("derived key length must be greater than zero")
    }

    let digestLength = try ckKeyDerivationDigestLength(algorithm)
    let effectiveSalt = salt.isEmpty ? Data(repeating: 0, count: digestLength) : salt
    let pseudorandomKey = try ckKeyDerivationHmac(algorithm, key: effectiveSalt, message: sharedSecret)

    var output = Data()
    var previousBlock = Data()
    var counter: UInt8 = 1

    while output.count < outputLen {
        var blockInput = Data()
        blockInput.append(previousBlock)
        blockInput.append(info)
        blockInput.append(contentsOf: [counter])
        previousBlock = try ckKeyDerivationHmac(algorithm, key: pseudorandomKey, message: blockInput)
        output.append(previousBlock)
        counter &+= 1
    }

    return output.prefix(outputLen)
}

private func ckSharedSecretX963(
    _ algorithm: Int32,
    sharedSecret: Data,
    sharedInfo: Data,
    outputLen: Int
) throws -> Data {
    guard outputLen > 0 else {
        throw CKBridgeError.invalidArgument("derived key length must be greater than zero")
    }

    var output = Data()
    var counter: UInt32 = 1
    while output.count < outputLen {
        var digestInput = Data()
        digestInput.append(sharedSecret)
        var counterBigEndian = counter.bigEndian
        withUnsafeBytes(of: &counterBigEndian) { digestInput.append(contentsOf: $0) }
        digestInput.append(sharedInfo)
        output.append(try ckKeyDerivationDigest(algorithm, data: digestInput))
        counter &+= 1
    }
    return output.prefix(outputLen)
}

private func ckCopySharedSecretDerivation(
    _ data: Data,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    ckCopyData(data, outBytes, outLen, errorOut)
}

private func ckSharedSecretHkdfExport(
    _ algorithm: Int32,
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
        return ckCopySharedSecretDerivation(
            try ckSharedSecretHkdf(algorithm, sharedSecret: secret, salt: salt, info: info, outputLen: Int(outputLen)),
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

private func ckSharedSecretX963Export(
    _ algorithm: Int32,
    _ secretBytes: UnsafePointer<UInt8>?,
    _ secretLen: UInt,
    _ sharedInfoBytes: UnsafePointer<UInt8>?,
    _ sharedInfoLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let secret = try ckData(secretBytes, secretLen)
        let sharedInfo = try ckData(sharedInfoBytes, sharedInfoLen)
        return ckCopySharedSecretDerivation(
            try ckSharedSecretX963(algorithm, sharedSecret: secret, sharedInfo: sharedInfo, outputLen: Int(outputLen)),
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
    ckSharedSecretHkdfExport(
        CK_HASH_SHA256,
        secretBytes,
        secretLen,
        saltBytes,
        saltLen,
        infoBytes,
        infoLen,
        outputLen,
        outBytes,
        outLen,
        errorOut
    )
}

@_cdecl("ck_shared_secret_hkdf_sha384")
public func ck_shared_secret_hkdf_sha384(
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
    ckSharedSecretHkdfExport(
        CK_HASH_SHA384,
        secretBytes,
        secretLen,
        saltBytes,
        saltLen,
        infoBytes,
        infoLen,
        outputLen,
        outBytes,
        outLen,
        errorOut
    )
}

@_cdecl("ck_shared_secret_hkdf_sha512")
public func ck_shared_secret_hkdf_sha512(
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
    ckSharedSecretHkdfExport(
        CK_HASH_SHA512,
        secretBytes,
        secretLen,
        saltBytes,
        saltLen,
        infoBytes,
        infoLen,
        outputLen,
        outBytes,
        outLen,
        errorOut
    )
}

@_cdecl("ck_shared_secret_x963_sha256")
public func ck_shared_secret_x963_sha256(
    _ secretBytes: UnsafePointer<UInt8>?,
    _ secretLen: UInt,
    _ sharedInfoBytes: UnsafePointer<UInt8>?,
    _ sharedInfoLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    ckSharedSecretX963Export(
        CK_HASH_SHA256,
        secretBytes,
        secretLen,
        sharedInfoBytes,
        sharedInfoLen,
        outputLen,
        outBytes,
        outLen,
        errorOut
    )
}

@_cdecl("ck_shared_secret_x963_sha384")
public func ck_shared_secret_x963_sha384(
    _ secretBytes: UnsafePointer<UInt8>?,
    _ secretLen: UInt,
    _ sharedInfoBytes: UnsafePointer<UInt8>?,
    _ sharedInfoLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    ckSharedSecretX963Export(
        CK_HASH_SHA384,
        secretBytes,
        secretLen,
        sharedInfoBytes,
        sharedInfoLen,
        outputLen,
        outBytes,
        outLen,
        errorOut
    )
}

@_cdecl("ck_shared_secret_x963_sha512")
public func ck_shared_secret_x963_sha512(
    _ secretBytes: UnsafePointer<UInt8>?,
    _ secretLen: UInt,
    _ sharedInfoBytes: UnsafePointer<UInt8>?,
    _ sharedInfoLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    ckSharedSecretX963Export(
        CK_HASH_SHA512,
        secretBytes,
        secretLen,
        sharedInfoBytes,
        sharedInfoLen,
        outputLen,
        outBytes,
        outLen,
        errorOut
    )
}
