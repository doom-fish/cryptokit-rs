import CryptoKit
import Foundation

private func ckSigningPrivateKeyData(_ algorithm: Int32, raw: Data) throws -> Data {
    switch algorithm {
    case CK_SIGNING_P256:
        return try Data(P256.Signing.PrivateKey(rawRepresentation: raw).rawRepresentation)
    case CK_SIGNING_P384:
        return try Data(P384.Signing.PrivateKey(rawRepresentation: raw).rawRepresentation)
    case CK_SIGNING_P521:
        return try Data(P521.Signing.PrivateKey(rawRepresentation: raw).rawRepresentation)
    case CK_SIGNING_ED25519:
        return try Data(Curve25519.Signing.PrivateKey(rawRepresentation: raw).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported signing algorithm: \(algorithm)")
    }
}

private func ckSigningPublicKeyData(_ algorithm: Int32, raw: Data) throws -> Data {
    switch algorithm {
    case CK_SIGNING_P256:
        return try Data(P256.Signing.PublicKey(rawRepresentation: raw).rawRepresentation)
    case CK_SIGNING_P384:
        return try Data(P384.Signing.PublicKey(rawRepresentation: raw).rawRepresentation)
    case CK_SIGNING_P521:
        return try Data(P521.Signing.PublicKey(rawRepresentation: raw).rawRepresentation)
    case CK_SIGNING_ED25519:
        return try Data(Curve25519.Signing.PublicKey(rawRepresentation: raw).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported signing algorithm: \(algorithm)")
    }
}

private func ckSigningPublicKeyFromPrivate(_ algorithm: Int32, privateKey: Data) throws -> Data {
    switch algorithm {
    case CK_SIGNING_P256:
        return try Data(P256.Signing.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation)
    case CK_SIGNING_P384:
        return try Data(P384.Signing.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation)
    case CK_SIGNING_P521:
        return try Data(P521.Signing.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation)
    case CK_SIGNING_ED25519:
        return try Data(Curve25519.Signing.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported signing algorithm: \(algorithm)")
    }
}

private func ckSigningSignature(_ algorithm: Int32, privateKey: Data, message: Data) throws -> Data {
    switch algorithm {
    case CK_SIGNING_P256:
        let key = try P256.Signing.PrivateKey(rawRepresentation: privateKey)
        return try Data(key.signature(for: message).rawRepresentation)
    case CK_SIGNING_P384:
        let key = try P384.Signing.PrivateKey(rawRepresentation: privateKey)
        return try Data(key.signature(for: message).rawRepresentation)
    case CK_SIGNING_P521:
        let key = try P521.Signing.PrivateKey(rawRepresentation: privateKey)
        return try Data(key.signature(for: message).rawRepresentation)
    case CK_SIGNING_ED25519:
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
        return try key.signature(for: message)
    default:
        throw CKBridgeError.invalidArgument("unsupported signing algorithm: \(algorithm)")
    }
}

private func ckVerifySignature(
    _ algorithm: Int32,
    publicKey: Data,
    message: Data,
    signature: Data
) throws -> Bool {
    switch algorithm {
    case CK_SIGNING_P256:
        let key = try P256.Signing.PublicKey(rawRepresentation: publicKey)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        return key.isValidSignature(signature, for: message)
    case CK_SIGNING_P384:
        let key = try P384.Signing.PublicKey(rawRepresentation: publicKey)
        let signature = try P384.Signing.ECDSASignature(rawRepresentation: signature)
        return key.isValidSignature(signature, for: message)
    case CK_SIGNING_P521:
        let key = try P521.Signing.PublicKey(rawRepresentation: publicKey)
        let signature = try P521.Signing.ECDSASignature(rawRepresentation: signature)
        return key.isValidSignature(signature, for: message)
    case CK_SIGNING_ED25519:
        let key = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
        return key.isValidSignature(signature, for: message)
    default:
        throw CKBridgeError.invalidArgument("unsupported signing algorithm: \(algorithm)")
    }
}

private func ckKeyAgreementPrivateKeyData(_ algorithm: Int32, raw: Data) throws -> Data {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        return try Data(P256.KeyAgreement.PrivateKey(rawRepresentation: raw).rawRepresentation)
    case CK_KEY_AGREEMENT_P384:
        return try Data(P384.KeyAgreement.PrivateKey(rawRepresentation: raw).rawRepresentation)
    case CK_KEY_AGREEMENT_P521:
        return try Data(P521.KeyAgreement.PrivateKey(rawRepresentation: raw).rawRepresentation)
    case CK_KEY_AGREEMENT_X25519:
        return try Data(Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported key agreement algorithm: \(algorithm)")
    }
}

private func ckKeyAgreementPublicKeyData(_ algorithm: Int32, raw: Data) throws -> Data {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        return try Data(P256.KeyAgreement.PublicKey(rawRepresentation: raw).rawRepresentation)
    case CK_KEY_AGREEMENT_P384:
        return try Data(P384.KeyAgreement.PublicKey(rawRepresentation: raw).rawRepresentation)
    case CK_KEY_AGREEMENT_P521:
        return try Data(P521.KeyAgreement.PublicKey(rawRepresentation: raw).rawRepresentation)
    case CK_KEY_AGREEMENT_X25519:
        return try Data(Curve25519.KeyAgreement.PublicKey(rawRepresentation: raw).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported key agreement algorithm: \(algorithm)")
    }
}

private func ckKeyAgreementPublicKeyFromPrivate(_ algorithm: Int32, privateKey: Data) throws -> Data {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        return try Data(P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation)
    case CK_KEY_AGREEMENT_P384:
        return try Data(P384.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation)
    case CK_KEY_AGREEMENT_P521:
        return try Data(P521.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation)
    case CK_KEY_AGREEMENT_X25519:
        return try Data(Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey).publicKey.rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported key agreement algorithm: \(algorithm)")
    }
}

private func ckSharedSecret(
    _ algorithm: Int32,
    privateKey: Data,
    publicKey: Data
) throws -> Data {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        let secret = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            .sharedSecretFromKeyAgreement(with: P256.KeyAgreement.PublicKey(rawRepresentation: publicKey))
        return secret.withUnsafeBytes(ckOwnedData)
    case CK_KEY_AGREEMENT_P384:
        let secret = try P384.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            .sharedSecretFromKeyAgreement(with: P384.KeyAgreement.PublicKey(rawRepresentation: publicKey))
        return secret.withUnsafeBytes(ckOwnedData)
    case CK_KEY_AGREEMENT_P521:
        let secret = try P521.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            .sharedSecretFromKeyAgreement(with: P521.KeyAgreement.PublicKey(rawRepresentation: publicKey))
        return secret.withUnsafeBytes(ckOwnedData)
    case CK_KEY_AGREEMENT_X25519:
        let secret = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            .sharedSecretFromKeyAgreement(with: Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey))
        return secret.withUnsafeBytes(ckOwnedData)
    default:
        throw CKBridgeError.invalidArgument("unsupported key agreement algorithm: \(algorithm)")
    }
}

@_cdecl("ck_signing_private_key_generate")
public func ck_signing_private_key_generate(
    _ algorithm: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    let data: Data
    switch algorithm {
    case CK_SIGNING_P256:
        data = Data(P256.Signing.PrivateKey().rawRepresentation)
    case CK_SIGNING_P384:
        data = Data(P384.Signing.PrivateKey().rawRepresentation)
    case CK_SIGNING_P521:
        data = Data(P521.Signing.PrivateKey().rawRepresentation)
    case CK_SIGNING_ED25519:
        data = Data(Curve25519.Signing.PrivateKey().rawRepresentation)
    default:
        return ckInvalidArgument(errorOut, "unsupported signing algorithm: \(algorithm)")
    }
    return ckCopyData(data, outBytes, outLen, errorOut)
}

@_cdecl("ck_signing_private_key_validate")
public func ck_signing_private_key_validate(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        return ckCopyData(try ckSigningPrivateKeyData(algorithm, raw: privateKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_signing_public_key_validate")
public func ck_signing_public_key_validate(
    _ algorithm: Int32,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let publicKey = try ckData(publicKeyBytes, publicKeyLen)
        return ckCopyData(try ckSigningPublicKeyData(algorithm, raw: publicKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_signing_public_key_from_private")
public func ck_signing_public_key_from_private(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        return ckCopyData(try ckSigningPublicKeyFromPrivate(algorithm, privateKey: privateKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_sign")
public func ck_sign(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        let message = try ckData(messageBytes, messageLen)
        return ckCopyData(try ckSigningSignature(algorithm, privateKey: privateKey, message: message), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_SIGNATURE_FAILED, error, errorOut)
    }
}

@_cdecl("ck_verify")
public func ck_verify(
    _ algorithm: Int32,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: UInt,
    _ signatureBytes: UnsafePointer<UInt8>?,
    _ signatureLen: UInt,
    _ outValid: UnsafeMutablePointer<UInt8>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let outValid else {
            throw CKBridgeError.invalidArgument("missing verification output pointer")
        }
        let publicKey = try ckData(publicKeyBytes, publicKeyLen)
        let message = try ckData(messageBytes, messageLen)
        let signature = try ckData(signatureBytes, signatureLen)
        outValid.pointee = try ckVerifySignature(algorithm, publicKey: publicKey, message: message, signature: signature) ? 1 : 0
        return CK_OK
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_SIGNATURE_FAILED, error, errorOut)
    }
}

@_cdecl("ck_key_agreement_private_key_generate")
public func ck_key_agreement_private_key_generate(
    _ algorithm: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    let data: Data
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        data = Data(P256.KeyAgreement.PrivateKey().rawRepresentation)
    case CK_KEY_AGREEMENT_P384:
        data = Data(P384.KeyAgreement.PrivateKey().rawRepresentation)
    case CK_KEY_AGREEMENT_P521:
        data = Data(P521.KeyAgreement.PrivateKey().rawRepresentation)
    case CK_KEY_AGREEMENT_X25519:
        data = Data(Curve25519.KeyAgreement.PrivateKey().rawRepresentation)
    default:
        return ckInvalidArgument(errorOut, "unsupported key agreement algorithm: \(algorithm)")
    }
    return ckCopyData(data, outBytes, outLen, errorOut)
}

@_cdecl("ck_key_agreement_private_key_validate")
public func ck_key_agreement_private_key_validate(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        return ckCopyData(try ckKeyAgreementPrivateKeyData(algorithm, raw: privateKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_key_agreement_public_key_validate")
public func ck_key_agreement_public_key_validate(
    _ algorithm: Int32,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let publicKey = try ckData(publicKeyBytes, publicKeyLen)
        return ckCopyData(try ckKeyAgreementPublicKeyData(algorithm, raw: publicKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_key_agreement_public_key_from_private")
public func ck_key_agreement_public_key_from_private(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        return ckCopyData(try ckKeyAgreementPublicKeyFromPrivate(algorithm, privateKey: privateKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_key_agreement_shared_secret")
public func ck_key_agreement_shared_secret(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        let publicKey = try ckData(publicKeyBytes, publicKeyLen)
        return ckCopyData(try ckSharedSecret(algorithm, privateKey: privateKey, publicKey: publicKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_AGREEMENT_FAILED, error, errorOut)
    }
}
