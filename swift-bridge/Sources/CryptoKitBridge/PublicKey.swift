import CryptoKit
import Foundation

private let CK_ECDSA_SIGNATURE_RAW: Int32 = 1
private let CK_ECDSA_SIGNATURE_DER: Int32 = 2

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

private func ckEcdsaRawSignature(
    _ algorithm: Int32,
    format: Int32,
    signature: Data
) throws -> Data {
    switch algorithm {
    case CK_SIGNING_P256:
        switch format {
        case CK_ECDSA_SIGNATURE_RAW:
            return try Data(P256.Signing.ECDSASignature(rawRepresentation: signature).rawRepresentation)
        case CK_ECDSA_SIGNATURE_DER:
            return try Data(P256.Signing.ECDSASignature(derRepresentation: signature).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported ECDSA signature format: \(format)")
        }
    case CK_SIGNING_P384:
        switch format {
        case CK_ECDSA_SIGNATURE_RAW:
            return try Data(P384.Signing.ECDSASignature(rawRepresentation: signature).rawRepresentation)
        case CK_ECDSA_SIGNATURE_DER:
            return try Data(P384.Signing.ECDSASignature(derRepresentation: signature).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported ECDSA signature format: \(format)")
        }
    case CK_SIGNING_P521:
        switch format {
        case CK_ECDSA_SIGNATURE_RAW:
            return try Data(P521.Signing.ECDSASignature(rawRepresentation: signature).rawRepresentation)
        case CK_ECDSA_SIGNATURE_DER:
            return try Data(P521.Signing.ECDSASignature(derRepresentation: signature).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported ECDSA signature format: \(format)")
        }
    default:
        throw CKBridgeError.invalidArgument("ECDSA signatures are unsupported for algorithm: \(algorithm)")
    }
}

private func ckEcdsaSignatureRepresentation(
    _ algorithm: Int32,
    format: Int32,
    rawSignature: Data
) throws -> Data {
    switch algorithm {
    case CK_SIGNING_P256:
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: rawSignature)
        switch format {
        case CK_ECDSA_SIGNATURE_RAW:
            return Data(signature.rawRepresentation)
        case CK_ECDSA_SIGNATURE_DER:
            return signature.derRepresentation
        default:
            throw CKBridgeError.invalidArgument("unsupported ECDSA signature format: \(format)")
        }
    case CK_SIGNING_P384:
        let signature = try P384.Signing.ECDSASignature(rawRepresentation: rawSignature)
        switch format {
        case CK_ECDSA_SIGNATURE_RAW:
            return Data(signature.rawRepresentation)
        case CK_ECDSA_SIGNATURE_DER:
            return signature.derRepresentation
        default:
            throw CKBridgeError.invalidArgument("unsupported ECDSA signature format: \(format)")
        }
    case CK_SIGNING_P521:
        let signature = try P521.Signing.ECDSASignature(rawRepresentation: rawSignature)
        switch format {
        case CK_ECDSA_SIGNATURE_RAW:
            return Data(signature.rawRepresentation)
        case CK_ECDSA_SIGNATURE_DER:
            return signature.derRepresentation
        default:
            throw CKBridgeError.invalidArgument("unsupported ECDSA signature format: \(format)")
        }
    default:
        throw CKBridgeError.invalidArgument("ECDSA signatures are unsupported for algorithm: \(algorithm)")
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

private func ckPemString(_ data: Data) throws -> String {
    guard let pem = String(data: data, encoding: .utf8) else {
        throw CKBridgeError.invalidArgument("PEM data must be valid UTF-8")
    }
    return pem
}

private func ckPemData(_ string: String) -> Data {
    Data(string.utf8)
}

private func ckSigningPrivateKeyGenerate(_ algorithm: Int32, compactRepresentable: Bool) throws -> Data {
    switch algorithm {
    case CK_SIGNING_P256:
        return Data(P256.Signing.PrivateKey(compactRepresentable: compactRepresentable).rawRepresentation)
    case CK_SIGNING_P384:
        return Data(P384.Signing.PrivateKey(compactRepresentable: compactRepresentable).rawRepresentation)
    case CK_SIGNING_P521:
        return Data(P521.Signing.PrivateKey(compactRepresentable: compactRepresentable).rawRepresentation)
    case CK_SIGNING_ED25519:
        guard compactRepresentable else {
            throw CKBridgeError.invalidArgument("compactRepresentable is unsupported for Ed25519")
        }
        return Data(Curve25519.Signing.PrivateKey().rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported signing algorithm: \(algorithm)")
    }
}

private func ckSigningPrivateKeyFromRepresentation(
    _ algorithm: Int32,
    format: Int32,
    input: Data
) throws -> Data {
    switch algorithm {
    case CK_SIGNING_P256:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P256.Signing.PrivateKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P256.Signing.PrivateKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P256.Signing.PrivateKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P256.Signing.PrivateKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing private-key representation: \(format)")
        }
    case CK_SIGNING_P384:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P384.Signing.PrivateKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P384.Signing.PrivateKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P384.Signing.PrivateKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P384.Signing.PrivateKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing private-key representation: \(format)")
        }
    case CK_SIGNING_P521:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P521.Signing.PrivateKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P521.Signing.PrivateKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P521.Signing.PrivateKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P521.Signing.PrivateKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing private-key representation: \(format)")
        }
    case CK_SIGNING_ED25519:
        guard format == CK_KEY_FORMAT_RAW else {
            throw CKBridgeError.invalidArgument("only raw Ed25519 private-key representations are supported")
        }
        return try Data(Curve25519.Signing.PrivateKey(rawRepresentation: input).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported signing algorithm: \(algorithm)")
    }
}

private func ckSigningPrivateKeyRepresentation(
    _ algorithm: Int32,
    rawPrivateKey: Data,
    format: Int32
) throws -> Data {
    switch algorithm {
    case CK_SIGNING_P256:
        let key = try P256.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing private-key representation: \(format)")
        }
    case CK_SIGNING_P384:
        let key = try P384.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing private-key representation: \(format)")
        }
    case CK_SIGNING_P521:
        let key = try P521.Signing.PrivateKey(rawRepresentation: rawPrivateKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing private-key representation: \(format)")
        }
    case CK_SIGNING_ED25519:
        guard format == CK_KEY_FORMAT_RAW else {
            throw CKBridgeError.invalidArgument("only raw Ed25519 private-key representations are supported")
        }
        return try Data(Curve25519.Signing.PrivateKey(rawRepresentation: rawPrivateKey).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported signing algorithm: \(algorithm)")
    }
}

private func ckSigningPublicKeyFromRepresentation(
    _ algorithm: Int32,
    format: Int32,
    input: Data
) throws -> Data {
    switch algorithm {
    case CK_SIGNING_P256:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P256.Signing.PublicKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return try Data(P256.Signing.PublicKey(compactRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P256.Signing.PublicKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return try Data(P256.Signing.PublicKey(compressedRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P256.Signing.PublicKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P256.Signing.PublicKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing public-key representation: \(format)")
        }
    case CK_SIGNING_P384:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P384.Signing.PublicKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return try Data(P384.Signing.PublicKey(compactRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P384.Signing.PublicKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return try Data(P384.Signing.PublicKey(compressedRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P384.Signing.PublicKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P384.Signing.PublicKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing public-key representation: \(format)")
        }
    case CK_SIGNING_P521:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P521.Signing.PublicKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return try Data(P521.Signing.PublicKey(compactRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P521.Signing.PublicKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return try Data(P521.Signing.PublicKey(compressedRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P521.Signing.PublicKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P521.Signing.PublicKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing public-key representation: \(format)")
        }
    case CK_SIGNING_ED25519:
        guard format == CK_KEY_FORMAT_RAW else {
            throw CKBridgeError.invalidArgument("only raw Ed25519 public-key representations are supported")
        }
        return try Data(Curve25519.Signing.PublicKey(rawRepresentation: input).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported signing algorithm: \(algorithm)")
    }
}

private func ckSigningPublicKeyRepresentation(
    _ algorithm: Int32,
    rawPublicKey: Data,
    format: Int32
) throws -> Data? {
    switch algorithm {
    case CK_SIGNING_P256:
        let key = try P256.Signing.PublicKey(rawRepresentation: rawPublicKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return key.compactRepresentation
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return Data(key.compressedRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing public-key representation: \(format)")
        }
    case CK_SIGNING_P384:
        let key = try P384.Signing.PublicKey(rawRepresentation: rawPublicKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return key.compactRepresentation
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return Data(key.compressedRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing public-key representation: \(format)")
        }
    case CK_SIGNING_P521:
        let key = try P521.Signing.PublicKey(rawRepresentation: rawPublicKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return key.compactRepresentation
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return Data(key.compressedRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported signing public-key representation: \(format)")
        }
    case CK_SIGNING_ED25519:
        guard format == CK_KEY_FORMAT_RAW else {
            throw CKBridgeError.invalidArgument("only raw Ed25519 public-key representations are supported")
        }
        return try Data(Curve25519.Signing.PublicKey(rawRepresentation: rawPublicKey).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported signing algorithm: \(algorithm)")
    }
}

private func ckKeyAgreementPrivateKeyGenerate(_ algorithm: Int32, compactRepresentable: Bool) throws -> Data {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        return Data(P256.KeyAgreement.PrivateKey(compactRepresentable: compactRepresentable).rawRepresentation)
    case CK_KEY_AGREEMENT_P384:
        return Data(P384.KeyAgreement.PrivateKey(compactRepresentable: compactRepresentable).rawRepresentation)
    case CK_KEY_AGREEMENT_P521:
        return Data(P521.KeyAgreement.PrivateKey(compactRepresentable: compactRepresentable).rawRepresentation)
    case CK_KEY_AGREEMENT_X25519:
        guard compactRepresentable else {
            throw CKBridgeError.invalidArgument("compactRepresentable is unsupported for X25519")
        }
        return Data(Curve25519.KeyAgreement.PrivateKey().rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported key agreement algorithm: \(algorithm)")
    }
}

private func ckKeyAgreementPrivateKeyFromRepresentation(
    _ algorithm: Int32,
    format: Int32,
    input: Data
) throws -> Data {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P256.KeyAgreement.PrivateKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P256.KeyAgreement.PrivateKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P256.KeyAgreement.PrivateKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P256.KeyAgreement.PrivateKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement private-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_P384:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P384.KeyAgreement.PrivateKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P384.KeyAgreement.PrivateKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P384.KeyAgreement.PrivateKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P384.KeyAgreement.PrivateKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement private-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_P521:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P521.KeyAgreement.PrivateKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P521.KeyAgreement.PrivateKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P521.KeyAgreement.PrivateKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P521.KeyAgreement.PrivateKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement private-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_X25519:
        guard format == CK_KEY_FORMAT_RAW else {
            throw CKBridgeError.invalidArgument("only raw X25519 private-key representations are supported")
        }
        return try Data(Curve25519.KeyAgreement.PrivateKey(rawRepresentation: input).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported key agreement algorithm: \(algorithm)")
    }
}

private func ckKeyAgreementPrivateKeyRepresentation(
    _ algorithm: Int32,
    rawPrivateKey: Data,
    format: Int32
) throws -> Data {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: rawPrivateKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement private-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_P384:
        let key = try P384.KeyAgreement.PrivateKey(rawRepresentation: rawPrivateKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement private-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_P521:
        let key = try P521.KeyAgreement.PrivateKey(rawRepresentation: rawPrivateKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement private-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_X25519:
        guard format == CK_KEY_FORMAT_RAW else {
            throw CKBridgeError.invalidArgument("only raw X25519 private-key representations are supported")
        }
        return try Data(Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawPrivateKey).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported key agreement algorithm: \(algorithm)")
    }
}

private func ckKeyAgreementPublicKeyFromRepresentation(
    _ algorithm: Int32,
    format: Int32,
    input: Data
) throws -> Data {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P256.KeyAgreement.PublicKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return try Data(P256.KeyAgreement.PublicKey(compactRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P256.KeyAgreement.PublicKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return try Data(P256.KeyAgreement.PublicKey(compressedRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P256.KeyAgreement.PublicKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P256.KeyAgreement.PublicKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement public-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_P384:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P384.KeyAgreement.PublicKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return try Data(P384.KeyAgreement.PublicKey(compactRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P384.KeyAgreement.PublicKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return try Data(P384.KeyAgreement.PublicKey(compressedRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P384.KeyAgreement.PublicKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P384.KeyAgreement.PublicKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement public-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_P521:
        switch format {
        case CK_KEY_FORMAT_RAW:
            return try Data(P521.KeyAgreement.PublicKey(rawRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return try Data(P521.KeyAgreement.PublicKey(compactRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_X963:
            return try Data(P521.KeyAgreement.PublicKey(x963Representation: input).rawRepresentation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return try Data(P521.KeyAgreement.PublicKey(compressedRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return try Data(P521.KeyAgreement.PublicKey(derRepresentation: input).rawRepresentation)
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return try Data(P521.KeyAgreement.PublicKey(pemRepresentation: ckPemString(input)).rawRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement public-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_X25519:
        guard format == CK_KEY_FORMAT_RAW else {
            throw CKBridgeError.invalidArgument("only raw X25519 public-key representations are supported")
        }
        return try Data(Curve25519.KeyAgreement.PublicKey(rawRepresentation: input).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported key agreement algorithm: \(algorithm)")
    }
}

private func ckKeyAgreementPublicKeyRepresentation(
    _ algorithm: Int32,
    rawPublicKey: Data,
    format: Int32
) throws -> Data? {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        let key = try P256.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return key.compactRepresentation
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return Data(key.compressedRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement public-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_P384:
        let key = try P384.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return key.compactRepresentation
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return Data(key.compressedRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement public-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_P521:
        let key = try P521.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey)
        switch format {
        case CK_KEY_FORMAT_RAW:
            return Data(key.rawRepresentation)
        case CK_KEY_FORMAT_COMPACT:
            return key.compactRepresentation
        case CK_KEY_FORMAT_X963:
            return Data(key.x963Representation)
        case CK_KEY_FORMAT_COMPRESSED:
            guard #available(macOS 13.0, *) else {
                throw CKBridgeError.invalidArgument("compressed key representations require macOS 13.0 or newer")
            }
            return Data(key.compressedRepresentation)
        case CK_KEY_FORMAT_DER:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("DER key representations require macOS 11.0 or newer")
            }
            return key.derRepresentation
        case CK_KEY_FORMAT_PEM:
            guard #available(macOS 11.0, *) else {
                throw CKBridgeError.invalidArgument("PEM key representations require macOS 11.0 or newer")
            }
            return ckPemData(key.pemRepresentation)
        default:
            throw CKBridgeError.invalidArgument("unsupported key-agreement public-key representation: \(format)")
        }
    case CK_KEY_AGREEMENT_X25519:
        guard format == CK_KEY_FORMAT_RAW else {
            throw CKBridgeError.invalidArgument("only raw X25519 public-key representations are supported")
        }
        return try Data(Curve25519.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported key agreement algorithm: \(algorithm)")
    }
}

@_cdecl("ck_signing_private_key_generate_with_options")
public func ck_signing_private_key_generate_with_options(
    _ algorithm: Int32,
    _ compactRepresentable: UInt8,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        return ckCopyData(
            try ckSigningPrivateKeyGenerate(algorithm, compactRepresentable: compactRepresentable != 0),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_signing_private_key_from_representation")
public func ck_signing_private_key_from_representation(
    _ algorithm: Int32,
    _ format: Int32,
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let input = try ckData(inputBytes, inputLen)
        return ckCopyData(
            try ckSigningPrivateKeyFromRepresentation(algorithm, format: format, input: input),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_signing_private_key_representation")
public func ck_signing_private_key_representation(
    _ algorithm: Int32,
    _ rawPrivateKeyBytes: UnsafePointer<UInt8>?,
    _ rawPrivateKeyLen: UInt,
    _ format: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let rawPrivateKey = try ckData(rawPrivateKeyBytes, rawPrivateKeyLen)
        return ckCopyData(
            try ckSigningPrivateKeyRepresentation(algorithm, rawPrivateKey: rawPrivateKey, format: format),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_signing_public_key_from_representation")
public func ck_signing_public_key_from_representation(
    _ algorithm: Int32,
    _ format: Int32,
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let input = try ckData(inputBytes, inputLen)
        return ckCopyData(
            try ckSigningPublicKeyFromRepresentation(algorithm, format: format, input: input),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_signing_public_key_representation")
public func ck_signing_public_key_representation(
    _ algorithm: Int32,
    _ rawPublicKeyBytes: UnsafePointer<UInt8>?,
    _ rawPublicKeyLen: UInt,
    _ format: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let rawPublicKey = try ckData(rawPublicKeyBytes, rawPublicKeyLen)
        return ckCopyOptionalData(
            try ckSigningPublicKeyRepresentation(algorithm, rawPublicKey: rawPublicKey, format: format),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_key_agreement_private_key_generate_with_options")
public func ck_key_agreement_private_key_generate_with_options(
    _ algorithm: Int32,
    _ compactRepresentable: UInt8,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        return ckCopyData(
            try ckKeyAgreementPrivateKeyGenerate(algorithm, compactRepresentable: compactRepresentable != 0),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_key_agreement_private_key_from_representation")
public func ck_key_agreement_private_key_from_representation(
    _ algorithm: Int32,
    _ format: Int32,
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let input = try ckData(inputBytes, inputLen)
        return ckCopyData(
            try ckKeyAgreementPrivateKeyFromRepresentation(algorithm, format: format, input: input),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_key_agreement_private_key_representation")
public func ck_key_agreement_private_key_representation(
    _ algorithm: Int32,
    _ rawPrivateKeyBytes: UnsafePointer<UInt8>?,
    _ rawPrivateKeyLen: UInt,
    _ format: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let rawPrivateKey = try ckData(rawPrivateKeyBytes, rawPrivateKeyLen)
        return ckCopyData(
            try ckKeyAgreementPrivateKeyRepresentation(algorithm, rawPrivateKey: rawPrivateKey, format: format),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_key_agreement_public_key_from_representation")
public func ck_key_agreement_public_key_from_representation(
    _ algorithm: Int32,
    _ format: Int32,
    _ inputBytes: UnsafePointer<UInt8>?,
    _ inputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let input = try ckData(inputBytes, inputLen)
        return ckCopyData(
            try ckKeyAgreementPublicKeyFromRepresentation(algorithm, format: format, input: input),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_key_agreement_public_key_representation")
public func ck_key_agreement_public_key_representation(
    _ algorithm: Int32,
    _ rawPublicKeyBytes: UnsafePointer<UInt8>?,
    _ rawPublicKeyLen: UInt,
    _ format: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let rawPublicKey = try ckData(rawPublicKeyBytes, rawPublicKeyLen)
        return ckCopyOptionalData(
            try ckKeyAgreementPublicKeyRepresentation(algorithm, rawPublicKey: rawPublicKey, format: format),
            outBytes,
            outLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
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

@_cdecl("ck_ecdsa_signature_validate")
public func ck_ecdsa_signature_validate(
    _ algorithm: Int32,
    _ format: Int32,
    _ signatureBytes: UnsafePointer<UInt8>?,
    _ signatureLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let signature = try ckData(signatureBytes, signatureLen)
        return ckCopyData(try ckEcdsaRawSignature(algorithm, format: format, signature: signature), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_SIGNATURE_FAILED, error, errorOut)
    }
}

@_cdecl("ck_ecdsa_signature_representation")
public func ck_ecdsa_signature_representation(
    _ algorithm: Int32,
    _ rawSignatureBytes: UnsafePointer<UInt8>?,
    _ rawSignatureLen: UInt,
    _ format: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        let rawSignature = try ckData(rawSignatureBytes, rawSignatureLen)
        return ckCopyData(try ckEcdsaSignatureRepresentation(algorithm, format: format, rawSignature: rawSignature), outBytes, outLen, errorOut)
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
