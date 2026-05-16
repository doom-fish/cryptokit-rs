import CryptoKit
import Foundation

@available(macOS 14.0, *)
private final class CKHPKESenderHolder {
    var sender: HPKE.Sender

    init(_ sender: HPKE.Sender) {
        self.sender = sender
    }
}

@available(macOS 14.0, *)
private final class CKHPKERecipientHolder {
    var recipient: HPKE.Recipient

    init(_ recipient: HPKE.Recipient) {
        self.recipient = recipient
    }
}

@available(macOS 14.0, *)
private func ckHpkeKem(_ kem: Int32) throws -> HPKE.KEM {
    switch kem {
    case CK_HPKE_KEM_P256_HKDF_SHA256:
        return .P256_HKDF_SHA256
    case CK_HPKE_KEM_P384_HKDF_SHA384:
        return .P384_HKDF_SHA384
    case CK_HPKE_KEM_P521_HKDF_SHA512:
        return .P521_HKDF_SHA512
    case CK_HPKE_KEM_CURVE25519_HKDF_SHA256:
        return .Curve25519_HKDF_SHA256
    case CK_HPKE_KEM_XWING_MLKEM768_X25519:
        guard #available(macOS 26.0, *) else {
            throw CKBridgeError.invalidArgument("X-Wing HPKE requires macOS 26.0 or newer")
        }
        return .XWingMLKEM768X25519
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE KEM: \(kem)")
    }
}

@available(macOS 14.0, *)
private func ckHpkeKdf(_ kdf: Int32) throws -> HPKE.KDF {
    switch kdf {
    case CK_HPKE_KDF_SHA256:
        return .HKDF_SHA256
    case CK_HPKE_KDF_SHA384:
        return .HKDF_SHA384
    case CK_HPKE_KDF_SHA512:
        return .HKDF_SHA512
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE KDF: \(kdf)")
    }
}

@available(macOS 14.0, *)
private func ckHpkeAead(_ aead: Int32) throws -> HPKE.AEAD {
    switch aead {
    case CK_HPKE_AEAD_AES_GCM_128:
        return .AES_GCM_128
    case CK_HPKE_AEAD_AES_GCM_256:
        return .AES_GCM_256
    case CK_HPKE_AEAD_CHACHA_POLY:
        return .chaChaPoly
    case CK_HPKE_AEAD_EXPORT_ONLY:
        return .exportOnly
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE AEAD: \(aead)")
    }
}

@available(macOS 14.0, *)
private func ckHpkeCiphersuite(kem: Int32, kdf: Int32, aead: Int32) throws -> HPKE.Ciphersuite {
    HPKE.Ciphersuite(kem: try ckHpkeKem(kem), kdf: try ckHpkeKdf(kdf), aead: try ckHpkeAead(aead))
}

@available(macOS 14.0, *)
private func ckHpkeSymmetricKey(_ bytes: Data) -> SymmetricKey {
    SymmetricKey(data: bytes)
}

@available(macOS 14.0, *)
private func ckHpkeExportedSecret(_ key: SymmetricKey) -> Data {
    key.withUnsafeBytes(ckOwnedData)
}

@available(macOS 14.0, *)
private func ckHpkeDhPublicKeyFromSerialization(
    _ algorithm: Int32,
    serialization: Data,
    kem: HPKE.KEM
) throws -> Data {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        return try Data(P256.KeyAgreement.PublicKey(serialization, kem: kem).rawRepresentation)
    case CK_KEY_AGREEMENT_P384:
        return try Data(P384.KeyAgreement.PublicKey(serialization, kem: kem).rawRepresentation)
    case CK_KEY_AGREEMENT_P521:
        return try Data(P521.KeyAgreement.PublicKey(serialization, kem: kem).rawRepresentation)
    case CK_KEY_AGREEMENT_X25519:
        return try Data(Curve25519.KeyAgreement.PublicKey(serialization, kem: kem).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE Diffie-Hellman algorithm: \(algorithm)")
    }
}

@available(macOS 14.0, *)
private func ckHpkeDhPublicKeyRepresentation(
    _ algorithm: Int32,
    rawPublicKey: Data,
    kem: HPKE.KEM
) throws -> Data {
    switch algorithm {
    case CK_KEY_AGREEMENT_P256:
        return try P256.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey).hpkeRepresentation(kem: kem)
    case CK_KEY_AGREEMENT_P384:
        return try P384.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey).hpkeRepresentation(kem: kem)
    case CK_KEY_AGREEMENT_P521:
        return try P521.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey).hpkeRepresentation(kem: kem)
    case CK_KEY_AGREEMENT_X25519:
        return try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rawPublicKey).hpkeRepresentation(kem: kem)
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE Diffie-Hellman algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckHpkeKemPublicKeyFromSerialization(
    _ algorithm: Int32,
    serialization: Data,
    kem: HPKE.KEM
) throws -> Data {
    switch algorithm {
    case CK_KEM_XWING_MLKEM768_X25519:
        return try Data(XWingMLKEM768X25519.PublicKey(serialization, kem: kem).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE KEM public-key algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckHpkeKemPublicKeyRepresentation(
    _ algorithm: Int32,
    rawPublicKey: Data,
    kem: HPKE.KEM
) throws -> Data {
    switch algorithm {
    case CK_KEM_XWING_MLKEM768_X25519:
        return try XWingMLKEM768X25519.PublicKey(rawRepresentation: rawPublicKey).hpkeRepresentation(kem: kem)
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE KEM public-key algorithm: \(algorithm)")
    }
}

@available(macOS 14.0, *)
private func ckRequired(_ value: Data?, name: String) throws -> Data {
    guard let value else {
        throw CKBridgeError.invalidArgument("missing \(name)")
    }
    return value
}

@available(macOS 14.0, *)
private func ckHpkeSenderDhHolder(
    recipientAlgorithm: Int32,
    recipientPublicKey: Data,
    ciphersuite: HPKE.Ciphersuite,
    info: Data,
    mode: Int32,
    authPrivateKey: Data?,
    psk: Data?,
    pskID: Data?
) throws -> CKHPKESenderHolder {
    switch recipientAlgorithm {
    case CK_KEY_AGREEMENT_P256:
        let recipientKey = try P256.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey)
        switch mode {
        case CK_HPKE_MODE_BASE:
            return try CKHPKESenderHolder(HPKE.Sender(recipientKey: recipientKey, ciphersuite: ciphersuite, info: info))
        case CK_HPKE_MODE_PSK:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        case CK_HPKE_MODE_AUTH:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    authenticatedBy: P256.KeyAgreement.PrivateKey(rawRepresentation: try ckRequired(authPrivateKey, name: "HPKE authentication private key"))
                )
            )
        case CK_HPKE_MODE_AUTH_PSK:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    authenticatedBy: P256.KeyAgreement.PrivateKey(rawRepresentation: try ckRequired(authPrivateKey, name: "HPKE authentication private key")),
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        default:
            throw CKBridgeError.invalidArgument("unsupported HPKE sender mode: \(mode)")
        }
    case CK_KEY_AGREEMENT_P384:
        let recipientKey = try P384.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey)
        switch mode {
        case CK_HPKE_MODE_BASE:
            return try CKHPKESenderHolder(HPKE.Sender(recipientKey: recipientKey, ciphersuite: ciphersuite, info: info))
        case CK_HPKE_MODE_PSK:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        case CK_HPKE_MODE_AUTH:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    authenticatedBy: P384.KeyAgreement.PrivateKey(rawRepresentation: try ckRequired(authPrivateKey, name: "HPKE authentication private key"))
                )
            )
        case CK_HPKE_MODE_AUTH_PSK:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    authenticatedBy: P384.KeyAgreement.PrivateKey(rawRepresentation: try ckRequired(authPrivateKey, name: "HPKE authentication private key")),
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        default:
            throw CKBridgeError.invalidArgument("unsupported HPKE sender mode: \(mode)")
        }
    case CK_KEY_AGREEMENT_P521:
        let recipientKey = try P521.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey)
        switch mode {
        case CK_HPKE_MODE_BASE:
            return try CKHPKESenderHolder(HPKE.Sender(recipientKey: recipientKey, ciphersuite: ciphersuite, info: info))
        case CK_HPKE_MODE_PSK:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        case CK_HPKE_MODE_AUTH:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    authenticatedBy: P521.KeyAgreement.PrivateKey(rawRepresentation: try ckRequired(authPrivateKey, name: "HPKE authentication private key"))
                )
            )
        case CK_HPKE_MODE_AUTH_PSK:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    authenticatedBy: P521.KeyAgreement.PrivateKey(rawRepresentation: try ckRequired(authPrivateKey, name: "HPKE authentication private key")),
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        default:
            throw CKBridgeError.invalidArgument("unsupported HPKE sender mode: \(mode)")
        }
    case CK_KEY_AGREEMENT_X25519:
        let recipientKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPublicKey)
        switch mode {
        case CK_HPKE_MODE_BASE:
            return try CKHPKESenderHolder(HPKE.Sender(recipientKey: recipientKey, ciphersuite: ciphersuite, info: info))
        case CK_HPKE_MODE_PSK:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        case CK_HPKE_MODE_AUTH:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    authenticatedBy: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: try ckRequired(authPrivateKey, name: "HPKE authentication private key"))
                )
            )
        case CK_HPKE_MODE_AUTH_PSK:
            return try CKHPKESenderHolder(
                HPKE.Sender(
                    recipientKey: recipientKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    authenticatedBy: Curve25519.KeyAgreement.PrivateKey(rawRepresentation: try ckRequired(authPrivateKey, name: "HPKE authentication private key")),
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        default:
            throw CKBridgeError.invalidArgument("unsupported HPKE sender mode: \(mode)")
        }
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE Diffie-Hellman algorithm: \(recipientAlgorithm)")
    }
}

@available(macOS 26.0, *)
private func ckHpkeSenderKemHolder(
    recipientAlgorithm: Int32,
    recipientPublicKey: Data,
    ciphersuite: HPKE.Ciphersuite,
    info: Data
) throws -> CKHPKESenderHolder {
    switch recipientAlgorithm {
    case CK_KEM_XWING_MLKEM768_X25519:
        let recipientKey = try XWingMLKEM768X25519.PublicKey(rawRepresentation: recipientPublicKey)
        return try CKHPKESenderHolder(HPKE.Sender(recipientKey: recipientKey, ciphersuite: ciphersuite, info: info))
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE KEM public-key algorithm: \(recipientAlgorithm)")
    }
}

@available(macOS 14.0, *)
private func ckHpkeRecipientDhHolder(
    privateAlgorithm: Int32,
    privateKey: Data,
    ciphersuite: HPKE.Ciphersuite,
    info: Data,
    encapsulatedKey: Data,
    mode: Int32,
    authPublicKey: Data?,
    psk: Data?,
    pskID: Data?
) throws -> CKHPKERecipientHolder {
    switch privateAlgorithm {
    case CK_KEY_AGREEMENT_P256:
        let privateKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        switch mode {
        case CK_HPKE_MODE_BASE:
            return try CKHPKERecipientHolder(HPKE.Recipient(privateKey: privateKey, ciphersuite: ciphersuite, info: info, encapsulatedKey: encapsulatedKey))
        case CK_HPKE_MODE_PSK:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        case CK_HPKE_MODE_AUTH:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    authenticatedBy: try P256.KeyAgreement.PublicKey(rawRepresentation: ckRequired(authPublicKey, name: "HPKE authentication public key"))
                )
            )
        case CK_HPKE_MODE_AUTH_PSK:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    authenticatedBy: try P256.KeyAgreement.PublicKey(rawRepresentation: ckRequired(authPublicKey, name: "HPKE authentication public key")),
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        default:
            throw CKBridgeError.invalidArgument("unsupported HPKE recipient mode: \(mode)")
        }
    case CK_KEY_AGREEMENT_P384:
        let privateKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        switch mode {
        case CK_HPKE_MODE_BASE:
            return try CKHPKERecipientHolder(HPKE.Recipient(privateKey: privateKey, ciphersuite: ciphersuite, info: info, encapsulatedKey: encapsulatedKey))
        case CK_HPKE_MODE_PSK:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        case CK_HPKE_MODE_AUTH:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    authenticatedBy: try P384.KeyAgreement.PublicKey(rawRepresentation: ckRequired(authPublicKey, name: "HPKE authentication public key"))
                )
            )
        case CK_HPKE_MODE_AUTH_PSK:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    authenticatedBy: try P384.KeyAgreement.PublicKey(rawRepresentation: ckRequired(authPublicKey, name: "HPKE authentication public key")),
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        default:
            throw CKBridgeError.invalidArgument("unsupported HPKE recipient mode: \(mode)")
        }
    case CK_KEY_AGREEMENT_P521:
        let privateKey = try P521.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        switch mode {
        case CK_HPKE_MODE_BASE:
            return try CKHPKERecipientHolder(HPKE.Recipient(privateKey: privateKey, ciphersuite: ciphersuite, info: info, encapsulatedKey: encapsulatedKey))
        case CK_HPKE_MODE_PSK:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        case CK_HPKE_MODE_AUTH:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    authenticatedBy: try P521.KeyAgreement.PublicKey(rawRepresentation: ckRequired(authPublicKey, name: "HPKE authentication public key"))
                )
            )
        case CK_HPKE_MODE_AUTH_PSK:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    authenticatedBy: try P521.KeyAgreement.PublicKey(rawRepresentation: ckRequired(authPublicKey, name: "HPKE authentication public key")),
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        default:
            throw CKBridgeError.invalidArgument("unsupported HPKE recipient mode: \(mode)")
        }
    case CK_KEY_AGREEMENT_X25519:
        let privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        switch mode {
        case CK_HPKE_MODE_BASE:
            return try CKHPKERecipientHolder(HPKE.Recipient(privateKey: privateKey, ciphersuite: ciphersuite, info: info, encapsulatedKey: encapsulatedKey))
        case CK_HPKE_MODE_PSK:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        case CK_HPKE_MODE_AUTH:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    authenticatedBy: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ckRequired(authPublicKey, name: "HPKE authentication public key"))
                )
            )
        case CK_HPKE_MODE_AUTH_PSK:
            return try CKHPKERecipientHolder(
                HPKE.Recipient(
                    privateKey: privateKey,
                    ciphersuite: ciphersuite,
                    info: info,
                    encapsulatedKey: encapsulatedKey,
                    authenticatedBy: try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ckRequired(authPublicKey, name: "HPKE authentication public key")),
                    presharedKey: ckHpkeSymmetricKey(try ckRequired(psk, name: "HPKE preshared key")),
                    presharedKeyIdentifier: try ckRequired(pskID, name: "HPKE preshared-key identifier")
                )
            )
        default:
            throw CKBridgeError.invalidArgument("unsupported HPKE recipient mode: \(mode)")
        }
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE Diffie-Hellman algorithm: \(privateAlgorithm)")
    }
}

@available(macOS 26.0, *)
private func ckHpkeRecipientKemHolder(
    privateAlgorithm: Int32,
    privateKey: Data,
    ciphersuite: HPKE.Ciphersuite,
    info: Data,
    encapsulatedKey: Data
) throws -> CKHPKERecipientHolder {
    switch privateAlgorithm {
    case CK_KEM_XWING_MLKEM768_X25519:
        let privateKey = try XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: privateKey)
        return try CKHPKERecipientHolder(HPKE.Recipient(privateKey: privateKey, ciphersuite: ciphersuite, info: info, encapsulatedKey: encapsulatedKey))
    default:
        throw CKBridgeError.invalidArgument("unsupported HPKE KEM private-key algorithm: \(privateAlgorithm)")
    }
}

@_cdecl("ck_hpke_dh_public_key_from_serialization")
public func ck_hpke_dh_public_key_from_serialization(
    _ algorithm: Int32,
    _ kem: Int32,
    _ serializationBytes: UnsafePointer<UInt8>?,
    _ serializationLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 14.0, *) else {
        return ckInvalidArgument(errorOut, "HPKE requires macOS 14.0 or newer")
    }

    do {
        let serialization = try ckData(serializationBytes, serializationLen)
        return ckCopyData(
            try ckHpkeDhPublicKeyFromSerialization(algorithm, serialization: serialization, kem: ckHpkeKem(kem)),
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

@_cdecl("ck_hpke_dh_public_key_representation")
public func ck_hpke_dh_public_key_representation(
    _ algorithm: Int32,
    _ rawPublicKeyBytes: UnsafePointer<UInt8>?,
    _ rawPublicKeyLen: UInt,
    _ kem: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 14.0, *) else {
        return ckInvalidArgument(errorOut, "HPKE requires macOS 14.0 or newer")
    }

    do {
        let rawPublicKey = try ckData(rawPublicKeyBytes, rawPublicKeyLen)
        return ckCopyData(
            try ckHpkeDhPublicKeyRepresentation(algorithm, rawPublicKey: rawPublicKey, kem: ckHpkeKem(kem)),
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

@_cdecl("ck_hpke_kem_public_key_from_serialization")
public func ck_hpke_kem_public_key_from_serialization(
    _ algorithm: Int32,
    _ kem: Int32,
    _ serializationBytes: UnsafePointer<UInt8>?,
    _ serializationLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "HPKE KEM public-key serialization requires macOS 26.0 or newer")
    }

    do {
        let serialization = try ckData(serializationBytes, serializationLen)
        return ckCopyData(
            try ckHpkeKemPublicKeyFromSerialization(algorithm, serialization: serialization, kem: ckHpkeKem(kem)),
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

@_cdecl("ck_hpke_kem_public_key_representation")
public func ck_hpke_kem_public_key_representation(
    _ algorithm: Int32,
    _ rawPublicKeyBytes: UnsafePointer<UInt8>?,
    _ rawPublicKeyLen: UInt,
    _ kem: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "HPKE KEM public-key serialization requires macOS 26.0 or newer")
    }

    do {
        let rawPublicKey = try ckData(rawPublicKeyBytes, rawPublicKeyLen)
        return ckCopyData(
            try ckHpkeKemPublicKeyRepresentation(algorithm, rawPublicKey: rawPublicKey, kem: ckHpkeKem(kem)),
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

@_cdecl("ck_hpke_sender_create_dh")
public func ck_hpke_sender_create_dh(
    _ recipientAlgorithm: Int32,
    _ recipientPublicKeyBytes: UnsafePointer<UInt8>?,
    _ recipientPublicKeyLen: UInt,
    _ kem: Int32,
    _ kdf: Int32,
    _ aead: Int32,
    _ infoBytes: UnsafePointer<UInt8>?,
    _ infoLen: UInt,
    _ mode: Int32,
    _ authPrivateKeyBytes: UnsafePointer<UInt8>?,
    _ authPrivateKeyLen: UInt,
    _ pskBytes: UnsafePointer<UInt8>?,
    _ pskLen: UInt,
    _ pskIDBytes: UnsafePointer<UInt8>?,
    _ pskIDLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 14.0, *) else {
        ckWriteError(errorOut, "HPKE requires macOS 14.0 or newer")
        return nil
    }

    do {
        let recipientPublicKey = try ckData(recipientPublicKeyBytes, recipientPublicKeyLen)
        let info = try ckData(infoBytes, infoLen)
        let authPrivateKey = authPrivateKeyLen > 0 ? try ckData(authPrivateKeyBytes, authPrivateKeyLen) : nil
        let psk = pskLen > 0 ? try ckData(pskBytes, pskLen) : nil
        let pskID = pskIDLen > 0 ? try ckData(pskIDBytes, pskIDLen) : nil
        let holder = try ckHpkeSenderDhHolder(
            recipientAlgorithm: recipientAlgorithm,
            recipientPublicKey: recipientPublicKey,
            ciphersuite: ckHpkeCiphersuite(kem: kem, kdf: kdf, aead: aead),
            info: info,
            mode: mode,
            authPrivateKey: authPrivateKey,
            psk: psk,
            pskID: pskID
        )
        return Unmanaged.passRetained(holder).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_hpke_sender_create_kem")
public func ck_hpke_sender_create_kem(
    _ recipientAlgorithm: Int32,
    _ recipientPublicKeyBytes: UnsafePointer<UInt8>?,
    _ recipientPublicKeyLen: UInt,
    _ kem: Int32,
    _ kdf: Int32,
    _ aead: Int32,
    _ infoBytes: UnsafePointer<UInt8>?,
    _ infoLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "HPKE KEM sender mode requires macOS 26.0 or newer")
        return nil
    }

    do {
        let recipientPublicKey = try ckData(recipientPublicKeyBytes, recipientPublicKeyLen)
        let info = try ckData(infoBytes, infoLen)
        let holder = try ckHpkeSenderKemHolder(
            recipientAlgorithm: recipientAlgorithm,
            recipientPublicKey: recipientPublicKey,
            ciphersuite: ckHpkeCiphersuite(kem: kem, kdf: kdf, aead: aead),
            info: info
        )
        return Unmanaged.passRetained(holder).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_hpke_sender_release")
public func ck_hpke_sender_release(_ handle: UnsafeMutableRawPointer?) {
    guard #available(macOS 14.0, *), let handle else {
        return
    }
    Unmanaged<CKHPKESenderHolder>.fromOpaque(handle).release()
}

@_cdecl("ck_hpke_sender_encapsulated_key")
public func ck_hpke_sender_encapsulated_key(
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 14.0, *) else {
        return ckInvalidArgument(errorOut, "HPKE requires macOS 14.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing HPKE sender handle")
        }
        let holder = Unmanaged<CKHPKESenderHolder>.fromOpaque(handle).takeUnretainedValue()
        return ckCopyData(holder.sender.encapsulatedKey, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_hpke_sender_seal")
public func ck_hpke_sender_seal(
    _ handle: UnsafeMutableRawPointer?,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: UInt,
    _ aadBytes: UnsafePointer<UInt8>?,
    _ aadLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 14.0, *) else {
        return ckInvalidArgument(errorOut, "HPKE requires macOS 14.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing HPKE sender handle")
        }
        let message = try ckData(messageBytes, messageLen)
        let aad = try ckData(aadBytes, aadLen)
        let holder = Unmanaged<CKHPKESenderHolder>.fromOpaque(handle).takeUnretainedValue()
        let ciphertext: Data
        if aad.isEmpty {
            ciphertext = try holder.sender.seal(message)
        } else {
            ciphertext = try holder.sender.seal(message, authenticating: aad)
        }
        return ckCopyData(ciphertext, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_ENCRYPTION_FAILED, error, errorOut)
    }
}

@_cdecl("ck_hpke_sender_export_secret")
public func ck_hpke_sender_export_secret(
    _ handle: UnsafeMutableRawPointer?,
    _ contextBytes: UnsafePointer<UInt8>?,
    _ contextLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 14.0, *) else {
        return ckInvalidArgument(errorOut, "HPKE requires macOS 14.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing HPKE sender handle")
        }
        let context = try ckData(contextBytes, contextLen)
        let holder = Unmanaged<CKHPKESenderHolder>.fromOpaque(handle).takeUnretainedValue()
        let exported = try holder.sender.exportSecret(context: context, outputByteCount: Int(outputLen))
        return ckCopyData(ckHpkeExportedSecret(exported), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_hpke_recipient_create_dh")
public func ck_hpke_recipient_create_dh(
    _ privateAlgorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ kem: Int32,
    _ kdf: Int32,
    _ aead: Int32,
    _ infoBytes: UnsafePointer<UInt8>?,
    _ infoLen: UInt,
    _ encapsulatedKeyBytes: UnsafePointer<UInt8>?,
    _ encapsulatedKeyLen: UInt,
    _ mode: Int32,
    _ authPublicKeyBytes: UnsafePointer<UInt8>?,
    _ authPublicKeyLen: UInt,
    _ pskBytes: UnsafePointer<UInt8>?,
    _ pskLen: UInt,
    _ pskIDBytes: UnsafePointer<UInt8>?,
    _ pskIDLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 14.0, *) else {
        ckWriteError(errorOut, "HPKE requires macOS 14.0 or newer")
        return nil
    }

    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        let info = try ckData(infoBytes, infoLen)
        let encapsulatedKey = try ckData(encapsulatedKeyBytes, encapsulatedKeyLen)
        let authPublicKey = authPublicKeyLen > 0 ? try ckData(authPublicKeyBytes, authPublicKeyLen) : nil
        let psk = pskLen > 0 ? try ckData(pskBytes, pskLen) : nil
        let pskID = pskIDLen > 0 ? try ckData(pskIDBytes, pskIDLen) : nil
        let holder = try ckHpkeRecipientDhHolder(
            privateAlgorithm: privateAlgorithm,
            privateKey: privateKey,
            ciphersuite: ckHpkeCiphersuite(kem: kem, kdf: kdf, aead: aead),
            info: info,
            encapsulatedKey: encapsulatedKey,
            mode: mode,
            authPublicKey: authPublicKey,
            psk: psk,
            pskID: pskID
        )
        return Unmanaged.passRetained(holder).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_hpke_recipient_create_kem")
public func ck_hpke_recipient_create_kem(
    _ privateAlgorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ kem: Int32,
    _ kdf: Int32,
    _ aead: Int32,
    _ infoBytes: UnsafePointer<UInt8>?,
    _ infoLen: UInt,
    _ encapsulatedKeyBytes: UnsafePointer<UInt8>?,
    _ encapsulatedKeyLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "HPKE KEM recipient mode requires macOS 26.0 or newer")
        return nil
    }

    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        let info = try ckData(infoBytes, infoLen)
        let encapsulatedKey = try ckData(encapsulatedKeyBytes, encapsulatedKeyLen)
        let holder = try ckHpkeRecipientKemHolder(
            privateAlgorithm: privateAlgorithm,
            privateKey: privateKey,
            ciphersuite: ckHpkeCiphersuite(kem: kem, kdf: kdf, aead: aead),
            info: info,
            encapsulatedKey: encapsulatedKey
        )
        return Unmanaged.passRetained(holder).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_hpke_recipient_release")
public func ck_hpke_recipient_release(_ handle: UnsafeMutableRawPointer?) {
    guard #available(macOS 14.0, *), let handle else {
        return
    }
    Unmanaged<CKHPKERecipientHolder>.fromOpaque(handle).release()
}

@_cdecl("ck_hpke_recipient_open")
public func ck_hpke_recipient_open(
    _ handle: UnsafeMutableRawPointer?,
    _ ciphertextBytes: UnsafePointer<UInt8>?,
    _ ciphertextLen: UInt,
    _ aadBytes: UnsafePointer<UInt8>?,
    _ aadLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 14.0, *) else {
        return ckInvalidArgument(errorOut, "HPKE requires macOS 14.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing HPKE recipient handle")
        }
        let ciphertext = try ckData(ciphertextBytes, ciphertextLen)
        let aad = try ckData(aadBytes, aadLen)
        let holder = Unmanaged<CKHPKERecipientHolder>.fromOpaque(handle).takeUnretainedValue()
        let plaintext: Data
        if aad.isEmpty {
            plaintext = try holder.recipient.open(ciphertext)
        } else {
            plaintext = try holder.recipient.open(ciphertext, authenticating: aad)
        }
        return ckCopyData(plaintext, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_DECRYPTION_FAILED, error, errorOut)
    }
}

@_cdecl("ck_hpke_recipient_export_secret")
public func ck_hpke_recipient_export_secret(
    _ handle: UnsafeMutableRawPointer?,
    _ contextBytes: UnsafePointer<UInt8>?,
    _ contextLen: UInt,
    _ outputLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 14.0, *) else {
        return ckInvalidArgument(errorOut, "HPKE requires macOS 14.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing HPKE recipient handle")
        }
        let context = try ckData(contextBytes, contextLen)
        let holder = Unmanaged<CKHPKERecipientHolder>.fromOpaque(handle).takeUnretainedValue()
        let exported = try holder.recipient.exportSecret(context: context, outputByteCount: Int(outputLen))
        return ckCopyData(ckHpkeExportedSecret(exported), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}
