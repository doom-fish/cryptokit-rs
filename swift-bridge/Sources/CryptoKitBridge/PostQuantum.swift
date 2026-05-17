import CryptoKit
import Darwin
import Foundation

@available(macOS 26.0, *)
private func ckPostQuantumSymmetricKeyData(_ key: SymmetricKey) -> Data {
    key.withUnsafeBytes(ckOwnedData)
}

@available(macOS 26.0, *)
private func ckCopyTwoData(
    _ first: Data,
    _ firstOutBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ firstOutLen: UnsafeMutablePointer<UInt>?,
    _ second: Data,
    _ secondOutBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ secondOutLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    let firstStatus = ckCopyData(first, firstOutBytes, firstOutLen, errorOut)
    guard firstStatus == CK_OK else {
        return firstStatus
    }

    let secondStatus = ckCopyData(second, secondOutBytes, secondOutLen, errorOut)
    guard secondStatus == CK_OK else {
        if let buffer = firstOutBytes?.pointee {
            free(buffer)
            firstOutBytes?.pointee = nil
        }
        firstOutLen?.pointee = 0
        return secondStatus
    }

    return CK_OK
}

@available(macOS 26.0, *)
private final class CKSecureEnclaveMLDSA65PrivateKeyHolder {
    let key: SecureEnclave.MLDSA65.PrivateKey

    init(_ key: SecureEnclave.MLDSA65.PrivateKey) {
        self.key = key
    }
}

@available(macOS 26.0, *)
private final class CKSecureEnclaveMLDSA87PrivateKeyHolder {
    let key: SecureEnclave.MLDSA87.PrivateKey

    init(_ key: SecureEnclave.MLDSA87.PrivateKey) {
        self.key = key
    }
}

@available(macOS 26.0, *)
private final class CKSecureEnclaveMLKEM768PrivateKeyHolder {
    let key: SecureEnclave.MLKEM768.PrivateKey

    init(_ key: SecureEnclave.MLKEM768.PrivateKey) {
        self.key = key
    }
}

@available(macOS 26.0, *)
private final class CKSecureEnclaveMLKEM1024PrivateKeyHolder {
    let key: SecureEnclave.MLKEM1024.PrivateKey

    init(_ key: SecureEnclave.MLKEM1024.PrivateKey) {
        self.key = key
    }
}

@available(macOS 26.0, *)
private func ckKemPublicKeyData(_ algorithm: Int32, raw: Data) throws -> Data {
    switch algorithm {
    case CK_KEM_MLKEM768:
        return try Data(MLKEM768.PublicKey(rawRepresentation: raw).rawRepresentation)
    case CK_KEM_MLKEM1024:
        return try Data(MLKEM1024.PublicKey(rawRepresentation: raw).rawRepresentation)
    case CK_KEM_XWING_MLKEM768_X25519:
        return try Data(XWingMLKEM768X25519.PublicKey(rawRepresentation: raw).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckKemPrivateKeyGenerate(_ algorithm: Int32) throws -> Data {
    switch algorithm {
    case CK_KEM_MLKEM768:
        return try Data(MLKEM768.PrivateKey.generate().integrityCheckedRepresentation)
    case CK_KEM_MLKEM1024:
        return try Data(MLKEM1024.PrivateKey.generate().integrityCheckedRepresentation)
    case CK_KEM_XWING_MLKEM768_X25519:
        return try Data(XWingMLKEM768X25519.PrivateKey.generate().integrityCheckedRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckKemPrivateKeyFromSeed(
    _ algorithm: Int32,
    seed: Data,
    publicKey: Data?
) throws -> Data {
    switch algorithm {
    case CK_KEM_MLKEM768:
        let publicKey = try publicKey.map { try MLKEM768.PublicKey(rawRepresentation: $0) }
        return try Data(MLKEM768.PrivateKey(seedRepresentation: seed, publicKey: publicKey).integrityCheckedRepresentation)
    case CK_KEM_MLKEM1024:
        let publicKey = try publicKey.map { try MLKEM1024.PublicKey(rawRepresentation: $0) }
        return try Data(MLKEM1024.PrivateKey(seedRepresentation: seed, publicKey: publicKey).integrityCheckedRepresentation)
    case CK_KEM_XWING_MLKEM768_X25519:
        let publicKey = try publicKey.map { try XWingMLKEM768X25519.PublicKey(rawRepresentation: $0) }
        return try Data(XWingMLKEM768X25519.PrivateKey(seedRepresentation: seed, publicKey: publicKey).integrityCheckedRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckKemPrivateKeyData(_ algorithm: Int32, integrityChecked: Data) throws -> Data {
    switch algorithm {
    case CK_KEM_MLKEM768:
        return try Data(MLKEM768.PrivateKey(integrityCheckedRepresentation: integrityChecked).integrityCheckedRepresentation)
    case CK_KEM_MLKEM1024:
        return try Data(MLKEM1024.PrivateKey(integrityCheckedRepresentation: integrityChecked).integrityCheckedRepresentation)
    case CK_KEM_XWING_MLKEM768_X25519:
        return try Data(XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: integrityChecked).integrityCheckedRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckKemPrivateKeySeedRepresentation(_ algorithm: Int32, integrityChecked: Data) throws -> Data {
    switch algorithm {
    case CK_KEM_MLKEM768:
        return try Data(MLKEM768.PrivateKey(integrityCheckedRepresentation: integrityChecked).seedRepresentation)
    case CK_KEM_MLKEM1024:
        return try Data(MLKEM1024.PrivateKey(integrityCheckedRepresentation: integrityChecked).seedRepresentation)
    case CK_KEM_XWING_MLKEM768_X25519:
        return try Data(XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: integrityChecked).seedRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckKemPrivateKeyPublicKey(_ algorithm: Int32, integrityChecked: Data) throws -> Data {
    switch algorithm {
    case CK_KEM_MLKEM768:
        return try Data(MLKEM768.PrivateKey(integrityCheckedRepresentation: integrityChecked).publicKey.rawRepresentation)
    case CK_KEM_MLKEM1024:
        return try Data(MLKEM1024.PrivateKey(integrityCheckedRepresentation: integrityChecked).publicKey.rawRepresentation)
    case CK_KEM_XWING_MLKEM768_X25519:
        return try Data(XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: integrityChecked).publicKey.rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckKemDecapsulate(_ algorithm: Int32, integrityChecked: Data, encapsulated: Data) throws -> Data {
    switch algorithm {
    case CK_KEM_MLKEM768:
        return try ckPostQuantumSymmetricKeyData(
            MLKEM768.PrivateKey(integrityCheckedRepresentation: integrityChecked).decapsulate(encapsulated)
        )
    case CK_KEM_MLKEM1024:
        return try ckPostQuantumSymmetricKeyData(
            MLKEM1024.PrivateKey(integrityCheckedRepresentation: integrityChecked).decapsulate(encapsulated)
        )
    case CK_KEM_XWING_MLKEM768_X25519:
        return try ckPostQuantumSymmetricKeyData(
            XWingMLKEM768X25519.PrivateKey(integrityCheckedRepresentation: integrityChecked).decapsulate(encapsulated)
        )
    default:
        throw CKBridgeError.invalidArgument("unsupported KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckKemEncapsulate(_ algorithm: Int32, rawPublicKey: Data) throws -> (Data, Data) {
    switch algorithm {
    case CK_KEM_MLKEM768:
        let result = try MLKEM768.PublicKey(rawRepresentation: rawPublicKey).encapsulate()
        return (ckPostQuantumSymmetricKeyData(result.sharedSecret), result.encapsulated)
    case CK_KEM_MLKEM1024:
        let result = try MLKEM1024.PublicKey(rawRepresentation: rawPublicKey).encapsulate()
        return (ckPostQuantumSymmetricKeyData(result.sharedSecret), result.encapsulated)
    case CK_KEM_XWING_MLKEM768_X25519:
        let result = try XWingMLKEM768X25519.PublicKey(rawRepresentation: rawPublicKey).encapsulate()
        return (ckPostQuantumSymmetricKeyData(result.sharedSecret), result.encapsulated)
    default:
        throw CKBridgeError.invalidArgument("unsupported KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckMldsaPublicKeyData(_ algorithm: Int32, raw: Data) throws -> Data {
    switch algorithm {
    case CK_MLDSA_65:
        return try Data(MLDSA65.PublicKey(rawRepresentation: raw).rawRepresentation)
    case CK_MLDSA_87:
        return try Data(MLDSA87.PublicKey(rawRepresentation: raw).rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckMldsaPrivateKeyGenerate(_ algorithm: Int32) throws -> Data {
    switch algorithm {
    case CK_MLDSA_65:
        return try Data(MLDSA65.PrivateKey().integrityCheckedRepresentation)
    case CK_MLDSA_87:
        return try Data(MLDSA87.PrivateKey().integrityCheckedRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckMldsaPrivateKeyFromSeed(
    _ algorithm: Int32,
    seed: Data,
    publicKey: Data?
) throws -> Data {
    switch algorithm {
    case CK_MLDSA_65:
        let publicKey = try publicKey.map { try MLDSA65.PublicKey(rawRepresentation: $0) }
        return try Data(MLDSA65.PrivateKey(seedRepresentation: seed, publicKey: publicKey).integrityCheckedRepresentation)
    case CK_MLDSA_87:
        let publicKey = try publicKey.map { try MLDSA87.PublicKey(rawRepresentation: $0) }
        return try Data(MLDSA87.PrivateKey(seedRepresentation: seed, publicKey: publicKey).integrityCheckedRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckMldsaPrivateKeyData(_ algorithm: Int32, integrityChecked: Data) throws -> Data {
    switch algorithm {
    case CK_MLDSA_65:
        return try Data(MLDSA65.PrivateKey(integrityCheckedRepresentation: integrityChecked).integrityCheckedRepresentation)
    case CK_MLDSA_87:
        return try Data(MLDSA87.PrivateKey(integrityCheckedRepresentation: integrityChecked).integrityCheckedRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckMldsaPrivateKeySeedRepresentation(_ algorithm: Int32, integrityChecked: Data) throws -> Data {
    switch algorithm {
    case CK_MLDSA_65:
        return try Data(MLDSA65.PrivateKey(integrityCheckedRepresentation: integrityChecked).seedRepresentation)
    case CK_MLDSA_87:
        return try Data(MLDSA87.PrivateKey(integrityCheckedRepresentation: integrityChecked).seedRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckMldsaPrivateKeyPublicKey(_ algorithm: Int32, integrityChecked: Data) throws -> Data {
    switch algorithm {
    case CK_MLDSA_65:
        return try Data(MLDSA65.PrivateKey(integrityCheckedRepresentation: integrityChecked).publicKey.rawRepresentation)
    case CK_MLDSA_87:
        return try Data(MLDSA87.PrivateKey(integrityCheckedRepresentation: integrityChecked).publicKey.rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckMldsaSign(
    _ algorithm: Int32,
    integrityChecked: Data,
    data: Data,
    context: Data?
) throws -> Data {
    switch algorithm {
    case CK_MLDSA_65:
        let key = try MLDSA65.PrivateKey(integrityCheckedRepresentation: integrityChecked)
        if let context {
            return try key.signature(for: data, context: context)
        }
        return try key.signature(for: data)
    case CK_MLDSA_87:
        let key = try MLDSA87.PrivateKey(integrityCheckedRepresentation: integrityChecked)
        if let context {
            return try key.signature(for: data, context: context)
        }
        return try key.signature(for: data)
    default:
        throw CKBridgeError.invalidArgument("unsupported ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckMldsaVerify(
    _ algorithm: Int32,
    rawPublicKey: Data,
    signature: Data,
    data: Data,
    context: Data?
) throws -> Bool {
    switch algorithm {
    case CK_MLDSA_65:
        let key = try MLDSA65.PublicKey(rawRepresentation: rawPublicKey)
        if let context {
            return key.isValidSignature(signature, for: data, context: context)
        }
        return key.isValidSignature(signature, for: data)
    case CK_MLDSA_87:
        let key = try MLDSA87.PublicKey(rawRepresentation: rawPublicKey)
        if let context {
            return key.isValidSignature(signature, for: data, context: context)
        }
        return key.isValidSignature(signature, for: data)
    default:
        throw CKBridgeError.invalidArgument("unsupported ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveMldsaHolder(_ algorithm: Int32) throws -> AnyObject {
    switch algorithm {
    case CK_MLDSA_65:
        return CKSecureEnclaveMLDSA65PrivateKeyHolder(try SecureEnclave.MLDSA65.PrivateKey())
    case CK_MLDSA_87:
        return CKSecureEnclaveMLDSA87PrivateKeyHolder(try SecureEnclave.MLDSA87.PrivateKey())
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveMldsaHolder(
    _ algorithm: Int32,
    accessibility: Int32,
    accessControlFlags: UInt64,
    authenticationContextHandle: UnsafeMutableRawPointer?
) throws -> AnyObject {
    let authenticationContext = try ckAuthenticationContext(authenticationContextHandle)
    let accessControl = try ckSecureEnclaveAccessControl(accessibility, accessControlFlags)
    switch algorithm {
    case CK_MLDSA_65:
        if let accessControl {
            return CKSecureEnclaveMLDSA65PrivateKeyHolder(
                try SecureEnclave.MLDSA65.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
            )
        }
        return CKSecureEnclaveMLDSA65PrivateKeyHolder(
            try SecureEnclave.MLDSA65.PrivateKey(authenticationContext: authenticationContext)
        )
    case CK_MLDSA_87:
        if let accessControl {
            return CKSecureEnclaveMLDSA87PrivateKeyHolder(
                try SecureEnclave.MLDSA87.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
            )
        }
        return CKSecureEnclaveMLDSA87PrivateKeyHolder(
            try SecureEnclave.MLDSA87.PrivateKey(authenticationContext: authenticationContext)
        )
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveMldsaHolder(_ algorithm: Int32, dataRepresentation: Data) throws -> AnyObject {
    switch algorithm {
    case CK_MLDSA_65:
        return CKSecureEnclaveMLDSA65PrivateKeyHolder(try SecureEnclave.MLDSA65.PrivateKey(dataRepresentation: dataRepresentation))
    case CK_MLDSA_87:
        return CKSecureEnclaveMLDSA87PrivateKeyHolder(try SecureEnclave.MLDSA87.PrivateKey(dataRepresentation: dataRepresentation))
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveMldsaHolder(
    _ algorithm: Int32,
    dataRepresentation: Data,
    authenticationContextHandle: UnsafeMutableRawPointer?
) throws -> AnyObject {
    let authenticationContext = try ckAuthenticationContext(authenticationContextHandle)
    switch algorithm {
    case CK_MLDSA_65:
        return CKSecureEnclaveMLDSA65PrivateKeyHolder(
            try SecureEnclave.MLDSA65.PrivateKey(
                dataRepresentation: dataRepresentation,
                authenticationContext: authenticationContext
            )
        )
    case CK_MLDSA_87:
        return CKSecureEnclaveMLDSA87PrivateKeyHolder(
            try SecureEnclave.MLDSA87.PrivateKey(
                dataRepresentation: dataRepresentation,
                authenticationContext: authenticationContext
            )
        )
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveMldsaPublicKey(_ algorithm: Int32, handle: UnsafeMutableRawPointer) throws -> Data {
    switch algorithm {
    case CK_MLDSA_65:
        let holder = Unmanaged<CKSecureEnclaveMLDSA65PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return Data(holder.key.publicKey.rawRepresentation)
    case CK_MLDSA_87:
        let holder = Unmanaged<CKSecureEnclaveMLDSA87PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return Data(holder.key.publicKey.rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveMldsaDataRepresentation(_ algorithm: Int32, handle: UnsafeMutableRawPointer) throws -> Data {
    switch algorithm {
    case CK_MLDSA_65:
        let holder = Unmanaged<CKSecureEnclaveMLDSA65PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return holder.key.dataRepresentation
    case CK_MLDSA_87:
        let holder = Unmanaged<CKSecureEnclaveMLDSA87PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return holder.key.dataRepresentation
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveMldsaSign(
    _ algorithm: Int32,
    handle: UnsafeMutableRawPointer,
    data: Data,
    context: Data?
) throws -> Data {
    switch algorithm {
    case CK_MLDSA_65:
        let holder = Unmanaged<CKSecureEnclaveMLDSA65PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        if let context {
            return try holder.key.signature(for: data, context: context)
        }
        return try holder.key.signature(for: data)
    case CK_MLDSA_87:
        let holder = Unmanaged<CKSecureEnclaveMLDSA87PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        if let context {
            return try holder.key.signature(for: data, context: context)
        }
        return try holder.key.signature(for: data)
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveKemHolder(_ algorithm: Int32) throws -> AnyObject {
    switch algorithm {
    case CK_KEM_MLKEM768:
        return CKSecureEnclaveMLKEM768PrivateKeyHolder(try SecureEnclave.MLKEM768.PrivateKey.generate())
    case CK_KEM_MLKEM1024:
        return CKSecureEnclaveMLKEM1024PrivateKeyHolder(try SecureEnclave.MLKEM1024.PrivateKey.generate())
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveKemHolder(
    _ algorithm: Int32,
    accessibility: Int32,
    accessControlFlags: UInt64,
    authenticationContextHandle: UnsafeMutableRawPointer?
) throws -> AnyObject {
    let authenticationContext = try ckAuthenticationContext(authenticationContextHandle)
    let accessControl = try ckSecureEnclaveAccessControl(accessibility, accessControlFlags)
    switch algorithm {
    case CK_KEM_MLKEM768:
        if let accessControl {
            return CKSecureEnclaveMLKEM768PrivateKeyHolder(
                try SecureEnclave.MLKEM768.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
            )
        }
        return CKSecureEnclaveMLKEM768PrivateKeyHolder(
            try SecureEnclave.MLKEM768.PrivateKey(authenticationContext: authenticationContext)
        )
    case CK_KEM_MLKEM1024:
        if let accessControl {
            return CKSecureEnclaveMLKEM1024PrivateKeyHolder(
                try SecureEnclave.MLKEM1024.PrivateKey(
                    accessControl: accessControl,
                    authenticationContext: authenticationContext
                )
            )
        }
        return CKSecureEnclaveMLKEM1024PrivateKeyHolder(
            try SecureEnclave.MLKEM1024.PrivateKey(authenticationContext: authenticationContext)
        )
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveKemHolder(_ algorithm: Int32, dataRepresentation: Data) throws -> AnyObject {
    switch algorithm {
    case CK_KEM_MLKEM768:
        return CKSecureEnclaveMLKEM768PrivateKeyHolder(try SecureEnclave.MLKEM768.PrivateKey(dataRepresentation: dataRepresentation))
    case CK_KEM_MLKEM1024:
        return CKSecureEnclaveMLKEM1024PrivateKeyHolder(try SecureEnclave.MLKEM1024.PrivateKey(dataRepresentation: dataRepresentation))
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveKemHolder(
    _ algorithm: Int32,
    dataRepresentation: Data,
    authenticationContextHandle: UnsafeMutableRawPointer?
) throws -> AnyObject {
    let authenticationContext = try ckAuthenticationContext(authenticationContextHandle)
    switch algorithm {
    case CK_KEM_MLKEM768:
        return CKSecureEnclaveMLKEM768PrivateKeyHolder(
            try SecureEnclave.MLKEM768.PrivateKey(
                dataRepresentation: dataRepresentation,
                authenticationContext: authenticationContext
            )
        )
    case CK_KEM_MLKEM1024:
        return CKSecureEnclaveMLKEM1024PrivateKeyHolder(
            try SecureEnclave.MLKEM1024.PrivateKey(
                dataRepresentation: dataRepresentation,
                authenticationContext: authenticationContext
            )
        )
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveKemPublicKey(_ algorithm: Int32, handle: UnsafeMutableRawPointer) throws -> Data {
    switch algorithm {
    case CK_KEM_MLKEM768:
        let holder = Unmanaged<CKSecureEnclaveMLKEM768PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return Data(holder.key.publicKey.rawRepresentation)
    case CK_KEM_MLKEM1024:
        let holder = Unmanaged<CKSecureEnclaveMLKEM1024PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return Data(holder.key.publicKey.rawRepresentation)
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveKemDataRepresentation(_ algorithm: Int32, handle: UnsafeMutableRawPointer) throws -> Data {
    switch algorithm {
    case CK_KEM_MLKEM768:
        let holder = Unmanaged<CKSecureEnclaveMLKEM768PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return holder.key.dataRepresentation
    case CK_KEM_MLKEM1024:
        let holder = Unmanaged<CKSecureEnclaveMLKEM1024PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return holder.key.dataRepresentation
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
private func ckSecureEnclaveKemDecapsulate(
    _ algorithm: Int32,
    handle: UnsafeMutableRawPointer,
    encapsulated: Data
) throws -> Data {
    switch algorithm {
    case CK_KEM_MLKEM768:
        let holder = Unmanaged<CKSecureEnclaveMLKEM768PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return try ckPostQuantumSymmetricKeyData(holder.key.decapsulate(encapsulated))
    case CK_KEM_MLKEM1024:
        let holder = Unmanaged<CKSecureEnclaveMLKEM1024PrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return try ckPostQuantumSymmetricKeyData(holder.key.decapsulate(encapsulated))
    default:
        throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_kem_public_key_validate")
public func ck_kem_public_key_validate(
    _ algorithm: Int32,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Post-quantum KEM APIs require macOS 26.0 or newer")
    }

    do {
        let publicKey = try ckData(publicKeyBytes, publicKeyLen)
        return ckCopyData(try ckKemPublicKeyData(algorithm, raw: publicKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_kem_public_key_encapsulate")
public func ck_kem_public_key_encapsulate(
    _ algorithm: Int32,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ sharedSecretOutBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ sharedSecretOutLen: UnsafeMutablePointer<UInt>?,
    _ encapsulatedOutBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ encapsulatedOutLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Post-quantum KEM APIs require macOS 26.0 or newer")
    }

    do {
        let publicKey = try ckData(publicKeyBytes, publicKeyLen)
        let (sharedSecret, encapsulated) = try ckKemEncapsulate(algorithm, rawPublicKey: publicKey)
        return ckCopyTwoData(
            sharedSecret,
            sharedSecretOutBytes,
            sharedSecretOutLen,
            encapsulated,
            encapsulatedOutBytes,
            encapsulatedOutLen,
            errorOut
        )
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_kem_private_key_generate")
public func ck_kem_private_key_generate(
    _ algorithm: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Post-quantum KEM APIs require macOS 26.0 or newer")
    }

    do {
        return ckCopyData(try ckKemPrivateKeyGenerate(algorithm), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_kem_private_key_from_seed")
public func ck_kem_private_key_from_seed(
    _ algorithm: Int32,
    _ seedBytes: UnsafePointer<UInt8>?,
    _ seedLen: UInt,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Post-quantum KEM APIs require macOS 26.0 or newer")
    }

    do {
        let seed = try ckData(seedBytes, seedLen)
        let publicKey = publicKeyLen > 0 ? try ckData(publicKeyBytes, publicKeyLen) : nil
        return ckCopyData(try ckKemPrivateKeyFromSeed(algorithm, seed: seed, publicKey: publicKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_kem_private_key_validate")
public func ck_kem_private_key_validate(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Post-quantum KEM APIs require macOS 26.0 or newer")
    }

    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        return ckCopyData(try ckKemPrivateKeyData(algorithm, integrityChecked: privateKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_kem_private_key_seed_representation")
public func ck_kem_private_key_seed_representation(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Post-quantum KEM APIs require macOS 26.0 or newer")
    }

    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        return ckCopyData(try ckKemPrivateKeySeedRepresentation(algorithm, integrityChecked: privateKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_kem_private_key_public_key")
public func ck_kem_private_key_public_key(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Post-quantum KEM APIs require macOS 26.0 or newer")
    }

    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        return ckCopyData(try ckKemPrivateKeyPublicKey(algorithm, integrityChecked: privateKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_kem_private_key_decapsulate")
public func ck_kem_private_key_decapsulate(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ encapsulatedBytes: UnsafePointer<UInt8>?,
    _ encapsulatedLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Post-quantum KEM APIs require macOS 26.0 or newer")
    }

    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        let encapsulated = try ckData(encapsulatedBytes, encapsulatedLen)
        return ckCopyData(try ckKemDecapsulate(algorithm, integrityChecked: privateKey, encapsulated: encapsulated), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_mldsa_public_key_validate")
public func ck_mldsa_public_key_validate(
    _ algorithm: Int32,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "ML-DSA APIs require macOS 26.0 or newer")
    }

    do {
        let publicKey = try ckData(publicKeyBytes, publicKeyLen)
        return ckCopyData(try ckMldsaPublicKeyData(algorithm, raw: publicKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_mldsa_public_key_verify")
public func ck_mldsa_public_key_verify(
    _ algorithm: Int32,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ signatureBytes: UnsafePointer<UInt8>?,
    _ signatureLen: UInt,
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ contextBytes: UnsafePointer<UInt8>?,
    _ contextLen: UInt,
    _ outValid: UnsafeMutablePointer<UInt8>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "ML-DSA APIs require macOS 26.0 or newer")
    }

    do {
        guard let outValid else {
            throw CKBridgeError.invalidArgument("missing ML-DSA verification output pointer")
        }
        let publicKey = try ckData(publicKeyBytes, publicKeyLen)
        let signature = try ckData(signatureBytes, signatureLen)
        let data = try ckData(dataBytes, dataLen)
        let context = contextLen > 0 ? try ckData(contextBytes, contextLen) : nil
        outValid.pointee = try ckMldsaVerify(algorithm, rawPublicKey: publicKey, signature: signature, data: data, context: context) ? 1 : 0
        return CK_OK
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_SIGNATURE_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_mldsa_private_key_generate")
public func ck_mldsa_private_key_generate(
    _ algorithm: Int32,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "ML-DSA APIs require macOS 26.0 or newer")
    }

    do {
        return ckCopyData(try ckMldsaPrivateKeyGenerate(algorithm), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_mldsa_private_key_from_seed")
public func ck_mldsa_private_key_from_seed(
    _ algorithm: Int32,
    _ seedBytes: UnsafePointer<UInt8>?,
    _ seedLen: UInt,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "ML-DSA APIs require macOS 26.0 or newer")
    }

    do {
        let seed = try ckData(seedBytes, seedLen)
        let publicKey = publicKeyLen > 0 ? try ckData(publicKeyBytes, publicKeyLen) : nil
        return ckCopyData(try ckMldsaPrivateKeyFromSeed(algorithm, seed: seed, publicKey: publicKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_mldsa_private_key_validate")
public func ck_mldsa_private_key_validate(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "ML-DSA APIs require macOS 26.0 or newer")
    }

    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        return ckCopyData(try ckMldsaPrivateKeyData(algorithm, integrityChecked: privateKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_mldsa_private_key_seed_representation")
public func ck_mldsa_private_key_seed_representation(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "ML-DSA APIs require macOS 26.0 or newer")
    }

    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        return ckCopyData(try ckMldsaPrivateKeySeedRepresentation(algorithm, integrityChecked: privateKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_mldsa_private_key_public_key")
public func ck_mldsa_private_key_public_key(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "ML-DSA APIs require macOS 26.0 or newer")
    }

    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        return ckCopyData(try ckMldsaPrivateKeyPublicKey(algorithm, integrityChecked: privateKey), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_mldsa_private_key_sign")
public func ck_mldsa_private_key_sign(
    _ algorithm: Int32,
    _ privateKeyBytes: UnsafePointer<UInt8>?,
    _ privateKeyLen: UInt,
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ contextBytes: UnsafePointer<UInt8>?,
    _ contextLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "ML-DSA APIs require macOS 26.0 or newer")
    }

    do {
        let privateKey = try ckData(privateKeyBytes, privateKeyLen)
        let data = try ckData(dataBytes, dataLen)
        let context = contextLen > 0 ? try ckData(contextBytes, contextLen) : nil
        return ckCopyData(try ckMldsaSign(algorithm, integrityChecked: privateKey, data: data, context: context), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_SIGNATURE_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_mldsa_private_key_generate")
public func ck_secure_enclave_mldsa_private_key_generate(
    _ algorithm: Int32,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
        return nil
    }

    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let holder = try ckSecureEnclaveMldsaHolder(algorithm)
        switch algorithm {
        case CK_MLDSA_65:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLDSA65PrivateKeyHolder).toOpaque()
        case CK_MLDSA_87:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLDSA87PrivateKeyHolder).toOpaque()
        default:
            throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
        }
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_mldsa_private_key_generate_with_options")
public func ck_secure_enclave_mldsa_private_key_generate_with_options(
    _ algorithm: Int32,
    _ accessibility: Int32,
    _ accessControlFlags: UInt64,
    _ authenticationContext: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
        return nil
    }

    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let holder = try ckSecureEnclaveMldsaHolder(
            algorithm,
            accessibility: accessibility,
            accessControlFlags: accessControlFlags,
            authenticationContextHandle: authenticationContext
        )
        switch algorithm {
        case CK_MLDSA_65:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLDSA65PrivateKeyHolder).toOpaque()
        case CK_MLDSA_87:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLDSA87PrivateKeyHolder).toOpaque()
        default:
            throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
        }
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_mldsa_private_key_from_data_representation")
public func ck_secure_enclave_mldsa_private_key_from_data_representation(
    _ algorithm: Int32,
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
        return nil
    }

    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let dataRepresentation = try ckData(dataBytes, dataLen)
        let holder = try ckSecureEnclaveMldsaHolder(algorithm, dataRepresentation: dataRepresentation)
        switch algorithm {
        case CK_MLDSA_65:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLDSA65PrivateKeyHolder).toOpaque()
        case CK_MLDSA_87:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLDSA87PrivateKeyHolder).toOpaque()
        default:
            throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
        }
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_mldsa_private_key_from_data_representation_with_context")
public func ck_secure_enclave_mldsa_private_key_from_data_representation_with_context(
    _ algorithm: Int32,
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ authenticationContext: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
        return nil
    }

    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let dataRepresentation = try ckData(dataBytes, dataLen)
        let holder = try ckSecureEnclaveMldsaHolder(
            algorithm,
            dataRepresentation: dataRepresentation,
            authenticationContextHandle: authenticationContext
        )
        switch algorithm {
        case CK_MLDSA_65:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLDSA65PrivateKeyHolder).toOpaque()
        case CK_MLDSA_87:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLDSA87PrivateKeyHolder).toOpaque()
        default:
            throw CKBridgeError.invalidArgument("unsupported Secure Enclave ML-DSA algorithm: \(algorithm)")
        }
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_mldsa_private_key_release")
public func ck_secure_enclave_mldsa_private_key_release(
    _ algorithm: Int32,
    _ handle: UnsafeMutableRawPointer?
) {
    guard #available(macOS 26.0, *), let handle else {
        return
    }

    switch algorithm {
    case CK_MLDSA_65:
        Unmanaged<CKSecureEnclaveMLDSA65PrivateKeyHolder>.fromOpaque(handle).release()
    case CK_MLDSA_87:
        Unmanaged<CKSecureEnclaveMLDSA87PrivateKeyHolder>.fromOpaque(handle).release()
    default:
        break
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_mldsa_private_key_public_key")
public func ck_secure_enclave_mldsa_private_key_public_key(
    _ algorithm: Int32,
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave ML-DSA handle")
        }
        return ckCopyData(try ckSecureEnclaveMldsaPublicKey(algorithm, handle: handle), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_mldsa_private_key_data_representation")
public func ck_secure_enclave_mldsa_private_key_data_representation(
    _ algorithm: Int32,
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave ML-DSA handle")
        }
        return ckCopyData(try ckSecureEnclaveMldsaDataRepresentation(algorithm, handle: handle), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_mldsa_private_key_sign")
public func ck_secure_enclave_mldsa_private_key_sign(
    _ algorithm: Int32,
    _ handle: UnsafeMutableRawPointer?,
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ contextBytes: UnsafePointer<UInt8>?,
    _ contextLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave ML-DSA handle")
        }
        let data = try ckData(dataBytes, dataLen)
        let context = contextLen > 0 ? try ckData(contextBytes, contextLen) : nil
        return ckCopyData(try ckSecureEnclaveMldsaSign(algorithm, handle: handle, data: data, context: context), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_SIGNATURE_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_kem_private_key_generate")
public func ck_secure_enclave_kem_private_key_generate(
    _ algorithm: Int32,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
        return nil
    }

    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let holder = try ckSecureEnclaveKemHolder(algorithm)
        switch algorithm {
        case CK_KEM_MLKEM768:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLKEM768PrivateKeyHolder).toOpaque()
        case CK_KEM_MLKEM1024:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLKEM1024PrivateKeyHolder).toOpaque()
        default:
            throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
        }
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_kem_private_key_generate_with_options")
public func ck_secure_enclave_kem_private_key_generate_with_options(
    _ algorithm: Int32,
    _ accessibility: Int32,
    _ accessControlFlags: UInt64,
    _ authenticationContext: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
        return nil
    }

    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let holder = try ckSecureEnclaveKemHolder(
            algorithm,
            accessibility: accessibility,
            accessControlFlags: accessControlFlags,
            authenticationContextHandle: authenticationContext
        )
        switch algorithm {
        case CK_KEM_MLKEM768:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLKEM768PrivateKeyHolder).toOpaque()
        case CK_KEM_MLKEM1024:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLKEM1024PrivateKeyHolder).toOpaque()
        default:
            throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
        }
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_kem_private_key_from_data_representation")
public func ck_secure_enclave_kem_private_key_from_data_representation(
    _ algorithm: Int32,
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
        return nil
    }

    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let dataRepresentation = try ckData(dataBytes, dataLen)
        let holder = try ckSecureEnclaveKemHolder(algorithm, dataRepresentation: dataRepresentation)
        switch algorithm {
        case CK_KEM_MLKEM768:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLKEM768PrivateKeyHolder).toOpaque()
        case CK_KEM_MLKEM1024:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLKEM1024PrivateKeyHolder).toOpaque()
        default:
            throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
        }
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_kem_private_key_from_data_representation_with_context")
public func ck_secure_enclave_kem_private_key_from_data_representation_with_context(
    _ algorithm: Int32,
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ authenticationContext: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    guard #available(macOS 26.0, *) else {
        ckWriteError(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
        return nil
    }

    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let dataRepresentation = try ckData(dataBytes, dataLen)
        let holder = try ckSecureEnclaveKemHolder(
            algorithm,
            dataRepresentation: dataRepresentation,
            authenticationContextHandle: authenticationContext
        )
        switch algorithm {
        case CK_KEM_MLKEM768:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLKEM768PrivateKeyHolder).toOpaque()
        case CK_KEM_MLKEM1024:
            return Unmanaged.passRetained(holder as! CKSecureEnclaveMLKEM1024PrivateKeyHolder).toOpaque()
        default:
            throw CKBridgeError.invalidArgument("unsupported Secure Enclave KEM algorithm: \(algorithm)")
        }
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_kem_private_key_release")
public func ck_secure_enclave_kem_private_key_release(
    _ algorithm: Int32,
    _ handle: UnsafeMutableRawPointer?
) {
    guard #available(macOS 26.0, *), let handle else {
        return
    }

    switch algorithm {
    case CK_KEM_MLKEM768:
        Unmanaged<CKSecureEnclaveMLKEM768PrivateKeyHolder>.fromOpaque(handle).release()
    case CK_KEM_MLKEM1024:
        Unmanaged<CKSecureEnclaveMLKEM1024PrivateKeyHolder>.fromOpaque(handle).release()
    default:
        break
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_kem_private_key_public_key")
public func ck_secure_enclave_kem_private_key_public_key(
    _ algorithm: Int32,
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave KEM handle")
        }
        return ckCopyData(try ckSecureEnclaveKemPublicKey(algorithm, handle: handle), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_kem_private_key_data_representation")
public func ck_secure_enclave_kem_private_key_data_representation(
    _ algorithm: Int32,
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave KEM handle")
        }
        return ckCopyData(try ckSecureEnclaveKemDataRepresentation(algorithm, handle: handle), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@available(macOS 26.0, *)
@_cdecl("ck_secure_enclave_kem_private_key_decapsulate")
public func ck_secure_enclave_kem_private_key_decapsulate(
    _ algorithm: Int32,
    _ handle: UnsafeMutableRawPointer?,
    _ encapsulatedBytes: UnsafePointer<UInt8>?,
    _ encapsulatedLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard #available(macOS 26.0, *) else {
        return ckInvalidArgument(errorOut, "Secure Enclave post-quantum APIs require macOS 26.0 or newer")
    }

    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave KEM handle")
        }
        let encapsulated = try ckData(encapsulatedBytes, encapsulatedLen)
        return ckCopyData(try ckSecureEnclaveKemDecapsulate(algorithm, handle: handle, encapsulated: encapsulated), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}
