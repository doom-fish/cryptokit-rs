import CryptoKit
import Foundation

private final class CKSecureEnclaveSigningPrivateKeyHolder {
    let key: SecureEnclave.P256.Signing.PrivateKey

    init(_ key: SecureEnclave.P256.Signing.PrivateKey) {
        self.key = key
    }
}

private final class CKSecureEnclaveKeyAgreementPrivateKeyHolder {
    let key: SecureEnclave.P256.KeyAgreement.PrivateKey

    init(_ key: SecureEnclave.P256.KeyAgreement.PrivateKey) {
        self.key = key
    }
}

private func ckSecureEnclaveSigningPrivateKeyHolder(from dataRepresentation: Data) throws -> CKSecureEnclaveSigningPrivateKeyHolder {
    try CKSecureEnclaveSigningPrivateKeyHolder(
        SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
    )
}

private func ckSecureEnclaveKeyAgreementPrivateKeyHolder(from dataRepresentation: Data) throws -> CKSecureEnclaveKeyAgreementPrivateKeyHolder {
    try CKSecureEnclaveKeyAgreementPrivateKeyHolder(
        SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: dataRepresentation)
    )
}

private func ckSecureEnclaveSigningPrivateKeyHolder(
    compactRepresentable: Bool,
    accessibility: Int32,
    accessControlFlags: UInt64,
    authenticationContextHandle: UnsafeMutableRawPointer?
) throws -> CKSecureEnclaveSigningPrivateKeyHolder {
    let authenticationContext = try ckAuthenticationContext(authenticationContextHandle)
    if let accessControl = try ckSecureEnclaveAccessControl(accessibility, accessControlFlags) {
        return try CKSecureEnclaveSigningPrivateKeyHolder(
            SecureEnclave.P256.Signing.PrivateKey(
                compactRepresentable: compactRepresentable,
                accessControl: accessControl,
                authenticationContext: authenticationContext
            )
        )
    }
    return try CKSecureEnclaveSigningPrivateKeyHolder(
        SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: compactRepresentable,
            authenticationContext: authenticationContext
        )
    )
}

private func ckSecureEnclaveSigningPrivateKeyHolder(
    from dataRepresentation: Data,
    authenticationContextHandle: UnsafeMutableRawPointer?
) throws -> CKSecureEnclaveSigningPrivateKeyHolder {
    try CKSecureEnclaveSigningPrivateKeyHolder(
        SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: dataRepresentation,
            authenticationContext: try ckAuthenticationContext(authenticationContextHandle)
        )
    )
}

private func ckSecureEnclaveKeyAgreementPrivateKeyHolder(
    compactRepresentable: Bool,
    accessibility: Int32,
    accessControlFlags: UInt64,
    authenticationContextHandle: UnsafeMutableRawPointer?
) throws -> CKSecureEnclaveKeyAgreementPrivateKeyHolder {
    let authenticationContext = try ckAuthenticationContext(authenticationContextHandle)
    if let accessControl = try ckSecureEnclaveAccessControl(accessibility, accessControlFlags) {
        return try CKSecureEnclaveKeyAgreementPrivateKeyHolder(
            SecureEnclave.P256.KeyAgreement.PrivateKey(
                compactRepresentable: compactRepresentable,
                accessControl: accessControl,
                authenticationContext: authenticationContext
            )
        )
    }
    return try CKSecureEnclaveKeyAgreementPrivateKeyHolder(
        SecureEnclave.P256.KeyAgreement.PrivateKey(
            compactRepresentable: compactRepresentable,
            authenticationContext: authenticationContext
        )
    )
}

private func ckSecureEnclaveKeyAgreementPrivateKeyHolder(
    from dataRepresentation: Data,
    authenticationContextHandle: UnsafeMutableRawPointer?
) throws -> CKSecureEnclaveKeyAgreementPrivateKeyHolder {
    try CKSecureEnclaveKeyAgreementPrivateKeyHolder(
        SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: dataRepresentation,
            authenticationContext: try ckAuthenticationContext(authenticationContextHandle)
        )
    )
}

@_cdecl("ck_secure_enclave_is_available")
public func ck_secure_enclave_is_available(
    _ outAvailable: UnsafeMutablePointer<UInt8>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    guard let outAvailable else {
        return ckInvalidArgument(errorOut, "missing Secure Enclave availability output pointer")
    }
    outAvailable.pointee = SecureEnclave.isAvailable ? 1 : 0
    return CK_OK
}

@_cdecl("ck_secure_enclave_signing_private_key_generate")
public func ck_secure_enclave_signing_private_key_generate(
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey()
        return Unmanaged.passRetained(CKSecureEnclaveSigningPrivateKeyHolder(key)).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_secure_enclave_signing_private_key_generate_with_options")
public func ck_secure_enclave_signing_private_key_generate_with_options(
    _ compactRepresentable: UInt8,
    _ accessibility: Int32,
    _ accessControlFlags: UInt64,
    _ authenticationContext: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let holder = try ckSecureEnclaveSigningPrivateKeyHolder(
            compactRepresentable: compactRepresentable != 0,
            accessibility: accessibility,
            accessControlFlags: accessControlFlags,
            authenticationContextHandle: authenticationContext
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

@_cdecl("ck_secure_enclave_signing_private_key_from_data_representation")
public func ck_secure_enclave_signing_private_key_from_data_representation(
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let dataRepresentation = try ckData(dataBytes, dataLen)
        return Unmanaged.passRetained(try ckSecureEnclaveSigningPrivateKeyHolder(from: dataRepresentation)).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_secure_enclave_signing_private_key_from_data_representation_with_context")
public func ck_secure_enclave_signing_private_key_from_data_representation_with_context(
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ authenticationContext: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let dataRepresentation = try ckData(dataBytes, dataLen)
        return Unmanaged.passRetained(
            try ckSecureEnclaveSigningPrivateKeyHolder(
                from: dataRepresentation,
                authenticationContextHandle: authenticationContext
            )
        ).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_secure_enclave_signing_private_key_release")
public func ck_secure_enclave_signing_private_key_release(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else {
        return
    }
    Unmanaged<CKSecureEnclaveSigningPrivateKeyHolder>.fromOpaque(handle).release()
}

@_cdecl("ck_secure_enclave_signing_private_key_public_key")
public func ck_secure_enclave_signing_private_key_public_key(
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave signing-key handle")
        }
        let holder = Unmanaged<CKSecureEnclaveSigningPrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return ckCopyData(Data(holder.key.publicKey.rawRepresentation), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_secure_enclave_signing_private_key_data_representation")
public func ck_secure_enclave_signing_private_key_data_representation(
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave signing-key handle")
        }
        let holder = Unmanaged<CKSecureEnclaveSigningPrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return ckCopyData(holder.key.dataRepresentation, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_secure_enclave_signing_private_key_sign")
public func ck_secure_enclave_signing_private_key_sign(
    _ handle: UnsafeMutableRawPointer?,
    _ messageBytes: UnsafePointer<UInt8>?,
    _ messageLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave signing-key handle")
        }
        let message = try ckData(messageBytes, messageLen)
        let holder = Unmanaged<CKSecureEnclaveSigningPrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        let signature = try holder.key.signature(for: message)
        return ckCopyData(Data(signature.rawRepresentation), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_SIGNATURE_FAILED, error, errorOut)
    }
}

@_cdecl("ck_secure_enclave_key_agreement_private_key_generate")
public func ck_secure_enclave_key_agreement_private_key_generate(
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let key = try SecureEnclave.P256.KeyAgreement.PrivateKey()
        return Unmanaged.passRetained(CKSecureEnclaveKeyAgreementPrivateKeyHolder(key)).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_secure_enclave_key_agreement_private_key_generate_with_options")
public func ck_secure_enclave_key_agreement_private_key_generate_with_options(
    _ compactRepresentable: UInt8,
    _ accessibility: Int32,
    _ accessControlFlags: UInt64,
    _ authenticationContext: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let holder = try ckSecureEnclaveKeyAgreementPrivateKeyHolder(
            compactRepresentable: compactRepresentable != 0,
            accessibility: accessibility,
            accessControlFlags: accessControlFlags,
            authenticationContextHandle: authenticationContext
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

@_cdecl("ck_secure_enclave_key_agreement_private_key_from_data_representation")
public func ck_secure_enclave_key_agreement_private_key_from_data_representation(
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let dataRepresentation = try ckData(dataBytes, dataLen)
        return Unmanaged.passRetained(try ckSecureEnclaveKeyAgreementPrivateKeyHolder(from: dataRepresentation)).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_secure_enclave_key_agreement_private_key_from_data_representation_with_context")
public func ck_secure_enclave_key_agreement_private_key_from_data_representation_with_context(
    _ dataBytes: UnsafePointer<UInt8>?,
    _ dataLen: UInt,
    _ authenticationContext: UnsafeMutableRawPointer?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> UnsafeMutableRawPointer? {
    do {
        guard SecureEnclave.isAvailable else {
            throw CKBridgeError.invalidArgument("Secure Enclave is unavailable on this Mac")
        }
        let dataRepresentation = try ckData(dataBytes, dataLen)
        return Unmanaged.passRetained(
            try ckSecureEnclaveKeyAgreementPrivateKeyHolder(
                from: dataRepresentation,
                authenticationContextHandle: authenticationContext
            )
        ).toOpaque()
    } catch let error as CKBridgeError {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    } catch {
        ckWriteError(errorOut, error.localizedDescription)
        return nil
    }
}

@_cdecl("ck_secure_enclave_key_agreement_private_key_release")
public func ck_secure_enclave_key_agreement_private_key_release(_ handle: UnsafeMutableRawPointer?) {
    guard let handle else {
        return
    }
    Unmanaged<CKSecureEnclaveKeyAgreementPrivateKeyHolder>.fromOpaque(handle).release()
}

@_cdecl("ck_secure_enclave_key_agreement_private_key_public_key")
public func ck_secure_enclave_key_agreement_private_key_public_key(
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave key-agreement handle")
        }
        let holder = Unmanaged<CKSecureEnclaveKeyAgreementPrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return ckCopyData(Data(holder.key.publicKey.rawRepresentation), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_secure_enclave_key_agreement_private_key_data_representation")
public func ck_secure_enclave_key_agreement_private_key_data_representation(
    _ handle: UnsafeMutableRawPointer?,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave key-agreement handle")
        }
        let holder = Unmanaged<CKSecureEnclaveKeyAgreementPrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        return ckCopyData(holder.key.dataRepresentation, outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_KEY_FAILED, error, errorOut)
    }
}

@_cdecl("ck_secure_enclave_key_agreement_private_key_shared_secret")
public func ck_secure_enclave_key_agreement_private_key_shared_secret(
    _ handle: UnsafeMutableRawPointer?,
    _ publicKeyBytes: UnsafePointer<UInt8>?,
    _ publicKeyLen: UInt,
    _ outBytes: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>?,
    _ outLen: UnsafeMutablePointer<UInt>?,
    _ errorOut: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?
) -> Int32 {
    do {
        guard let handle else {
            throw CKBridgeError.invalidArgument("missing Secure Enclave key-agreement handle")
        }
        let peerPublicKey = try P256.KeyAgreement.PublicKey(rawRepresentation: ckData(publicKeyBytes, publicKeyLen))
        let holder = Unmanaged<CKSecureEnclaveKeyAgreementPrivateKeyHolder>.fromOpaque(handle).takeUnretainedValue()
        let sharedSecret = try holder.key.sharedSecretFromKeyAgreement(with: peerPublicKey)
        return ckCopyData(sharedSecret.withUnsafeBytes(ckOwnedData), outBytes, outLen, errorOut)
    } catch let error as CKBridgeError {
        return ckFail(CK_INVALID_ARGUMENT, error, errorOut)
    } catch {
        return ckFail(CK_AGREEMENT_FAILED, error, errorOut)
    }
}
