import Foundation
import OSLog
import OpenSSL

#if !os(macOS)

/// Errors specific to ECDH key agreement operations
@available(iOS 15, *)
public enum ECDHKeyAgreementError: Error, LocalizedError {
    case failedToGetECGroup
    case failedToCreateBignum
    case failedToGetGroupParameters
    case failedToComputeSharedSecret
    case failedToCreateGenerator
    case failedToMapNonce
    case failedToCreateEphemeralParams
    case failedToConfigureParams
    
    public var errorDescription: String? {
        switch self {
        case .failedToGetECGroup:
            return "Unable to get EC group"
        case .failedToCreateBignum:
            return "Unable to create BIGNUM"
        case .failedToGetGroupParameters:
            return "Unable to get order or cofactor from group"
        case .failedToComputeSharedSecret:
            return "Failed to compute shared secret mapping point"
        case .failedToCreateGenerator:
            return "Unable to create new mapping generator point"
        case .failedToMapNonce:
            return "Failed to map nonce to get new generator params"
        case .failedToCreateEphemeralParams:
            return "Unable to create ephemeral params"
        case .failedToConfigureParams:
            return "Unable to configure new ephemeral params"
        }
    }
}

/// Handles Elliptic Curve Diffie-Hellman key agreement for PACE Generic Mapping
@available(iOS 15, *)
public struct ECDHKeyAgreement {
    
    /// Performs ECDH key mapping agreement for PACE GM
    /// - Parameters:
    ///   - mappingKey: EVP_PKEY containing the EC mapping key
    ///   - passportPublicKeyData: Public key data received from passport
    ///   - nonce: BIGNUM containing the decrypted nonce
    /// - Returns: EVP_PKEY containing the mapped ephemeral parameters
    public static func performMappingAgreement(
        mappingKey: OpaquePointer,
        passportPublicKeyData: [UInt8],
        nonce: OpaquePointer
    ) throws -> OpaquePointer {
        
        let ecMappingKey = EVP_PKEY_get1_EC_KEY(mappingKey)
        defer { EC_KEY_free(ecMappingKey) }
        
        guard let group = EC_GROUP_dup(EC_KEY_get0_group(ecMappingKey)) else {
            throw ECDHKeyAgreementError.failedToGetECGroup
        }
        defer { EC_GROUP_free(group) }
        
        // Get group parameters
        guard let order = BN_new(), let cofactor = BN_new() else {
            throw ECDHKeyAgreementError.failedToCreateBignum
        }
        defer { BN_free(order); BN_free(cofactor) }
        
        guard EC_GROUP_get_order(group, order, nil) == 1,
              EC_GROUP_get_cofactor(group, cofactor, nil) == 1 else {
            throw ECDHKeyAgreementError.failedToGetGroupParameters
        }
        
        // Compute shared secret as EC point
        guard let sharedSecretPoint = computeMappingKeyPoint(
            privateKey: mappingKey,
            publicKeyData: passportPublicKeyData
        ) else {
            throw ECDHKeyAgreementError.failedToComputeSharedSecret
        }
        defer { EC_POINT_free(sharedSecretPoint) }
        
        // Map nonce using Generic Mapping to get new generator
        guard let newGenerator = EC_POINT_new(group) else {
            throw ECDHKeyAgreementError.failedToCreateGenerator
        }
        
        // g = (generator * nonce) + (sharedSecretPoint * 1)
        guard EC_POINT_mul(group, newGenerator, nonce, sharedSecretPoint, BN_value_one(), nil) == 1 else {
            EC_POINT_free(newGenerator)
            throw ECDHKeyAgreementError.failedToMapNonce
        }
        defer { EC_POINT_free(newGenerator) }
        
        // Create ephemeral params
        guard let ephemeralParams = EVP_PKEY_new() else {
            throw ECDHKeyAgreementError.failedToCreateEphemeralParams
        }
        
        let ephemeralKey = EC_KEY_dup(ecMappingKey)
        defer { EC_KEY_free(ephemeralKey) }
        
        // Configure new EC_KEY with mapped generator
        guard EVP_PKEY_set1_EC_KEY(ephemeralParams, ephemeralKey) == 1,
              EC_GROUP_set_generator(group, newGenerator, order, cofactor) == 1,
              EC_GROUP_check(group, nil) == 1,
              EC_KEY_set_group(ephemeralKey, group) == 1 else {
            EVP_PKEY_free(ephemeralParams)
            throw ECDHKeyAgreementError.failedToConfigureParams
        }
        
        return ephemeralParams
    }
    
    // MARK: - Private Helpers
    
    /// Computes the ECDH mapping key point by multiplying private key with public key
    /// - Parameters:
    ///   - privateKey: EVP_PKEY containing ECDH private key
    ///   - publicKeyData: Public key bytes
    /// - Returns: EC_POINT representing the computed point
    private static func computeMappingKeyPoint(
        privateKey: OpaquePointer,
        publicKeyData: [UInt8]
    ) -> OpaquePointer? {
        
        let ecdh = EVP_PKEY_get1_EC_KEY(privateKey)
        defer { EC_KEY_free(ecdh) }
        
        let privateECKey = EC_KEY_get0_private_key(ecdh)
        
        guard let group = EC_KEY_get0_group(ecdh),
              let inputPoint = EC_POINT_new(group) else {
            return nil
        }
        defer { EC_POINT_free(inputPoint) }
        
        // Decode public key to EC point
        guard EC_POINT_oct2point(group, inputPoint, publicKeyData, publicKeyData.count, nil) != 0 else {
            return nil
        }
        
        // Create output point
        guard let outputPoint = EC_POINT_new(group) else {
            return nil
        }
        
        // Multiply private key with passport's public key
        EC_POINT_mul(group, outputPoint, nil, inputPoint, privateECKey, nil)
        
        return outputPoint
    }
}

#endif
