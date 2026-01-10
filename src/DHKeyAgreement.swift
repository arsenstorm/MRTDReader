
import Foundation
import OSLog
import OpenSSL

#if !os(macOS)

/// Errors specific to DH key agreement operations
@available(iOS 15, *)
public enum DHKeyAgreementError: Error, LocalizedError {
    case failedToGetMappingKey
    case failedToInitializeEphemeralParams
    case failedToGenerateNewParams
    case failedToSetParameters
    case failedToCreateEphemeralParams
    
    public var errorDescription: String? {
        switch self {
        case .failedToGetMappingKey:
            return "Unable to get DH mapping key"
        case .failedToInitializeEphemeralParams:
            return "Unable to initialize ephemeral parameters from DH mapping key"
        case .failedToGenerateNewParams:
            return "Failed to generate new DH parameters"
        case .failedToSetParameters:
            return "Unable to set DH pqg parameters"
        case .failedToCreateEphemeralParams:
            return "Unable to create DH ephemeral params"
        }
    }
}

/// Handles Diffie-Hellman key agreement for PACE Generic Mapping
@available(iOS 15, *)
public struct DHKeyAgreement {
    
    /// Performs DH key mapping agreement for PACE GM
    /// - Parameters:
    ///   - mappingKey: EVP_PKEY containing the DH mapping key
    ///   - passportPublicKeyData: Public key data received from passport
    ///   - nonce: BIGNUM containing the decrypted nonce
    /// - Returns: EVP_PKEY containing the mapped ephemeral parameters
    public static func performMappingAgreement(
        mappingKey: OpaquePointer,
        passportPublicKeyData: [UInt8],
        nonce: OpaquePointer
    ) throws -> OpaquePointer {
        
        guard let dhMappingKey = EVP_PKEY_get1_DH(mappingKey) else {
            throw DHKeyAgreementError.failedToGetMappingKey
        }
        defer { DH_free(dhMappingKey) }
        
        // Compute shared secret using mapping key and passport's public mapping key
        let sharedSecret = computeSharedSecret(dhKey: dhMappingKey, publicKeyData: passportPublicKeyData)
        
        // Convert shared secret to BIGNUM
        let bnH = BN_bin2bn(sharedSecret, Int32(sharedSecret.count), nil)
        defer { BN_clear_free(bnH) }
        
        // Initialize ephemeral parameters from mapping key
        guard let ephemeralKey = DHparams_dup(dhMappingKey) else {
            throw DHKeyAgreementError.failedToInitializeEphemeralParams
        }
        
        // Get p, q, g from mapping key
        var p: OpaquePointer?
        var q: OpaquePointer?
        var g: OpaquePointer?
        DH_get0_pqg(dhMappingKey, &p, &q, &g)
        
        // Map to new generator
        let newGenerator = try computeNewGenerator(p: p!, g: g!, nonce: nonce, h: bnH!)
        
        // Set new parameters
        guard DH_set0_pqg(ephemeralKey, BN_dup(p), BN_dup(q), newGenerator) == 1 else {
            DH_free(ephemeralKey)
            BN_free(newGenerator)
            throw DHKeyAgreementError.failedToSetParameters
        }
        
        // Wrap in EVP_PKEY
        guard let ephemeralParams = EVP_PKEY_new() else {
            DH_free(ephemeralKey)
            throw DHKeyAgreementError.failedToCreateEphemeralParams
        }
        
        guard EVP_PKEY_set1_DH(ephemeralParams, ephemeralKey) == 1 else {
            EVP_PKEY_free(ephemeralParams)
            DH_free(ephemeralKey)
            throw DHKeyAgreementError.failedToSetParameters
        }
        
        DH_free(ephemeralKey)
        return ephemeralParams
    }
    
    // MARK: - Private Helpers
    
    private static func computeSharedSecret(dhKey: OpaquePointer, publicKeyData: [UInt8]) -> [UInt8] {
        let bn = BN_bin2bn(publicKeyData, Int32(publicKeyData.count), nil)
        defer { BN_free(bn) }
        
        var secret = [UInt8](repeating: 0, count: Int(DH_size(dhKey)))
        DH_compute_key(&secret, bn, dhKey)
        return secret
    }
    
    private static func computeNewGenerator(
        p: OpaquePointer,
        g: OpaquePointer,
        nonce: OpaquePointer,
        h: OpaquePointer
    ) throws -> OpaquePointer {
        
        guard let bnG = BN_new(), let newG = BN_new() else {
            throw DHKeyAgreementError.failedToGenerateNewParams
        }
        
        let ctx = BN_CTX_new()
        defer { BN_CTX_free(ctx) }
        
        // bn_g = g^nonce mod p
        // new_g = bn_g * h mod p => (g^nonce mod p) * h mod p
        guard BN_mod_exp(bnG, g, nonce, p, ctx) == 1,
              BN_mod_mul(newG, bnG, h, p, ctx) == 1 else {
            BN_free(bnG)
            BN_free(newG)
            throw DHKeyAgreementError.failedToGenerateNewParams
        }
        
        BN_free(bnG)
        return newG
    }
}

#endif
