//
//  SecureMessagingSessionKeyGenerator.swift
//

import Foundation
import CryptoKit

@available(iOS 13, macOS 10.15, *)
class SecureMessagingSessionKeyGenerator {
    
    static let NO_PACE_KEY_REFERENCE: UInt8 = 0x00
    
    enum SMSMode: UInt8 {
        case ENC_MODE = 0x1
        case MAC_MODE = 0x2
        case PACE_MODE = 0x3
    }
    
    // MARK: - Key Derivation
    
    /// Derives ENC or MAC key for BAC from keySeed
    func deriveKey(keySeed: [UInt8], mode: SMSMode) throws -> [UInt8] {
        try deriveKey(keySeed: keySeed, cipherAlgName: "DESede", keyLength: 128, mode: mode)
    }
    
    /// Derives ENC or MAC key for BAC, PACE, or CA
    func deriveKey(keySeed: [UInt8], cipherAlgName: String, keyLength: Int, mode: SMSMode) throws -> [UInt8] {
        try deriveKey(keySeed: keySeed, cipherAlgName: cipherAlgName, keyLength: keyLength, nonce: nil, mode: mode)
    }
    
    /// Derives ENC or MAC key with optional nonce
    func deriveKey(keySeed: [UInt8], cipherAlgName: String, keyLength: Int, nonce: [UInt8]? = nil, mode: SMSMode) throws -> [UInt8] {
        try deriveKey(keySeed: keySeed, cipherAlgName: cipherAlgName, keyLength: keyLength, nonce: nonce, mode: mode, paceKeyReference: Self.NO_PACE_KEY_REFERENCE)
    }

    /// Full key derivation with all parameters
    func deriveKey(keySeed: [UInt8], cipherAlgName: String, keyLength: Int, nonce: [UInt8]?, mode: SMSMode, paceKeyReference: UInt8) throws -> [UInt8] {
        let digestAlgo = try inferDigestAlgorithm(cipherAlg: cipherAlgName, keyLength: keyLength)
        
        var dataElements = [Data(keySeed)]
        if let nonce = nonce {
            dataElements.append(Data(nonce))
        }
        dataElements.append(Data([0x00, 0x00, 0x00, mode.rawValue]))
        
        let hashResult = try computeHash(algorithm: digestAlgo, data: dataElements)
        return try extractKeyBytes(from: hashResult, cipher: cipherAlgName, keyLength: keyLength)
    }
    
    // MARK: - Private Helpers
    
    private func extractKeyBytes(from hash: [UInt8], cipher: String, keyLength: Int) throws -> [UInt8] {
        let cipherLower = cipher.lowercased()
        
        if cipher == "DESede" || cipher == "3DES" {
            guard keyLength == 112 || keyLength == 128 else {
                throw NFCPassportReaderError.InvalidDataPassed("Can only use DESede with 128-bit key length")
            }
            // TR-SAC 1.01, 4.2.1: E (1-8), D (9-16), E (1-8 again)
            return Array(hash[0..<16] + hash[0..<8])
        }
        
        if cipherLower == "aes" || cipherLower.hasPrefix("aes") {
            // TR-SAC 1.01, 4.2.2
            switch keyLength {
            case 128: return Array(hash[0..<16])
            case 192: return Array(hash[0..<24])
            case 256: return Array(hash[0..<32])
            default:
                throw NFCPassportReaderError.InvalidDataPassed("AES requires 128, 192, or 256-bit key length")
            }
        }
        
        throw NFCPassportReaderError.InvalidDataPassed("Unsupported cipher algorithm")
    }
    
    private func inferDigestAlgorithm(cipherAlg: String, keyLength: Int) throws -> String {
        switch (cipherAlg, keyLength) {
        case ("DESede", _), ("AES-128", _), ("AES", 128):
            return "SHA1"
        case ("AES-256", _), ("AES-192", _), ("AES", 192), ("AES", 256):
            return "SHA256"
        default:
            throw NFCPassportReaderError.InvalidDataPassed("Unsupported cipher algorithm or key length")
        }
    }
    
    private func computeHash(algorithm: String, data: [Data]) throws -> [UInt8] {
        switch algorithm.lowercased() {
        case "sha1":
            var hasher = Insecure.SHA1()
            data.forEach { hasher.update(data: $0) }
            return Array(hasher.finalize())
        case "sha256":
            var hasher = SHA256()
            data.forEach { hasher.update(data: $0) }
            return Array(hasher.finalize())
        case "sha384":
            var hasher = SHA384()
            data.forEach { hasher.update(data: $0) }
            return Array(hasher.finalize())
        case "sha512":
            var hasher = SHA512()
            data.forEach { hasher.update(data: $0) }
            return Array(hasher.finalize())
        default:
            throw NFCPassportReaderError.InvalidHashAlgorithmSpecified
        }
    }
}
