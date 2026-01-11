
import Foundation
import OSLog
import OpenSSL

#if !os(macOS)
import CoreNFC
import CryptoKit

@available(iOS 15, *)
class ChipAuthenticationHandler {
    
    // MARK: - Constants
    
    private static let commandChainingChunkSize = 224
    
    /// OID inference mapping from public key type to chip auth algorithm
    private static let oidInference: [String: String] = [
        SecurityInfo.ID_PK_ECDH_OID: SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID,
        SecurityInfo.ID_PK_DH_OID: SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID
    ]
    
    // MARK: - Properties
    
    private weak var tagReader: TagReader?
    private var gaSegments = [[UInt8]]()
    
    private var chipAuthInfos = [Int: ChipAuthenticationInfo]()
    private var chipAuthPublicKeyInfos = [ChipAuthenticationPublicKeyInfo]()
    
    private(set) var isChipAuthenticationSupported = false
    
    // MARK: - Initialization
    
    init(dg14: DataGroup14, tagReader: TagReader) {
        self.tagReader = tagReader
        
        for secInfo in dg14.securityInfos {
            if let cai = secInfo as? ChipAuthenticationInfo {
                chipAuthInfos[cai.getKeyId()] = cai
            } else if let capki = secInfo as? ChipAuthenticationPublicKeyInfo {
                chipAuthPublicKeyInfos.append(capki)
            }
        }
        
        isChipAuthenticationSupported = !chipAuthPublicKeyInfos.isEmpty
    }
    
    // MARK: - Public API
    
    func doChipAuthentication() async throws {
        Logger.chipAuth.infoIfEnabled("Performing Chip Authentication - \(self.chipAuthPublicKeyInfos.count) public key(s) found")
        
        guard isChipAuthenticationSupported else {
            throw NFCPassportReaderError.NotYetSupported("ChipAuthentication not supported")
        }
        
        for pubKey in chipAuthPublicKeyInfos {
            if try await performChipAuth(with: pubKey) {
                return
            }
        }
        
        throw NFCPassportReaderError.ChipAuthenticationFailed
    }
    
    // MARK: - Private Implementation
    
    private func performChipAuth(with publicKeyInfo: ChipAuthenticationPublicKeyInfo) async throws -> Bool {
        let keyId = publicKeyInfo.keyId
        
        // Determine OID: from ChipAuthInfo if available, otherwise infer from public key
        let chipAuthOID: String
        if let chipAuthInfo = chipAuthInfos[keyId ?? 0] {
            chipAuthOID = chipAuthInfo.oid
        } else if let inferredOID = Self.oidInference[publicKeyInfo.oid] {
            Logger.chipAuth.warningIfEnabled("No ChipAuthenticationInfo - inferring OID")
            chipAuthOID = inferredOID
        } else {
            Logger.chipAuth.warningIfEnabled("Unsupported ChipAuthenticationPublicKeyInfo public key OID")
            return false
        }
        
        try await executeChipAuth(keyId: keyId, oid: chipAuthOID, publicKey: publicKeyInfo.pubKey)
        return true
    }
    
    private func executeChipAuth(keyId: Int?, oid: String, publicKey: OpaquePointer) async throws {
        // Generate ephemeral key pair from DG14 public key parameters
        var ephemeralKeyPair: OpaquePointer?
        let pctx = EVP_PKEY_CTX_new(publicKey, nil)
        defer { EVP_PKEY_CTX_free(pctx) }
        
        EVP_PKEY_keygen_init(pctx)
        EVP_PKEY_keygen(pctx, &ephemeralKeyPair)
        
        guard let keyPair = ephemeralKeyPair else {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }
        defer { EVP_PKEY_free(keyPair) }
        
        // Send public key to passport
        try await sendPublicKey(oid: oid, keyId: keyId, pcdPublicKey: keyPair)
        Logger.chipAuth.debugIfEnabled("Public key successfully sent to passport")
        
        // Compute shared secret using ECDH/DH
        let sharedSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair: keyPair, publicKey: publicKey)
        
        // Restart secure messaging with new keys
        try restartSecureMessaging(oid: oid, sharedSecret: sharedSecret)
    }
    
    // MARK: - Public Key Exchange
    
    private func sendPublicKey(oid: String, keyId: Int?, pcdPublicKey: OpaquePointer) async throws {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        
        guard let keyData = OpenSSLUtils.getPublicKeyData(from: pcdPublicKey) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get public key data")
        }
        
        if cipherAlg.hasPrefix("DESede") {
            try await sendPublicKeyDES(keyData: keyData, keyId: keyId)
        } else if cipherAlg.hasPrefix("AES") {
            try await sendPublicKeyAES(oid: oid, keyId: keyId, keyData: keyData)
        } else {
            throw NFCPassportReaderError.InvalidDataPassed("Cipher algorithm \(cipherAlg) not supported")
        }
    }
    
    private func sendPublicKeyDES(keyData: [UInt8], keyId: Int?) async throws {
        var idData = [UInt8]()
        if let keyId = keyId {
            idData = wrapDO(b: 0x84, arr: intToBytes(val: keyId, removePadding: true))
        }
        let wrappedKeyData = wrapDO(b: 0x91, arr: keyData)
        
        _ = try await tagReader?.sendMSEKAT(keyData: Data(wrappedKeyData), idData: Data(idData))
    }
    
    private func sendPublicKeyAES(oid: String, keyId: Int?, keyData: [UInt8]) async throws {
        _ = try await tagReader?.sendMSESetATIntAuth(oid: oid, keyId: keyId)
        
        let wrappedData = wrapDO(b: 0x80, arr: keyData)
        gaSegments = chunk(wrappedData, size: Self.commandChainingChunkSize)
        
        while !gaSegments.isEmpty {
            let segment = gaSegments.removeFirst()
            _ = try await tagReader?.sendGeneralAuthenticate(data: segment, isLast: gaSegments.isEmpty)
        }
    }
    
    // MARK: - Secure Messaging
    
    private func restartSecureMessaging(oid: String, sharedSecret: [UInt8]) throws {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        let keyLength = try ChipAuthenticationInfo.toKeyLength(oid: oid)
        
        // Derive session keys
        let smskg = SecureMessagingSessionKeyGenerator()
        let ksEnc = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let ksMac = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)
        
        Logger.chipAuth.infoIfEnabled("Restarting secure messaging using \(cipherAlg) encryption")
        tagReader?.secureMessaging = createSecureMessaging(cipherAlgorithm: cipherAlg, ksEnc: ksEnc, ksMac: ksMac)
    }
}
#endif
