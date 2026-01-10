
import Foundation
import OSLog
import OpenSSL
import CryptoTokenKit

#if !os(macOS)
import CoreNFC
import CryptoKit

// MARK: - PACE Key Reference Types

@available(iOS 15, *)
private enum PACEKeyReference: UInt8 {
    case mrz = 0x01
    case can = 0x02  // Not currently supported
    case pin = 0x03  // Not currently supported
    case puk = 0x04  // Not currently supported
}

// MARK: - PACEHandler

@available(iOS 15, *)
public class PACEHandler {
    
    // MARK: - Properties
    
    private let tagReader: TagReader
    private let paceInfo: PACEInfo
    
    private(set) var isPACESupported = false
    private(set) var paceError = ""
    
    // Protocol parameters (set during doPACE)
    private var paceKey = [UInt8]()
    private var paceKeyType: UInt8 = 0
    private var paceOID = ""
    private var parameterSpec: Int32 = -1
    private var mappingType: PACEMappingType!
    private var agreementAlg = ""
    private var cipherAlg = ""
    private var digestAlg = ""
    private var keyLength = -1
    
    // CAM-specific: CA public key extracted from PACE response
    private var camPublicKeyData: [UInt8]?
    
    /// Indicates whether Chip Authentication was implicitly performed via CAM
    public private(set) var chipAuthenticationPerformed = false
    
    // MARK: - Initialization
    
    public init(cardAccess: CardAccess, tagReader: TagReader) throws {
        guard let pi = cardAccess.paceInfo else {
            throw NFCPassportReaderError.NotYetSupported("PACE not supported")
        }
        
        self.tagReader = tagReader
        self.paceInfo = pi
        self.isPACESupported = true
    }
    
    // MARK: - Public API
    
    /// Performs PACE protocol for secure channel establishment
    /// - Parameters:
    ///   - mrzKey: The MRZ key derived from document number, date of birth, and expiry date
    ///   - dg14: Optional DataGroup14 for CAM (Chip Authentication Mapping) verification.
    ///           Required if the passport uses CAM and you want to verify chip authenticity.
    /// - Throws: NFCPassportReaderError if PACE fails
    public func doPACE(mrzKey: String, dg14: DataGroup14? = nil) async throws {
        guard isPACESupported else {
            throw NFCPassportReaderError.NotYetSupported("PACE not supported")
        }
        
        // Reset CAM state
        camPublicKeyData = nil
        chipAuthenticationPerformed = false
        
        Logger.pace.info("Performing PACE with \(self.paceInfo.getProtocolOIDString())")
        
        // Initialize protocol parameters
        try initializeParameters(mrzKey: mrzKey)
        logParameters()
        
        // Start PACE protocol
        _ = try await tagReader.sendMSESetATMutualAuth(oid: paceOID, keyType: paceKeyType)
        
        // Step 1: Get and decrypt nonce
        let decryptedNonce = try await performStep1GetNonce()
        
        // Step 2: Compute ephemeral parameters via mapping
        let ephemeralParams = try await performStep2Mapping(passportNonce: decryptedNonce)
        defer { EVP_PKEY_free(ephemeralParams) }
        
        // Step 3: Key exchange
        let (ephemeralKeyPair, passportPublicKey) = try await performStep3KeyExchange(ephemeralParams: ephemeralParams)
        defer { EVP_PKEY_free(ephemeralKeyPair); EVP_PKEY_free(passportPublicKey) }
        
        // Step 4: Key agreement and authentication
        let (encKey, macKey) = try await performStep4KeyAgreement(
            pcdKeyPair: ephemeralKeyPair,
            passportPublicKey: passportPublicKey
        )
        
        // Complete PACE and restart secure messaging
        try completePACE(ksEnc: encKey, ksMac: macKey)
        Logger.pace.debug("PACE SUCCESSFUL")
        
        // CAM verification: If using CAM and DG14 is provided, verify chip authentication
        if mappingType == .CAM {
            if let dg14 = dg14 {
                try verifyChipAuthenticationMapping(dg14: dg14)
            } else if camPublicKeyData != nil {
                Logger.pace.warning("CAM: CA public key received but DG14 not provided for verification")
                Logger.pace.warning("CAM: Chip authentication cannot be verified without DG14")
            }
        }
    }
    
    // MARK: - Parameter Initialization
    
    private func initializeParameters(mrzKey: String) throws {
        paceOID = paceInfo.getObjectIdentifier()
        parameterSpec = try paceInfo.getParameterSpec()
        mappingType = try paceInfo.getMappingType()
        agreementAlg = try paceInfo.getKeyAgreementAlgorithm()
        cipherAlg = try paceInfo.getCipherAlgorithm()
        digestAlg = try paceInfo.getDigestAlgorithm()
        keyLength = try paceInfo.getKeyLength()
        
        paceKeyType = PACEKeyReference.mrz.rawValue
        paceKey = try createPaceKey(from: mrzKey)
    }
    
    private func logParameters() {
        Logger.pace.debug("PACE parameters:")
        Logger.pace.debug("  OID: \(self.paceOID)")
        Logger.pace.debug("  parameterSpec: \(self.parameterSpec)")
        Logger.pace.debug("  mappingType: \(self.mappingType!.description)")
        Logger.pace.debug("  agreementAlg: \(self.agreementAlg)")
        Logger.pace.debug("  cipherAlg: \(self.cipherAlg)")
        Logger.pace.debug("  digestAlg: \(self.digestAlg)")
        Logger.pace.debug("  keyLength: \(self.keyLength)")
        Logger.pace.debug("  paceKey: \(self.paceKey.hexString)")
    }
    
    // MARK: - Step 1: Get Encrypted Nonce
    
    private func performStep1GetNonce() async throws -> [UInt8] {
        Logger.pace.debug("Step 1: Getting encrypted nonce...")
        
        let response = try await tagReader.sendGeneralAuthenticate(data: [], isLast: false)
        let encryptedNonce = try unwrapDO(tag: 0x80, wrappedData: response.data)
        Logger.pace.debug("Encrypted nonce: \(encryptedNonce.hexString)")
        
        let decryptedNonce = decryptNonce(encryptedNonce)
        Logger.pace.debug("Decrypted nonce: \(decryptedNonce.hexString)")
        
        return decryptedNonce
    }
    
    private func decryptNonce(_ encrypted: [UInt8]) -> [UInt8] {
        switch cipherAlg {
        case "DESede":
            return tripleDESDecrypt(key: paceKey, message: encrypted, iv: [UInt8](repeating: 0, count: 8))
        case "AES":
            return AESDecrypt(key: paceKey, message: encrypted, iv: [UInt8](repeating: 0, count: 16))
        default:
            return encrypted
        }
    }
    
    // MARK: - Step 2: Compute Ephemeral Parameters via Mapping
    
    private func performStep2Mapping(passportNonce: [UInt8]) async throws -> OpaquePointer {
        Logger.pace.debug("Step 2: Computing ephemeral parameters...")
        
        switch mappingType {
        case .GM, .CAM:
            Logger.pace.debug("Using Generic Mapping (GM)")
            return try await performGenericMapping(passportNonce: passportNonce)
        case .IM:
            Logger.pace.debug("Using Integrated Mapping (IM)")
            return try await performIntegratedMapping(passportNonce: passportNonce)
        default:
            throw NFCPassportReaderError.PACEError("Step2", "Unsupported mapping type")
        }
    }
    
    private func performGenericMapping(passportNonce: [UInt8]) async throws -> OpaquePointer {
        // Create mapping key
        let mappingKey = try paceInfo.createMappingKey()
        defer { EVP_PKEY_free(mappingKey) }
        
        guard let pcdMappingPublicKey = OpenSSLUtils.getPublicKeyData(from: mappingKey) else {
            throw NFCPassportReaderError.PACEError("Step2GM", "Unable to get public key from mapping key")
        }
        Logger.pace.debug("PCD mapping public key: \(pcdMappingPublicKey.hexString)")
        
        // Exchange mapping keys with passport
        let step2Data = wrapDO(b: 0x81, arr: pcdMappingPublicKey)
        let response = try await tagReader.sendGeneralAuthenticate(data: step2Data, isLast: false)
        let piccMappingPublicKey = try unwrapDO(tag: 0x82, wrappedData: response.data)
        Logger.pace.debug("PICC mapping public key: \(piccMappingPublicKey.hexString)")
        
        // Convert nonce to BIGNUM
        guard let bnNonce = BN_bin2bn(passportNonce, Int32(passportNonce.count), nil) else {
            throw NFCPassportReaderError.PACEError("Step2GM", "Unable to convert nonce to BIGNUM")
        }
        defer { BN_free(bnNonce) }
        
        // Perform key agreement based on algorithm
        if agreementAlg == "DH" {
            Logger.pace.debug("Performing DH mapping agreement")
            return try DHKeyAgreement.performMappingAgreement(
                mappingKey: mappingKey,
                passportPublicKeyData: piccMappingPublicKey,
                nonce: bnNonce
            )
        } else if agreementAlg == "ECDH" {
            Logger.pace.debug("Performing ECDH mapping agreement")
            return try ECDHKeyAgreement.performMappingAgreement(
                mappingKey: mappingKey,
                passportPublicKeyData: piccMappingPublicKey,
                nonce: bnNonce
            )
        } else {
            throw NFCPassportReaderError.PACEError("Step2GM", "Unsupported agreement algorithm")
        }
    }
    
    private func performIntegratedMapping(passportNonce: [UInt8]) async throws -> OpaquePointer {
        // Create mapping key (generates random scalar internally)
        let mappingKey = try paceInfo.createMappingKey()
        defer { EVP_PKEY_free(mappingKey) }
        
        guard let pcdMappingPublicKey = OpenSSLUtils.getPublicKeyData(from: mappingKey) else {
            throw NFCPassportReaderError.PACEError("Step2IM", "Unable to get public key from mapping key")
        }
        Logger.pace.debug("PCD mapping public key (IM): \(pcdMappingPublicKey.hexString)")
        
        // Exchange mapping keys with passport (same as GM)
        let step2Data = wrapDO(b: 0x81, arr: pcdMappingPublicKey)
        let response = try await tagReader.sendGeneralAuthenticate(data: step2Data, isLast: false)
        let piccMappingPublicKey = try unwrapDO(tag: 0x82, wrappedData: response.data)
        Logger.pace.debug("PICC mapping public key (IM): \(piccMappingPublicKey.hexString)")
        
        // Perform Integrated Mapping based on algorithm
        if agreementAlg == "DH" {
            Logger.pace.debug("Performing DH Integrated Mapping")
            return try DHKeyAgreement.performIntegratedMappingAgreement(
                mappingKey: mappingKey,
                passportPublicKeyData: piccMappingPublicKey,
                nonce: passportNonce,
                cipherAlg: cipherAlg,
                keyLength: keyLength
            )
        } else if agreementAlg == "ECDH" {
            Logger.pace.debug("Performing ECDH Integrated Mapping")
            return try ECDHKeyAgreement.performIntegratedMappingAgreement(
                mappingKey: mappingKey,
                passportPublicKeyData: piccMappingPublicKey,
                nonce: passportNonce,
                cipherAlg: cipherAlg,
                keyLength: keyLength
            )
        } else {
            throw NFCPassportReaderError.PACEError("Step2IM", "Unsupported agreement algorithm")
        }
    }
    
    // MARK: - Step 3: Key Exchange
    
    private func performStep3KeyExchange(ephemeralParams: OpaquePointer) async throws -> (OpaquePointer, OpaquePointer) {
        Logger.pace.debug("Step 3: Key exchange...")
        
        // Generate ephemeral key pair
        let ephemeralKeyPair = try generateEphemeralKeyPair(from: ephemeralParams)
        
        guard let publicKey = OpenSSLUtils.getPublicKeyData(from: ephemeralKeyPair) else {
            EVP_PKEY_free(ephemeralKeyPair)
            throw NFCPassportReaderError.PACEError("Step3", "Unable to get public key from ephemeral key pair")
        }
        Logger.pace.debug("PCD ephemeral public key: \(publicKey.hexString)")
        
        // Exchange public keys
        let step3Data = wrapDO(b: 0x83, arr: publicKey)
        let response = try await tagReader.sendGeneralAuthenticate(data: step3Data, isLast: false)
        
        guard let passportPublicKeyData = try? unwrapDO(tag: 0x84, wrappedData: response.data),
              let passportPublicKey = OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: passportPublicKeyData, params: ephemeralKeyPair) else {
            EVP_PKEY_free(ephemeralKeyPair)
            throw NFCPassportReaderError.PACEError("Step3", "Unable to decode passport's ephemeral key")
        }
        Logger.pace.debug("PICC ephemeral public key: \(passportPublicKeyData.hexString)")
        
        return (ephemeralKeyPair, passportPublicKey)
    }
    
    private func generateEphemeralKeyPair(from params: OpaquePointer) throws -> OpaquePointer {
        guard let ephEcKey = EC_KEY_new() else {
            throw NFCPassportReaderError.PACEError("Step3", "Failed to create EC key")
        }
        defer { EC_KEY_free(ephEcKey) }
        
        guard let ecParams = EVP_PKEY_get0_EC_KEY(params),
              let group = EC_KEY_get0_group(ecParams),
              EC_KEY_set_group(ephEcKey, group) == 1,
              EC_KEY_generate_key(ephEcKey) == 1 else {
            throw NFCPassportReaderError.PACEError("Step3", "Failed to generate EC key")
        }
        
        guard let ephemeralKeyPair = EVP_PKEY_new(),
              EVP_PKEY_set1_EC_KEY(ephemeralKeyPair, ephEcKey) == 1 else {
            throw NFCPassportReaderError.PACEError("Step3", "Unable to create ephemeral key pair")
        }
        
        Logger.pace.debug("Generated ephemeral key pair")
        return ephemeralKeyPair
    }
    
    // MARK: - Step 4: Key Agreement
    
    private func performStep4KeyAgreement(
        pcdKeyPair: OpaquePointer,
        passportPublicKey: OpaquePointer
    ) async throws -> ([UInt8], [UInt8]) {
        Logger.pace.debug("Step 4: Key agreement...")
        
        // Compute shared secret
        let sharedSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair: pcdKeyPair, publicKey: passportPublicKey)
        Logger.pace.debug("Shared secret: \(sharedSecret.hexString)")
        
        // Derive session keys
        let gen = SecureMessagingSessionKeyGenerator()
        let encKey = try gen.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let macKey = try gen.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)
        Logger.pace.debug("encKey: \(encKey.hexString)")
        Logger.pace.debug("macKey: \(macKey.hexString)")
        
        // Generate and send authentication token
        let pcdAuthToken = try generateAuthenticationToken(publicKey: passportPublicKey, macKey: macKey)
        Logger.pace.debug("PCD auth token: \(pcdAuthToken.hexString)")
        
        let step4Data = wrapDO(b: 0x85, arr: pcdAuthToken)
        let response = try await tagReader.sendGeneralAuthenticate(data: step4Data, isLast: true)
        
        // Verify passport's authentication token
        let tlvResponse = TKBERTLVRecord.sequenceOfRecords(from: Data(response.data))!
        
        var piccTokenData: [UInt8]?
        
        // Parse response TLV records
        for record in tlvResponse {
            switch record.tag {
            case 0x86:
                // Authentication token
                piccTokenData = [UInt8](record.value)
            case 0x87:
                // CAM: Chip Authentication public key (only present in CAM)
                camPublicKeyData = [UInt8](record.value)
                Logger.pace.debug("CAM: Received CA public key: \(self.camPublicKeyData!.hexString)")
            default:
                Logger.pace.debug("Step4: Ignoring unknown tag \(String(format: "0x%02X", record.tag))")
            }
        }
        
        guard let piccToken = piccTokenData else {
            throw NFCPassportReaderError.PACEError("Step4", "Missing authentication token (tag 0x86)")
        }
        
        let expectedPICCToken = try generateAuthenticationToken(publicKey: pcdKeyPair, macKey: macKey)
        
        Logger.pace.debug("Expected PICC token: \(expectedPICCToken.hexString)")
        Logger.pace.debug("Received PICC token: \(piccToken.hexString)")
        
        guard piccToken == expectedPICCToken else {
            throw NFCPassportReaderError.PACEError("Step4", "PICC token mismatch")
        }
        
        Logger.pace.debug("Auth token verified!")
        return (encKey, macKey)
    }
    
    // MARK: - PACE Completion
    
    private func completePACE(ksEnc: [UInt8], ksMac: [UInt8]) throws {
        Logger.pace.info("Restarting secure messaging using \(self.cipherAlg) encryption")
        tagReader.secureMessaging = createSecureMessaging(cipherAlgorithm: cipherAlg, ksEnc: ksEnc, ksMac: ksMac)
    }
    
    // MARK: - CAM Verification
    
    /// Verifies Chip Authentication Mapping by comparing the CA public key from PACE with DG14
    /// - Parameter dg14: DataGroup14 containing the chip's public key info
    /// - Throws: NFCPassportReaderError if verification fails
    private func verifyChipAuthenticationMapping(dg14: DataGroup14) throws {
        guard let camPublicKey = camPublicKeyData else {
            throw NFCPassportReaderError.PACEError("CAM", "No CA public key received from chip")
        }
        
        Logger.pace.debug("CAM: Verifying chip authentication...")
        
        // Find matching public key in DG14
        var foundMatch = false
        
        for secInfo in dg14.securityInfos {
            guard let capki = secInfo as? ChipAuthenticationPublicKeyInfo else {
                continue
            }
            
            // Get the public key data from DG14
            guard let dg14PublicKeyData = OpenSSLUtils.getPublicKeyData(from: capki.pubKey) else {
                Logger.pace.warning("CAM: Unable to extract public key data from DG14")
                continue
            }
            
            // Compare the public keys
            if camPublicKey == dg14PublicKeyData {
                Logger.pace.info("CAM: Chip authentication verified successfully (keyId: \(capki.keyId ?? 0))")
                foundMatch = true
                chipAuthenticationPerformed = true
                break
            }
        }
        
        if !foundMatch {
            Logger.pace.error("CAM: CA public key from PACE does not match any key in DG14")
            throw NFCPassportReaderError.PACEError("CAM", "CA public key verification failed - no matching key in DG14")
        }
    }
    
    // MARK: - Authentication Token
    
    private func generateAuthenticationToken(publicKey: OpaquePointer, macKey: [UInt8]) throws -> [UInt8] {
        var encodedPublicKey = try encodePublicKey(oid: paceOID, key: publicKey)
        
        if cipherAlg == "DESede" {
            encodedPublicKey = pad(encodedPublicKey, blockSize: 8)
        }
        
        Logger.pace.debug("Encoded public key: \(encodedPublicKey.hexString)")
        
        let algorithm: SecureMessagingSupportedAlgorithms = cipherAlg == "DESede" ? .DES : .AES
        let maccedData = mac(algoName: algorithm, key: macKey, msg: encodedPublicKey)
        
        return [UInt8](maccedData[0..<8])
    }
    
    private func encodePublicKey(oid: String, key: OpaquePointer) throws -> [UInt8] {
        let encodedOid = oidToBytes(oid: oid, replaceTag: false)
        
        guard let pubKeyData = OpenSSLUtils.getPublicKeyData(from: key) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get public key data")
        }
        
        let keyType = EVP_PKEY_get_base_id(key)
        let tag: TKTLVTag = (keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX) ? 0x84 : 0x86
        
        guard let encOid = TKBERTLVRecord(from: Data(encodedOid)) else {
            throw NFCPassportReaderError.InvalidASN1Value
        }
        
        let encPub = TKBERTLVRecord(tag: tag, value: Data(pubKeyData))
        let record = TKBERTLVRecord(tag: 0x7F49, records: [encOid, encPub])
        
        return [UInt8](record.data)
    }
    
    // MARK: - PACE Key Derivation
    
    private func createPaceKey(from mrzKey: String) throws -> [UInt8] {
        let hash = calcSHA1Hash(Array(mrzKey.utf8))
        let smskg = SecureMessagingSessionKeyGenerator()
        return try smskg.deriveKey(
            keySeed: hash,
            cipherAlgName: cipherAlg,
            keyLength: keyLength,
            nonce: nil,
            mode: .PACE_MODE,
            paceKeyReference: paceKeyType
        )
    }
}

#endif
