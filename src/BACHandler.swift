//
//  BACHandler.swift
//

import Foundation
import OSLog

#if !os(macOS)
import CoreNFC

/// Handles Basic Access Control (BAC) authentication with the passport chip
@available(iOS 15, *)
public class BACHandler {
    
    public var ksenc: [UInt8] = []
    public var ksmac: [UInt8] = []
    public var kifd: [UInt8] = []
    
    var rnd_icc: [UInt8] = []
    var rnd_ifd: [UInt8] = []
    var tagReader: TagReader?
    
    public init() {}
    
    public init(tagReader: TagReader) {
        self.tagReader = tagReader
    }

    // MARK: - Public API
    
    public func performBACAndGetSessionKeys(mrzKey: String) async throws {
        guard let tagReader = self.tagReader else {
            throw NFCPassportReaderError.NoConnectedTag
        }
        
        Logger.bac.debugIfEnabled("BACHandler - deriving Document Basic Access Keys")
        _ = try deriveDocumentBasicAccessKeys(mrz: mrzKey)
        
        // Clear secure messaging (could happen if we read an invalid DG or hit a secure error)
        tagReader.secureMessaging = nil
        
        Logger.bac.debugIfEnabled("BACHandler - Getting initial challenge")
        let response = try await tagReader.getChallenge()
        Logger.bac.debugIfEnabled("Received challenge (\(response.data.count) bytes)")
        
        Logger.bac.debugIfEnabled("BACHandler - Doing mutual authentication")
        let cmdData = authentication(rnd_icc: [UInt8](response.data))
        let maResponse = try await tagReader.doMutualAuthentication(cmdData: Data(cmdData))
        Logger.bac.debugIfEnabled("Received mutual auth response (\(maResponse.data.count) bytes)")
        
        guard !maResponse.data.isEmpty else {
            throw NFCPassportReaderError.InvalidMRZKey
        }
        
        let (KSenc, KSmac, ssc) = try sessionKeys(data: [UInt8](maResponse.data))
        tagReader.secureMessaging = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        Logger.bac.debugIfEnabled("BACHandler - complete")
    }

    // MARK: - Key Derivation
    
    func deriveDocumentBasicAccessKeys(mrz: String) throws -> ([UInt8], [UInt8]) {
        let kseed = generateInitialKseed(kmrz: mrz)
    
        Logger.bac.debugIfEnabled("Calculate the Basic Access Keys (Kenc and Kmac) using TR-SAC 1.01, 4.2")
        let smskg = SecureMessagingSessionKeyGenerator()
        ksenc = try smskg.deriveKey(keySeed: kseed, mode: .ENC_MODE)
        ksmac = try smskg.deriveKey(keySeed: kseed, mode: .MAC_MODE)
                
        return (ksenc, ksmac)
    }
    
    /// Calculate kseed from kmrz: SHA-1 hash, take first 16 bytes
    func generateInitialKseed(kmrz: String) -> [UInt8] {
        Logger.bac.debugIfEnabled("Calculate the SHA-1 hash of MRZ_information")
        
        let hash = calcSHA1Hash([UInt8](kmrz.data(using: .utf8)!))
        Logger.bac.debugIfEnabled("Generated hash (\(hash.count) bytes)")
        
        let subHash = Array(hash[0..<16])
        Logger.bac.debugIfEnabled("Take the most significant 16 bytes to form the Kseed")
        
        return subHash
    }
    
    // MARK: - Authentication
    
    /// Construct command data for mutual authentication
    func authentication(rnd_icc: [UInt8]) -> [UInt8] {
        self.rnd_icc = rnd_icc
        
        Logger.bac.debugIfEnabled("Received 8 byte random number from the MRTD's chip")

        let rnd_ifd = generateRandomUInt8Array(8)
        let kifd = generateRandomUInt8Array(16)
        
        Logger.bac.debugIfEnabled("Generated 8 byte and 16 byte random values")
        
        let s = rnd_ifd + rnd_icc + kifd
        Logger.bac.debugIfEnabled("Concatenated RND.IFD, RND.ICC and Kifd (\(s.count) bytes)")
        
        let iv: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let eifd = tripleDESEncrypt(key: ksenc, message: s, iv: iv)
        Logger.bac.debugIfEnabled("Encrypted S with TDES key Kenc (\(eifd.count) bytes)")
        
        let mifd = mac(algoName: .DES, key: ksmac, msg: pad(eifd, blockSize: 8))
        Logger.bac.debugIfEnabled("Computed MAC over eifd (\(mifd.count) bytes)")
        
        let cmdData = eifd + mifd
        Logger.bac.debugIfEnabled("Constructed command data for MUTUAL AUTHENTICATE (\(cmdData.count) bytes)")
        
        self.rnd_ifd = rnd_ifd
        self.kifd = kifd

        return cmdData
    }
    
    // MARK: - Session Keys
    
    /// Calculate session keys (KSenc, KSmac) and SSC from mutual auth response
    public func sessionKeys(data: [UInt8]) throws -> ([UInt8], [UInt8], [UInt8]) {
        Logger.bac.debugIfEnabled("Decrypt and verify received data")
        
        let response = tripleDESDecrypt(key: ksenc, message: Array(data[0..<32]), iv: [0, 0, 0, 0, 0, 0, 0, 0])
        let responseKicc = Array(response[16..<32])
        let Kseed = xor(kifd, responseKicc)
        
        Logger.bac.debugIfEnabled("Calculated XOR of Kifd and Kicc")
        
        let smskg = SecureMessagingSessionKeyGenerator()
        let KSenc = try smskg.deriveKey(keySeed: Kseed, mode: .ENC_MODE)
        let KSmac = try smskg.deriveKey(keySeed: Kseed, mode: .MAC_MODE)
        
        Logger.bac.debugIfEnabled("Calculated Session Keys (enc: \(KSenc.count) bytes, mac: \(KSmac.count) bytes)")
        
        let ssc = Array(rnd_icc.suffix(4) + rnd_ifd.suffix(4))
        Logger.bac.debugIfEnabled("Calculated Send Sequence Counter (\(ssc.count) bytes)")
        
        return (KSenc, KSmac, ssc)
    }
}

#endif
