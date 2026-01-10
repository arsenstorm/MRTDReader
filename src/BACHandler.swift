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
        
        Logger.bac.debug("BACHandler - deriving Document Basic Access Keys")
        _ = try deriveDocumentBasicAccessKeys(mrz: mrzKey)
        
        // Clear secure messaging (could happen if we read an invalid DG or hit a secure error)
        tagReader.secureMessaging = nil
        
        Logger.bac.debug("BACHandler - Getting initial challenge")
        let response = try await tagReader.getChallenge()
        Logger.bac.debug("DATA - \(response.data)")
        
        Logger.bac.debug("BACHandler - Doing mutual authentication")
        let cmdData = authentication(rnd_icc: [UInt8](response.data))
        let maResponse = try await tagReader.doMutualAuthentication(cmdData: Data(cmdData))
        Logger.bac.debug("DATA - \(maResponse.data)")
        
        guard !maResponse.data.isEmpty else {
            throw NFCPassportReaderError.InvalidMRZKey
        }
        
        let (KSenc, KSmac, ssc) = try sessionKeys(data: [UInt8](maResponse.data))
        tagReader.secureMessaging = SecureMessaging(ksenc: KSenc, ksmac: KSmac, ssc: ssc)
        Logger.bac.debug("BACHandler - complete")
    }

    // MARK: - Key Derivation
    
    func deriveDocumentBasicAccessKeys(mrz: String) throws -> ([UInt8], [UInt8]) {
        let kseed = generateInitialKseed(kmrz: mrz)
    
        Logger.bac.debug("Calculate the Basic Access Keys (Kenc and Kmac) using TR-SAC 1.01, 4.2")
        let smskg = SecureMessagingSessionKeyGenerator()
        ksenc = try smskg.deriveKey(keySeed: kseed, mode: .ENC_MODE)
        ksmac = try smskg.deriveKey(keySeed: kseed, mode: .MAC_MODE)
                
        return (ksenc, ksmac)
    }
    
    /// Calculate kseed from kmrz: SHA-1 hash, take first 16 bytes
    func generateInitialKseed(kmrz: String) -> [UInt8] {
        Logger.bac.debug("Calculate the SHA-1 hash of MRZ_information")
        Logger.bac.debug("\tMRZ KEY - \(kmrz)")
        
        let hash = calcSHA1Hash([UInt8](kmrz.data(using: .utf8)!))
        Logger.bac.debug("\tsha1(MRZ_information): \(hash.hexString)")
        
        let subHash = Array(hash[0..<16])
        Logger.bac.debug("Take the most significant 16 bytes to form the Kseed")
        Logger.bac.debug("\tKseed: \(subHash.hexString)")
        
        return subHash
    }
    
    // MARK: - Authentication
    
    /// Construct command data for mutual authentication
    func authentication(rnd_icc: [UInt8]) -> [UInt8] {
        self.rnd_icc = rnd_icc
        
        Logger.bac.debug("Request an 8 byte random number from the MRTD's chip")
        Logger.bac.debug("\tRND.ICC: \(rnd_icc.hexString)")

        let rnd_ifd = generateRandomUInt8Array(8)
        let kifd = generateRandomUInt8Array(16)
        
        Logger.bac.debug("Generate an 8 byte random and a 16 byte random")
        Logger.bac.debug("\tRND.IFD: \(rnd_ifd.hexString)")
        Logger.bac.debug("\tRND.Kifd: \(kifd.hexString)")
        
        let s = rnd_ifd + rnd_icc + kifd
        Logger.bac.debug("Concatenate RND.IFD, RND.ICC and Kifd")
        Logger.bac.debug("\tS: \(s.hexString)")
        
        let iv: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
        let eifd = tripleDESEncrypt(key: ksenc, message: s, iv: iv)
        Logger.bac.debug("Encrypt S with TDES key Kenc")
        Logger.bac.debug("\tEifd: \(eifd.hexString)")
        
        let mifd = mac(algoName: .DES, key: ksmac, msg: pad(eifd, blockSize: 8))
        Logger.bac.debug("Compute MAC over eifd with TDES key Kmac")
        Logger.bac.debug("\tMifd: \(mifd.hexString)")
        
        let cmdData = eifd + mifd
        Logger.bac.debug("Construct command data for MUTUAL AUTHENTICATE")
        Logger.bac.debug("\tcmd_data: \(cmdData.hexString)")
        
        self.rnd_ifd = rnd_ifd
        self.kifd = kifd

        return cmdData
    }
    
    // MARK: - Session Keys
    
    /// Calculate session keys (KSenc, KSmac) and SSC from mutual auth response
    public func sessionKeys(data: [UInt8]) throws -> ([UInt8], [UInt8], [UInt8]) {
        Logger.bac.debug("Decrypt and verify received data")
        
        let response = tripleDESDecrypt(key: ksenc, message: Array(data[0..<32]), iv: [0, 0, 0, 0, 0, 0, 0, 0])
        let responseKicc = Array(response[16..<32])
        let Kseed = xor(kifd, responseKicc)
        
        Logger.bac.debug("Calculate XOR of Kifd and Kicc")
        Logger.bac.debug("\tKseed: \(Kseed.hexString)")
        
        let smskg = SecureMessagingSessionKeyGenerator()
        let KSenc = try smskg.deriveKey(keySeed: Kseed, mode: .ENC_MODE)
        let KSmac = try smskg.deriveKey(keySeed: Kseed, mode: .MAC_MODE)
        
        Logger.bac.debug("Calculate Session Keys")
        Logger.bac.debug("\tKSenc: \(KSenc.hexString)")
        Logger.bac.debug("\tKSmac: \(KSmac.hexString)")
        
        let ssc = Array(rnd_icc.suffix(4) + rnd_ifd.suffix(4))
        Logger.bac.debug("Calculate Send Sequence Counter")
        Logger.bac.debug("\tSSC: \(ssc.hexString)")
        
        return (KSenc, KSmac, ssc)
    }
}

#endif
