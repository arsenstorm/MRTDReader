
import Foundation
import OSLog

/// Supported encryption algorithms for secure messaging
public enum SecureMessagingSupportedAlgorithms {
    case DES
    case AES
    
    var blockSize: Int {
        self == .DES ? 8 : 16
    }
    
    var zeroIV: [UInt8] {
        [UInt8](repeating: 0, count: blockSize)
    }
}

#if !os(macOS)
import CoreNFC

/// Implements the secure messaging protocol for ICAO 9303 compliant documents.
///
/// This class provides a layer between the reader and ISO 7816 communication,
/// encrypting outgoing APDUs and decrypting incoming responses according to
/// the ICAO Doc 9303 specification.
@available(iOS 13, *)
public class SecureMessaging {
    
    // MARK: - Properties
    
    private let ksenc: [UInt8]
    private let ksmac: [UInt8]
    private var ssc: [UInt8]
    private let algorithm: SecureMessagingSupportedAlgorithms
    
    // MARK: - Initialization
    
    public init(
        encryptionAlgorithm: SecureMessagingSupportedAlgorithms = .DES,
        ksenc: [UInt8],
        ksmac: [UInt8],
        ssc: [UInt8]
    ) {
        self.ksenc = ksenc
        self.ksmac = ksmac
        self.ssc = ssc
        self.algorithm = encryptionAlgorithm
    }
    
    // MARK: - Public API
    
    /// Protects an APDU following the ICAO Doc 9303 specification
    func protect(apdu: NFCISO7816APDU, useExtendedMode: Bool = false) throws -> NFCISO7816APDU {
        Logger.secureMessaging.debug("SSC: \(self.ssc.hexString)")
        incrementSSC()
        Logger.secureMessaging.debug("SSC incremented: \(self.ssc.hexString)")
        
        let paddedSSC = paddedSendSequenceCounter
        let maskedHeader = maskClassAndPad(apdu: apdu)
        
        // Build data objects
        let encryptedDataObject = apdu.data != nil ? try buildEncryptedDataObject(apdu: apdu) : []
        let expectedLengthObject = shouldIncludeExpectedLength(apdu: apdu) ? try buildExpectedLengthObject(apdu: apdu) : []
        
        // Concatenate for MAC calculation
        let dataToMAC = maskedHeader + encryptedDataObject + expectedLengthObject
        Logger.secureMessaging.debug("M: \(dataToMAC.hexString)")
        
        // Compute MAC
        let macInput = pad(paddedSSC + dataToMAC, blockSize: algorithm.blockSize)
        Logger.secureMessaging.debug("N (padded): \(macInput.hexString)")
        
        let mac = computeMAC(macInput)
        Logger.secureMessaging.debug("CC: \(mac.hexString)")
        
        let macObject = buildMACObject(mac: mac)
        
        // Build final protected APDU
        return try buildProtectedAPDU(
            header: maskedHeader,
            encryptedData: encryptedDataObject,
            expectedLength: expectedLengthObject,
            mac: macObject,
            useExtendedMode: useExtendedMode,
            originalExpectedLength: apdu.expectedResponseLength
        )
    }
    
    /// Unprotects a response APDU following the ICAO Doc 9303 specification
    func unprotect(rapdu: ResponseAPDU) throws -> ResponseAPDU {
        // Check for SM error
        guard rapdu.isSuccess else {
            return rapdu
        }
        
        incrementSSC()
        let paddedSSC = paddedSendSequenceCounter
        Logger.secureMessaging.debug("SSC incremented: \(self.ssc.hexString)")
        
        let responseData = rapdu.data + [rapdu.sw1, rapdu.sw2]
        Logger.secureMessaging.debug("RAPDU: \(responseData.hexString)")
        
        var offset = 0
        var encryptedDataObject = [UInt8]()
        var encryptedContent = [UInt8]()
        var statusObject = [UInt8]()
        var needsMAC = false
        
        // Parse DO'87 (encrypted data) if present
        if responseData[offset] == ISO7816.SMTag.encryptedData {
            let (length, lengthBytes) = try asn1Length([UInt8](responseData[(offset + 1)...]))
            offset += 1 + lengthBytes
            
            guard responseData[offset] == 0x01 else {
                throw NFCPassportReaderError.D087Malformed
            }
            
            encryptedDataObject = [UInt8](responseData[0..<(offset + length)])
            encryptedContent = [UInt8](responseData[(offset + 1)..<(offset + length)])
            offset += length
            needsMAC = true
        }
        
        // Parse DO'99 (status word)
        guard responseData.count >= offset + 4 else {
            Logger.secureMessaging.error("Response too short for status")
            let sw1 = responseData.count > offset + 2 ? responseData[offset + 2] : 0
            let sw2 = responseData.count > offset + 3 ? responseData[offset + 3] : 0
            return ResponseAPDU(data: [], sw1: sw1, sw2: sw2)
        }
        
        statusObject = [UInt8](responseData[offset..<(offset + 4)])
        let sw1 = responseData[offset + 2]
        let sw2 = responseData[offset + 3]
        offset += 4
        needsMAC = true
        
        guard statusObject[0] == ISO7816.SMTag.processingStatus && statusObject[1] == 0x02 else {
            return ResponseAPDU(data: [], sw1: sw1, sw2: sw2)
        }
        
        // Parse DO'8E (MAC) if required
        if responseData[offset] == ISO7816.SMTag.cryptographicChecksum {
            let macLength = Int(responseData[offset + 1])
            let receivedMAC = [UInt8](responseData[(offset + 2)..<(offset + 2 + macLength)])
            
            // Verify MAC
            let macInput = pad(paddedSSC + encryptedDataObject + statusObject, blockSize: algorithm.blockSize)
            Logger.secureMessaging.debug("K (padded): \(macInput.hexString)")
            
            let expectedMAC = computeMAC(macInput)
            Logger.secureMessaging.debug("Expected CC: \(expectedMAC.hexString)")
            
            guard receivedMAC == expectedMAC else {
                throw NFCPassportReaderError.InvalidResponseChecksum
            }
        } else if needsMAC {
            throw NFCPassportReaderError.MissingMandatoryFields
        }
        
        // Decrypt data if present
        var decryptedData = [UInt8]()
        if !encryptedContent.isEmpty {
            decryptedData = unpad(decryptData(encryptedContent))
            Logger.secureMessaging.debug("Decrypted data: \(decryptedData.hexString)")
        }
        
        Logger.secureMessaging.debug("Unprotected APDU: [\(decryptedData.hexString)] \(String(format: "%02X %02X", sw1, sw2))")
        return ResponseAPDU(data: decryptedData, sw1: sw1, sw2: sw2)
    }
    
    // MARK: - SSC Management
    
    private var paddedSendSequenceCounter: [UInt8] {
        algorithm == .DES ? ssc : [UInt8](repeating: 0, count: 8) + ssc
    }
    
    private func incrementSSC() {
        let value = binToHex(ssc) + 1
        ssc = withUnsafeBytes(of: value.bigEndian, Array.init)
    }
    
    // MARK: - Header Processing
    
    private func maskClassAndPad(apdu: NFCISO7816APDU) -> [UInt8] {
        let masked = [ISO7816.InstructionClass.secureMessaging, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter]
        let padded = pad(masked, blockSize: algorithm.blockSize)
        Logger.secureMessaging.debug("Masked header: \(padded.hexString)")
        return padded
    }
    
    // MARK: - Data Object Building
    
    /// Builds DO'87 - Encrypted data object
    private func buildEncryptedDataObject(apdu: NFCISO7816APDU) throws -> [UInt8] {
        let paddingIndicator: UInt8 = 0x01
        let encryptedContent = paddingIndicator.bytes + encryptData(apdu)
        let result = try [ISO7816.SMTag.encryptedData] + toAsn1Length(encryptedContent.count) + encryptedContent
        Logger.secureMessaging.debug("DO'87: \(result.hexString)")
        return result
    }
    
    /// Builds DO'97 - Expected response length object
    private func buildExpectedLengthObject(apdu: NFCISO7816APDU) throws -> [UInt8] {
        let le = apdu.expectedResponseLength
        var encodedLength = intToBin(le)
        
        // Handle special cases for max length
        if le == 256 || le == 65536 {
            encodedLength = [0x00] + (le > 256 ? [0x00] : [])
        }
        
        let result = try [ISO7816.SMTag.expectedLength] + toAsn1Length(encodedLength.count) + encodedLength
        Logger.secureMessaging.debug("DO'97: \(result.hexString)")
        return result
    }
    
    /// Builds DO'8E - MAC object
    private func buildMACObject(mac: [UInt8]) -> [UInt8] {
        let result = [ISO7816.SMTag.cryptographicChecksum, UInt8(mac.count)] + mac
        Logger.secureMessaging.debug("DO'8E: \(result.hexString)")
        return result
    }
    
    // MARK: - Encryption/Decryption
    
    private func encryptData(_ apdu: NFCISO7816APDU) -> [UInt8] {
        let data = [UInt8](apdu.data!)
        let paddedData = pad(data, blockSize: algorithm.blockSize)
        
        let encrypted: [UInt8]
        switch algorithm {
        case .DES:
            encrypted = tripleDESEncrypt(key: ksenc, message: paddedData, iv: algorithm.zeroIV)
        case .AES:
            let iv = computeAESIV()
            encrypted = AESEncrypt(key: ksenc, message: paddedData, iv: iv)
        }
        
        Logger.secureMessaging.debug("Padded data: \(paddedData.hexString)")
        Logger.secureMessaging.debug("Encrypted: \(encrypted.hexString)")
        return encrypted
    }
    
    private func decryptData(_ encryptedData: [UInt8]) -> [UInt8] {
        switch algorithm {
        case .DES:
            return tripleDESDecrypt(key: ksenc, message: encryptedData, iv: algorithm.zeroIV)
        case .AES:
            let iv = computeAESIV()
            return AESDecrypt(key: ksenc, message: encryptedData, iv: iv)
        }
    }
    
    private func computeAESIV() -> [UInt8] {
        let paddedSSC = [UInt8](repeating: 0, count: 8) + ssc
        return AESECBEncrypt(key: ksenc, message: paddedSSC)
    }
    
    // MARK: - MAC Computation
    
    private func computeMAC(_ data: [UInt8]) -> [UInt8] {
        var result = mac(algoName: algorithm, key: ksmac, msg: data)
        if result.count > 8 {
            result = [UInt8](result[0..<8])
        }
        return result
    }
    
    // MARK: - Protected APDU Construction
    
    private func buildProtectedAPDU(
        header: [UInt8],
        encryptedData: [UInt8],
        expectedLength: [UInt8],
        mac: [UInt8],
        useExtendedMode: Bool,
        originalExpectedLength: Int
    ) throws -> NFCISO7816APDU {
        let dataSize = encryptedData.count + expectedLength.count + mac.count
        let useExtended = dataSize > 255 || (useExtendedMode && originalExpectedLength > 231)
        
        // Build length encoding
        let sizeBytes: [UInt8] = useExtended
            ? [0x00] + intToBin(dataSize, pad: 4)
            : intToBin(dataSize)
        
        // Build final APDU
        var protectedAPDU = [UInt8](header[0..<4]) + sizeBytes
        protectedAPDU += encryptedData + expectedLength + mac
        protectedAPDU += useExtended ? [0x00, 0x00] : [0x00]
        
        Logger.secureMessaging.debug("Protected APDU: \(protectedAPDU.hexString)")
        
        guard let apdu = NFCISO7816APDU(data: Data(protectedAPDU)) else {
            throw NFCPassportReaderError.UnableToProtectAPDU
        }
        return apdu
    }
    
    // MARK: - Helpers
    
    private func shouldIncludeExpectedLength(apdu: NFCISO7816APDU) -> Bool {
        let isMSE = apdu.instructionCode == ISO7816.Instruction.mseSetAT
        return apdu.expectedResponseLength > 0 && (isMSE ? apdu.expectedResponseLength < 256 : true)
    }
}

// MARK: - UInt8 Extension

private extension UInt8 {
    var bytes: [UInt8] { [self] }
}
#endif
