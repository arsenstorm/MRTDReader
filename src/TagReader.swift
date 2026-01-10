
import Foundation
import OSLog

#if !os(macOS)
import CoreNFC

@available(iOS 15, *)
public class TagReader {
    
    // MARK: - Properties
    
    let tag: NFCISO7816Tag
    var secureMessaging: SecureMessaging?
    var progress: ((Int) -> Void)?
    
    /// Maximum bytes to read per command. Starts high for speed, reduces on errors for compatibility.
    private var maxReadLength: Int = 0xFF
    
    /// Stepping values for reducing read length on errors
    private static let readLengthSteps: [Int] = [0xA0, 0x80, 0x40, 0x20]
    
    // MARK: - Initialization
    
    init(tag: NFCISO7816Tag) {
        self.tag = tag
    }
    
    // MARK: - Read Length Management
    
    func reduceDataReadingAmount() {
        for step in Self.readLengthSteps where maxReadLength > step {
            maxReadLength = step
            return
        }
    }
    
    // MARK: - Data Group Reading
    
    func readDataGroup(dataGroup: DataGroupId) async throws -> [UInt8] {
        guard let fileTag = dataGroup.getFileIDTag() else {
            throw NFCPassportReaderError.UnsupportedDataGroup
        }
        return try await selectFileAndRead(tag: fileTag)
    }
    
    // MARK: - Authentication Commands
    
    func getChallenge() async throws -> ResponseAPDU {
        let cmd = NFCISO7816APDU(
            instructionClass: ISO7816.InstructionClass.standard,
            instructionCode: ISO7816.Instruction.getChallenge,
            p1Parameter: 0,
            p2Parameter: 0,
            data: Data(),
            expectedResponseLength: 8
        )
        return try await send(cmd: cmd)
    }
    
    func doInternalAuthentication(challenge: [UInt8], useExtendedMode: Bool) async throws -> ResponseAPDU {
        let responseLength = useExtendedMode ? 65535 : 256
        let cmd = NFCISO7816APDU(
            instructionClass: ISO7816.InstructionClass.standard,
            instructionCode: ISO7816.Instruction.internalAuthenticate,
            p1Parameter: 0,
            p2Parameter: 0,
            data: Data(challenge),
            expectedResponseLength: responseLength
        )
        return try await send(cmd: cmd, useExtendedMode: useExtendedMode)
    }
    
    func doMutualAuthentication(cmdData: Data) async throws -> ResponseAPDU {
        let cmd = NFCISO7816APDU(
            instructionClass: ISO7816.InstructionClass.standard,
            instructionCode: ISO7816.Instruction.externalAuthenticate,
            p1Parameter: 0,
            p2Parameter: 0,
            data: cmdData,
            expectedResponseLength: 256
        )
        return try await send(cmd: cmd)
    }
    
    // MARK: - MSE Commands
    
    /// MSE KAT APDU for DESede case (EAC 1.11 spec, Section B.1)
    func sendMSEKAT(keyData: Data, idData: Data?) async throws -> ResponseAPDU {
        var data = keyData
        if let idData = idData {
            data += idData
        }
        
        let cmd = NFCISO7816APDU(
            instructionClass: ISO7816.InstructionClass.standard,
            instructionCode: ISO7816.Instruction.mseSetAT,
            p1Parameter: ISO7816.MSE.setForInternalAuth,
            p2Parameter: ISO7816.MSE.templateKAT,
            data: data,
            expectedResponseLength: 256
        )
        return try await send(cmd: cmd)
    }
    
    /// MSE Set AT for Chip Authentication (AES case)
    func sendMSESetATIntAuth(oid: String, keyId: Int?) async throws -> ResponseAPDU {
        var data = oidToBytes(oid: oid, replaceTag: true)
        
        if let keyId = keyId, keyId != 0 {
            let keyIdBytes = wrapDO(b: 0x84, arr: intToBytes(val: keyId, removePadding: true))
            data += keyIdBytes
        }
        
        let cmd = NFCISO7816APDU(
            instructionClass: ISO7816.InstructionClass.standard,
            instructionCode: ISO7816.Instruction.mseSetAT,
            p1Parameter: ISO7816.MSE.setForInternalAuth,
            p2Parameter: ISO7816.MSE.templateAT,
            data: Data(data),
            expectedResponseLength: 256
        )
        return try await send(cmd: cmd)
    }
    
    func sendMSESetATMutualAuth(oid: String, keyType: UInt8) async throws -> ResponseAPDU {
        let oidBytes = oidToBytes(oid: oid, replaceTag: true)
        let keyTypeBytes = wrapDO(b: 0x83, arr: [keyType])
        let data = oidBytes + keyTypeBytes
        
        let cmd = NFCISO7816APDU(
            instructionClass: ISO7816.InstructionClass.standard,
            instructionCode: ISO7816.Instruction.mseSetAT,
            p1Parameter: ISO7816.MSE.setForMutualAuth,
            p2Parameter: ISO7816.MSE.templateAT,
            data: Data(data),
            expectedResponseLength: -1
        )
        return try await send(cmd: cmd)
    }
    
    // MARK: - General Authenticate
    
    /// Sends a General Authenticate command (PACE protocol)
    /// - Parameters:
    ///   - data: Data to send (without 0x7C prefix - this method adds it)
    ///   - lengthExpected: Expected response length (default 256)
    ///   - isLast: Whether this is the last command in the chain
    /// - Returns: Response data (without 0x7C prefix - this method removes it)
    func sendGeneralAuthenticate(data: [UInt8], lengthExpected: Int = 256, isLast: Bool) async throws -> ResponseAPDU {
        let wrappedData = wrapDO(b: 0x7C, arr: data)
        let instructionClass: UInt8 = isLast ? ISO7816.InstructionClass.standard : ISO7816.InstructionClass.chaining
        
        let cmd = NFCISO7816APDU(
            instructionClass: instructionClass,
            instructionCode: ISO7816.Instruction.generalAuthenticate,
            p1Parameter: 0x00,
            p2Parameter: 0x00,
            data: Data(wrappedData),
            expectedResponseLength: lengthExpected
        )
        
        var response: ResponseAPDU
        do {
            response = try await send(cmd: cmd)
            response.data = try unwrapDO(tag: 0x7C, wrappedData: response.data)
        } catch let error as NFCPassportReaderError {
            // Retry with different length on wrong length error
            if case .ResponseError(_, let sw1, let sw2) = error, sw1 == 0x67, sw2 == 0x00 {
                let retryCmd = NFCISO7816APDU(
                    instructionClass: instructionClass,
                    instructionCode: ISO7816.Instruction.generalAuthenticate,
                    p1Parameter: 0x00,
                    p2Parameter: 0x00,
                    data: Data(wrappedData),
                    expectedResponseLength: 256
                )
                response = try await send(cmd: retryCmd)
                response.data = try unwrapDO(tag: 0x7C, wrappedData: response.data)
            } else {
                throw error
            }
        }
        return response
    }
    
    // MARK: - File Operations
    
    func selectFileAndRead(tag: [UInt8]) async throws -> [UInt8] {
        _ = try await selectFile(tag: tag)
        
        // Read first 4 bytes of header to determine data structure size
        guard let readHeaderCmd = NFCISO7816APDU(data: Data([0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x04])) else {
            throw NFCPassportReaderError.UnexpectedError
        }
        let headerResp = try await send(cmd: readHeaderCmd)
        
        // Parse header: <tag><length><nextTag>
        // Total length = length value + header bytes
        let (length, lengthBytes) = try asn1Length([UInt8](headerResp.data[1..<4]))
        var remaining = Int(length)
        var amountRead = lengthBytes + 1
        var data = [UInt8](headerResp.data[..<amountRead])
        
        Logger.tagReader.debug("Bytes to read: \(remaining)")
        
        // Read remaining data in chunks
        while remaining > 0 {
            let readAmount = min(remaining, maxReadLength == 256 ? maxReadLength : min(remaining, maxReadLength))
            reportProgress(amountRead: amountRead, total: amountRead + remaining)
            
            let offset = intToBin(amountRead, pad: 4)
            Logger.tagReader.debug("Reading \(readAmount) bytes at offset \(amountRead)")
            
            let cmd = NFCISO7816APDU(
                instructionClass: ISO7816.InstructionClass.standard,
                instructionCode: ISO7816.Instruction.readBinary,
                p1Parameter: offset[0],
                p2Parameter: offset[1],
                data: Data(),
                expectedResponseLength: readAmount
            )
            let resp = try await send(cmd: cmd)
            
            Logger.tagReader.debug("Received \(resp.data.count) bytes")
            data += resp.data
            remaining -= resp.data.count
            amountRead += resp.data.count
        }
        
        return data
    }
    
    func readCardAccess() async throws -> [UInt8] {
        // Select master file using ISO/IEC 7816-4 alternative method
        // (Some European passports require data field 0x3F00)
        let selectMFCmd = NFCISO7816APDU(
            instructionClass: ISO7816.InstructionClass.standard,
            instructionCode: ISO7816.Instruction.select,
            p1Parameter: ISO7816.SelectP1.selectMF,
            p2Parameter: ISO7816.SelectP2.returnNone,
            data: Data(ISO7816.AID.masterFile),
            expectedResponseLength: -1
        )
        _ = try await send(cmd: selectMFCmd)
        
        return try await selectFileAndRead(tag: ISO7816.FileID.cardAccess)
    }
    
    func selectPassportApplication() async throws -> ResponseAPDU {
        Logger.tagReader.debug("Selecting eMRTD application")
        let cmd = NFCISO7816APDU(
            instructionClass: ISO7816.InstructionClass.standard,
            instructionCode: ISO7816.Instruction.select,
            p1Parameter: ISO7816.SelectP1.selectByDFName,
            p2Parameter: ISO7816.SelectP2.returnNone,
            data: Data(ISO7816.AID.eMRTD),
            expectedResponseLength: -1
        )
        return try await send(cmd: cmd)
    }
    
    func selectFile(tag: [UInt8]) async throws -> ResponseAPDU {
        let data: [UInt8] = [0x00, ISO7816.Instruction.select, ISO7816.SelectP1.selectByEFId, ISO7816.SelectP2.returnNone, 0x02] + tag
        let cmd = NFCISO7816APDU(data: Data(data))!
        return try await send(cmd: cmd)
    }
    
    // MARK: - Core Send
    
    func send(cmd: NFCISO7816APDU, useExtendedMode: Bool = false) async throws -> ResponseAPDU {
        Logger.tagReader.debug("Sending: \(cmd)")
        
        var toSend = cmd
        if let sm = secureMessaging {
            toSend = try sm.protect(apdu: cmd, useExtendedMode: useExtendedMode)
            Logger.tagReader.debug("[SM] \(toSend)")
        }
        
        var (data, sw1, sw2) = try await tag.sendCommand(apdu: toSend)
        Logger.tagReader.debug("Received \(data.count) bytes")
        
        // Handle chained responses (GET RESPONSE)
        while sw1 == 0x61 {
            let getResponseCmd = NFCISO7816APDU(
                instructionClass: ISO7816.InstructionClass.standard,
                instructionCode: ISO7816.Instruction.getResponse,
                p1Parameter: 0x00,
                p2Parameter: 0x00,
                data: Data(),
                expectedResponseLength: Int(sw2)
            )
            let (nextSegment, nextSw1, nextSw2) = try await tag.sendCommand(apdu: getResponseCmd)
            Logger.tagReader.debug("Chained read: +\(nextSegment.count) bytes, \(nextSw2) remaining")
            data += nextSegment
            sw1 = nextSw1
            sw2 = nextSw2
        }
        
        var response = ResponseAPDU(data: [UInt8](data), sw1: sw1, sw2: sw2)
        
        if let sm = secureMessaging {
            response = try sm.unprotect(rapdu: response)
            Logger.tagReader.debug("[SM unprotected] \(response.data.hexString), SW: \(String(format: "%02X%02X", response.sw1, response.sw2))")
        } else {
            Logger.tagReader.debug("[Unprotected] \(response.data.hexString), SW: \(String(format: "%02X%02X", response.sw1, response.sw2))")
        }
        
        // Check for errors
        guard response.isSuccess else {
            let statusWord = ISO7816StatusWord(sw1: response.sw1, sw2: response.sw2)
            Logger.tagReader.error("Error: \(statusWord.errorDescription)")
            
            if response.sw1 == 0x63 && response.sw2 == 0x00 {
                throw NFCPassportReaderError.InvalidMRZKey
            }
            throw NFCPassportReaderError.ResponseError(statusWord.errorDescription, sw1, sw2)
        }
        
        return response
    }
    
    // MARK: - Private Helpers
    
    private func reportProgress(amountRead: Int, total: Int) {
        guard total > 0 else { return }
        let percent = Int(Float(amountRead) / Float(total) * 100)
        progress?(percent)
    }
}
#endif
