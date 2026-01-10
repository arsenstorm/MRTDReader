
import Foundation

// MARK: - ISO 7816 APDU Constants

/// ISO 7816-4 Instruction Codes
public enum ISO7816 {
    
    // MARK: - Instruction Classes
    
    public enum InstructionClass {
        public static let standard: UInt8 = 0x00
        public static let chaining: UInt8 = 0x10
        public static let secureMessaging: UInt8 = 0x0C
    }
    
    // MARK: - Instruction Codes
    
    public enum Instruction {
        public static let select: UInt8 = 0xA4
        public static let readBinary: UInt8 = 0xB0
        public static let getChallenge: UInt8 = 0x84
        public static let externalAuthenticate: UInt8 = 0x82
        public static let internalAuthenticate: UInt8 = 0x88
        public static let mseSetAT: UInt8 = 0x22
        public static let generalAuthenticate: UInt8 = 0x86
        public static let getResponse: UInt8 = 0xC0
    }
    
    // MARK: - MSE (Manage Security Environment) Parameters
    
    public enum MSE {
        public static let setForMutualAuth: UInt8 = 0xC1
        public static let setForInternalAuth: UInt8 = 0x41
        public static let templateAT: UInt8 = 0xA4
        public static let templateKAT: UInt8 = 0xA6
    }
    
    // MARK: - File Selection Parameters
    
    public enum SelectP1 {
        public static let selectMF: UInt8 = 0x00
        public static let selectByDFName: UInt8 = 0x04
        public static let selectByEFId: UInt8 = 0x02
    }
    
    public enum SelectP2 {
        public static let returnFCI: UInt8 = 0x00
        public static let returnFCP: UInt8 = 0x04
        public static let returnNone: UInt8 = 0x0C
    }
    
    // MARK: - Secure Messaging Data Object Tags
    
    public enum SMTag {
        /// Encrypted data (padding indicator + encrypted content)
        public static let encryptedData: UInt8 = 0x87
        /// Expected response length
        public static let expectedLength: UInt8 = 0x97
        /// Processing status (SW1-SW2)
        public static let processingStatus: UInt8 = 0x99
        /// Cryptographic checksum (MAC)
        public static let cryptographicChecksum: UInt8 = 0x8E
    }
    
    // MARK: - Application Identifiers
    
    public enum AID {
        /// eMRTD LDS1 Application (ICAO 9303)
        public static let eMRTD: [UInt8] = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01]
        /// Master File
        public static let masterFile: [UInt8] = [0x3F, 0x00]
    }
    
    // MARK: - File Identifiers
    
    public enum FileID {
        public static let cardAccess: [UInt8] = [0x01, 0x1C]
    }
}

// MARK: - ISO 7816 Status Words

/// ISO 7816-4 Status Word (SW1-SW2) definitions
public struct ISO7816StatusWord: Equatable {
    public let sw1: UInt8
    public let sw2: UInt8
    
    public init(sw1: UInt8, sw2: UInt8) {
        self.sw1 = sw1
        self.sw2 = sw2
    }
    
    public var value: UInt16 {
        UInt16(sw1) << 8 | UInt16(sw2)
    }
    
    public var isSuccess: Bool {
        sw1 == 0x90 && sw2 == 0x00
    }
    
    public var hasMoreData: Bool {
        sw1 == 0x61
    }
    
    public var bytesAvailable: Int {
        hasMoreData ? Int(sw2) : 0
    }
    
    // MARK: - Common Status Words
    
    public static let success = ISO7816StatusWord(sw1: 0x90, sw2: 0x00)
    public static let wrongLength = ISO7816StatusWord(sw1: 0x67, sw2: 0x00)
    public static let securityNotSatisfied = ISO7816StatusWord(sw1: 0x69, sw2: 0x82)
    public static let authMethodBlocked = ISO7816StatusWord(sw1: 0x69, sw2: 0x83)
    public static let fileNotFound = ISO7816StatusWord(sw1: 0x6A, sw2: 0x82)
    public static let classNotSupported = ISO7816StatusWord(sw1: 0x6E, sw2: 0x00)
    public static let smDataMissing = ISO7816StatusWord(sw1: 0x69, sw2: 0x87)
    public static let smDataIncorrect = ISO7816StatusWord(sw1: 0x69, sw2: 0x88)
    
    // MARK: - Error Description
    
    /// Human-readable description of the status word
    public var errorDescription: String {
        Self.errorMessages[sw1]?[sw2] ?? specialCaseDescription ?? unknownDescription
    }
    
    private var specialCaseDescription: String? {
        switch sw1 {
        case 0x61:
            return "SW2 indicates the number of response bytes still available - (\(sw2) bytes)"
        case 0x64:
            return "State of non-volatile memory unchanged"
        case 0x6C:
            return "Wrong length Le: exact length is \(sw2)"
        default:
            return nil
        }
    }
    
    private var unknownDescription: String {
        "Unknown error - SW1: 0x\(String(format: "%02X", sw1)), SW2: 0x\(String(format: "%02X", sw2))"
    }
    
    // MARK: - Error Message Lookup
    
    private static let errorMessages: [UInt8: [UInt8: String]] = [
        0x62: [
            0x00: "No information given",
            0x81: "Part of returned data may be corrupted",
            0x82: "End of file/record reached before reading Le bytes",
            0x83: "Selected file invalidated",
            0x84: "FCI not formatted according to ISO7816-4 section 5.1.5"
        ],
        0x63: [
            0x00: "No information given",
            0x81: "File filled up by the last write",
            0x82: "Card Key not supported",
            0x83: "Reader Key not supported",
            0x84: "Plain transmission not supported",
            0x85: "Secured Transmission not supported",
            0x86: "Volatile memory not available",
            0x87: "Non Volatile memory not available",
            0x88: "Key number not valid",
            0x89: "Key length is not correct"
        ],
        0x65: [
            0x00: "No information given",
            0x81: "Memory failure"
        ],
        0x67: [
            0x00: "Wrong length"
        ],
        0x68: [
            0x00: "No information given",
            0x81: "Logical channel not supported",
            0x82: "Secure messaging not supported",
            0x83: "Last command of the chain expected",
            0x84: "Command chaining not supported"
        ],
        0x69: [
            0x00: "No information given",
            0x81: "Command incompatible with file structure",
            0x82: "Security status not satisfied",
            0x83: "Authentication method blocked",
            0x84: "Referenced data invalidated",
            0x85: "Conditions of use not satisfied",
            0x86: "Command not allowed (no current EF)",
            0x87: "Expected SM data objects missing",
            0x88: "SM data objects incorrect"
        ],
        0x6A: [
            0x00: "No information given",
            0x80: "Incorrect parameters in the data field",
            0x81: "Function not supported",
            0x82: "File not found",
            0x83: "Record not found",
            0x84: "Not enough memory space in the file",
            0x85: "Lc inconsistent with TLV structure",
            0x86: "Incorrect parameters P1-P2",
            0x87: "Lc inconsistent with P1-P2",
            0x88: "Referenced data not found"
        ],
        0x6B: [
            0x00: "Wrong parameter(s) P1-P2"
        ],
        0x6D: [
            0x00: "Instruction code not supported or invalid"
        ],
        0x6E: [
            0x00: "Class not supported"
        ],
        0x6F: [
            0x00: "No precise diagnosis"
        ],
        0x90: [
            0x00: "Success"
        ]
    ]
}
