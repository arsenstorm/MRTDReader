//
//  ResponseAPDU.swift
//

#if !os(macOS)

/// Represents an ISO 7816 APDU response from the passport chip
@available(iOS 13, *)
public struct ResponseAPDU {
    public var data: [UInt8]
    public let sw1: UInt8
    public let sw2: UInt8
    
    public init(data: [UInt8], sw1: UInt8, sw2: UInt8) {
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
    }
    
    /// Status word (SW1 << 8 | SW2)
    public var statusWord: UInt16 {
        UInt16(sw1) << 8 | UInt16(sw2)
    }
    
    /// True if status indicates success (0x9000)
    public var isSuccess: Bool {
        statusWord == 0x9000
    }
}

#endif
