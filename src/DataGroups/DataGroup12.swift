//
//  DataGroup12.swift
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class DataGroup12: DataGroup {
    
    public private(set) var issuingAuthority: String?
    public private(set) var dateOfIssue: String?
    public private(set) var otherPersonsDetails: String?
    public private(set) var endorsementsOrObservations: String?
    public private(set) var taxOrExitRequirements: String?
    public private(set) var frontImage: [UInt8]?
    public private(set) var rearImage: [UInt8]?
    public private(set) var personalizationTime: String?
    public private(set) var personalizationDeviceSerialNr: String?

    public override var datagroupType: DataGroupId { .DG12 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }

    override func parse(_ data: [UInt8]) throws {
        // Tag list (0x5C)
        try verifyTag(try getNextTag(), equals: 0x5C)
        _ = try getNextValue()
        
        // Parse all TLV fields
        while pos < data.count {
            let tag = try getNextTag()
            let value = try getNextValue()
            
            switch tag {
            case 0x5F19: issuingAuthority = String(bytes: value, encoding: .utf8)
            case 0x5F26: dateOfIssue = parseDateOfIssue(value)
            case 0xA0:   break // Other persons - not yet handled
            case 0x5F1B: endorsementsOrObservations = String(bytes: value, encoding: .utf8)
            case 0x5F1C: taxOrExitRequirements = String(bytes: value, encoding: .utf8)
            case 0x5F1D: frontImage = value
            case 0x5F1E: rearImage = value
            case 0x5F55: personalizationTime = String(bytes: value, encoding: .utf8)
            case 0x5F56: personalizationDeviceSerialNr = String(bytes: value, encoding: .utf8)
            default: break
            }
        }
    }
    
    /// Parse date of issue - may be BCD encoded (4 bytes) or ASCII (8 bytes)
    private func parseDateOfIssue(_ value: [UInt8]) -> String? {
        if value.count == 4 {
            // BCD: each byte represents two digits
            return value.map { String(format: "%02X", $0) }.joined()
        } else {
            return String(bytes: value, encoding: .utf8)
        }
    }
}
