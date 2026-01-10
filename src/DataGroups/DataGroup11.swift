//
//  DataGroup11.swift
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class DataGroup11: DataGroup {
    
    public private(set) var fullName: String?
    public private(set) var personalNumber: String?
    public private(set) var dateOfBirth: String?
    public private(set) var placeOfBirth: String?
    public private(set) var address: String?
    public private(set) var telephone: String?
    public private(set) var profession: String?
    public private(set) var title: String?
    public private(set) var personalSummary: String?
    public private(set) var proofOfCitizenship: String?
    public private(set) var tdNumbers: String?
    public private(set) var custodyInfo: String?

    public override var datagroupType: DataGroupId { .DG11 }

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
            let value = String(bytes: try getNextValue(), encoding: .utf8)
            
            switch tag {
            case 0x5F0E: fullName = value
            case 0x5F10: personalNumber = value
            case 0x5F11: placeOfBirth = value
            case 0x5F2B: dateOfBirth = value
            case 0x5F42: address = value
            case 0x5F12: telephone = value
            case 0x5F13: profession = value
            case 0x5F14: title = value
            case 0x5F15: personalSummary = value
            case 0x5F16: proofOfCitizenship = value
            case 0x5F17: tdNumbers = value
            case 0x5F18: custodyInfo = value
            default: break
            }
        }
    }
}
