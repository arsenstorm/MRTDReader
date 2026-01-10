//
//  DataGroup1.swift
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum DocTypeEnum: String {
    case TD1, TD2, OTHER
}

@available(iOS 13, macOS 10.15, *)
public class DataGroup1: DataGroup {
    public private(set) var elements: [String: String] = [:]
    
    public override var datagroupType: DataGroupId { .DG1 }
    
    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        try verifyTag(try getNextTag(), equals: 0x5F1F)
        let mrzData = try getNextValue()
        
        parseMRZ(mrzData, type: mrzType(for: mrzData.count))
        elements["5F1F"] = String(bytes: mrzData, encoding: .utf8)
    }
    
    // MARK: - MRZ Type Detection
    
    private func mrzType(for length: Int) -> DocTypeEnum {
        switch length {
        case 0x5A: return .TD1
        case 0x48: return .TD2
        default:   return .OTHER
        }
    }
    
    // MARK: - MRZ Parsing
    
    private func parseMRZ(_ data: [UInt8], type: DocTypeEnum) {
        switch type {
        case .TD1:   parseTD1(data)
        case .TD2:   parseTD2(data)
        case .OTHER: parseOther(data)
        }
    }
    
    private func parseTD1(_ d: [UInt8]) {
        setField("5F03", d, 0..<2)     // Document code
        setField("5F28", d, 2..<5)     // Issuing state
        setField("5A",   d, 5..<14)    // Document number
        setField("5F04", d, 14..<15)   // Check digit (doc number)
        setField("5F57", d, 30..<36)   // Date of birth
        setField("5F05", d, 36..<37)   // Check digit (DOB)
        setField("5F35", d, 37..<38)   // Sex
        setField("59",   d, 38..<44)   // Date of expiry
        setField("5F06", d, 44..<45)   // Check digit (expiry)
        setField("5F2C", d, 45..<48)   // Nationality
        setField("5F07", d, 59..<60)   // Check digit (composite)
        setField("5B",   d, 60...)     // Name
        // Optional data spans two lines
        elements["53"] = (String(bytes: d[15..<30], encoding: .utf8) ?? "") +
                         (String(bytes: d[48..<59], encoding: .utf8) ?? "")
    }
    
    private func parseTD2(_ d: [UInt8]) {
        setField("5F03", d, 0..<2)     // Document code
        setField("5F28", d, 2..<5)     // Issuing state
        setField("5B",   d, 5..<36)    // Name
        setField("5A",   d, 36..<45)   // Document number
        setField("5F04", d, 45..<46)   // Check digit (doc number)
        setField("5F2C", d, 46..<49)   // Nationality
        setField("5F57", d, 49..<55)   // Date of birth
        setField("5F05", d, 55..<56)   // Check digit (DOB)
        setField("5F35", d, 56..<57)   // Sex
        setField("59",   d, 57..<63)   // Date of expiry
        setField("5F06", d, 63..<64)   // Check digit (expiry)
        setField("53",   d, 64..<71)   // Optional data
        setField("5F07", d, 71..<72)   // Check digit (composite)
    }
    
    private func parseOther(_ d: [UInt8]) {
        setField("5F03", d, 0..<2)     // Document code
        setField("5F28", d, 2..<5)     // Issuing state
        setField("5B",   d, 5..<44)    // Name
        setField("5A",   d, 44..<53)   // Document number
        setField("5F04", d, 53..<54)   // Check digit (doc number)
        setField("5F2C", d, 54..<57)   // Nationality
        setField("5F57", d, 57..<63)   // Date of birth
        setField("5F05", d, 63..<64)   // Check digit (DOB)
        setField("5F35", d, 64..<65)   // Sex
        setField("59",   d, 65..<71)   // Date of expiry
        setField("5F06", d, 71..<72)   // Check digit (expiry)
        setField("53",   d, 72..<86)   // Optional data
        setField("5F02", d, 86..<87)   // Optional data 2
        setField("5F07", d, 87..<88)   // Check digit (composite)
    }
    
    // MARK: - Helpers
    
    private func setField(_ tag: String, _ data: [UInt8], _ range: Range<Int>) {
        elements[tag] = String(bytes: data[range], encoding: .utf8)
    }
    
    private func setField(_ tag: String, _ data: [UInt8], _ range: PartialRangeFrom<Int>) {
        elements[tag] = String(bytes: data[range], encoding: .utf8)
    }
}
