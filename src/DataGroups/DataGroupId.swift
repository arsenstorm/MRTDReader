//
//  DataGroupId.swift
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum DataGroupId: Int, CaseIterable {
    case COM = 0x60
    case DG1 = 0x61
    case DG2 = 0x75
    case DG3 = 0x63
    case DG4 = 0x76
    case DG5 = 0x65
    case DG6 = 0x66
    case DG7 = 0x67
    case DG8 = 0x68
    case DG9 = 0x69
    case DG10 = 0x6A
    case DG11 = 0x6B
    case DG12 = 0x6C
    case DG13 = 0x6D
    case DG14 = 0x6E
    case DG15 = 0x6F
    case DG16 = 0x70
    case SOD = 0x77
    case Unknown = 0x00
    
    /// Returns the name of this data group (e.g., "DG1", "COM", "SOD")
    public var name: String {
        String(describing: self)
    }
    
    /// Legacy method - use `name` property instead
    public func getName() -> String { name }
    
    /// File ID tag for selecting this data group
    public var fileIDTag: [UInt8]? {
        switch self {
        case .COM:     return [0x01, 0x1E]
        case .DG1:     return [0x01, 0x01]
        case .DG2:     return [0x01, 0x02]
        case .DG3:     return [0x01, 0x03]
        case .DG4:     return [0x01, 0x04]
        case .DG5:     return [0x01, 0x05]
        case .DG6:     return [0x01, 0x06]
        case .DG7:     return [0x01, 0x07]
        case .DG8:     return [0x01, 0x08]
        case .DG9:     return [0x01, 0x09]
        case .DG10:    return [0x01, 0x0A]
        case .DG11:    return [0x01, 0x0B]
        case .DG12:    return [0x01, 0x0C]
        case .DG13:    return [0x01, 0x0D]
        case .DG14:    return [0x01, 0x0E]
        case .DG15:    return [0x01, 0x0F]
        case .DG16:    return [0x01, 0x10]
        case .SOD:     return [0x01, 0x1D]
        case .Unknown: return nil
        }
    }
    
    /// Legacy method - use `fileIDTag` property instead
    func getFileIDTag() -> [UInt8]? { fileIDTag }
    
    /// Look up DataGroupId by name
    public static func from(name: String) -> DataGroupId {
        // Handle alternative names from DataGroupParser
        switch name {
        case "Common":       return .COM
        case "SecurityData": return .SOD
        default:
            return allCases.first { $0.name == name } ?? .Unknown
        }
    }
    
    /// Legacy method - use `from(name:)` instead
    static public func getIDFromName(name: String) -> DataGroupId {
        from(name: name)
    }
}
