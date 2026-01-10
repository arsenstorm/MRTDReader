//
//  COM.swift
//

import Foundation
import OSLog

@available(iOS 13, macOS 10.15, *)
public class COM : DataGroup {
    public private(set) var version: String = "Unknown"
    public private(set) var unicodeVersion: String = "Unknown"
    public private(set) var dataGroupsPresent: [String] = []

    public override var datagroupType: DataGroupId { .COM }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        // Parse LDS version (tag 0x5F01)
        try verifyTag(try getNextTag(), equals: 0x5F01)
        let ldsVersionBytes = try getNextValue()
        if let parsed = Self.parseVersion(ldsVersionBytes, components: 2) {
            version = parsed
        }
        
        // Parse Unicode version (tag 0x5F36)
        try verifyTag(try getNextTag(), equals: 0x5F36)
        let unicodeVersionBytes = try getNextValue()
        if let parsed = Self.parseVersion(unicodeVersionBytes, components: 3) {
            unicodeVersion = parsed
        }
        
        // Parse data groups present (tag 0x5C)
        try verifyTag(try getNextTag(), equals: 0x5C)
        let dgBytes = try getNextValue()
        dataGroupsPresent = dgBytes.compactMap { byte in
            DataGroupParser.tags.firstIndex(of: byte).map { DataGroupParser.dataGroupNames[$0] }
        }
        
        Logger.passportReader.debug("DG Found - \(self.dataGroupsPresent)")
    }
    
    /// Parse ASCII version bytes into dotted version string
    /// - Parameters:
    ///   - bytes: Raw ASCII bytes (e.g., "0107" for version 1.7)
    ///   - components: Number of version components (2 for "X.Y", 3 for "X.Y.Z")
    /// - Returns: Formatted version string or nil if parsing fails
    private static func parseVersion(_ bytes: [UInt8], components: Int) -> String? {
        let chunkSize = 2
        guard bytes.count == components * chunkSize else { return nil }
        
        var parts: [String] = []
        parts.reserveCapacity(components)
        
        for i in 0..<components {
            let start = i * chunkSize
            let chunk = bytes[start..<(start + chunkSize)]
            guard let str = String(bytes: chunk, encoding: .ascii),
                  let num = Int(str) else {
                return nil
            }
            parts.append(String(num))
        }
        
        return parts.joined(separator: ".")
    }
}
