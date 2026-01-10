//
//  NotImplementedDG.swift
//

import Foundation

/// Placeholder for data groups that are not yet implemented
@available(iOS 13, macOS 10.15, *)
public class NotImplementedDG: DataGroup {
    
    public override var datagroupType: DataGroupId { .Unknown }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}
