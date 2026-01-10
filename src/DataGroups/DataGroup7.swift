//
//  DataGroup7.swift
//

import Foundation

#if !os(macOS)
import UIKit
#endif

@available(iOS 13, macOS 10.15, *)
public class DataGroup7: DataGroup {
    
    public private(set) var imageData: [UInt8] = []

    public override var datagroupType: DataGroupId { .DG7 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
    
    #if !os(macOS)
    public func getImage() -> UIImage? {
        guard !imageData.isEmpty else { return nil }
        return UIImage(data: Data(imageData))
    }
    #endif
    
    override func parse(_ data: [UInt8]) throws {
        // Number of displayed signature/images (0x02)
        try verifyTag(try getNextTag(), equals: 0x02)
        _ = try getNextValue()
        
        // Displayed signature/image (0x5F43)
        try verifyTag(try getNextTag(), equals: 0x5F43)
        imageData = try getNextValue()
    }
}
