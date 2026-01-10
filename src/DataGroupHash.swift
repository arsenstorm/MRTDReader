//
//  DataGroupHash.swift
//

import Foundation

/// Represents a hash comparison for a data group
@available(iOS 13, macOS 10.15, *)
public struct DataGroupHash {
    public let id: String
    public let sodHash: String
    public let computedHash: String
    public let match: Bool
}
