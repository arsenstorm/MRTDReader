//
//  DataGroup.swift
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class DataGroup {
    
    public var datagroupType: DataGroupId { .Unknown }
    
    /// Body contains the actual data (without header)
    public private(set) var body: [UInt8] = []
    
    /// Full DataGroup data (used for hash calculation)
    public private(set) var data: [UInt8] = []
    
    /// Parsed ASN1 representation of the body (lazily initialized)
    public private(set) lazy var asn1Body: ASN1Node? = {
        try? ASN1.parse(body)
    }()
    
    /// Current parsing position
    var pos = 0
    
    // MARK: - Init
    
    required init(_ data: [UInt8]) throws {
        self.data = data
        
        // Skip header tag, parse length to find body start
        pos = 1
        _ = try getNextLength()
        self.body = Array(data[pos...])
        
        try parse(data)
    }
    
    func parse(_ data: [UInt8]) throws {
        // Override in subclasses
    }
    
    // MARK: - TLV Parsing Helpers
    
    func getNextTag() throws -> Int {
        guard pos < data.count else {
            throw NFCPassportReaderError.TagNotValid
        }
        
        let firstByte = data[pos]
        
        // Check if this is a multi-byte tag (low 5 bits all set)
        if (firstByte & 0x1F) == 0x1F {
            let tag = Int(data[pos]) << 8 | Int(data[pos + 1])
            pos += 2
            return tag
        } else {
            pos += 1
            return Int(firstByte)
        }
    }
    
    func getNextLength() throws -> Int {
        let end = min(pos + 4, data.count)
        let (length, bytesConsumed) = try asn1Length(Array(data[pos..<end]))
        pos += bytesConsumed
        return length
    }
    
    func getNextValue() throws -> [UInt8] {
        let length = try getNextLength()
        let value = Array(data[pos..<(pos + length)])
        pos += length
        return value
    }
    
    // MARK: - Hashing
    
    public func hash(_ algorithm: String) -> [UInt8] {
        switch algorithm {
        case "SHA1":   return calcSHA1Hash(data)
        case "SHA224": return calcSHA224Hash(data)
        case "SHA256": return calcSHA256Hash(data)
        case "SHA384": return calcSHA384Hash(data)
        case "SHA512": return calcSHA512Hash(data)
        default:       return []
        }
    }
    
    // MARK: - Tag Verification
    
    public func verifyTag(_ tag: Int, equals expectedTag: Int) throws {
        guard tag == expectedTag else {
            throw NFCPassportReaderError.InvalidResponse(
                dataGroupId: datagroupType,
                expectedTag: expectedTag,
                actualTag: tag
            )
        }
    }
    
    public func verifyTag(_ tag: Int, oneOf expectedTags: [Int]) throws {
        guard expectedTags.contains(tag) else {
            throw NFCPassportReaderError.InvalidResponse(
                dataGroupId: datagroupType,
                expectedTag: expectedTags[0],
                actualTag: tag
            )
        }
    }
}
