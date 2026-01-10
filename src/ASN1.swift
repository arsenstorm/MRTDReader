//
//  ASN1.swift
//

import Foundation

// MARK: - ASN1 Errors

public enum ASN1Error: Error, LocalizedError {
    case invalidTag
    case invalidLength
    case truncatedData
    case invalidOID
    case unsupportedLengthEncoding
    
    public var errorDescription: String? {
        switch self {
        case .invalidTag: return "Invalid ASN1 tag"
        case .invalidLength: return "Invalid ASN1 length encoding"
        case .truncatedData: return "Truncated ASN1 data"
        case .invalidOID: return "Invalid OID encoding"
        case .unsupportedLengthEncoding: return "Unsupported length encoding (indefinite or too large)"
        }
    }
}

// MARK: - ASN1 Tag

/// ASN1 tag classification
public enum ASN1Tag: Equatable, CustomStringConvertible {
    case boolean            // 0x01
    case integer            // 0x02
    case bitString          // 0x03
    case octetString        // 0x04
    case null               // 0x05
    case objectIdentifier   // 0x06
    case objectDescriptor   // 0x07
    case external           // 0x08
    case real               // 0x09
    case enumerated         // 0x0A
    case embeddedPDV        // 0x0B
    case utf8String         // 0x0C
    case relativeOID        // 0x0D
    case sequence           // 0x10
    case set                // 0x11
    case numericString      // 0x12
    case printableString    // 0x13
    case t61String          // 0x14
    case videotexString     // 0x15
    case ia5String          // 0x16
    case utcTime            // 0x17
    case generalizedTime    // 0x18
    case graphicString      // 0x19
    case visibleString      // 0x1A
    case generalString      // 0x1B
    case universalString    // 0x1C
    case bmpString          // 0x1E
    case contextSpecific(Int)  // [0], [1], etc.
    case application(Int)      // Application-specific tags
    case privateTag(Int)       // Private tags
    case unknown(UInt8)
    
    /// Initialize from raw tag byte (without constructed bit consideration)
    public init(tagNumber: UInt8, tagClass: UInt8) {
        switch tagClass {
        case 0x00: // Universal
            switch tagNumber {
            case 0x01: self = .boolean
            case 0x02: self = .integer
            case 0x03: self = .bitString
            case 0x04: self = .octetString
            case 0x05: self = .null
            case 0x06: self = .objectIdentifier
            case 0x07: self = .objectDescriptor
            case 0x08: self = .external
            case 0x09: self = .real
            case 0x0A: self = .enumerated
            case 0x0B: self = .embeddedPDV
            case 0x0C: self = .utf8String
            case 0x0D: self = .relativeOID
            case 0x10: self = .sequence
            case 0x11: self = .set
            case 0x12: self = .numericString
            case 0x13: self = .printableString
            case 0x14: self = .t61String
            case 0x15: self = .videotexString
            case 0x16: self = .ia5String
            case 0x17: self = .utcTime
            case 0x18: self = .generalizedTime
            case 0x19: self = .graphicString
            case 0x1A: self = .visibleString
            case 0x1B: self = .generalString
            case 0x1C: self = .universalString
            case 0x1E: self = .bmpString
            default: self = .unknown(tagNumber)
            }
        case 0x40: // Application
            self = .application(Int(tagNumber))
        case 0x80: // Context-specific
            self = .contextSpecific(Int(tagNumber))
        case 0xC0: // Private
            self = .privateTag(Int(tagNumber))
        default:
            self = .unknown(tagNumber)
        }
    }
    
    public var description: String {
        switch self {
        case .boolean: return "BOOLEAN"
        case .integer: return "INTEGER"
        case .bitString: return "BIT STRING"
        case .octetString: return "OCTET STRING"
        case .null: return "NULL"
        case .objectIdentifier: return "OBJECT IDENTIFIER"
        case .objectDescriptor: return "ObjectDescriptor"
        case .external: return "EXTERNAL"
        case .real: return "REAL"
        case .enumerated: return "ENUMERATED"
        case .embeddedPDV: return "EMBEDDED PDV"
        case .utf8String: return "UTF8String"
        case .relativeOID: return "RELATIVE-OID"
        case .sequence: return "SEQUENCE"
        case .set: return "SET"
        case .numericString: return "NumericString"
        case .printableString: return "PrintableString"
        case .t61String: return "T61String"
        case .videotexString: return "VideotexString"
        case .ia5String: return "IA5String"
        case .utcTime: return "UTCTime"
        case .generalizedTime: return "GeneralizedTime"
        case .graphicString: return "GraphicString"
        case .visibleString: return "VisibleString"
        case .generalString: return "GeneralString"
        case .universalString: return "UniversalString"
        case .bmpString: return "BMPString"
        case .contextSpecific(let n): return "[\(n)]"
        case .application(let n): return "[APPLICATION \(n)]"
        case .privateTag(let n): return "[PRIVATE \(n)]"
        case .unknown(let b): return "UNKNOWN(0x\(String(format: "%02X", b)))"
        }
    }
    
    /// Whether this tag type is typically a string type
    public var isStringType: Bool {
        switch self {
        case .utf8String, .printableString, .ia5String, .t61String,
             .videotexString, .graphicString, .visibleString,
             .generalString, .universalString, .bmpString, .numericString:
            return true
        default:
            return false
        }
    }
}

// MARK: - ASN1 Node

/// Parsed ASN1 node
public struct ASN1Node: CustomDebugStringConvertible {
    public let tag: ASN1Tag
    public let rawTag: UInt8
    public let isConstructed: Bool
    
    /// Byte offset in original data where this node starts
    public let offset: Int
    /// Length of the tag + length encoding (header)
    public let headerLength: Int
    /// Length of the content
    public let contentLength: Int
    
    /// Raw content bytes (for primitive types)
    public let bytes: [UInt8]
    /// Children nodes (for constructed types)
    public let children: [ASN1Node]
    
    // MARK: - Subscript Access
    
    public subscript(_ index: Int) -> ASN1Node? {
        guard index >= 0, index < children.count else { return nil }
        return children[index]
    }
    
    /// Number of children
    public var count: Int { children.count }
    
    // MARK: - Value Extraction
    
    /// Integer value (for INTEGER tags)
    public var intValue: Int? {
        guard !bytes.isEmpty else { return nil }
        
        // Handle signed integers (two's complement)
        var result: Int = 0
        let isNegative = (bytes[0] & 0x80) != 0
        
        for byte in bytes {
            result = (result << 8) | Int(isNegative ? ~byte : byte)
        }
        
        if isNegative {
            result = -(result + 1)
        }
        
        return result
    }
    
    /// Unsigned integer value
    public var uintValue: UInt64? {
        guard !bytes.isEmpty else { return nil }
        var result: UInt64 = 0
        for byte in bytes {
            result = (result << 8) | UInt64(byte)
        }
        return result
    }
    
    /// String value (for string types)
    public var stringValue: String? {
        switch tag {
        case .utf8String:
            return String(bytes: bytes, encoding: .utf8)
        case .printableString, .ia5String, .visibleString, .numericString:
            return String(bytes: bytes, encoding: .ascii)
        case .bmpString:
            // BMP strings are UTF-16BE
            return String(bytes: bytes, encoding: .utf16BigEndian)
        case .t61String, .generalString:
            // Try Latin-1 for these legacy types
            return String(bytes: bytes, encoding: .isoLatin1)
        case .utcTime, .generalizedTime:
            return String(bytes: bytes, encoding: .ascii)
        default:
            // Try UTF-8 as fallback
            return String(bytes: bytes, encoding: .utf8)
        }
    }
    
    /// OID value as dotted string (e.g., "1.2.840.113549.1.7.2")
    public var oidValue: String? {
        guard tag == .objectIdentifier || tag == .relativeOID else { return nil }
        guard !bytes.isEmpty else { return nil }
        
        var components: [UInt64] = []
        
        if tag == .objectIdentifier {
            // First byte encodes first two components: first * 40 + second
            let first = UInt64(bytes[0] / 40)
            let second = UInt64(bytes[0] % 40)
            components.append(first)
            components.append(second)
        }
        
        // Remaining bytes use base-128 encoding
        var value: UInt64 = 0
        let startIndex = tag == .objectIdentifier ? 1 : 0
        
        for i in startIndex..<bytes.count {
            let byte = bytes[i]
            value = (value << 7) | UInt64(byte & 0x7F)
            
            if (byte & 0x80) == 0 {
                // Last byte of this component
                components.append(value)
                value = 0
            }
        }
        
        return components.map(String.init).joined(separator: ".")
    }
    
    /// Hex string representation of bytes (uppercase)
    public var hexValue: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
    
    /// Raw bytes as Data
    public var dataValue: Data {
        Data(bytes)
    }
    
    /// Boolean value
    public var boolValue: Bool? {
        guard tag == .boolean, bytes.count == 1 else { return nil }
        return bytes[0] != 0
    }
    
    /// Bit string content (skipping the unused bits count byte)
    public var bitStringContent: [UInt8]? {
        guard tag == .bitString, !bytes.isEmpty else { return nil }
        // First byte indicates number of unused bits in last byte
        return Array(bytes.dropFirst())
    }
    
    /// Number of unused bits in bit string
    public var bitStringUnusedBits: UInt8? {
        guard tag == .bitString, !bytes.isEmpty else { return nil }
        return bytes[0]
    }
    
    // MARK: - Debug
    
    public var debugDescription: String {
        descriptionWithIndent(0)
    }
    
    private func descriptionWithIndent(_ indent: Int) -> String {
        let prefix = String(repeating: "  ", count: indent)
        var result = "\(prefix)\(tag)"
        
        if isConstructed {
            result += " {\n"
            for child in children {
                result += child.descriptionWithIndent(indent + 1) + "\n"
            }
            result += "\(prefix)}"
        } else {
            switch tag {
            case .objectIdentifier, .relativeOID:
                if let oid = oidValue {
                    result += ": \(oid)"
                }
            case .integer, .enumerated:
                if let value = intValue {
                    result += ": \(value)"
                } else {
                    result += ": 0x\(hexValue)"
                }
            case .boolean:
                if let value = boolValue {
                    result += ": \(value)"
                }
            case .null:
                break
            case _ where tag.isStringType:
                if let str = stringValue {
                    result += ": \"\(str)\""
                }
            case .utcTime, .generalizedTime:
                if let str = stringValue {
                    result += ": \(str)"
                }
            default:
                if bytes.count <= 20 {
                    result += ": 0x\(hexValue)"
                } else {
                    result += ": (\(bytes.count) bytes)"
                }
            }
        }
        
        return result
    }
    
    // MARK: - Navigation Helpers
    
    /// Find first child with matching tag
    public func firstChild(withTag tag: ASN1Tag) -> ASN1Node? {
        children.first { $0.tag == tag }
    }
    
    /// Find all children with matching tag
    public func children(withTag tag: ASN1Tag) -> [ASN1Node] {
        children.filter { $0.tag == tag }
    }
}

// MARK: - ASN1 Parser

public enum ASN1 {
    
    /// Parse ASN1/DER encoded data
    public static func parse(_ data: Data) throws -> ASN1Node {
        try parse([UInt8](data))
    }
    
    /// Parse ASN1/DER encoded bytes
    public static func parse(_ bytes: [UInt8]) throws -> ASN1Node {
        var offset = 0
        return try parseNode(bytes, offset: &offset)
    }
    
    /// Parse multiple consecutive ASN1 nodes
    public static func parseAll(_ bytes: [UInt8]) throws -> [ASN1Node] {
        var offset = 0
        var nodes: [ASN1Node] = []
        
        while offset < bytes.count {
            nodes.append(try parseNode(bytes, offset: &offset))
        }
        
        return nodes
    }
    
    // MARK: - Internal Parsing
    
    private static func parseNode(_ bytes: [UInt8], offset: inout Int) throws -> ASN1Node {
        let startOffset = offset
        
        guard offset < bytes.count else {
            throw ASN1Error.truncatedData
        }
        
        // Parse tag
        let tagByte = bytes[offset]
        offset += 1
        
        let tagClass = tagByte & 0xC0
        let isConstructed = (tagByte & 0x20) != 0
        var tagNumber = tagByte & 0x1F
        
        // Handle multi-byte tag numbers (high tag form)
        if tagNumber == 0x1F {
            tagNumber = 0
            while offset < bytes.count {
                let byte = bytes[offset]
                offset += 1
                tagNumber = (tagNumber << 7) | (byte & 0x7F)
                if (byte & 0x80) == 0 {
                    break
                }
            }
        }
        
        let tag = ASN1Tag(tagNumber: tagNumber, tagClass: tagClass)
        
        // Parse length
        guard offset < bytes.count else {
            throw ASN1Error.truncatedData
        }
        
        let (contentLength, lengthBytes) = try parseLength(bytes, offset: offset)
        offset += lengthBytes
        
        let headerLength = offset - startOffset
        
        // Validate we have enough data
        guard offset + contentLength <= bytes.count else {
            throw ASN1Error.truncatedData
        }
        
        // Parse content
        let contentBytes = Array(bytes[offset..<(offset + contentLength)])
        var children: [ASN1Node] = []
        
        if isConstructed && contentLength > 0 {
            // Parse children
            var childOffset = 0
            while childOffset < contentBytes.count {
                let child = try parseNode(contentBytes, offset: &childOffset)
                children.append(child)
            }
        }
        
        offset += contentLength
        
        return ASN1Node(
            tag: tag,
            rawTag: tagByte,
            isConstructed: isConstructed,
            offset: startOffset,
            headerLength: headerLength,
            contentLength: contentLength,
            bytes: isConstructed ? [] : contentBytes,
            children: children
        )
    }
    
    private static func parseLength(_ bytes: [UInt8], offset: Int) throws -> (length: Int, bytesConsumed: Int) {
        guard offset < bytes.count else {
            throw ASN1Error.truncatedData
        }
        
        let firstByte = bytes[offset]
        
        if firstByte < 0x80 {
            // Short form: single byte length
            return (Int(firstByte), 1)
        }
        
        if firstByte == 0x80 {
            // Indefinite length - not supported in DER
            throw ASN1Error.unsupportedLengthEncoding
        }
        
        // Long form: first byte indicates number of length bytes
        let numLengthBytes = Int(firstByte & 0x7F)
        
        guard numLengthBytes <= 4 else {
            // Length too large
            throw ASN1Error.unsupportedLengthEncoding
        }
        
        guard offset + 1 + numLengthBytes <= bytes.count else {
            throw ASN1Error.truncatedData
        }
        
        var length = 0
        for i in 0..<numLengthBytes {
            length = (length << 8) | Int(bytes[offset + 1 + i])
        }
        
        return (length, 1 + numLengthBytes)
    }
}

// MARK: - OID Constants

extension ASN1 {
    /// Common OID prefixes for passport data
    public enum OID {
        // Signed data content type
        public static let signedData = "1.2.840.113549.1.7.2"
        public static let data = "1.2.840.113549.1.7.1"
        
        // Digest algorithms
        public static let sha1 = "1.3.14.3.2.26"
        public static let sha224 = "2.16.840.1.101.3.4.2.4"
        public static let sha256 = "2.16.840.1.101.3.4.2.1"
        public static let sha384 = "2.16.840.1.101.3.4.2.2"
        public static let sha512 = "2.16.840.1.101.3.4.2.3"
        
        // Signature algorithms
        public static let rsaEncryption = "1.2.840.113549.1.1.1"
        public static let sha1WithRSAEncryption = "1.2.840.113549.1.1.5"
        public static let sha256WithRSAEncryption = "1.2.840.113549.1.1.11"
        public static let sha384WithRSAEncryption = "1.2.840.113549.1.1.12"
        public static let sha512WithRSAEncryption = "1.2.840.113549.1.1.13"
        public static let rsassaPss = "1.2.840.113549.1.1.10"
        
        // ECDSA
        public static let ecPublicKey = "1.2.840.10045.2.1"
        public static let ecdsaWithSHA1 = "1.2.840.10045.4.1"
        public static let ecdsaWithSHA256 = "1.2.840.10045.4.3.2"
        public static let ecdsaWithSHA384 = "1.2.840.10045.4.3.3"
        public static let ecdsaWithSHA512 = "1.2.840.10045.4.3.4"
        
        // Attribute types
        public static let contentType = "1.2.840.113549.1.9.3"
        public static let messageDigest = "1.2.840.113549.1.9.4"
        public static let signingTime = "1.2.840.113549.1.9.5"
        
        // LDS Security Object
        public static let ldsSecurityObject = "2.23.136.1.1.1"
    }
    
    /// Map OID string to human-readable name
    public static func oidName(_ oid: String) -> String {
        switch oid {
        case OID.signedData: return "signedData"
        case OID.data: return "data"
        case OID.sha1: return "sha1"
        case OID.sha224: return "sha224"
        case OID.sha256: return "sha256"
        case OID.sha384: return "sha384"
        case OID.sha512: return "sha512"
        case OID.rsaEncryption: return "rsaEncryption"
        case OID.sha1WithRSAEncryption: return "sha1WithRSAEncryption"
        case OID.sha256WithRSAEncryption: return "sha256WithRSAEncryption"
        case OID.sha384WithRSAEncryption: return "sha384WithRSAEncryption"
        case OID.sha512WithRSAEncryption: return "sha512WithRSAEncryption"
        case OID.rsassaPss: return "rsassaPss"
        case OID.ecPublicKey: return "ecPublicKey"
        case OID.ecdsaWithSHA1: return "ecdsaWithSHA1"
        case OID.ecdsaWithSHA256: return "ecdsaWithSHA256"
        case OID.ecdsaWithSHA384: return "ecdsaWithSHA384"
        case OID.ecdsaWithSHA512: return "ecdsaWithSHA512"
        case OID.contentType: return "contentType"
        case OID.messageDigest: return "messageDigest"
        case OID.signingTime: return "signingTime"
        case OID.ldsSecurityObject: return "ldsSecurityObject"
        default: return oid
        }
    }
}
