
import Foundation
import OSLog
import CommonCrypto
import CryptoTokenKit

#if canImport(CryptoKit)
import CryptoKit
#endif

// MARK: - Hex String Extensions

public extension Data {
    /// Initialize Data from a hex string (e.g., "AABB" -> [0xAA, 0xBB])
    init?(hexString: String) {
        let hex = hexString.replacingOccurrences(of: " ", with: "")
        guard hex.count % 2 == 0 else { return nil }
        
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
    
    /// Convert Data to uppercase hex string (e.g., [0xAA, 0xBB] -> "AABB")
    var hexString: String {
        map { String(format: "%02X", $0) }.joined()
    }
}

public extension Array where Element == UInt8 {
    /// Initialize [UInt8] from a hex string (e.g., "AABB" -> [0xAA, 0xBB])
    init?(hexString: String) {
        guard let data = Data(hexString: hexString) else { return nil }
        self = Array(data)
    }
    
    /// Convert [UInt8] to uppercase hex string (e.g., [0xAA, 0xBB] -> "AABB")
    var hexString: String {
        map { String(format: "%02X", $0) }.joined()
    }
}

extension Int {
    var hexString: String { String(format: "%02X", self) }
}

extension FileManager {
    static var documentDir: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
    }
}

// MARK: - String Subscript Extensions

extension StringProtocol {
    subscript(bounds: CountableClosedRange<Int>) -> SubSequence {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(start, offsetBy: bounds.count)
        return self[start..<end]
    }
    
    subscript(bounds: CountableRange<Int>) -> SubSequence {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(start, offsetBy: bounds.count)
        return self[start..<end]
    }
    
    func index(of string: Self, options: String.CompareOptions = []) -> Index? {
        range(of: string, options: options)?.lowerBound
    }
}

// MARK: - Binary/Hex Conversion

/// Convert bytes to hex string representation (for logging)
public func binToHexRep(_ val: [UInt8], asArray: Bool = false) -> String {
    if asArray {
        return "[" + val.map { String(format: "0x%02x, ", $0) }.joined() + "]"
    }
    return val.map { String(format: "%02X", $0) }.joined()
}

/// Convert single byte to hex string
public func binToHexRep(_ val: UInt8) -> String {
    String(format: "%02X", val)
}

/// Convert single byte to Int
public func binToHex(_ val: UInt8) -> Int {
    Int(val)
}

/// Convert bytes to UInt64
public func binToHex(_ val: [UInt8]) -> UInt64 {
    val.reduce(0) { ($0 << 8) | UInt64($1) }
}

/// Convert byte slice to UInt64
public func binToHex(_ val: ArraySlice<UInt8>) -> UInt64 {
    binToHex([UInt8](val))
}

/// Convert UInt64 to bytes
public func hexToBin(_ val: UInt64) -> [UInt8] {
    var result: [UInt8] = []
    var v = val
    while v > 0 {
        result.insert(UInt8(v & 0xFF), at: 0)
        v >>= 8
    }
    return result.isEmpty ? [0] : result
}

/// Convert bytes to Int
public func binToInt(_ val: [UInt8]) -> Int {
    val.reduce(0) { ($0 << 8) | Int($1) }
}

/// Convert byte slice to Int
public func binToInt(_ val: ArraySlice<UInt8>) -> Int {
    binToInt([UInt8](val))
}

/// Convert Int to bytes with padding
public func intToBin(_ data: Int, pad: Int = 2) -> [UInt8] {
    let format = pad == 2 ? "%02x" : "%04x"
    return hexRepToBin(String(format: format, data))
}

/// Convert hex string to bytes (e.g., "AABB" -> [0xAA, 0xBB])
public func hexRepToBin(_ val: String) -> [UInt8] {
    var output: [UInt8] = []
    var x = 0
    while x < val.count {
        let end = min(x + 2, val.count)
        if let byte = UInt8(val[x..<end], radix: 16) {
            output.append(byte)
        }
        x += 2
    }
    return output
}

/// Convert Int to bytes, optionally removing leading zeros
public func intToBytes(val: Int, removePadding: Bool) -> [UInt8] {
    guard val != 0 else { return [0] }
    
    var data = withUnsafeBytes(of: val.bigEndian, Array.init)
    
    if removePadding {
        if let firstNonZero = data.firstIndex(where: { $0 != 0 }) {
            data = Array(data[firstNonZero...])
        }
    }
    return data
}

// MARK: - Cryptographic Utilities

/// XOR two byte arrays
public func xor(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
    zip(a, b).map { $0 ^ $1 }
}

/// Generate random bytes
public func generateRandomUInt8Array(_ size: Int) -> [UInt8] {
    (0..<size).map { _ in UInt8.random(in: 0...255) }
}

// MARK: - Padding

/// Add ISO 9797-1 padding (0x80 followed by 0x00s)
public func pad(_ toPad: [UInt8], blockSize: Int) -> [UInt8] {
    var result = toPad + [0x80]
    while result.count % blockSize != 0 {
        result.append(0x00)
    }
    return result
}

/// Remove ISO 9797-1 padding
public func unpad(_ data: [UInt8]) -> [UInt8] {
    guard let paddingIndex = data.lastIndex(of: 0x80),
          data[paddingIndex...].allSatisfy({ $0 == 0x80 || $0 == 0x00 }) else {
        return data // No valid padding found
    }
    return Array(data[..<paddingIndex])
}

// MARK: - MAC (Message Authentication Code)

@available(iOS 13, macOS 10.15, *)
public func mac(algoName: SecureMessagingSupportedAlgorithms, key: [UInt8], msg: [UInt8]) -> [UInt8] {
    algoName == .DES ? desMAC(key: key, msg: msg) : aesMAC(key: key, msg: msg)
}

@available(iOS 13, macOS 10.15, *)
public func desMAC(key: [UInt8], msg: [UInt8]) -> [UInt8] {
    let blockCount = msg.count / 8
    var y: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
    
    Logger.reader.debugIfEnabled("Computing DES MAC over \(blockCount) blocks")
    for i in 0..<blockCount {
        let block = Array(msg[i * 8..<i * 8 + 8])
        y = DESEncrypt(key: Array(key[0..<8]), message: block, iv: y)
    }
    
    let zeroIV: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0]
    let b = DESDecrypt(key: Array(key[8..<16]), message: y, iv: zeroIV, options: UInt32(kCCOptionECBMode))
    let a = DESEncrypt(key: Array(key[0..<8]), message: b, iv: zeroIV, options: UInt32(kCCOptionECBMode))
    
    Logger.reader.debugIfEnabled("DES MAC computed (\(a.count) bytes)")
    return a
}

@available(iOS 13, macOS 10.15, *)
public func aesMAC(key: [UInt8], msg: [UInt8]) -> [UInt8] {
    OpenSSLUtils.generateAESCMAC(key: key, message: msg)
}

// MARK: - TLV (Tag-Length-Value) Operations

/// Wrap data in a TLV structure
@available(iOS 13, macOS 10.15, *)
public func wrapDO(b: UInt8, arr: [UInt8]) -> [UInt8] {
    let tag = TKBERTLVRecord(tag: TKTLVTag(b), value: Data(arr))
    return [UInt8](tag.data)
}

/// Unwrap data from a TLV structure
@available(iOS 13, macOS 10.15, *)
public func unwrapDO(tag: UInt8, wrappedData: [UInt8]) throws -> [UInt8] {
    guard let rec = TKBERTLVRecord(from: Data(wrappedData)),
          rec.tag == tag else {
        throw NFCPassportReaderError.InvalidASN1Value
    }
    return [UInt8](rec.value)
}

// MARK: - ASN1 Length Encoding

/// Decode ASN1 length from bytes
/// - Returns: Tuple of (decoded length, bytes consumed for length encoding)
/// - Note: For full ASN1 parsing, use `ASN1.parse()` instead
@available(iOS 13, macOS 10.15, *)
public func asn1Length(_ data: ArraySlice<UInt8>) throws -> (Int, Int) {
    try asn1Length(Array(data))
}

@available(iOS 13, macOS 10.15, *)
public func asn1Length(_ data: [UInt8]) throws -> (Int, Int) {
    guard !data.isEmpty else { throw NFCPassportReaderError.CannotDecodeASN1Length }
    
    let firstByte = data[0]
    
    // Short form: single byte length (0-127)
    if firstByte < 0x80 {
        return (Int(firstByte), 1)
    }
    
    // Long form: first byte indicates number of length bytes
    switch firstByte {
    case 0x81:
        guard data.count > 1 else { throw NFCPassportReaderError.CannotDecodeASN1Length }
        return (Int(data[1]), 2)
    case 0x82:
        guard data.count > 2 else { throw NFCPassportReaderError.CannotDecodeASN1Length }
        return (Int(binToHex(Array(data[1..<3]))), 3)
    default:
        throw NFCPassportReaderError.CannotDecodeASN1Length
    }
}

/// Encode length in ASN1 format
@available(iOS 13, macOS 10.15, *)
public func toAsn1Length(_ length: Int) throws -> [UInt8] {
    switch length {
    case 0..<0x80:
        return [UInt8(length)]
    case 0x80...0xFF:
        return [0x81, UInt8(length)]
    case 0x100...0xFFFF:
        return [0x82, UInt8(length >> 8), UInt8(length & 0xFF)]
    default:
        throw NFCPassportReaderError.InvalidASN1Value
    }
}

// MARK: - OID Encoding

/// Encode OID string to bytes
@available(iOS 13, macOS 10.15, *)
public func oidToBytes(oid: String, replaceTag: Bool) -> [UInt8] {
    var encOID = OpenSSLUtils.asn1EncodeOID(oid: oid)
    if replaceTag {
        encOID[0] = 0x80 // Replace tag 0x06 with 0x80
    }
    return encOID
}

// MARK: - Array Chunking

/// Split data into chunks of specified size
/// - Parameters:
///   - data: The data to split
///   - chunkSize: Maximum size of each chunk
/// - Returns: Array of chunks
public func chunk(_ data: [UInt8], size chunkSize: Int) -> [[UInt8]] {
    stride(from: 0, to: data.count, by: chunkSize).map {
        Array(data[$0..<min($0 + chunkSize, data.count)])
    }
}

// MARK: - Secure Messaging Factory

/// Creates a SecureMessaging instance with the given parameters
/// - Parameters:
///   - cipherAlgorithm: The cipher algorithm name (e.g., "DESede", "AES")
///   - ksEnc: Encryption key
///   - ksMac: MAC key
/// - Returns: Configured SecureMessaging instance
@available(iOS 13, macOS 10.15, *)
public func createSecureMessaging(
    cipherAlgorithm: String,
    ksEnc: [UInt8],
    ksMac: [UInt8]
) -> SecureMessaging {
    let ssc = withUnsafeBytes(of: 0.bigEndian, Array.init)
    let algorithm: SecureMessagingSupportedAlgorithms = cipherAlgorithm.hasPrefix("DESede") ? .DES : .AES
    return SecureMessaging(encryptionAlgorithm: algorithm, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
}

// MARK: - Hash Functions

/// Calculate hash using specified algorithm
@available(iOS 13, macOS 10.15, *)
public func calcHash(data: [UInt8], hashAlgorithm: String) throws -> [UInt8] {
    switch hashAlgorithm.lowercased() {
    case "sha1": return calcSHA1Hash(data)
    case "sha224": return calcSHA224Hash(data)
    case "sha256": return calcSHA256Hash(data)
    case "sha384": return calcSHA384Hash(data)
    case "sha512": return calcSHA512Hash(data)
    default: throw NFCPassportReaderError.InvalidHashAlgorithmSpecified
    }
}

@available(iOS 13, macOS 10.15, *)
public func calcSHA1Hash(_ data: [UInt8]) -> [UInt8] {
    #if canImport(CryptoKit)
    var sha1 = Insecure.SHA1()
    sha1.update(data: data)
    return Array(sha1.finalize())
    #else
    fatalError("CryptoKit not available")
    #endif
}

@available(iOS 13, macOS 10.15, *)
public func calcSHA224Hash(_ data: [UInt8]) -> [UInt8] {
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA224($0.baseAddress, CC_LONG(data.count), &digest)
    }
    return digest
}

@available(iOS 13, macOS 10.15, *)
public func calcSHA256Hash(_ data: [UInt8]) -> [UInt8] {
    #if canImport(CryptoKit)
    var sha256 = SHA256()
    sha256.update(data: data)
    return Array(sha256.finalize())
    #else
    fatalError("CryptoKit not available")
    #endif
}

@available(iOS 13, macOS 10.15, *)
public func calcSHA384Hash(_ data: [UInt8]) -> [UInt8] {
    #if canImport(CryptoKit)
    var sha384 = SHA384()
    sha384.update(data: data)
    return Array(sha384.finalize())
    #else
    fatalError("CryptoKit not available")
    #endif
}

@available(iOS 13, macOS 10.15, *)
public func calcSHA512Hash(_ data: [UInt8]) -> [UInt8] {
    #if canImport(CryptoKit)
    var sha512 = SHA512()
    sha512.update(data: data)
    return Array(sha512.finalize())
    #else
    fatalError("CryptoKit not available")
    #endif
}
