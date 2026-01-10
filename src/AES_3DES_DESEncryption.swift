
import Foundation
import OSLog
import CommonCrypto

// MARK: - Core Crypto Helper

/// Performs symmetric encryption/decryption using CommonCrypto
/// - Parameters:
///   - operation: kCCEncrypt or kCCDecrypt
///   - algorithm: kCCAlgorithmAES, kCCAlgorithm3DES, or kCCAlgorithmDES
///   - options: CCOptions (0 for CBC, kCCOptionECBMode for ECB)
///   - key: Encryption/decryption key
///   - keyLength: Size of the key (use key.count for AES, kCCKeySize3DES/kCCKeySizeDES for others)
///   - iv: Initialization vector (nil for ECB mode)
///   - message: Data to encrypt/decrypt
///   - blockSize: Block size for the algorithm
/// - Returns: Encrypted/decrypted bytes, or empty array on failure
@available(iOS 13, macOS 10.15, *)
private func performCrypto(
    operation: CCOperation,
    algorithm: CCAlgorithm,
    options: CCOptions,
    key: [UInt8],
    keyLength: Int,
    iv: [UInt8]?,
    message: [UInt8],
    blockSize: Int,
    errorLabel: String
) -> [UInt8] {
    let cryptLen = message.count + blockSize
    var cryptData = Data(count: cryptLen)
    var numBytesProcessed = 0
    
    let cryptStatus: CCCryptorStatus = key.withUnsafeBytes { keyBytes in
        message.withUnsafeBytes { dataBytes in
            cryptData.withUnsafeMutableBytes { cryptBytes in
                if let iv = iv {
                    return iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            operation,
                            algorithm,
                            options,
                            keyBytes.baseAddress, keyLength,
                            ivBytes.baseAddress,
                            dataBytes.baseAddress, message.count,
                            cryptBytes.bindMemory(to: UInt8.self).baseAddress, cryptLen,
                            &numBytesProcessed
                        )
                    }
                } else {
                    return CCCrypt(
                        operation,
                        algorithm,
                        options,
                        keyBytes.baseAddress, keyLength,
                        nil,
                        dataBytes.baseAddress, message.count,
                        cryptBytes.bindMemory(to: UInt8.self).baseAddress, cryptLen,
                        &numBytesProcessed
                    )
                }
            }
        }
    }
    
    guard cryptStatus == kCCSuccess else {
        Logger.passportReader.error("\(errorLabel) Error: \(cryptStatus)")
        return []
    }
    
    cryptData.count = numBytesProcessed
    return [UInt8](cryptData)
}

/// Expands a 16-byte key to 24 bytes for 3DES compatibility
private func expandKeyFor3DES(_ key: [UInt8]) -> [UInt8] {
    key.count == 16 ? key + key[0..<8] : key
}

// MARK: - AES Functions

/// Encrypts a message using AES/CBC/NOPADDING
@available(iOS 13, macOS 10.15, *)
public func AESEncrypt(key: [UInt8], message: [UInt8], iv: [UInt8]) -> [UInt8] {
    performCrypto(
        operation: CCOperation(kCCEncrypt),
        algorithm: CCAlgorithm(kCCAlgorithmAES),
        options: 0,
        key: key,
        keyLength: key.count,
        iv: iv,
        message: message,
        blockSize: kCCBlockSizeAES128,
        errorLabel: "AES Encrypt"
    )
}

/// Decrypts a message using AES/CBC/NOPADDING
@available(iOS 13, macOS 10.15, *)
public func AESDecrypt(key: [UInt8], message: [UInt8], iv: [UInt8]) -> [UInt8] {
    let fixedKey = expandKeyFor3DES(key)
    return performCrypto(
        operation: CCOperation(kCCDecrypt),
        algorithm: CCAlgorithm(kCCAlgorithmAES),
        options: 0,
        key: fixedKey,
        keyLength: key.count,
        iv: iv,
        message: message,
        blockSize: kCCBlockSizeAES128,
        errorLabel: "AES Decrypt"
    )
}

/// Encrypts a message using AES/ECB/NOPADDING
@available(iOS 13, macOS 10.15, *)
public func AESECBEncrypt(key: [UInt8], message: [UInt8]) -> [UInt8] {
    performCrypto(
        operation: CCOperation(kCCEncrypt),
        algorithm: CCAlgorithm(kCCAlgorithmAES),
        options: CCOptions(kCCOptionECBMode),
        key: key,
        keyLength: key.count,
        iv: nil,
        message: message,
        blockSize: kCCBlockSizeAES128,
        errorLabel: "AES ECB Encrypt"
    )
}

// MARK: - Triple DES Functions

/// Encrypts a message using 3DES/CBC/NOPADDING
@available(iOS 13, macOS 10.15, *)
public func tripleDESEncrypt(key: [UInt8], message: [UInt8], iv: [UInt8]) -> [UInt8] {
    performCrypto(
        operation: CCOperation(kCCEncrypt),
        algorithm: CCAlgorithm(kCCAlgorithm3DES),
        options: 0,
        key: expandKeyFor3DES(key),
        keyLength: kCCKeySize3DES,
        iv: iv,
        message: message,
        blockSize: kCCBlockSize3DES,
        errorLabel: "3DES Encrypt"
    )
}

/// Decrypts a message using 3DES/CBC/NOPADDING
@available(iOS 13, macOS 10.15, *)
public func tripleDESDecrypt(key: [UInt8], message: [UInt8], iv: [UInt8]) -> [UInt8] {
    performCrypto(
        operation: CCOperation(kCCDecrypt),
        algorithm: CCAlgorithm(kCCAlgorithm3DES),
        options: 0,
        key: expandKeyFor3DES(key),
        keyLength: kCCKeySize3DES,
        iv: iv,
        message: message,
        blockSize: kCCBlockSize3DES,
        errorLabel: "3DES Decrypt"
    )
}

// MARK: - DES Functions

/// Encrypts a message using DES/CBC/NOPADDING
@available(iOS 13, macOS 10.15, *)
public func DESEncrypt(key: [UInt8], message: [UInt8], iv: [UInt8], options: UInt32 = 0) -> [UInt8] {
    performCrypto(
        operation: CCOperation(kCCEncrypt),
        algorithm: CCAlgorithm(kCCAlgorithmDES),
        options: CCOptions(options),
        key: key,
        keyLength: kCCKeySizeDES,
        iv: iv,
        message: message,
        blockSize: kCCBlockSizeDES,
        errorLabel: "DES Encrypt"
    )
}

/// Decrypts a message using DES
@available(iOS 13, macOS 10.15, *)
public func DESDecrypt(key: [UInt8], message: [UInt8], iv: [UInt8], options: UInt32 = 0) -> [UInt8] {
    performCrypto(
        operation: CCOperation(kCCDecrypt),
        algorithm: CCAlgorithm(kCCAlgorithmDES),
        options: CCOptions(options),
        key: key,
        keyLength: kCCKeySizeDES,
        iv: nil,
        message: message,
        blockSize: kCCBlockSizeDES,
        errorLabel: "DES Decrypt"
    )
}
