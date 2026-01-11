//
//  Errors.swift
//

import Foundation

// MARK: - MRTDReaderError

@available(iOS 13, macOS 10.15, *)
public enum MRTDReaderError: Error {
    case ResponseError(String, UInt8, UInt8)
    case InvalidResponse(dataGroupId: DataGroupId, expectedTag: Int, actualTag: Int)
    case UnexpectedError
    case NFCNotSupported
    case NoConnectedTag
    case D087Malformed
    case InvalidResponseChecksum
    case MissingMandatoryFields
    case CannotDecodeASN1Length
    case InvalidASN1Value
    case UnableToProtectAPDU
    case UnableToUnprotectAPDU
    case UnsupportedDataGroup
    case DataGroupNotRead
    case UnknownTag
    case UnknownImageFormat
    case NotImplemented
    case TagNotValid
    case ConnectionError
    case TimeOutError
    case UserCanceled
    case InvalidMRZKey
    case MoreThanOneTagFound
    case InvalidHashAlgorithmSpecified
    case UnsupportedCipherAlgorithm
    case UnsupportedMappingType
    case PACEError(String, String)
    case ChipAuthenticationFailed
    case InvalidDataPassed(String)
    case NotYetSupported(String)
    case Unknown(Error)

    public var value: String {
        switch self {
        case .ResponseError(let msg, _, _):
            return msg
        case .InvalidResponse(let dgId, let expected, let actual):
            return "InvalidResponse in \(dgId.name). Expected: \(expected.hexString) Actual: \(actual.hexString)"
        case .PACEError(let step, let reason):
            return "PACEError (\(step)) - \(reason)"
        case .InvalidDataPassed(let reason):
            return "Invalid data passed - \(reason)"
        case .NotYetSupported(let reason):
            return "Not yet supported - \(reason)"
        case .Unknown(let error):
            return "Unknown error: \(error.localizedDescription)"
        default:
            return String(describing: self)
        }
    }
}

@available(iOS 13, macOS 10.15, *)
extension MRTDReaderError: LocalizedError {
    public var errorDescription: String? {
        NSLocalizedString(value, comment: "MRTDReaderError")
    }
}

/// Type alias for backwards compatibility
@available(iOS 13, macOS 10.15, *)
public typealias NFCPassportReaderError = MRTDReaderError

// MARK: - OpenSSLError

@available(iOS 13, macOS 10.15, *)
public enum OpenSSLError: Error {
    case UnableToGetX509CertificateFromPKCS7(String)
    case UnableToVerifyX509CertificateForSOD(String)
    case VerifyAndReturnSODEncapsulatedData(String)
    case UnableToReadECPublicKey(String)
    case UnableToExtractSignedDataFromPKCS7(String)
    case VerifySignedAttributes(String)
    case UnableToParseASN1(String)
    case UnableToDecryptRSASignature(String)
}

@available(iOS 13, macOS 10.15, *)
extension OpenSSLError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .UnableToGetX509CertificateFromPKCS7(let reason):
            return "Unable to read the SOD PKCS7 Certificate. \(reason)"
        case .UnableToVerifyX509CertificateForSOD(let reason):
            return "Unable to verify the SOD X509 certificate. \(reason)"
        case .VerifyAndReturnSODEncapsulatedData(let reason):
            return "Unable to verify the SOD Datagroup hashes. \(reason)"
        case .UnableToReadECPublicKey(let reason):
            return "Unable to read ECDSA Public key \(reason)!"
        case .UnableToExtractSignedDataFromPKCS7(let reason):
            return "Unable to extract Signer data from PKCS7 \(reason)!"
        case .VerifySignedAttributes(let reason):
            return "Unable to Verify the SOD SignedAttributes \(reason)!"
        case .UnableToParseASN1(let reason):
            return "Unable to parse ASN1 \(reason)!"
        case .UnableToDecryptRSASignature(let reason):
            return "Unable to decrypt RSA Signature \(reason)!"
        }
    }
}

// MARK: - PassiveAuthenticationError

public enum PassiveAuthenticationError: Error {
    case UnableToParseSODHashes(String)
    case InvalidDataGroupHash(String)
    case SODMissing(String)
}

extension PassiveAuthenticationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .UnableToParseSODHashes(let reason):
            return "Unable to parse the SOD Datagroup hashes. \(reason)"
        case .InvalidDataGroupHash(let reason):
            return "DataGroup hash not present or didn't match \(reason)!"
        case .SODMissing(let reason):
            return "DataGroup SOD not present or not read \(reason)!"
        }
    }
}
