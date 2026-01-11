//
//  MRTDModel.swift
//

import Foundation
import OSLog

#if os(iOS)
import UIKit
#endif

public enum PassportAuthenticationStatus {
    case notDone
    case success
    case failed
}

@available(iOS 13, macOS 10.15, *)
public class MRTDModel {
    
    // MARK: - MRZ Data (from DG1)
    
    public private(set) lazy var documentType: String = {
        String(passportDataElements?["5F03"]?.first ?? "?")
    }()
    
    public private(set) lazy var documentSubType: String = {
        String(passportDataElements?["5F03"]?.last ?? "?")
    }()
    
    public private(set) lazy var documentNumber: String = {
        (passportDataElements?["5A"] ?? "?").replacingOccurrences(of: "<", with: "")
    }()
    
    public private(set) lazy var issuingAuthority: String = {
        passportDataElements?["5F28"] ?? "?"
    }()
    
    public private(set) lazy var documentExpiryDate: String = {
        passportDataElements?["59"] ?? "?"
    }()
    
    public private(set) lazy var dateOfBirth: String = {
        passportDataElements?["5F57"] ?? "?"
    }()
    
    public private(set) lazy var gender: String = {
        passportDataElements?["5F35"] ?? "?"
    }()
    
    public private(set) lazy var nationality: String = {
        passportDataElements?["5F2C"] ?? "?"
    }()
    
    public private(set) lazy var lastName: String = {
        names[0].replacingOccurrences(of: "<", with: " ")
    }()
    
    public private(set) lazy var firstName: String = {
        names.dropFirst()
            .map { $0.replacingOccurrences(of: "<", with: " ").trimmingCharacters(in: .whitespacesAndNewlines) }
            .joined(separator: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }()
    
    public private(set) lazy var passportMRZ: String = {
        passportDataElements?["5F1F"] ?? "NOT FOUND"
    }()
    
    // MARK: - Extended Data (from DG11)
    
    private lazy var names: [String] = {
        if let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
           let fullName = dg11.fullName?.components(separatedBy: "<<") {
            return fullName
        }
        return (passportDataElements?["5B"] ?? "?").components(separatedBy: "<<")
    }()
    
    public private(set) lazy var placeOfBirth: String? = {
        (dataGroupsRead[.DG11] as? DataGroup11)?.placeOfBirth
    }()
    
    public private(set) lazy var residenceAddress: String? = {
        (dataGroupsRead[.DG11] as? DataGroup11)?.address
    }()
    
    public private(set) lazy var phoneNumber: String? = {
        (dataGroupsRead[.DG11] as? DataGroup11)?.telephone
    }()
    
    public private(set) lazy var personalNumber: String? = {
        if let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
           let personalNumber = dg11.personalNumber {
            return personalNumber
        }
        return (passportDataElements?["53"] ?? "?").replacingOccurrences(of: "<", with: "")
    }()
    
    // MARK: - Biometric Data (from DG2)
    
    public private(set) lazy var faceImageInfo: FaceImageInfo? = {
        guard let dg2 = dataGroupsRead[.DG2] as? DataGroup2 else { return nil }
        return FaceImageInfo.from(dg2: dg2)
    }()
    
    // MARK: - Certificates
    
    public private(set) lazy var documentSigningCertificate: X509Wrapper? = {
        certificateSigningGroups[.documentSigningCertificate]
    }()

    public private(set) lazy var countrySigningCertificate: X509Wrapper? = {
        certificateSigningGroups[.issuerSigningCertificate]
    }()
    
    // MARK: - LDS Info (from COM)
    
    public private(set) lazy var LDSVersion: String = {
        (dataGroupsRead[.COM] as? COM)?.version ?? "Unknown"
    }()
    
    public private(set) lazy var dataGroupsPresent: [String] = {
        (dataGroupsRead[.COM] as? COM)?.dataGroupsPresent ?? []
    }()
    
    // MARK: - Data Group Storage
    
    public private(set) var dataGroupsAvailable = [DataGroupId]()
    public private(set) var dataGroupsRead: [DataGroupId: DataGroup] = [:]
    public private(set) var dataGroupHashes = [DataGroupId: DataGroupHash]()

    public internal(set) var cardAccess: CardAccess?
    public internal(set) var BACStatus: PassportAuthenticationStatus = .notDone
    public internal(set) var PACEStatus: PassportAuthenticationStatus = .notDone
    public internal(set) var chipAuthenticationStatus: PassportAuthenticationStatus = .notDone

    // MARK: - Verification Status
    
    public private(set) var passportCorrectlySigned = false
    public private(set) var documentSigningCertificateVerified = false
    public private(set) var passportDataNotTampered = false
    public private(set) var activeAuthenticationPassed = false
    public private(set) var activeAuthenticationChallenge: [UInt8] = []
    public private(set) var activeAuthenticationSignature: [UInt8] = []
    public private(set) var verificationErrors: [Error] = []

    // MARK: - Computed Properties
    
    public var isPACESupported: Bool {
        if cardAccess?.paceInfo != nil { return true }
        if let dg14 = dataGroupsRead[.DG14] as? DataGroup14 {
            return dg14.securityInfos.contains { $0 is PACEInfo }
        }
        return false
    }
    
    public var isChipAuthenticationSupported: Bool {
        guard let dg14 = dataGroupsRead[.DG14] as? DataGroup14 else { return false }
        return dg14.securityInfos.contains { $0 is ChipAuthenticationPublicKeyInfo }
    }
    
    public var activeAuthenticationSupported: Bool {
        guard let dg15 = dataGroupsRead[.DG15] as? DataGroup15 else { return false }
        return dg15.ecdsaPublicKey != nil || dg15.rsaPublicKey != nil
    }

    #if os(iOS)
    public var passportImage: UIImage? {
        (dataGroupsRead[.DG2] as? DataGroup2)?.getImage()
    }

    public var signatureImage: UIImage? {
        (dataGroupsRead[.DG7] as? DataGroup7)?.getImage()
    }
    #endif

    // MARK: - Private Properties
    
    private var certificateSigningGroups: [CertificateType: X509Wrapper] = [:]

    private var passportDataElements: [String: String]? {
        (dataGroupsRead[.DG1] as? DataGroup1)?.elements
    }
    
    // MARK: - Init
    
    public init() {}
    
    public init(from dump: [String: String]) {
        var aaChallenge: [UInt8]?
        var aaSignature: [UInt8]?
        
        for (key, value) in dump {
            guard let data = Data(base64Encoded: value) else { continue }
            let bytes = [UInt8](data)
            
            switch key {
            case "AAChallenge":
                aaChallenge = bytes
            case "AASignature":
                aaSignature = bytes
            default:
                do {
                    let dg = try DataGroupParser().parseDG(data: bytes)
                    let dgId = DataGroupId.from(name: key)
                    addDataGroup(dgId, dataGroup: dg)
                } catch {
                    Logger.reader.errorIfEnabled("Failed to import Datagroup \(key)")
                }
            }
        }

        if let challenge = aaChallenge, let signature = aaSignature {
            verifyActiveAuthentication(challenge: challenge, signature: signature)
        }
    }
    
    // MARK: - Data Group Management
    
    public func addDataGroup(_ id: DataGroupId, dataGroup: DataGroup) {
        dataGroupsRead[id] = dataGroup
        if id != .COM && id != .SOD {
            dataGroupsAvailable.append(id)
        }
    }

    public func getDataGroup(_ id: DataGroupId) -> DataGroup? {
        dataGroupsRead[id]
    }

    /// Exports passport data as Base64-encoded dictionary
    public func dumpPassportData(selectedDataGroups: [DataGroupId], includeActiveAuthenticationData: Bool = false) -> [String: String] {
        var result = [String: String]()
        
        for dgId in selectedDataGroups {
            if let dataGroup = dataGroupsRead[dgId] {
                result[dgId.name] = Data(dataGroup.data).base64EncodedString()
            }
        }
        
        if includeActiveAuthenticationData && activeAuthenticationSupported {
            result["AAChallenge"] = Data(activeAuthenticationChallenge).base64EncodedString()
            result["AASignature"] = Data(activeAuthenticationSignature).base64EncodedString()
        }
        
        return result
    }

    public func getHashesForDatagroups(hashAlgorythm: String) -> [DataGroupId: [UInt8]] {
        var result = [DataGroupId: [UInt8]]()
        
        for (key, value) in dataGroupsRead {
            switch hashAlgorythm {
            case "SHA1":   result[key] = calcSHA1Hash(value.body)
            case "SHA224": result[key] = calcSHA224Hash(value.body)
            case "SHA256": result[key] = calcSHA256Hash(value.body)
            case "SHA384": result[key] = calcSHA384Hash(value.body)
            case "SHA512": result[key] = calcSHA512Hash(value.body)
            default: break
            }
        }
        
        return result
    }
    
    // MARK: - Verification
    
    /// Performs passive authentication on the passport
    public func verifyPassport(masterListURL: URL?, useCMSVerification: Bool = false) {
        if let masterListURL = masterListURL {
            do {
                try validateAndExtractSigningCertificates(masterListURL: masterListURL)
            } catch {
                verificationErrors.append(error)
            }
        }
        
        do {
            try ensureReadDataNotBeenTamperedWith(useCMSVerification: useCMSVerification)
        } catch {
            verificationErrors.append(error)
        }
    }
    
    public func verifyActiveAuthentication(challenge: [UInt8], signature: [UInt8]) {
        activeAuthenticationChallenge = challenge
        activeAuthenticationSignature = signature
        activeAuthenticationPassed = false
        
        Logger.reader.debugIfEnabled("Active Authentication - verifying challenge and signature")
        
        guard let dg15 = dataGroupsRead[.DG15] as? DataGroup15 else { return }
        
        if let rsaKey = dg15.rsaPublicKey {
            verifyRSAActiveAuthentication(challenge: challenge, signature: signature, rsaKey: rsaKey)
        } else if let ecdsaKey = dg15.ecdsaPublicKey {
            verifyECDSAActiveAuthentication(challenge: challenge, signature: signature, ecdsaKey: ecdsaKey)
        }
    }
    
    // MARK: - Private Verification Methods
    
    private func verifyRSAActiveAuthentication(challenge: [UInt8], signature: [UInt8], rsaKey: OpaquePointer) {
        do {
            var decryptedSig = try OpenSSLUtils.decryptRSASignature(signature: Data(signature), pubKey: rsaKey)
            
            // Parse trailer to determine hash algorithm
            var hashTypeByte = decryptedSig.popLast() ?? 0x00
            if hashTypeByte == 0xCC {
                hashTypeByte = decryptedSig.popLast() ?? 0x00
            }
            
            let (hashType, hashLength): (String, Int) = {
                switch hashTypeByte {
                case 0xBC, 0x33: return ("SHA1", 20)
                case 0x34: return ("SHA256", 32)
                case 0x35: return ("SHA512", 64)
                case 0x36: return ("SHA384", 48)
                case 0x38: return ("SHA224", 28)
                default: return ("", 0)
                }
            }()
            
            guard !hashType.isEmpty else {
                Logger.reader.errorIfEnabled("Error identifying AA RSA message digest hash algorithm")
                return
            }
            
            let message = Array(decryptedSig[1..<(decryptedSig.count - hashLength)])
            let digest = Array(decryptedSig[(decryptedSig.count - hashLength)...])
            let msgHash = try calcHash(data: message + challenge, hashAlgorithm: hashType)
            
            if msgHash == digest {
                activeAuthenticationPassed = true
                Logger.reader.debugIfEnabled("Active Authentication (RSA) successful")
            } else {
                Logger.reader.errorIfEnabled("AA RSA signature verification failed - hash mismatch")
            }
        } catch {
            Logger.reader.errorIfEnabled("Error verifying AA RSA signature")
        }
    }
    
    private func verifyECDSAActiveAuthentication(challenge: [UInt8], signature: [UInt8], ecdsaKey: OpaquePointer) {
        var digestType = ""
        if let dg14 = dataGroupsRead[.DG14] as? DataGroup14,
           let aa = dg14.securityInfos.compactMap({ $0 as? ActiveAuthenticationInfo }).first {
            digestType = aa.getSignatureAlgorithmOIDString() ?? ""
        }
        
        if OpenSSLUtils.verifyECDSASignature(publicKey: ecdsaKey, signature: signature, data: challenge, digestType: digestType) {
            activeAuthenticationPassed = true
            Logger.reader.debugIfEnabled("Active Authentication (ECDSA) successful")
        } else {
            Logger.reader.errorIfEnabled("Error verifying AA ECDSA signature")
        }
    }

    private func validateAndExtractSigningCertificates(masterListURL: URL) throws {
        passportCorrectlySigned = false
        
        guard let sod = getDataGroup(.SOD) else {
            throw PassiveAuthenticationError.SODMissing("No SOD found")
        }

        let cert = try OpenSSLUtils.getX509CertificatesFromPKCS7(pkcs7Der: Data(sod.body)).first!
        certificateSigningGroups[.documentSigningCertificate] = cert

        switch OpenSSLUtils.verifyTrustAndGetIssuerCertificate(x509: cert, CAFile: masterListURL) {
        case .success(let csca):
            certificateSigningGroups[.issuerSigningCertificate] = csca
        case .failure(let error):
            throw error
        }
                
        Logger.reader.debugIfEnabled("Passport passed SOD Verification")
        passportCorrectlySigned = true
    }

    private func ensureReadDataNotBeenTamperedWith(useCMSVerification: Bool) throws {
        guard let sod = getDataGroup(.SOD) as? SOD else {
            throw PassiveAuthenticationError.SODMissing("No SOD found")
        }

        var signedData: Data
        documentSigningCertificateVerified = false
        
        do {
            signedData = useCMSVerification
                ? try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod)
                : try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod)
            documentSigningCertificateVerified = true
        } catch {
            signedData = try sod.getEncapsulatedContent()
        }
                
        passportDataNotTampered = false
        let asn1Data = try OpenSSLUtils.ASN1Parse(data: signedData)
        let (sodHashAlgorythm, sodHashes) = try parseSODSignatureContent(asn1Data)
        
        var errors = ""
        for (id, dgVal) in dataGroupsRead {
            guard let sodHashVal = sodHashes[id] else {
                if id != .SOD && id != .COM {
                    errors += "DataGroup \(id) is missing!\n"
                }
                continue
            }
            
            let computedHashVal = dgVal.hash(sodHashAlgorythm).hexString
            let match = computedHashVal == sodHashVal
            
            if !match {
                errors += "\(id) invalid hash:\n  SOD: \(sodHashVal)\n  Computed: \(computedHashVal)\n"
            }

            dataGroupHashes[id] = DataGroupHash(id: id.name, sodHash: sodHashVal, computedHash: computedHashVal, match: match)
        }
        
        if !errors.isEmpty {
            Logger.reader.errorIfEnabled("Hash verification failed for one or more data groups")
            throw PassiveAuthenticationError.InvalidDataGroupHash(errors)
        }
        
        Logger.reader.debugIfEnabled("Passport passed Datagroup Tampering check")
        passportDataNotTampered = true
    }
    
    private func parseSODSignatureContent(_ content: String) throws -> (String, [DataGroupId: String]) {
        var currentDG = ""
        var sodHashAlgo = ""
        var sodHashes: [DataGroupId: String] = [:]
        
        let dgList: [DataGroupId] = [.COM, .DG1, .DG2, .DG3, .DG4, .DG5, .DG6, .DG7, .DG8, .DG9, .DG10, .DG11, .DG12, .DG13, .DG14, .DG15, .DG16, .SOD]

        for line in content.components(separatedBy: "\n") {
            if line.contains("d=2") && line.contains("OBJECT") {
                if line.contains("sha1") { sodHashAlgo = "SHA1" }
                else if line.contains("sha224") { sodHashAlgo = "SHA224" }
                else if line.contains("sha256") { sodHashAlgo = "SHA256" }
                else if line.contains("sha384") { sodHashAlgo = "SHA384" }
                else if line.contains("sha512") { sodHashAlgo = "SHA512" }
            } else if line.contains("d=3") && line.contains("INTEGER") {
                if let range = line.range(of: "INTEGER"),
                   let colonRange = line[range.upperBound...].range(of: ":") {
                    currentDG = String(line[colonRange.upperBound...])
                }
            } else if line.contains("d=3") && line.contains("OCTET STRING") {
                if let range = line.range(of: "[HEX DUMP]:"),
                   !currentDG.isEmpty,
                   let id = Int(currentDG, radix: 16) {
                    sodHashes[dgList[id]] = String(line[range.upperBound...])
                    currentDG = ""
                }
            }
        }
        
        guard !sodHashAlgo.isEmpty else {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unable to find hash algorithm")
        }
        guard !sodHashes.isEmpty else {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unable to extract hashes")
        }

        Logger.reader.debugIfEnabled("Parse SOD - Algo: \(sodHashAlgo), DataGroups: \(sodHashes.keys.map { $0.name })")
        return (sodHashAlgo, sodHashes)
    }
}

// MARK: - Type Aliases for backwards compatibility
@available(iOS 13, macOS 10.15, *)
public typealias NFCPassportModel = MRTDModel
