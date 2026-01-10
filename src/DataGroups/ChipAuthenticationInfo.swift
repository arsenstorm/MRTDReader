//
//  ChipAuthenticationInfo.swift
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class ChipAuthenticationInfo: SecurityInfo {
    
    private static let allowedOIDs: Set<String> = [
        ID_CA_DH_3DES_CBC_CBC_OID, ID_CA_ECDH_3DES_CBC_CBC_OID,
        ID_CA_DH_AES_CBC_CMAC_128_OID, ID_CA_DH_AES_CBC_CMAC_192_OID, ID_CA_DH_AES_CBC_CMAC_256_OID,
        ID_CA_ECDH_AES_CBC_CMAC_128_OID, ID_CA_ECDH_AES_CBC_CMAC_192_OID, ID_CA_ECDH_AES_CBC_CMAC_256_OID
    ]
    
    private static let dhOIDs: Set<String> = [
        ID_CA_DH_3DES_CBC_CBC_OID, ID_CA_DH_AES_CBC_CMAC_128_OID,
        ID_CA_DH_AES_CBC_CMAC_192_OID, ID_CA_DH_AES_CBC_CMAC_256_OID
    ]
    
    private static let tripleDesOIDs: Set<String> = [
        ID_CA_DH_3DES_CBC_CBC_OID, ID_CA_ECDH_3DES_CBC_CBC_OID
    ]
    
    var oid: String
    var version: Int
    var keyId: Int?
    
    static func checkRequiredIdentifier(_ oid: String) -> Bool {
        allowedOIDs.contains(oid)
    }
    
    init(oid: String, version: Int, keyId: Int? = nil) {
        self.oid = oid
        self.version = version
        self.keyId = keyId
    }
    
    public override func getObjectIdentifier() -> String { oid }
    
    public override func getProtocolOIDString() -> String {
        Self.protocolOIDStrings[oid] ?? oid
    }
    
    public func getKeyId() -> Int { keyId ?? 0 }
    
    // MARK: - Static Algorithm Lookups
    
    public static func toKeyAgreementAlgorithm(oid: String) throws -> String {
        if dhOIDs.contains(oid) { return "DH" }
        if allowedOIDs.contains(oid) { return "ECDH" }
        throw NFCPassportReaderError.InvalidDataPassed("Unable to lookup key agreement algorithm - invalid oid")
    }
    
    public static func toCipherAlgorithm(oid: String) throws -> String {
        if tripleDesOIDs.contains(oid) { return "DESede" }
        if allowedOIDs.contains(oid) { return "AES" }
        throw NFCPassportReaderError.InvalidDataPassed("Unable to lookup cipher algorithm - invalid oid")
    }
    
    public static func toKeyLength(oid: String) throws -> Int {
        switch oid {
        case ID_CA_DH_3DES_CBC_CBC_OID, ID_CA_ECDH_3DES_CBC_CBC_OID,
             ID_CA_DH_AES_CBC_CMAC_128_OID, ID_CA_ECDH_AES_CBC_CMAC_128_OID:
            return 128
        case ID_CA_DH_AES_CBC_CMAC_192_OID, ID_CA_ECDH_AES_CBC_CMAC_192_OID:
            return 192
        case ID_CA_DH_AES_CBC_CMAC_256_OID, ID_CA_ECDH_AES_CBC_CMAC_256_OID:
            return 256
        default:
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get key length - invalid oid")
        }
    }
    
    private static let protocolOIDStrings: [String: String] = [
        ID_CA_DH_3DES_CBC_CBC_OID: "id-CA-DH-3DES-CBC-CBC",
        ID_CA_DH_AES_CBC_CMAC_128_OID: "id-CA-DH-AES-CBC-CMAC-128",
        ID_CA_DH_AES_CBC_CMAC_192_OID: "id-CA-DH-AES-CBC-CMAC-192",
        ID_CA_DH_AES_CBC_CMAC_256_OID: "id-CA-DH-AES-CBC-CMAC-256",
        ID_CA_ECDH_3DES_CBC_CBC_OID: "id-CA-ECDH-3DES-CBC-CBC",
        ID_CA_ECDH_AES_CBC_CMAC_128_OID: "id-CA-ECDH-AES-CBC-CMAC-128",
        ID_CA_ECDH_AES_CBC_CMAC_192_OID: "id-CA-ECDH-AES-CBC-CMAC-192",
        ID_CA_ECDH_AES_CBC_CMAC_256_OID: "id-CA-ECDH-AES-CBC-CMAC-256"
    ]
}
