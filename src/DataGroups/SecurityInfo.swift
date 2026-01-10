//
//  SecurityInfo.swift
//

import Foundation
import OpenSSL

// MARK: - OID Constants

/// Object Identifiers for passport security protocols
public enum SecurityOID {
    // Active Authentication
    static let ID_AA = "2.23.136.1.1.5"

    // ECDSA Plain Signature Algorithms (BSI TR 03111 Section 5.2.1)
    static let ECDSA_PLAIN_SIGNATURES = "0.4.0.127.0.7.1.1.4.1"
    static let ECDSA_PLAIN_SHA1       = ECDSA_PLAIN_SIGNATURES + ".1"
    static let ECDSA_PLAIN_SHA224     = ECDSA_PLAIN_SIGNATURES + ".2"
    static let ECDSA_PLAIN_SHA256     = ECDSA_PLAIN_SIGNATURES + ".3"
    static let ECDSA_PLAIN_SHA384     = ECDSA_PLAIN_SIGNATURES + ".4"
    static let ECDSA_PLAIN_SHA512     = ECDSA_PLAIN_SIGNATURES + ".5"
    static let ECDSA_PLAIN_RIPEMD160  = ECDSA_PLAIN_SIGNATURES + ".6"
    
    // Chip Authentication Public Key
    static let ID_PK_DH   = "0.4.0.127.0.7.2.2.1.1"
    static let ID_PK_ECDH = "0.4.0.127.0.7.2.2.1.2"
    
    // Chip Authentication
    private static let ID_CA = "0.4.0.127.0.7.2.2.3"
    static let ID_CA_DH_3DES_CBC_CBC       = ID_CA + ".1.1"
    static let ID_CA_ECDH_3DES_CBC_CBC     = ID_CA + ".2.1"
    static let ID_CA_DH_AES_CBC_CMAC_128   = ID_CA + ".1.2"
    static let ID_CA_DH_AES_CBC_CMAC_192   = ID_CA + ".1.3"
    static let ID_CA_DH_AES_CBC_CMAC_256   = ID_CA + ".1.4"
    static let ID_CA_ECDH_AES_CBC_CMAC_128 = ID_CA + ".2.2"
    static let ID_CA_ECDH_AES_CBC_CMAC_192 = ID_CA + ".2.3"
    static let ID_CA_ECDH_AES_CBC_CMAC_256 = ID_CA + ".2.4"

    // PACE
    private static let ID_BSI  = "0.4.0.127.0.7"
    private static let ID_PACE = ID_BSI + ".2.2.4"
    
    // PACE DH-GM
    private static let ID_PACE_DH_GM = ID_PACE + ".1"
    static let ID_PACE_DH_GM_3DES_CBC_CBC       = ID_PACE_DH_GM + ".1"
    static let ID_PACE_DH_GM_AES_CBC_CMAC_128   = ID_PACE_DH_GM + ".2"
    static let ID_PACE_DH_GM_AES_CBC_CMAC_192   = ID_PACE_DH_GM + ".3"
    static let ID_PACE_DH_GM_AES_CBC_CMAC_256   = ID_PACE_DH_GM + ".4"
    
    // PACE ECDH-GM
    private static let ID_PACE_ECDH_GM = ID_PACE + ".2"
    static let ID_PACE_ECDH_GM_3DES_CBC_CBC     = ID_PACE_ECDH_GM + ".1"
    static let ID_PACE_ECDH_GM_AES_CBC_CMAC_128 = ID_PACE_ECDH_GM + ".2"
    static let ID_PACE_ECDH_GM_AES_CBC_CMAC_192 = ID_PACE_ECDH_GM + ".3"
    static let ID_PACE_ECDH_GM_AES_CBC_CMAC_256 = ID_PACE_ECDH_GM + ".4"
    
    // PACE DH-IM
    private static let ID_PACE_DH_IM = ID_PACE + ".3"
    static let ID_PACE_DH_IM_3DES_CBC_CBC       = ID_PACE_DH_IM + ".1"
    static let ID_PACE_DH_IM_AES_CBC_CMAC_128   = ID_PACE_DH_IM + ".2"
    static let ID_PACE_DH_IM_AES_CBC_CMAC_192   = ID_PACE_DH_IM + ".3"
    static let ID_PACE_DH_IM_AES_CBC_CMAC_256   = ID_PACE_DH_IM + ".4"
    
    // PACE ECDH-IM
    private static let ID_PACE_ECDH_IM = ID_PACE + ".4"
    static let ID_PACE_ECDH_IM_3DES_CBC_CBC     = ID_PACE_ECDH_IM + ".1"
    static let ID_PACE_ECDH_IM_AES_CBC_CMAC_128 = ID_PACE_ECDH_IM + ".2"
    static let ID_PACE_ECDH_IM_AES_CBC_CMAC_192 = ID_PACE_ECDH_IM + ".3"
    static let ID_PACE_ECDH_IM_AES_CBC_CMAC_256 = ID_PACE_ECDH_IM + ".4"
    
    // PACE ECDH-CAM
    private static let ID_PACE_ECDH_CAM = ID_PACE + ".6"
    static let ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 = ID_PACE_ECDH_CAM + ".2"
    static let ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 = ID_PACE_ECDH_CAM + ".3"
    static let ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 = ID_PACE_ECDH_CAM + ".4"
}

// MARK: - SecurityInfo Base Class

@available(iOS 13, macOS 10.15, *)
public class SecurityInfo {
    // Legacy OID constants for backward compatibility
    static let ID_AA_OID = SecurityOID.ID_AA
    static let ECDSA_PLAIN_SHA1_OID = SecurityOID.ECDSA_PLAIN_SHA1
    static let ECDSA_PLAIN_SHA224_OID = SecurityOID.ECDSA_PLAIN_SHA224
    static let ECDSA_PLAIN_SHA256_OID = SecurityOID.ECDSA_PLAIN_SHA256
    static let ECDSA_PLAIN_SHA384_OID = SecurityOID.ECDSA_PLAIN_SHA384
    static let ECDSA_PLAIN_SHA512_OID = SecurityOID.ECDSA_PLAIN_SHA512
    static let ECDSA_PLAIN_RIPEMD160_OID = SecurityOID.ECDSA_PLAIN_RIPEMD160
    static let ID_PK_DH_OID = SecurityOID.ID_PK_DH
    static let ID_PK_ECDH_OID = SecurityOID.ID_PK_ECDH
    static let ID_CA_DH_3DES_CBC_CBC_OID = SecurityOID.ID_CA_DH_3DES_CBC_CBC
    static let ID_CA_ECDH_3DES_CBC_CBC_OID = SecurityOID.ID_CA_ECDH_3DES_CBC_CBC
    static let ID_CA_DH_AES_CBC_CMAC_128_OID = SecurityOID.ID_CA_DH_AES_CBC_CMAC_128
    static let ID_CA_DH_AES_CBC_CMAC_192_OID = SecurityOID.ID_CA_DH_AES_CBC_CMAC_192
    static let ID_CA_DH_AES_CBC_CMAC_256_OID = SecurityOID.ID_CA_DH_AES_CBC_CMAC_256
    static let ID_CA_ECDH_AES_CBC_CMAC_128_OID = SecurityOID.ID_CA_ECDH_AES_CBC_CMAC_128
    static let ID_CA_ECDH_AES_CBC_CMAC_192_OID = SecurityOID.ID_CA_ECDH_AES_CBC_CMAC_192
    static let ID_CA_ECDH_AES_CBC_CMAC_256_OID = SecurityOID.ID_CA_ECDH_AES_CBC_CMAC_256
    static let ID_BSI = "0.4.0.127.0.7"
    static let ID_PACE = ID_BSI + ".2.2.4"
    static let ID_PACE_DH_GM = ID_PACE + ".1"
    static let ID_PACE_DH_GM_3DES_CBC_CBC = SecurityOID.ID_PACE_DH_GM_3DES_CBC_CBC
    static let ID_PACE_DH_GM_AES_CBC_CMAC_128 = SecurityOID.ID_PACE_DH_GM_AES_CBC_CMAC_128
    static let ID_PACE_DH_GM_AES_CBC_CMAC_192 = SecurityOID.ID_PACE_DH_GM_AES_CBC_CMAC_192
    static let ID_PACE_DH_GM_AES_CBC_CMAC_256 = SecurityOID.ID_PACE_DH_GM_AES_CBC_CMAC_256
    static let ID_PACE_ECDH_GM = ID_PACE + ".2"
    static let ID_PACE_ECDH_GM_3DES_CBC_CBC = SecurityOID.ID_PACE_ECDH_GM_3DES_CBC_CBC
    static let ID_PACE_ECDH_GM_AES_CBC_CMAC_128 = SecurityOID.ID_PACE_ECDH_GM_AES_CBC_CMAC_128
    static let ID_PACE_ECDH_GM_AES_CBC_CMAC_192 = SecurityOID.ID_PACE_ECDH_GM_AES_CBC_CMAC_192
    static let ID_PACE_ECDH_GM_AES_CBC_CMAC_256 = SecurityOID.ID_PACE_ECDH_GM_AES_CBC_CMAC_256
    static let ID_PACE_DH_IM = ID_PACE + ".3"
    static let ID_PACE_DH_IM_3DES_CBC_CBC = SecurityOID.ID_PACE_DH_IM_3DES_CBC_CBC
    static let ID_PACE_DH_IM_AES_CBC_CMAC_128 = SecurityOID.ID_PACE_DH_IM_AES_CBC_CMAC_128
    static let ID_PACE_DH_IM_AES_CBC_CMAC_192 = SecurityOID.ID_PACE_DH_IM_AES_CBC_CMAC_192
    static let ID_PACE_DH_IM_AES_CBC_CMAC_256 = SecurityOID.ID_PACE_DH_IM_AES_CBC_CMAC_256
    static let ID_PACE_ECDH_IM = ID_PACE + ".4"
    static let ID_PACE_ECDH_IM_3DES_CBC_CBC = SecurityOID.ID_PACE_ECDH_IM_3DES_CBC_CBC
    static let ID_PACE_ECDH_IM_AES_CBC_CMAC_128 = SecurityOID.ID_PACE_ECDH_IM_AES_CBC_CMAC_128
    static let ID_PACE_ECDH_IM_AES_CBC_CMAC_192 = SecurityOID.ID_PACE_ECDH_IM_AES_CBC_CMAC_192
    static let ID_PACE_ECDH_IM_AES_CBC_CMAC_256 = SecurityOID.ID_PACE_ECDH_IM_AES_CBC_CMAC_256
    static let ID_PACE_ECDH_CAM = ID_PACE + ".6"
    static let ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 = SecurityOID.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128
    static let ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 = SecurityOID.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192
    static let ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 = SecurityOID.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256

    public func getObjectIdentifier() -> String {
        preconditionFailure("This method must be overridden")
    }
    
    public func getProtocolOIDString() -> String {
        preconditionFailure("This method must be overridden")
    }
    
    static func getInstance(object: ASN1Node, body: [UInt8]) -> SecurityInfo? {
        let oid = object[0]?.oidValue ?? ""
        guard let requiredData = object[1] else { return nil }
        let optionalData: ASN1Node? = object.count == 3 ? object[2] : nil
        
        if ChipAuthenticationPublicKeyInfo.checkRequiredIdentifier(oid) {
            return parseChipAuthPublicKeyInfo(oid: oid, requiredData: requiredData, optionalData: optionalData, body: body)
        } else if ChipAuthenticationInfo.checkRequiredIdentifier(oid) {
            return parseChipAuthInfo(oid: oid, requiredData: requiredData, optionalData: optionalData)
        } else if PACEInfo.checkRequiredIdentifier(oid) {
            return parsePACEInfo(oid: oid, requiredData: requiredData, optionalData: optionalData)
        } else if ActiveAuthenticationInfo.checkRequiredIdentifier(oid) {
            return parseActiveAuthInfo(oid: oid, requiredData: requiredData, optionalData: optionalData)
        }
        return nil
    }
    
    private static func parseChipAuthPublicKeyInfo(oid: String, requiredData: ASN1Node, optionalData: ASN1Node?, body: [UInt8]) -> ChipAuthenticationPublicKeyInfo? {
        let start = requiredData.offset
        let totalLength = requiredData.headerLength + requiredData.contentLength
        let keyData = Array(body[start..<(start + totalLength)])
        
        var subjectPublicKeyInfo: OpaquePointer?
        keyData.withUnsafeBytes { ptr in
            var newPtr = ptr.baseAddress?.assumingMemoryBound(to: UInt8.self)
            subjectPublicKeyInfo = d2i_PUBKEY(nil, &newPtr, keyData.count)
        }
        
        guard let pubKey = subjectPublicKeyInfo else { return nil }
        let keyId = optionalData?.uintValue.map { Int($0) }
        return ChipAuthenticationPublicKeyInfo(oid: oid, pubKey: pubKey, keyId: keyId)
    }
    
    private static func parseChipAuthInfo(oid: String, requiredData: ASN1Node, optionalData: ASN1Node?) -> ChipAuthenticationInfo {
        let version = requiredData.intValue ?? -1
        let keyId = optionalData?.uintValue.map { Int($0) }
        return ChipAuthenticationInfo(oid: oid, version: version, keyId: keyId)
    }
    
    private static func parsePACEInfo(oid: String, requiredData: ASN1Node, optionalData: ASN1Node?) -> PACEInfo {
        let version = requiredData.intValue ?? -1
        let parameterId = optionalData?.uintValue.map { Int($0) }
        return PACEInfo(oid: oid, version: version, parameterId: parameterId)
    }
    
    private static func parseActiveAuthInfo(oid: String, requiredData: ASN1Node, optionalData: ASN1Node?) -> ActiveAuthenticationInfo {
        let version = requiredData.intValue ?? -1
        return ActiveAuthenticationInfo(oid: oid, version: version, signatureAlgorithmOID: optionalData?.oidValue)
    }
}
