//
//  ActiveAuthenticationInfo.swift
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class ActiveAuthenticationInfo: SecurityInfo {
    
    var oid: String
    var version: Int
    var signatureAlgorithmOID: String?

    static func checkRequiredIdentifier(_ oid: String) -> Bool {
        oid == ID_AA_OID
    }

    init(oid: String, version: Int, signatureAlgorithmOID: String? = nil) {
        self.oid = oid
        self.version = version
        self.signatureAlgorithmOID = signatureAlgorithmOID
    }

    public override func getObjectIdentifier() -> String { oid }

    public override func getProtocolOIDString() -> String {
        oid == Self.ID_AA_OID ? "id-AA" : oid
    }

    public func getSignatureAlgorithmOIDString() -> String? {
        guard let oid = signatureAlgorithmOID else { return nil }
        
        let oidMap: [String: String] = [
            SecurityInfo.ECDSA_PLAIN_SHA1_OID: "ecdsa-plain-SHA1",
            SecurityInfo.ECDSA_PLAIN_SHA224_OID: "ecdsa-plain-SHA224",
            SecurityInfo.ECDSA_PLAIN_SHA256_OID: "ecdsa-plain-SHA256",
            SecurityInfo.ECDSA_PLAIN_SHA384_OID: "ecdsa-plain-SHA384",
            SecurityInfo.ECDSA_PLAIN_SHA512_OID: "ecdsa-plain-SHA512",
            SecurityInfo.ECDSA_PLAIN_RIPEMD160_OID: "ecdsa-plain-RIPEMD160"
        ]
        
        return oidMap[oid]
    }
}
