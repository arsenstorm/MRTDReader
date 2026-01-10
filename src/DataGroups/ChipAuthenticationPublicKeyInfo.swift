//
//  ChipAuthenticationPublicKeyInfo.swift
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class ChipAuthenticationPublicKeyInfo: SecurityInfo {
    
    var oid: String
    var pubKey: OpaquePointer
    var keyId: Int?
    
    static func checkRequiredIdentifier(_ oid: String) -> Bool {
        oid == ID_PK_DH_OID || oid == ID_PK_ECDH_OID
    }
    
    init(oid: String, pubKey: OpaquePointer, keyId: Int? = nil) {
        self.oid = oid
        self.pubKey = pubKey
        self.keyId = keyId
    }
    
    public override func getObjectIdentifier() -> String { oid }
    
    public override func getProtocolOIDString() -> String {
        switch oid {
        case Self.ID_PK_DH_OID: return "id-PK-DH"
        case Self.ID_PK_ECDH_OID: return "id-PK-ECDH"
        default: return oid
        }
    }

    public func getKeyId() -> Int { keyId ?? 0 }
}
