//
//  DataGroup15.swift
//

import Foundation
import OpenSSL

@available(iOS 13, macOS 10.15, *)
public class DataGroup15: DataGroup {
    
    public private(set) var rsaPublicKey: OpaquePointer?
    public private(set) var ecdsaPublicKey: OpaquePointer?

    public override var datagroupType: DataGroupId { .DG15 }

    @MainActor
    deinit {
        if let key = ecdsaPublicKey {
            EVP_PKEY_free(key)
        }
        if let key = rsaPublicKey {
            EVP_PKEY_free(key)
        }
    }
    
    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        // Active Authentication public key - either EC or RSA format
        // Try EC first, fall back to RSA
        if let key = try? OpenSSLUtils.readECPublicKey(data: body) {
            ecdsaPublicKey = key
        } else if let key = try? OpenSSLUtils.readRSAPublicKey(data: body) {
            rsaPublicKey = key
        }
    }
}
