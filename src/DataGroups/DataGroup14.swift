//
//  DataGroup14.swift
//

import Foundation

/// DG14 contains security information for chip authentication.
/// Structure: SecurityInfos ::= SET of SecurityInfo
@available(iOS 13, macOS 10.15, *)
public class DataGroup14: DataGroup {
    
    public private(set) var securityInfos: [SecurityInfo] = []

    public override var datagroupType: DataGroupId { .DG14 }
    
    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
    
    override func parse(_ data: [UInt8]) throws {
        let asn1 = try ASN1.parse(body)
        
        securityInfos = (0..<asn1.count).compactMap { index in
            guard let child = asn1[index] else { return nil }
            return SecurityInfo.getInstance(object: child, body: body)
            }
        }
    }
