//
//  CardAccess.swift
//

import Foundation

/// CardAccess contains security protocol information for establishing secure messaging.
/// Structure: SecurityInfos ::= SET of SecurityInfo
@available(iOS 13, macOS 10.15, *)
public class CardAccess {
    
    public private(set) var securityInfos: [SecurityInfo] = []
    
    public var paceInfo: PACEInfo? {
        securityInfos.first { $0 is PACEInfo } as? PACEInfo
    }
    
    required init(_ data: [UInt8]) throws {
        let asn1 = try ASN1.parse(data)
        
        securityInfos = (0..<asn1.count).compactMap { index in
            guard let child = asn1[index] else { return nil }
            return SecurityInfo.getInstance(object: child, body: data)
            }
        }
    }
