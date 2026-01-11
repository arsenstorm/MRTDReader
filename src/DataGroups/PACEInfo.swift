
import Foundation
import OSLog
import OpenSSL

public enum PACEMappingType {
    case GM  // Generic Mapping
    case IM  // Integrated Mapping
    case CAM // Chip Authentication Mapping
    
    var description: String {
        switch self {
        case .GM: return "Generic Mapping"
        case .IM: return "Integrated Mapping"
        case .CAM: return "Chip Authentication Mapping"
        }
    }
}

@available(iOS 13, macOS 10.15, *)
public class PACEInfo: SecurityInfo {
    
    // MARK: - Standardized Domain Parameters (Table 6)
    
    public static let PARAM_ID_GFP_1024_160 = 0
    public static let PARAM_ID_GFP_2048_224 = 1
    public static let PARAM_ID_GFP_2048_256 = 2
    public static let PARAM_ID_ECP_NIST_P192_R1 = 8
    public static let PARAM_ID_ECP_BRAINPOOL_P192_R1 = 9
    public static let PARAM_ID_ECP_NIST_P224_R1 = 10
    public static let PARAM_ID_ECP_BRAINPOOL_P224_R1 = 11
    public static let PARAM_ID_ECP_NIST_P256_R1 = 12
    public static let PARAM_ID_ECP_BRAINPOOL_P256_R1 = 13
    public static let PARAM_ID_ECP_BRAINPOOL_P320_R1 = 14
    public static let PARAM_ID_ECP_NIST_P384_R1 = 15
    public static let PARAM_ID_ECP_BRAINPOOL_P384_R1 = 16
    public static let PARAM_ID_ECP_BRAINPOOL_P512_R1 = 17
    public static let PARAM_ID_ECP_NIST_P521_R1 = 18
    
    // MARK: - OID Classification Sets
    
    private static let gmOIDs: Set<String> = [
        ID_PACE_DH_GM_3DES_CBC_CBC, ID_PACE_DH_GM_AES_CBC_CMAC_128,
        ID_PACE_DH_GM_AES_CBC_CMAC_192, ID_PACE_DH_GM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_GM_3DES_CBC_CBC, ID_PACE_ECDH_GM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192, ID_PACE_ECDH_GM_AES_CBC_CMAC_256
    ]
    
    private static let imOIDs: Set<String> = [
        ID_PACE_DH_IM_3DES_CBC_CBC, ID_PACE_DH_IM_AES_CBC_CMAC_128,
        ID_PACE_DH_IM_AES_CBC_CMAC_192, ID_PACE_DH_IM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_IM_3DES_CBC_CBC, ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192, ID_PACE_ECDH_IM_AES_CBC_CMAC_256
    ]
    
    private static let camOIDs: Set<String> = [
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128, ID_PACE_ECDH_CAM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256
    ]
    
    private static let dhOIDs: Set<String> = [
        ID_PACE_DH_GM_3DES_CBC_CBC, ID_PACE_DH_GM_AES_CBC_CMAC_128,
        ID_PACE_DH_GM_AES_CBC_CMAC_192, ID_PACE_DH_GM_AES_CBC_CMAC_256,
        ID_PACE_DH_IM_3DES_CBC_CBC, ID_PACE_DH_IM_AES_CBC_CMAC_128,
        ID_PACE_DH_IM_AES_CBC_CMAC_192, ID_PACE_DH_IM_AES_CBC_CMAC_256
    ]
    
    private static let desedeOIDs: Set<String> = [
        ID_PACE_DH_GM_3DES_CBC_CBC, ID_PACE_DH_IM_3DES_CBC_CBC,
        ID_PACE_ECDH_GM_3DES_CBC_CBC, ID_PACE_ECDH_IM_3DES_CBC_CBC
    ]
    
    private static let keyLength128OIDs: Set<String> = [
        ID_PACE_DH_GM_3DES_CBC_CBC, ID_PACE_DH_IM_3DES_CBC_CBC,
        ID_PACE_ECDH_GM_3DES_CBC_CBC, ID_PACE_ECDH_IM_3DES_CBC_CBC,
        ID_PACE_DH_GM_AES_CBC_CMAC_128, ID_PACE_DH_IM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128, ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128
    ]
    
    private static let keyLength192OIDs: Set<String> = [
        ID_PACE_DH_GM_AES_CBC_CMAC_192, ID_PACE_DH_IM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192, ID_PACE_ECDH_IM_AES_CBC_CMAC_192,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192
    ]
    
    private static let keyLength256OIDs: Set<String> = [
        ID_PACE_DH_GM_AES_CBC_CMAC_256, ID_PACE_DH_IM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256, ID_PACE_ECDH_IM_AES_CBC_CMAC_256,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256
    ]
    
    private static let sha1OIDs: Set<String> = [
        ID_PACE_DH_GM_3DES_CBC_CBC, ID_PACE_DH_IM_3DES_CBC_CBC,
        ID_PACE_ECDH_GM_3DES_CBC_CBC, ID_PACE_ECDH_IM_3DES_CBC_CBC,
        ID_PACE_DH_GM_AES_CBC_CMAC_128, ID_PACE_DH_IM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128, ID_PACE_ECDH_IM_AES_CBC_CMAC_128,
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128
    ]
    
    private static let protocolOIDStrings: [String: String] = [
        ID_PACE_DH_GM_3DES_CBC_CBC: "id-PACE-DH-GM-3DES-CBC-CBC",
        ID_PACE_DH_GM_AES_CBC_CMAC_128: "id-PACE-DH-GM-AES-CBC-CMAC-128",
        ID_PACE_DH_GM_AES_CBC_CMAC_192: "id-PACE-DH-GM-AES-CBC-CMAC-192",
        ID_PACE_DH_GM_AES_CBC_CMAC_256: "id-PACE-DH-GM-AES-CBC-CMAC-256",
        ID_PACE_DH_IM_3DES_CBC_CBC: "id-PACE-DH-IM-3DES-CBC-CBC",
        ID_PACE_DH_IM_AES_CBC_CMAC_128: "id-PACE-DH-IM-AES-CBC-CMAC-128",
        ID_PACE_DH_IM_AES_CBC_CMAC_192: "id-PACE-DH-IM-AES-CBC-CMAC-192",
        ID_PACE_DH_IM_AES_CBC_CMAC_256: "id-PACE-DH-IM-AES-CBC-CMAC-256",
        ID_PACE_ECDH_GM_3DES_CBC_CBC: "id-PACE-ECDH-GM-3DES-CBC-CBC",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_128: "id-PACE-ECDH-GM-AES-CBC-CMAC-128",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_192: "id-PACE-ECDH-GM-AES-CBC-CMAC-192",
        ID_PACE_ECDH_GM_AES_CBC_CMAC_256: "id-PACE-ECDH-GM-AES-CBC-CMAC-256",
        ID_PACE_ECDH_IM_3DES_CBC_CBC: "id-PACE-ECDH-IM-3DES-CBC-CBC",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_128: "id-PACE-ECDH-IM-AES-CBC-CMAC-128",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_192: "id-PACE-ECDH-IM-AES-CBC-CMAC-192",
        ID_PACE_ECDH_IM_AES_CBC_CMAC_256: "id-PACE-ECDH-IM-AES-CBC-CMAC-256",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_128: "id-PACE-ECDH-CAM-AES-CBC-CMAC-128",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_192: "id-PACE-ECDH-CAM-AES-CBC-CMAC-192",
        ID_PACE_ECDH_CAM_AES_CBC_CMAC_256: "id-PACE-ECDH-CAM-AES-CBC-CMAC-256"
    ]
    
    static let allowedIdentifiers: Set<String> = gmOIDs.union(imOIDs).union(camOIDs)
    
    // MARK: - Instance Properties
    
    var oid: String
    var version: Int
    var parameterId: Int?
    
    // MARK: - Initialization
    
    init(oid: String, version: Int, parameterId: Int?) {
        self.oid = oid
        self.version = version
        self.parameterId = parameterId
    }
    
    static func checkRequiredIdentifier(_ oid: String) -> Bool {
        allowedIdentifiers.contains(oid)
    }
    
    // MARK: - Public Instance Methods
    
    public override func getObjectIdentifier() -> String { oid }
    public override func getProtocolOIDString() -> String { Self.toProtocolOIDString(oid: oid) }
    public func getVersion() -> Int { version }
    public func getParameterId() -> Int? { parameterId }
    
    public func getParameterSpec() throws -> Int32 {
        try Self.getParameterSpec(stdDomainParam: parameterId ?? -1)
    }
    
    public func getMappingType() throws -> PACEMappingType {
        try Self.toMappingType(oid: oid)
    }
    
    public func getKeyAgreementAlgorithm() throws -> String {
        try Self.toKeyAgreementAlgorithm(oid: oid)
    }
    
    public func getCipherAlgorithm() throws -> String {
        try Self.toCipherAlgorithm(oid: oid)
    }
    
    public func getDigestAlgorithm() throws -> String {
        try Self.toDigestAlgorithm(oid: oid)
    }
    
    public func getKeyLength() throws -> Int {
        try Self.toKeyLength(oid: oid)
    }
    
    /// Caller is required to free the returned EVP_PKEY value
    public func createMappingKey() throws -> OpaquePointer {
        let mappingKey: OpaquePointer = EVP_PKEY_new()
        
        switch try getKeyAgreementAlgorithm() {
        case "DH":
            Logger.pace.debugIfEnabled("Generating DH mapping keys")
            let dhKey: OpaquePointer? = try {
                switch try getParameterSpec() {
                case 0:
                    Logger.pace.debugIfEnabled("Using DH_get_1024_160")
                    return DH_get_1024_160()
                case 1:
                    Logger.pace.debugIfEnabled("Using DH_get_2048_224")
                    return DH_get_2048_224()
                case 2:
                    Logger.pace.debugIfEnabled("Using DH_get_2048_256")
                    return DH_get_2048_256()
                default:
                    return nil
                }
            }()
            
            guard let dhKey else {
                throw NFCPassportReaderError.InvalidDataPassed("Unable to create DH mapping key")
            }
            defer { DH_free(dhKey) }
            
            DH_generate_key(dhKey)
            EVP_PKEY_set1_DH(mappingKey, dhKey)
            
        case "ECDH":
            let parameterSpec = try getParameterSpec()
            Logger.pace.debugIfEnabled("Generating ECDH mapping keys")
            guard let ecKey = EC_KEY_new_by_curve_name(parameterSpec) else {
                throw NFCPassportReaderError.InvalidDataPassed("Unable to create EC mapping key")
            }
            defer { EC_KEY_free(ecKey) }
            
            EC_KEY_generate_key(ecKey)
            EVP_PKEY_set1_EC_KEY(mappingKey, ecKey)
            
        default:
            throw NFCPassportReaderError.InvalidDataPassed("Unsupported agreement algorithm")
        }
        
        return mappingKey
    }
    
    // MARK: - Static Lookup Methods
    
    public static func getParameterSpec(stdDomainParam: Int) throws -> Int32 {
        switch stdDomainParam {
        case PARAM_ID_GFP_1024_160: return 0
        case PARAM_ID_GFP_2048_224: return 1
        case PARAM_ID_GFP_2048_256: return 2
        case PARAM_ID_ECP_NIST_P192_R1: return NID_X9_62_prime192v1
        case PARAM_ID_ECP_NIST_P224_R1: return NID_secp224r1
        case PARAM_ID_ECP_NIST_P256_R1: return NID_X9_62_prime256v1
        case PARAM_ID_ECP_NIST_P384_R1: return NID_secp384r1
        case PARAM_ID_ECP_NIST_P521_R1: return NID_secp521r1
        case PARAM_ID_ECP_BRAINPOOL_P192_R1: return NID_brainpoolP192r1
        case PARAM_ID_ECP_BRAINPOOL_P224_R1: return NID_brainpoolP224r1
        case PARAM_ID_ECP_BRAINPOOL_P256_R1: return NID_brainpoolP256r1
        case PARAM_ID_ECP_BRAINPOOL_P320_R1: return NID_brainpoolP320r1
        case PARAM_ID_ECP_BRAINPOOL_P384_R1: return NID_brainpoolP384r1
        case PARAM_ID_ECP_BRAINPOOL_P512_R1: return NID_brainpoolP512r1
        default:
            throw NFCPassportReaderError.InvalidDataPassed("Unable to lookup parameterSpec - invalid oid")
        }
    }
    
    public static func toMappingType(oid: String) throws -> PACEMappingType {
        if gmOIDs.contains(oid) { return .GM }
        if imOIDs.contains(oid) { return .IM }
        if camOIDs.contains(oid) { return .CAM }
        throw NFCPassportReaderError.InvalidDataPassed("Unable to lookup mapping type - invalid oid")
    }
    
    public static func toKeyAgreementAlgorithm(oid: String) throws -> String {
        if dhOIDs.contains(oid) { return "DH" }
        if allowedIdentifiers.contains(oid) { return "ECDH" }
        throw NFCPassportReaderError.InvalidDataPassed("Unable to lookup key agreement algorithm - invalid oid")
    }
    
    public static func toCipherAlgorithm(oid: String) throws -> String {
        if desedeOIDs.contains(oid) { return "DESede" }
        if allowedIdentifiers.contains(oid) { return "AES" }
        throw NFCPassportReaderError.InvalidDataPassed("Unable to lookup cipher algorithm - invalid oid")
    }
    
    public static func toDigestAlgorithm(oid: String) throws -> String {
        if sha1OIDs.contains(oid) { return "SHA-1" }
        if allowedIdentifiers.contains(oid) { return "SHA-256" }
        throw NFCPassportReaderError.InvalidDataPassed("Unable to lookup digest algorithm - invalid oid")
    }
    
    public static func toKeyLength(oid: String) throws -> Int {
        if keyLength128OIDs.contains(oid) { return 128 }
        if keyLength192OIDs.contains(oid) { return 192 }
        if keyLength256OIDs.contains(oid) { return 256 }
        throw NFCPassportReaderError.InvalidDataPassed("Unable to get key length - invalid oid")
    }
    
    private static func toProtocolOIDString(oid: String) -> String {
        protocolOIDStrings[oid] ?? oid
    }
}
