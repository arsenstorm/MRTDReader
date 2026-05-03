
import Foundation
import OSLog
import OpenSSL
import CryptoTokenKit

#if !os(macOS)
import CoreNFC
import CryptoKit

/// Result of a successful CA-v2 chip authentication: the inputs and outputs the
/// terminal needs to forward so a verifier can recompute T_PICC under
/// TR-03110-2 §3.4 and TR-03110-3 §A.2.1.2 / §B.11.5. CA-v1 chips never
/// produce this — they only restart secure messaging.
@available(iOS 15, *)
public struct ChipAuthenticationTranscript {
    public let oid: String
    public let keyId: Int?
    /// Terminal ephemeral private scalar, left-padded to the curve coordinate
    /// width when the algorithm is ECDH.
    public let terminalPrivateKey: [UInt8]
    /// Terminal ephemeral public key, encoded as the chip received it (for
    /// ECDH this is the uncompressed point `04 || X || Y`).
    public let terminalPublicKey: [UInt8]
    /// `r_PICC` returned in tag `0x81` of the GA response.
    public let chipNonce: [UInt8]
    /// `T_PICC` returned in tag `0x82` of the GA response (truncated CMAC).
    public let chipToken: [UInt8]
}

@available(iOS 15, *)
class ChipAuthenticationHandler {

    // MARK: - Constants

    private static let commandChainingChunkSize = 224

    /// OID inference mapping from public key type to chip auth algorithm
    private static let oidInference: [String: String] = [
        SecurityInfo.ID_PK_ECDH_OID: SecurityInfo.ID_CA_ECDH_3DES_CBC_CBC_OID,
        SecurityInfo.ID_PK_DH_OID: SecurityInfo.ID_CA_DH_3DES_CBC_CBC_OID
    ]

    // MARK: - Properties

    private weak var tagReader: TagReader?

    private var chipAuthInfos = [Int: ChipAuthenticationInfo]()
    private var chipAuthPublicKeyInfos = [ChipAuthenticationPublicKeyInfo]()

    private(set) var isChipAuthenticationSupported = false

    /// Transcript captured from the most recent successful CA-v2 run. Nil when
    /// the chip used CA-v1 (DESede / no chip-side response) or never replied
    /// with the expected `0x81` + `0x82` data objects.
    private(set) var latestTranscript: ChipAuthenticationTranscript?

    // MARK: - Initialization

    init(dg14: DataGroup14, tagReader: TagReader) {
        self.tagReader = tagReader

        for secInfo in dg14.securityInfos {
            if let cai = secInfo as? ChipAuthenticationInfo {
                chipAuthInfos[cai.getKeyId()] = cai
            } else if let capki = secInfo as? ChipAuthenticationPublicKeyInfo {
                chipAuthPublicKeyInfos.append(capki)
            }
        }

        isChipAuthenticationSupported = !chipAuthPublicKeyInfos.isEmpty
    }

    // MARK: - Public API

    func doChipAuthentication() async throws {
        Logger.chipAuth.infoIfEnabled("Performing Chip Authentication - \(self.chipAuthPublicKeyInfos.count) public key(s) found")

        guard isChipAuthenticationSupported else {
            throw NFCPassportReaderError.NotYetSupported("ChipAuthentication not supported")
        }

        for pubKey in chipAuthPublicKeyInfos {
            if try await performChipAuth(with: pubKey) {
                return
            }
        }

        throw NFCPassportReaderError.ChipAuthenticationFailed
    }

    // MARK: - Private Implementation

    private func performChipAuth(with publicKeyInfo: ChipAuthenticationPublicKeyInfo) async throws -> Bool {
        let keyId = publicKeyInfo.keyId

        // Determine OID: from ChipAuthInfo if available, otherwise infer from public key
        let chipAuthOID: String
        if let chipAuthInfo = chipAuthInfos[keyId ?? 0] {
            chipAuthOID = chipAuthInfo.oid
        } else if let inferredOID = Self.oidInference[publicKeyInfo.oid] {
            Logger.chipAuth.warningIfEnabled("No ChipAuthenticationInfo - inferring OID")
            chipAuthOID = inferredOID
        } else {
            Logger.chipAuth.warningIfEnabled("Unsupported ChipAuthenticationPublicKeyInfo public key OID")
            return false
        }

        try await executeChipAuth(keyId: keyId, oid: chipAuthOID, publicKey: publicKeyInfo.pubKey)
        return true
    }

    private func executeChipAuth(keyId: Int?, oid: String, publicKey: OpaquePointer) async throws {
        // Generate ephemeral key pair from DG14 public key parameters
        var ephemeralKeyPair: OpaquePointer?
        let pctx = EVP_PKEY_CTX_new(publicKey, nil)
        defer { EVP_PKEY_CTX_free(pctx) }

        EVP_PKEY_keygen_init(pctx)
        EVP_PKEY_keygen(pctx, &ephemeralKeyPair)

        guard let keyPair = ephemeralKeyPair else {
            throw NFCPassportReaderError.ChipAuthenticationFailed
        }
        defer { EVP_PKEY_free(keyPair) }

        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)

        guard let terminalPublicKey = OpenSSLUtils.getPublicKeyData(from: keyPair) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get public key data")
        }

        // The CA-v2 transcript only makes sense for ECDH+AES; DH and DESede
        // paths fall back to CA-v1 with no chip-side data to capture.
        let coordBytes = ecdhCoordinateBytes(from: keyPair)
        let terminalPrivateKey = (coordBytes != nil)
            ? OpenSSLUtils.getPrivateKeyData(from: keyPair, paddedTo: coordBytes)
            : nil

        let chipResponseData: [UInt8]
        if cipherAlg.hasPrefix("DESede") {
            try await sendPublicKeyDES(keyData: terminalPublicKey, keyId: keyId)
            chipResponseData = []
        } else if cipherAlg.hasPrefix("AES") {
            chipResponseData = try await sendPublicKeyAES(
                oid: oid,
                keyId: keyId,
                keyData: terminalPublicKey
            ) ?? []
        } else {
            throw NFCPassportReaderError.InvalidDataPassed("Cipher algorithm \(cipherAlg) not supported")
        }
        Logger.chipAuth.debugIfEnabled("Public key successfully sent to passport")

        // Capture the CA-v2 transcript when the chip returned both
        // `0x81` (r_PICC) and `0x82` (T_PICC). Order is unspecified by the
        // TLV-iteration logic — we ignore unknown tags.
        latestTranscript = buildTranscript(
            oid: oid,
            keyId: keyId,
            terminalPrivateKey: terminalPrivateKey,
            terminalPublicKey: terminalPublicKey,
            chipResponseData: chipResponseData
        )

        // Compute shared secret using ECDH/DH
        let sharedSecret = OpenSSLUtils.computeSharedSecret(privateKeyPair: keyPair, publicKey: publicKey)

        // Restart secure messaging with new keys
        try restartSecureMessaging(oid: oid, sharedSecret: sharedSecret)
    }

    // MARK: - Public Key Exchange

    private func sendPublicKeyDES(keyData: [UInt8], keyId: Int?) async throws {
        var idData = [UInt8]()
        if let keyId = keyId {
            idData = wrapDO(b: 0x84, arr: intToBytes(val: keyId, removePadding: true))
        }
        let wrappedKeyData = wrapDO(b: 0x91, arr: keyData)

        _ = try await tagReader?.sendMSEKAT(keyData: Data(wrappedKeyData), idData: Data(idData))
    }

    /// Sends the terminal ephemeral public key to the chip via MSE:Set AT +
    /// chained GENERAL AUTHENTICATE. Returns the chip's reply to the final GA
    /// (with the outer `0x7C` already unwrapped by `TagReader`), which carries
    /// `r_PICC` / `T_PICC` for CA-v2 chips and is empty for CA-v1.
    private func sendPublicKeyAES(oid: String, keyId: Int?, keyData: [UInt8]) async throws -> [UInt8]? {
        _ = try await tagReader?.sendMSESetATIntAuth(oid: oid, keyId: keyId)

        let wrappedData = wrapDO(b: 0x80, arr: keyData)
        var gaSegments = chunk(wrappedData, size: Self.commandChainingChunkSize)

        var lastResponse: ResponseAPDU?
        while !gaSegments.isEmpty {
            let segment = gaSegments.removeFirst()
            lastResponse = try await tagReader?.sendGeneralAuthenticate(
                data: segment,
                isLast: gaSegments.isEmpty
            )
        }
        return lastResponse?.data
    }

    // MARK: - Transcript Construction

    /// Returns the EC coordinate width in bytes for `key`, or nil if the key
    /// is not EC. The coordinate width is `ceil(log256(p))` and matches what
    /// TR-03110-3 §A.2.3 / NIST SP 800-186 expect for the scalar encoding.
    private func ecdhCoordinateBytes(from key: OpaquePointer) -> Int? {
        guard EVP_PKEY_get_base_id(key) == EVP_PKEY_EC else { return nil }
        guard let ec = EVP_PKEY_get0_EC_KEY(key),
              let group = EC_KEY_get0_group(ec) else { return nil }
        let degree = EC_GROUP_get_degree(group)
        guard degree > 0 else { return nil }
        return (Int(degree) + 7) / 8
    }

    private func buildTranscript(
        oid: String,
        keyId: Int?,
        terminalPrivateKey: [UInt8]?,
        terminalPublicKey: [UInt8],
        chipResponseData: [UInt8]
    ) -> ChipAuthenticationTranscript? {
        guard let terminalPrivateKey, !chipResponseData.isEmpty else { return nil }
        guard let records = TKBERTLVRecord.sequenceOfRecords(from: Data(chipResponseData)),
              !records.isEmpty else {
            return nil
        }

        var chipNonce: [UInt8] = []
        var chipToken: [UInt8] = []
        for record in records {
            switch record.tag {
            case 0x81:
                chipNonce = [UInt8](record.value)
            case 0x82:
                chipToken = [UInt8](record.value)
            default:
                continue
            }
        }

        guard !chipNonce.isEmpty && !chipToken.isEmpty else { return nil }

        // Sanity log: a CA-v1 chip is not supposed to return r_PICC/T_PICC, so
        // surface it if we see one — verification will still proceed and the
        // backend will reject if the token is wrong.
        if let info = chipAuthInfos[keyId ?? 0], info.version < 2 {
            Logger.chipAuth.warningIfEnabled(
                "Chip returned CA-v2 transcript despite ChipAuthenticationInfo declaring version \(info.version)"
            )
        }

        return ChipAuthenticationTranscript(
            oid: oid,
            keyId: keyId,
            terminalPrivateKey: terminalPrivateKey,
            terminalPublicKey: terminalPublicKey,
            chipNonce: chipNonce,
            chipToken: chipToken
        )
    }

    // MARK: - Secure Messaging

    private func restartSecureMessaging(oid: String, sharedSecret: [UInt8]) throws {
        let cipherAlg = try ChipAuthenticationInfo.toCipherAlgorithm(oid: oid)
        let keyLength = try ChipAuthenticationInfo.toKeyLength(oid: oid)

        // Derive session keys
        let smskg = SecureMessagingSessionKeyGenerator()
        let ksEnc = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let ksMac = try smskg.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)

        Logger.chipAuth.infoIfEnabled("Restarting secure messaging using \(cipherAlg) encryption")
        tagReader?.secureMessaging = createSecureMessaging(cipherAlgorithm: cipherAlg, ksEnc: ksEnc, ksMac: ksMac)
    }
}
#endif
