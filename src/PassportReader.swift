
import Foundation
import OSLog

#if !os(macOS)
import UIKit
import CoreNFC

// MARK: - Configuration

/// Configuration for passport reading operations
@available(iOS 15, *)
public struct PassportReadingConfiguration {
    /// MRZ key derived from passport data (document number + date of birth + expiry date)
    public let mrzKey: String
    
    /// Data groups to read. If nil or empty, reads all available groups.
    /// Specified groups are intersected with what's available on the passport.
    /// DG3 and DG4 are always excluded (require Extended Access Control).
    public let dataGroups: Set<DataGroupId>?
    
    /// Optional challenge for Active Authentication (random if not provided)
    public let aaChallenge: [UInt8]?
    
    /// Custom message handler for NFC UI
    public let displayMessageHandler: ((NFCViewDisplayMessage) -> String?)?
    
    /// URL to master list for certificate verification
    public let masterListURL: URL?
    
    /// Whether to use OpenSSL CMS verification for passive authentication
    public let useOpenSSLForPassiveAuth: Bool
    
    /// Maximum retry attempts for reading a data group
    public static let maxReadRetries = 2
    
    public init(
        mrzKey: String,
        dataGroups: Set<DataGroupId>? = nil,
        aaChallenge: [UInt8]? = nil,
        displayMessageHandler: ((NFCViewDisplayMessage) -> String?)? = nil,
        masterListURL: URL? = nil,
        useOpenSSLForPassiveAuth: Bool = false
    ) {
        self.mrzKey = mrzKey
        self.dataGroups = dataGroups
        self.aaChallenge = aaChallenge
        self.displayMessageHandler = displayMessageHandler
        self.masterListURL = masterListURL
        self.useOpenSSLForPassiveAuth = useOpenSSLForPassiveAuth
    }
}

// MARK: - Reading Phase State Machine

/// Represents the current phase of passport reading
@available(iOS 15, *)
public enum ReadingPhase: CustomStringConvertible {
    case idle
    case connecting
    case authenticating(AuthMethod)
    case readingDataGroup(DataGroupId)
    case performingChipAuth
    case performingActiveAuth
    case verifying
    case complete
    case failed(NFCPassportReaderError)
    
    public enum AuthMethod {
        case pace
        case bac
    }
    
    public var description: String {
        switch self {
        case .idle: return "Idle"
        case .connecting: return "Connecting to passport"
        case .authenticating(let method):
            return method == .pace ? "PACE Authentication" : "BAC Authentication"
        case .readingDataGroup(let dg): return "Reading \(dg.getName())"
        case .performingChipAuth: return "Chip Authentication"
        case .performingActiveAuth: return "Active Authentication"
        case .verifying: return "Verifying passport"
        case .complete: return "Complete"
        case .failed(let error): return "Failed: \(error.value)"
        }
    }
}

// MARK: - Tracking Delegate

@available(iOS 15, *)
public protocol PassportReaderTrackingDelegate: AnyObject {
    func phaseChanged(_ phase: ReadingPhase)
    func nfcTagDetected()
    func readCardAccess(cardAccess: CardAccess)
    func paceStarted()
    func paceSucceeded()
    func paceFailed()
    func bacStarted()
    func bacSucceeded()
    func bacFailed()
}

@available(iOS 15, *)
public extension PassportReaderTrackingDelegate {
    func phaseChanged(_ phase: ReadingPhase) {}
    func nfcTagDetected() {}
    func readCardAccess(cardAccess: CardAccess) {}
    func paceStarted() {}
    func paceSucceeded() {}
    func paceFailed() {}
    func bacStarted() {}
    func bacSucceeded() {}
    func bacFailed() {}
}

// MARK: - PassportReader

@available(iOS 15, *)
public class PassportReader: NSObject {
    
    // MARK: - Types
    
    private typealias NFCCheckedContinuation = CheckedContinuation<NFCPassportModel, Error>
    
    // MARK: - Public Properties
    
    public weak var trackingDelegate: PassportReaderTrackingDelegate?
    
    /// By default, Passive Authentication uses the new RFS5652 method to verify the SOD,
    /// but can be switched to use the previous OpenSSL CMS verification if necessary
    public var passiveAuthenticationUsesOpenSSL: Bool = false
    
    // MARK: - Private State
    
    private var nfcContinuation: NFCCheckedContinuation?
    private var readerSession: NFCTagReaderSession?
    private var passport = NFCPassportModel()
    private var configuration: PassportReadingConfiguration?
    private var progressTracker = ProgressTracker()
    
    // Reading state
    private var currentPhase: ReadingPhase = .idle {
        didSet { trackingDelegate?.phaseChanged(currentPhase) }
    }
    private var currentlyReadingDataGroup: DataGroupId?
    private var caHandler: ChipAuthenticationHandler?
    private var shouldSuppressNextCancelError = false
    
    // MARK: - Legacy Properties (for backwards compatibility)
    
    private var masterListURL: URL?
    
    // MARK: - Initialization
    
    public init(masterListURL: URL? = nil) {
        super.init()
        self.masterListURL = masterListURL
    }
    
    public func setMasterListURL(_ masterListURL: URL) {
        self.masterListURL = masterListURL
    }
    
    // MARK: - Public API
    
    /// Read passport using the new configuration object
    public func readPassport(configuration: PassportReadingConfiguration) async throws -> NFCPassportModel {
        self.configuration = configuration
        self.passiveAuthenticationUsesOpenSSL = configuration.useOpenSSLForPassiveAuth
        return try await startNFCSession()
    }
    
    /// Read passport (legacy API for backwards compatibility)
    public func readPassport(
        mrzKey: String,
        aaChallenge: [UInt8]? = nil,
        customDisplayMessage: ((NFCViewDisplayMessage) -> String?)? = nil
    ) async throws -> NFCPassportModel {
        let config = PassportReadingConfiguration(
            mrzKey: mrzKey,
            aaChallenge: aaChallenge,
            displayMessageHandler: customDisplayMessage,
            masterListURL: masterListURL,
            useOpenSSLForPassiveAuth: passiveAuthenticationUsesOpenSSL
        )
        return try await readPassport(configuration: config)
    }
    
    // MARK: - Private Helpers
    
    private func startNFCSession() async throws -> NFCPassportModel {
        resetState()
        
        guard NFCNDEFReaderSession.readingAvailable else {
            throw NFCPassportReaderError.NFCNotSupported
        }
        
        guard NFCTagReaderSession.readingAvailable else {
            throw NFCPassportReaderError.NFCNotSupported
        }
        
        readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        updateDisplayMessage(.requestPresentPassport)
        readerSession?.begin()
        
        return try await withCheckedThrowingContinuation { continuation in
            self.nfcContinuation = continuation
        }
    }
    
    private func resetState() {
        passport = NFCPassportModel()
        currentPhase = .idle
        currentlyReadingDataGroup = nil
        caHandler = nil
        progressTracker.reset()
        shouldSuppressNextCancelError = false
    }
    
    private func updateDisplayMessage(_ message: NFCViewDisplayMessage) {
        readerSession?.alertMessage = configuration?.displayMessageHandler?(message) ?? message.description
    }
}

// MARK: - NFCTagReaderSessionDelegate

@available(iOS 15, *)
extension PassportReader: NFCTagReaderSessionDelegate {
    
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        Logger.passportReader.debug("NFC session became active")
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        Logger.passportReader.debug("Session invalidated: \(error.localizedDescription)")
        readerSession = nil
        
        // Suppress expected cancellation errors
        if let readerError = error as? NFCReaderError,
           readerError.code == .readerSessionInvalidationErrorUserCanceled,
           shouldSuppressNextCancelError {
            shouldSuppressNextCancelError = false
            return
        }
        
        let mappedError = mapNFCError(error)
        currentPhase = .failed(mappedError)
        nfcContinuation?.resume(throwing: mappedError)
        nfcContinuation = nil
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didDetect tags: [NFCTag]) {
        Logger.passportReader.debug("Detected \(tags.count) tag(s)")
        
        guard tags.count == 1 else {
            failSession(with: .MoreThanOneTagFound)
            return
        }
        
        guard case let .iso7816(passportTag) = tags[0] else {
            failSession(with: .TagNotValid)
            return
        }
        
        Task {
            await handleTagConnection(session: session, tag: tags[0], passportTag: passportTag)
        }
    }
    
    private func handleTagConnection(session: NFCTagReaderSession, tag: NFCTag, passportTag: NFCISO7816Tag) async {
        currentPhase = .connecting
        
        do {
            try await session.connect(to: tag)
            Logger.passportReader.debug("Connected to passport tag")
            
            let tagReader = TagReader(tag: passportTag)
            configureProgressCallback(tagReader: tagReader)
            
            let result = try await performReading(tagReader: tagReader)
            
            shouldSuppressNextCancelError = true
            readerSession?.invalidate()
            
            nfcContinuation?.resume(returning: result)
            nfcContinuation = nil
            
        } catch let error as NFCPassportReaderError {
            handleReadingError(error, session: session)
        } catch {
            handleConnectionError(error, session: session)
        }
    }
    
    private func configureProgressCallback(tagReader: TagReader) {
        tagReader.progress = { [weak self] progress in
            guard let self else { return }
            if let dgId = currentlyReadingDataGroup {
                let overall = progressTracker.dataGroupProgress(progress)
                updateDisplayMessage(.readingDataGroupProgress(dgId, overall))
            } else {
                updateDisplayMessage(.authenticatingWithPassport(progress))
            }
        }
    }
    
    private func handleReadingError(_ error: NFCPassportReaderError, session: NFCTagReaderSession) {
        if shouldRestartSession(for: error) {
            resetState()
            updateDisplayMessage(.error(error))
            session.restartPolling()
        } else {
            failSession(with: error)
        }
    }
    
    private func handleConnectionError(_ error: Error, session: NFCTagReaderSession) {
        Logger.passportReader.error("Connection error: \(error.localizedDescription)")
        
        if isRecoverableConnectionError(error) {
            resetState()
            updateDisplayMessage(.error(.ConnectionError))
            session.restartPolling()
        } else {
            failSession(with: .Unknown(error))
        }
    }
    
    private func isRecoverableConnectionError(_ error: Error) -> Bool {
        guard let nfcError = error as? NFCReaderError else { return false }
        return nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagResponseError.rawValue ||
               nfcError.errorCode == NFCReaderError.readerTransceiveErrorTagConnectionLost.rawValue
    }
    
    private func mapNFCError(_ error: Error) -> NFCPassportReaderError {
        guard let readerError = error as? NFCReaderError else {
            return .UnexpectedError
        }
        
        switch readerError.code {
        case .readerSessionInvalidationErrorUserCanceled: return .UserCanceled
        case .readerSessionInvalidationErrorSessionTimeout: return .TimeOutError
        default: return .UnexpectedError
        }
    }
    
    private func failSession(with error: NFCPassportReaderError) {
        currentPhase = .failed(error)
        shouldSuppressNextCancelError = true
        readerSession?.invalidate(errorMessage: NFCViewDisplayMessage.error(error).description)
        nfcContinuation?.resume(throwing: error)
        nfcContinuation = nil
    }
    
    private func shouldRestartSession(for error: NFCPassportReaderError) -> Bool {
        switch error {
        case .ConnectionError, .TagNotValid, .MoreThanOneTagFound:
            return true
        default:
            return false
        }
    }
}

// MARK: - Reading Flow

@available(iOS 15, *)
extension PassportReader {
    
    private func performReading(tagReader: TagReader) async throws -> NFCPassportModel {
        trackingDelegate?.nfcTagDetected()
        
        // Phase 1: Authentication (PACE or BAC)
        try await performAuthentication(tagReader: tagReader)
        
        // Phase 2: Select passport application
        _ = try await tagReader.selectPassportApplication()
        
        // Phase 3: Fallback to BAC if PACE failed
        if passport.PACEStatus != .success {
            try await performBACAuthentication(tagReader: tagReader)
        }
        
        updateDisplayMessage(.authenticatingWithPassport(progressTracker.authComplete()))
        
        // Phase 4: Read data groups
        try await readAllDataGroups(tagReader: tagReader)
        
        // Phase 5: Active Authentication (if supported)
        try await performActiveAuthenticationIfSupported(tagReader: tagReader)
        
        // Phase 6: Verification
        currentPhase = .verifying
        updateDisplayMessage(.successfulRead)
        
        let effectiveMasterListURL = configuration?.masterListURL ?? masterListURL
        passport.verifyPassport(
            masterListURL: effectiveMasterListURL,
            useCMSVerification: passiveAuthenticationUsesOpenSSL
        )
        
        currentPhase = .complete
        return passport
    }
    
    // MARK: - Phase 1: Authentication
    
    private func performAuthentication(tagReader: TagReader) async throws {
        guard let config = configuration else {
            throw NFCPassportReaderError.InvalidMRZKey
        }
        
        do {
            currentPhase = .authenticating(.pace)
            trackingDelegate?.paceStarted()
            
            let cardAccessData = try await tagReader.readCardAccess()
            Logger.passportReader.debug("Read CardAccess: \(cardAccessData.hexString)")
            
            let cardAccess = try CardAccess(cardAccessData)
            passport.cardAccess = cardAccess
            trackingDelegate?.readCardAccess(cardAccess: cardAccess)
            
            Logger.passportReader.info("Starting PACE authentication")
            let paceHandler = try PACEHandler(cardAccess: cardAccess, tagReader: tagReader)
            try await paceHandler.doPACE(mrzKey: config.mrzKey)
            
            passport.PACEStatus = .success
            Logger.passportReader.debug("PACE succeeded")
            trackingDelegate?.paceSucceeded()
            
        } catch {
            trackingDelegate?.paceFailed()
            passport.PACEStatus = .failed
            Logger.passportReader.error("PACE failed, will fall back to BAC: \(error.localizedDescription)")
        }
    }
    
    private func performBACAuthentication(tagReader: TagReader) async throws {
        guard let config = configuration else {
            throw NFCPassportReaderError.InvalidMRZKey
        }
        
        currentPhase = .authenticating(.bac)
        currentlyReadingDataGroup = nil
        trackingDelegate?.bacStarted()
        
        Logger.passportReader.info("Starting BAC authentication")
        passport.BACStatus = .failed
        
        do {
            let bacHandler = BACHandler(tagReader: tagReader)
            try await bacHandler.performBACAndGetSessionKeys(mrzKey: config.mrzKey)
            
            passport.BACStatus = .success
            Logger.passportReader.info("BAC succeeded")
            trackingDelegate?.bacSucceeded()
            
        } catch {
            trackingDelegate?.bacFailed()
            throw error
        }
    }
    
    // MARK: - Phase 4: Data Group Reading
    
    private func readAllDataGroups(tagReader: TagReader) async throws {
        progressTracker.reset()
        
        // Step 1: Read COM to discover available data groups
        let dataGroupsToRead = try await readCOMAndBuildReadingList(tagReader: tagReader)
        
        // Step 2: Handle DG14 specially (Chip Authentication)
        var remainingGroups = dataGroupsToRead
        if remainingGroups.contains(.DG14) {
            remainingGroups.removeAll { $0 == .DG14 }
            try await handleDG14AndChipAuth(tagReader: tagReader)
        }
        
        // Step 3: Read remaining data groups
        progressTracker.setDataGroupPlan(total: 1 + remainingGroups.count)
        
        for (index, dgId) in remainingGroups.enumerated() {
            progressTracker.beginDataGroup(index: index + 1)
            currentPhase = .readingDataGroup(dgId)
            updateDisplayMessage(.readingDataGroupProgress(dgId, progressTracker.dataGroupProgress(0)))
            
            if let dg = try await readDataGroupWithRetry(tagReader: tagReader, dgId: dgId) {
                passport.addDataGroup(dgId, dataGroup: dg)
            }
        }
    }
    
    private func readCOMAndBuildReadingList(tagReader: TagReader) async throws -> [DataGroupId] {
        currentPhase = .readingDataGroup(.COM)
        updateDisplayMessage(.readingDataGroupProgress(.COM, progressTracker.dataGroupProgress(0)))
        
        guard let com = try await readDataGroupWithRetry(tagReader: tagReader, dgId: .COM) as? COM else {
            throw NFCPassportReaderError.UnexpectedError
        }
        
        passport.addDataGroup(.COM, dataGroup: com)
        return buildDataGroupReadingList(from: com)
    }
    
    private func buildDataGroupReadingList(from com: COM) -> [DataGroupId] {
        // 1. Get available groups from COM (excluding COM itself)
        var available = com.dataGroupsPresent
            .compactMap { DataGroupId.getIDFromName(name: $0) }
            .filter { $0 != .COM }
        
        // 2. Always exclude DG3/DG4 (require Extended Access Control)
        available.removeAll { $0 == .DG3 || $0 == .DG4 }
        
        // 3. If specific groups requested, intersect with available
        var result: [DataGroupId]
        if let requested = configuration?.dataGroups, !requested.isEmpty {
            result = available.filter { requested.contains($0) }
        } else {
            result = available
        }
        
        // 4. Remove duplicates while preserving order
        var seen = Set<DataGroupId>()
        result = result.filter { seen.insert($0).inserted }
        
        // 5. Ensure SOD is read first (for passive authentication)
        result.removeAll { $0 == .SOD }
        result.insert(.SOD, at: 0)
        
        return result
    }
    
    // MARK: - Chip Authentication
    
    private func handleDG14AndChipAuth(tagReader: TagReader) async throws {
        currentPhase = .readingDataGroup(.DG14)
        
        guard let dg14 = try await readDataGroupWithRetry(tagReader: tagReader, dgId: .DG14) as? DataGroup14 else {
            return
        }
        
        passport.addDataGroup(.DG14, dataGroup: dg14)
        
        caHandler = ChipAuthenticationHandler(dg14: dg14, tagReader: tagReader)
        
        guard let handler = caHandler, handler.isChipAuthenticationSupported else {
            caHandler = nil
            return
        }
        
        currentPhase = .performingChipAuth
        
        do {
            try await handler.doChipAuthentication()
            passport.chipAuthenticationStatus = .success
            Logger.passportReader.info("Chip Authentication succeeded")
        } catch {
            Logger.passportReader.info("Chip Authentication failed, re-establishing BAC")
            passport.chipAuthenticationStatus = .failed
            caHandler = nil
            try await performBACAuthentication(tagReader: tagReader)
        }
    }
    
    // MARK: - Phase 5: Active Authentication
    
    private func performActiveAuthenticationIfSupported(tagReader: TagReader) async throws {
        guard passport.activeAuthenticationSupported else { return }
        
        currentPhase = .performingActiveAuth
        updateDisplayMessage(.activeAuthentication)
        
        Logger.passportReader.info("Performing Active Authentication")
        
        let challenge = configuration?.aaChallenge ?? generateRandomUInt8Array(8)
        Logger.passportReader.debug("AA challenge: \(challenge.hexString)")
        
        let response = try await tagReader.doInternalAuthentication(challenge: challenge, useExtendedMode: false)
        passport.verifyActiveAuthentication(challenge: challenge, signature: response.data)
    }
    
    // MARK: - Data Group Reading with Retry
    
    private func readDataGroupWithRetry(tagReader: TagReader, dgId: DataGroupId) async throws -> DataGroup? {
        currentlyReadingDataGroup = dgId
        Logger.passportReader.info("Reading \(dgId.getName())")
        
        var lastError: NFCPassportReaderError?
        
        for attempt in 0..<PassportReadingConfiguration.maxReadRetries {
            do {
                let response = try await tagReader.readDataGroup(dataGroup: dgId)
                return try DataGroupParser().parseDG(data: response)
                
            } catch let error as NFCPassportReaderError {
                Logger.passportReader.error("Read attempt \(attempt + 1) failed: \(error.value)")
                lastError = error
                
                switch recoveryAction(for: error, tagReader: tagReader) {
                case .retryAfterBAC:
                    try await performBACAuthentication(tagReader: tagReader)
                case .retryAfterBACAndSkip:
                    try await performBACAuthentication(tagReader: tagReader)
                    return nil
                case .retry:
                    continue
                case .skip:
                    Logger.passportReader.debug("Skipping unsupported DataGroup: \(dgId.rawValue)")
                    return nil
                case .fail:
                    throw error
                }
            }
        }
        
        throw lastError ?? NFCPassportReaderError.UnexpectedError
    }
    
    // MARK: - Error Recovery
    
    private enum ReadRecoveryAction {
        case retryAfterBAC
        case retryAfterBACAndSkip
        case retry
        case skip
        case fail
    }
    
    private func recoveryAction(for error: NFCPassportReaderError, tagReader: TagReader) -> ReadRecoveryAction {
        switch error {
        case .UnsupportedDataGroup:
            return .skip
        case .ResponseError(_, let sw1, let sw2):
            return recoveryActionForStatusWord(sw1: sw1, sw2: sw2, tagReader: tagReader)
        default:
            return .retry
        }
    }
    
    private func recoveryActionForStatusWord(sw1: UInt8, sw2: UInt8, tagReader: TagReader) -> ReadRecoveryAction {
        switch (sw1, sw2) {
        // Session/connection issues
        case (0x6E, 0x00), // Class not supported
             (0x69, 0x87), // Expected SM data objects missing
             (0x63, 0x00): // No information given
            if caHandler != nil {
                caHandler = nil
                return .retryAfterBAC
            }
            return .fail
            
        // Access denied or not found
        case (0x69, 0x82), // Security status not satisfied
             (0x6A, 0x82): // File not found
            return .retryAfterBACAndSkip
            
        // SM data objects incorrect
        case (0x69, 0x88):
            return .retryAfterBAC
            
        // Length errors
        case (0x67, _), (0x6C, _), (0x62, _):
            tagReader.reduceDataReadingAmount()
            return .retryAfterBAC
            
        default:
            return .retry
        }
    }
}
#endif
