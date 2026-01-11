
import Foundation
import OSLog

#if !os(macOS)
import UIKit
import CoreNFC

// MARK: - Configuration

/// Configuration for MRTD reading operations
@available(iOS 15, *)
public struct MRTDReaderConfiguration {
    /// MRZ key derived from document data (document number + date of birth + expiry date)
    public let mrzKey: String
    
    /// Data groups to read. If nil or empty, reads all available groups.
    /// Specified groups are intersected with what's available on the document.
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
    
    /// Whether to enable debug logging. Defaults to false for security.
    /// When enabled, detailed logs including cryptographic operations will be written.
    /// WARNING: Enable only for debugging - sensitive data may be logged.
    public let loggingEnabled: Bool
    
    /// Maximum retry attempts for reading a data group
    public static let maxReadRetries = 2
    
    public init(
        mrzKey: String,
        dataGroups: Set<DataGroupId>? = nil,
        aaChallenge: [UInt8]? = nil,
        displayMessageHandler: ((NFCViewDisplayMessage) -> String?)? = nil,
        masterListURL: URL? = nil,
        useOpenSSLForPassiveAuth: Bool = false,
        loggingEnabled: Bool = false
    ) {
        self.mrzKey = mrzKey
        self.dataGroups = dataGroups
        self.aaChallenge = aaChallenge
        self.displayMessageHandler = displayMessageHandler
        self.masterListURL = masterListURL
        self.useOpenSSLForPassiveAuth = useOpenSSLForPassiveAuth
        self.loggingEnabled = loggingEnabled
    }
}

// MARK: - Reading Phase State Machine

/// Represents the current phase of MRTD reading
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
    case failed(MRTDReaderError)
    
    public enum AuthMethod {
        case pace
        case bac
    }
    
    public var description: String {
        switch self {
        case .idle: return "Idle"
        case .connecting: return "Connecting to document"
        case .authenticating(let method):
            return method == .pace ? "PACE Authentication" : "BAC Authentication"
        case .readingDataGroup(let dg): return "Reading \(dg.getName())"
        case .performingChipAuth: return "Chip Authentication"
        case .performingActiveAuth: return "Active Authentication"
        case .verifying: return "Verifying document"
        case .complete: return "Complete"
        case .failed(let error): return "Failed: \(error.value)"
        }
    }
}

// MARK: - Tracking Delegate

@available(iOS 15, *)
public protocol MRTDReaderTrackingDelegate: AnyObject {
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
public extension MRTDReaderTrackingDelegate {
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

// MARK: - MRTDReader

@available(iOS 15, *)
public class MRTDReader: NSObject {
    
    // MARK: - Types
    
    private typealias NFCCheckedContinuation = CheckedContinuation<MRTDModel, Error>
    
    // MARK: - Public Properties
    
    public weak var trackingDelegate: MRTDReaderTrackingDelegate?
    
    /// By default, Passive Authentication uses the new RFS5652 method to verify the SOD,
    /// but can be switched to use the previous OpenSSL CMS verification if necessary
    public var passiveAuthenticationUsesOpenSSL: Bool = false
    
    // MARK: - Private State
    
    private var nfcContinuation: NFCCheckedContinuation?
    private var readerSession: NFCTagReaderSession?
    private var document = MRTDModel()
    private var configuration: MRTDReaderConfiguration?
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
    
    /// Read MRTD using the new configuration object
    public func read(configuration: MRTDReaderConfiguration) async throws -> MRTDModel {
        self.configuration = configuration
        self.passiveAuthenticationUsesOpenSSL = configuration.useOpenSSLForPassiveAuth
        MRTDLogging.isEnabled = configuration.loggingEnabled
        return try await startNFCSession()
    }
    
    /// Read MRTD (legacy API for backwards compatibility)
    public func readPassport(
        mrzKey: String,
        aaChallenge: [UInt8]? = nil,
        customDisplayMessage: ((NFCViewDisplayMessage) -> String?)? = nil
    ) async throws -> MRTDModel {
        let config = MRTDReaderConfiguration(
            mrzKey: mrzKey,
            aaChallenge: aaChallenge,
            displayMessageHandler: customDisplayMessage,
            masterListURL: masterListURL,
            useOpenSSLForPassiveAuth: passiveAuthenticationUsesOpenSSL
        )
        return try await read(configuration: config)
    }
    
    // MARK: - Private Helpers
    
    private func startNFCSession() async throws -> MRTDModel {
        resetState()
        
        guard NFCNDEFReaderSession.readingAvailable else {
            throw MRTDReaderError.NFCNotSupported
        }
        
        guard NFCTagReaderSession.readingAvailable else {
            throw MRTDReaderError.NFCNotSupported
        }
        
        readerSession = NFCTagReaderSession(pollingOption: [.iso14443], delegate: self, queue: nil)
        updateDisplayMessage(.requestPresentPassport)
        readerSession?.begin()
        
        return try await withCheckedThrowingContinuation { continuation in
            self.nfcContinuation = continuation
        }
    }
    
    private func resetState() {
        document = MRTDModel()
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
extension MRTDReader: NFCTagReaderSessionDelegate {
    
    public func tagReaderSessionDidBecomeActive(_ session: NFCTagReaderSession) {
        Logger.reader.debugIfEnabled("NFC session became active")
    }
    
    public func tagReaderSession(_ session: NFCTagReaderSession, didInvalidateWithError error: Error) {
        Logger.reader.debugIfEnabled("Session invalidated")
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
        Logger.reader.debugIfEnabled("Detected \(tags.count) tag(s)")
        
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
            Logger.reader.debugIfEnabled("Connected to document tag")
            
            let tagReader = TagReader(tag: passportTag)
            configureProgressCallback(tagReader: tagReader)
            
            let result = try await performReading(tagReader: tagReader)
            
            shouldSuppressNextCancelError = true
            readerSession?.invalidate()
            
            nfcContinuation?.resume(returning: result)
            nfcContinuation = nil
            
        } catch let error as MRTDReaderError {
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
    
    private func handleReadingError(_ error: MRTDReaderError, session: NFCTagReaderSession) {
        if shouldRestartSession(for: error) {
            resetState()
            updateDisplayMessage(.error(error))
            session.restartPolling()
        } else {
            failSession(with: error)
        }
    }
    
    private func handleConnectionError(_ error: Error, session: NFCTagReaderSession) {
        Logger.reader.errorIfEnabled("Connection error occurred")
        
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
    
    private func mapNFCError(_ error: Error) -> MRTDReaderError {
        guard let readerError = error as? NFCReaderError else {
            return .UnexpectedError
        }
        
        switch readerError.code {
        case .readerSessionInvalidationErrorUserCanceled: return .UserCanceled
        case .readerSessionInvalidationErrorSessionTimeout: return .TimeOutError
        default: return .UnexpectedError
        }
    }
    
    private func failSession(with error: MRTDReaderError) {
        currentPhase = .failed(error)
        shouldSuppressNextCancelError = true
        readerSession?.invalidate(errorMessage: NFCViewDisplayMessage.error(error).description)
        nfcContinuation?.resume(throwing: error)
        nfcContinuation = nil
    }
    
    private func shouldRestartSession(for error: MRTDReaderError) -> Bool {
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
extension MRTDReader {
    
    private func performReading(tagReader: TagReader) async throws -> MRTDModel {
        trackingDelegate?.nfcTagDetected()
        
        // Phase 1: Authentication (PACE or BAC)
        try await performAuthentication(tagReader: tagReader)
        
        // Phase 2: Select passport application
        _ = try await tagReader.selectPassportApplication()
        
        // Phase 3: Fallback to BAC if PACE failed
        if document.PACEStatus != .success {
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
        document.verifyPassport(
            masterListURL: effectiveMasterListURL,
            useCMSVerification: passiveAuthenticationUsesOpenSSL
        )
        
        currentPhase = .complete
        return document
    }
    
    // MARK: - Phase 1: Authentication
    
    private func performAuthentication(tagReader: TagReader) async throws {
        guard let config = configuration else {
            throw MRTDReaderError.InvalidMRZKey
        }
        
        do {
            currentPhase = .authenticating(.pace)
            trackingDelegate?.paceStarted()
            
            let cardAccessData = try await tagReader.readCardAccess()
            Logger.reader.debugIfEnabled("Read CardAccess successfully")
            
            let cardAccess = try CardAccess(cardAccessData)
            document.cardAccess = cardAccess
            trackingDelegate?.readCardAccess(cardAccess: cardAccess)
            
            Logger.reader.infoIfEnabled("Starting PACE authentication")
            let paceHandler = try PACEHandler(cardAccess: cardAccess, tagReader: tagReader)
            try await paceHandler.doPACE(mrzKey: config.mrzKey)
            
            document.PACEStatus = .success
            Logger.reader.debugIfEnabled("PACE succeeded")
            trackingDelegate?.paceSucceeded()
            
        } catch {
            trackingDelegate?.paceFailed()
            document.PACEStatus = .failed
            Logger.reader.debugIfEnabled("PACE failed, will fall back to BAC")
        }
    }
    
    private func performBACAuthentication(tagReader: TagReader) async throws {
        guard let config = configuration else {
            throw MRTDReaderError.InvalidMRZKey
        }
        
        currentPhase = .authenticating(.bac)
        currentlyReadingDataGroup = nil
        trackingDelegate?.bacStarted()
        
        Logger.reader.infoIfEnabled("Starting BAC authentication")
        document.BACStatus = .failed
        
        do {
            let bacHandler = BACHandler(tagReader: tagReader)
            try await bacHandler.performBACAndGetSessionKeys(mrzKey: config.mrzKey)
            
            document.BACStatus = .success
            Logger.reader.infoIfEnabled("BAC succeeded")
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
                document.addDataGroup(dgId, dataGroup: dg)
            }
        }
    }
    
    private func readCOMAndBuildReadingList(tagReader: TagReader) async throws -> [DataGroupId] {
        currentPhase = .readingDataGroup(.COM)
        updateDisplayMessage(.readingDataGroupProgress(.COM, progressTracker.dataGroupProgress(0)))
        
        guard let com = try await readDataGroupWithRetry(tagReader: tagReader, dgId: .COM) as? COM else {
            throw MRTDReaderError.UnexpectedError
        }
        
        document.addDataGroup(.COM, dataGroup: com)
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
        
        document.addDataGroup(.DG14, dataGroup: dg14)
        
        caHandler = ChipAuthenticationHandler(dg14: dg14, tagReader: tagReader)
        
        guard let handler = caHandler, handler.isChipAuthenticationSupported else {
            caHandler = nil
            return
        }
        
        currentPhase = .performingChipAuth
        
        do {
            try await handler.doChipAuthentication()
            document.chipAuthenticationStatus = .success
            Logger.reader.infoIfEnabled("Chip Authentication succeeded")
        } catch {
            Logger.reader.infoIfEnabled("Chip Authentication failed, re-establishing BAC")
            document.chipAuthenticationStatus = .failed
            caHandler = nil
            try await performBACAuthentication(tagReader: tagReader)
        }
    }
    
    // MARK: - Phase 5: Active Authentication
    
    private func performActiveAuthenticationIfSupported(tagReader: TagReader) async throws {
        guard document.activeAuthenticationSupported else { return }
        
        currentPhase = .performingActiveAuth
        updateDisplayMessage(.activeAuthentication)
        
        Logger.reader.infoIfEnabled("Performing Active Authentication")
        
        let challenge = configuration?.aaChallenge ?? generateRandomUInt8Array(8)
        Logger.reader.debugIfEnabled("AA challenge generated")
        
        let response = try await tagReader.doInternalAuthentication(challenge: challenge, useExtendedMode: false)
        document.verifyActiveAuthentication(challenge: challenge, signature: response.data)
    }
    
    // MARK: - Data Group Reading with Retry
    
    private func readDataGroupWithRetry(tagReader: TagReader, dgId: DataGroupId) async throws -> DataGroup? {
        currentlyReadingDataGroup = dgId
        Logger.reader.infoIfEnabled("Reading \(dgId.getName())")
        
        var lastError: MRTDReaderError?
        
        for attempt in 0..<MRTDReaderConfiguration.maxReadRetries {
            do {
                let response = try await tagReader.readDataGroup(dataGroup: dgId)
                return try DataGroupParser().parseDG(data: response)
                
            } catch let error as MRTDReaderError {
                Logger.reader.debugIfEnabled("Read attempt \(attempt + 1) failed")
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
                    Logger.reader.debugIfEnabled("Skipping unsupported DataGroup: \(dgId.rawValue)")
                    return nil
                case .fail:
                    throw error
                }
            }
        }
        
        throw lastError ?? MRTDReaderError.UnexpectedError
    }
    
    // MARK: - Error Recovery
    
    private enum ReadRecoveryAction {
        case retryAfterBAC
        case retryAfterBACAndSkip
        case retry
        case skip
        case fail
    }
    
    private func recoveryAction(for error: MRTDReaderError, tagReader: TagReader) -> ReadRecoveryAction {
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

// MARK: - Type Aliases for backwards compatibility
@available(iOS 15, *)
public typealias PassportReader = MRTDReader
@available(iOS 15, *)
public typealias PassportReadingConfiguration = MRTDReaderConfiguration
@available(iOS 15, *)
public typealias PassportReaderTrackingDelegate = MRTDReaderTrackingDelegate

#endif
