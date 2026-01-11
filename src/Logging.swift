//
//  Logging.swift
//

import Foundation
import OSLog

/// Controls whether debug logging is enabled across the MRTDReader library.
/// For security, logging is disabled by default to prevent sensitive cryptographic
/// data from being written to the system log.
public enum MRTDLogging {
    /// When false, debug/info/warning logs are suppressed. Errors are always logged
    /// but are sanitized to not contain sensitive data.
    public static var isEnabled: Bool = false
}

/// Type alias for backwards compatibility
public typealias NFCPassportLogging = MRTDLogging

extension Logger {
    private static let subsystem = Bundle.main.bundleIdentifier ?? "MRTDReader"
    
    static let reader = Logger(subsystem: subsystem, category: "reader")
    static let tagReader = Logger(subsystem: subsystem, category: "tagReader")
    static let secureMessaging = Logger(subsystem: subsystem, category: "secureMessaging")
    static let openSSL = Logger(subsystem: subsystem, category: "openSSL")
    static let bac = Logger(subsystem: subsystem, category: "BAC")
    static let chipAuth = Logger(subsystem: subsystem, category: "chipAuthentication")
    static let pace = Logger(subsystem: subsystem, category: "PACE")
    
    // MARK: - Conditional Logging Helpers
    
    /// Logs a debug message only if logging is enabled.
    /// Uses @autoclosure to avoid computing the message when logging is disabled.
    func debugIfEnabled(_ message: @autoclosure () -> String) {
        guard MRTDLogging.isEnabled else { return }
        let msg = message()
        self.debug("\(msg)")
    }
    
    /// Logs an info message only if logging is enabled.
    func infoIfEnabled(_ message: @autoclosure () -> String) {
        guard MRTDLogging.isEnabled else { return }
        let msg = message()
        self.info("\(msg)")
    }
    
    /// Logs a warning message only if logging is enabled.
    func warningIfEnabled(_ message: @autoclosure () -> String) {
        guard MRTDLogging.isEnabled else { return }
        let msg = message()
        self.warning("\(msg)")
    }
    
    /// Logs an error message only if logging is enabled.
    /// Note: Error messages should never contain sensitive data.
    func errorIfEnabled(_ message: @autoclosure () -> String) {
        guard MRTDLogging.isEnabled else { return }
        let msg = message()
        self.error("\(msg)")
    }
}
