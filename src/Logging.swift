//
//  Logging.swift
//

import Foundation
import OSLog

extension Logger {
    private static let subsystem = Bundle.main.bundleIdentifier!
    
    static let passportReader = Logger(subsystem: subsystem, category: "passportReader")
    static let tagReader = Logger(subsystem: subsystem, category: "tagReader")
    static let secureMessaging = Logger(subsystem: subsystem, category: "secureMessaging")
    static let openSSL = Logger(subsystem: subsystem, category: "openSSL")
    static let bac = Logger(subsystem: subsystem, category: "BAC")
    static let chipAuth = Logger(subsystem: subsystem, category: "chipAuthentication")
    static let pace = Logger(subsystem: subsystem, category: "PACE")
}
