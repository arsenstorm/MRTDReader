//
//  NFCViewDisplayMessage.swift
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum NFCViewDisplayMessage {
    case requestPresentPassport
    case authenticatingWithPassport(Int)
    case readingDataGroupProgress(DataGroupId, Int)
    case error(NFCPassportReaderError)
    case activeAuthentication
    case successfulRead
}

@available(iOS 13, macOS 10.15, *)
extension NFCViewDisplayMessage {
    
    public static let defaultHoldStillMessage = "Press your passport or ID card against your device\nand hold still to read the chip."
    
    public var description: String {
        switch self {
        case .requestPresentPassport:
            return Self.defaultHoldStillMessage
        case .authenticatingWithPassport(let progress):
            return progressBar(percent: progress)
        case .readingDataGroupProgress(_, let progress):
            return progressBar(percent: progress)
        case .error:
            return Self.defaultHoldStillMessage
        case .activeAuthentication:
            return progressBar(percent: 90)
        case .successfulRead:
            return progressBar(percent: 100)
        }
    }
    
    private func progressBar(percent: Int, width: Int = 10) -> String {
        let clamped = max(0, min(100, percent))
        let filled = Int(Double(clamped) / 100.0 * Double(width))
        return String(repeating: "●", count: filled) + String(repeating: "○", count: width - filled)
    }
}
