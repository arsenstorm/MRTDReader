
import Foundation

/// Tracks reading progress for NFC passport operations
@available(iOS 13, macOS 10.15, *)
public struct ProgressTracker {
    private var dataGroupTotal = 0
    private var currentDataGroupIndex = 0
    
    // MARK: - Progress Milestones (percentages)
    
    /// Progress shown when authentication starts
    public static let authStartProgress = 20
    
    /// Progress shown when authentication completes
    public static let authCompleteProgress = 40
    
    /// Remaining progress range allocated to data group reading (40-90%)
    public static let dataGroupRange = 50
    
    // MARK: - State Management
    
    public init() {}
    
    public mutating func reset() {
        dataGroupTotal = 0
        currentDataGroupIndex = 0
    }
    
    public mutating func setDataGroupPlan(total: Int) {
        dataGroupTotal = max(1, total)
        currentDataGroupIndex = 0
    }
    
    public mutating func beginDataGroup(index: Int) {
        currentDataGroupIndex = max(0, index)
    }
    
    // MARK: - Progress Calculation
    
    public func authStart() -> Int {
        Self.authStartProgress
    }
    
    public func authComplete() -> Int {
        Self.authCompleteProgress
    }
    
    /// Calculate overall progress based on current data group and its internal progress
    /// - Parameter progress: Progress within current data group (0-100)
    /// - Returns: Overall reading progress (0-100)
    public func dataGroupProgress(_ progress: Int) -> Int {
        let clampedProgress = max(0, min(100, progress))
        guard dataGroupTotal > 0 else { return authComplete() }
        
        let perGroup = 1.0 / Double(dataGroupTotal)
        let groupContribution = Double(currentDataGroupIndex) * perGroup
        let withinGroupContribution = (Double(clampedProgress) / 100.0) * perGroup
        let overallGroupProgress = groupContribution + withinGroupContribution
        
        return authComplete() + Int(Double(Self.dataGroupRange) * overallGroupProgress)
    }
}
