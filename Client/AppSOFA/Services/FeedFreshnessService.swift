import Foundation

enum FeedFreshnessStatus: Equatable {
    case fresh(ageHours: Int)
    case stale(ageHours: Int)
    case invalidTimestamp
    case futureTimestamp
}

struct FeedFreshnessService {
    static let maximumAge: TimeInterval = 48 * 60 * 60
    static let futureTolerance: TimeInterval = 5 * 60

    static func evaluate(
        generated: String,
        now: Date = Date()
    ) -> FeedFreshnessStatus {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]

        guard let generatedDate = formatter.date(from: generated) else {
            return .invalidTimestamp
        }

        let age = now.timeIntervalSince(generatedDate)

        if age < -futureTolerance {
            return .futureTimestamp
        }

        let ageHours = max(0, Int(age / 3600))

        if age > maximumAge {
            return .stale(ageHours: ageHours)
        }

        return .fresh(ageHours: ageHours)
    }
}
