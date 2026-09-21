import Foundation

enum SecurityPriority: String {
    case normal = "Normal"
    case elevated = "Elevated"
    case critical = "Critical"
    case activelyExploited = "Actively Exploited"
}

struct SecuritySLA {
    let priority: SecurityPriority
    let days: Int
    let reason: String
}

enum SecuritySLAService {
    static func calculate(release: FeedSecurityRelease) -> SecuritySLA {
        if release.cisaKEVCount > 0 {
            return SecuritySLA(
                priority: .activelyExploited,
                days: 1,
                reason: "Known exploited vulnerability detected"
            )
        }

        if release.cves.contains(where: { $0.severity == .critical }) {
            return SecuritySLA(
                priority: .critical,
                days: 3,
                reason: "Critical security vulnerability detected"
            )
        }

        if !release.cves.isEmpty {
            return SecuritySLA(
                priority: .elevated,
                days: 7,
                reason: "Security vulnerabilities detected"
            )
        }

        return SecuritySLA(
            priority: .normal,
            days: 14,
            reason: "Standard application update"
        )
    }
}
