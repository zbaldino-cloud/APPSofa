//
//  SecuritySLAService.swift
//  MyTool
//
//  Created by Zach Baldino on 9/21/26.
//

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

    static func calculate(
        release: ChromeSecurityRelease,
        exploitedCVEs: [ChromeCVE]
    ) -> SecuritySLA {

        // Highest priority:
        // Known exploitation / CISA KEV

        if !exploitedCVEs.isEmpty {

            return SecuritySLA(
                priority: .activelyExploited,
                days: 1,
                reason: "Known exploited vulnerability detected"
            )
        }

        // Critical vulnerability

        if !release.criticalCVEs.isEmpty {

            return SecuritySLA(
                priority: .critical,
                days: 3,
                reason: "Critical security vulnerability detected"
            )
        }

        // Security release with CVEs

        if !release.cves.isEmpty {

            return SecuritySLA(
                priority: .elevated,
                days: 7,
                reason: "Security vulnerabilities detected"
            )
        }

        // Ordinary update

        return SecuritySLA(
            priority: .normal,
            days: 14,
            reason: "Standard application update"
        )
    }
}
