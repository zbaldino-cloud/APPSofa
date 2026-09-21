//
//  ChromeSecurityRelease.swift
//  MyTool
//
//  Created by Zach Baldino on 9/21/26.
//

import Foundation

struct ChromeSecurityRelease {

    let minimumSecureVersion: String
    let releaseDate: Date

    let cves: [ChromeCVE]

    var criticalCVEs: [ChromeCVE] {
        cves.filter {
            $0.severity == .critical
        }
    }

    var highCVEs: [ChromeCVE] {
        cves.filter {
            $0.severity == .high
        }
    }
}

struct ChromeCVE: Identifiable {

    let cveID: String
    let severity: CVESeverity

    var id: String {
        cveID
    }
}

enum CVESeverity: String, Codable {
    case critical = "Critical"
    case high = "High"
    case medium = "Medium"
    case low = "Low"
    case unknown = "Unknown"
}
