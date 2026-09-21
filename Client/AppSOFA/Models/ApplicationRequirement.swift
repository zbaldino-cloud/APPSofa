import Foundation

struct ApplicationRequirement: Codable, Identifiable {
    let name: String
    let bundleID: String
    let applicationPath: String
    let latestVersion: String
    let minimumSecureVersion: String?
    let securityReleases: [FeedSecurityRelease]

    var id: String { bundleID }

    enum CodingKeys: String, CodingKey {
        case name = "Name"
        case bundleID = "BundleID"
        case applicationPath = "ApplicationPath"
        case latestVersion = "LatestVersion"
        case minimumSecureVersion = "MinimumSecureVersion"
        case securityReleases = "SecurityReleases"
    }
}

struct FeedSecurityRelease: Codable {
    let version: String
    let macVersions: [String]
    let releaseDate: String
    let cves: [FeedCVE]
    let sourceURL: String?
    let highestSeverity: String
    let cisaKEVCount: Int

    enum CodingKeys: String, CodingKey {
        case version = "Version"
        case macVersions = "MacVersions"
        case releaseDate = "ReleaseDate"
        case cves = "CVEs"
        case sourceURL = "SourceURL"
        case highestSeverity = "HighestSeverity"
        case cisaKEVCount = "CISAKEVCount"
    }
}

struct FeedCVE: Codable {
    let cve: String
    let severity: CVESeverity
    let cisaKEV: Bool

    enum CodingKeys: String, CodingKey {
        case cve = "CVE"
        case severity = "Severity"
        case cisaKEV = "CISAKEV"
    }
}
