import Foundation

struct SecurityInformation: Codable {

    let cves: [String]
    let activelyExploitedCVEs: [String]
    let cisaKEV: [String]
    let highestSeverity: String?

    var isActivelyExploited: Bool {
        !activelyExploitedCVEs.isEmpty || !cisaKEV.isEmpty
    }

    var hasKnownCVEs: Bool {
        !cves.isEmpty
    }

    enum CodingKeys: String, CodingKey {
        case cves = "CVEs"
        case activelyExploitedCVEs = "ActivelyExploitedCVEs"
        case cisaKEV = "CISAKEV"
        case highestSeverity = "HighestSeverity"
    }
}
