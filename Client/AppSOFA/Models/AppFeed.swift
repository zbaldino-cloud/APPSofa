import Foundation

struct AppFeed: Codable {
    let feedVersion: String
    let generated: String
    let applications: [ApplicationRequirement]
    let updateHash: String

    enum CodingKeys: String, CodingKey {
        case feedVersion = "FeedVersion"
        case generated = "Generated"
        case applications = "Applications"
        case updateHash = "UpdateHash"
    }
}
