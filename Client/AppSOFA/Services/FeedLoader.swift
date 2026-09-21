import Foundation

enum FeedLoader {
    static let feedURL = URL(
        string: "https://zbaldino-cloud.github.io/APPSofa/v1/macos_apps_data_feed.json"
    )!

    static func loadRemoteFeed() async throws -> AppFeed {
        var request = URLRequest(url: feedURL)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 30

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse,
              (200...299).contains(http.statusCode) else {
            throw FeedError.invalidResponse
        }

        return try JSONDecoder().decode(AppFeed.self, from: data)
    }
}

enum FeedError: Error {
    case invalidResponse
    case applicationNotFound(String)
    case noSecurityRelease(String)
}
