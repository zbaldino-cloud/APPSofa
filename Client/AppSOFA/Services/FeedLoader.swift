import Foundation

enum FeedLoader {
    static let feedURL = URL(
        string: "https://zbaldino-cloud.github.io/APPSofa/v1/macos_apps_data_feed.json"
    )!

    static let signatureURL = URL(
        string: "https://zbaldino-cloud.github.io/APPSofa/v1/macos_apps_data_feed.json.sig"
    )!

    static func loadRemoteFeed() async throws -> AppFeed {
        async let feedDownload = download(feedURL)
        async let signatureDownload = download(signatureURL)

        let (feedData, signatureData) = try await (feedDownload, signatureDownload)

        try FeedSignatureVerifier.verify(
            feedData: feedData,
            signatureData: signatureData
        )

        return try JSONDecoder().decode(AppFeed.self, from: feedData)
    }

    private static func download(_ url: URL) async throws -> Data {
        var request = URLRequest(url: url)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.timeoutInterval = 30

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let http = response as? HTTPURLResponse,
              (200...299).contains(http.statusCode) else {
            throw FeedError.invalidResponse
        }

        return data
    }
}

enum FeedError: Error {
    case invalidResponse
    case applicationNotFound(String)
    case noSecurityRelease(String)
}
