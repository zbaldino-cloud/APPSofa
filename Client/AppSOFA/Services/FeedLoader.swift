import Foundation

enum FeedLoader {

    static func loadLocalFeed() throws -> AppFeed {

        let fileManager = FileManager.default

        // During development, look for the feed
        // in the current working directory.
        let currentDirectory = fileManager.currentDirectoryPath

        let feedURL = URL(fileURLWithPath: currentDirectory)
            .appendingPathComponent("app_data_feed.json")

        print("Looking for feed at:")
        print(feedURL.path)
        print("")

        guard fileManager.fileExists(atPath: feedURL.path) else {
            throw FeedError.feedNotFound(feedURL.path)
        }

        let data = try Data(contentsOf: feedURL)

        return try JSONDecoder().decode(
            AppFeed.self,
            from: data
        )
    }
}

enum FeedError: Error {
    case feedNotFound(String)
}
