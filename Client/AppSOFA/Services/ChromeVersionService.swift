//
//  ChromeVersionServices.swift
//  MyTool
//
//  Created by Zach Baldino on 9/18/26.
//

import Foundation

struct ChromeVersionResponse: Codable {
    let versions: [ChromeVersion]
}

struct ChromeVersion: Codable {
    let name: String
    let version: String
}

enum ChromeVersionService {

    static func fetchLatestStableVersion() async throws -> String {

        let urlString =
            "https://versionhistory.googleapis.com/v1/chrome/platforms/mac/channels/stable/versions"

        guard let url = URL(string: urlString) else {
            throw ChromeVersionError.invalidURL
        }

        let (data, response) = try await URLSession.shared.data(from: url)

        guard
            let httpResponse = response as? HTTPURLResponse,
            (200...299).contains(httpResponse.statusCode)
        else {
            throw ChromeVersionError.invalidResponse
        }

        let result = try JSONDecoder().decode(
            ChromeVersionResponse.self,
            from: data
        )

        guard !result.versions.isEmpty else {
            throw ChromeVersionError.noVersionsFound
        }

        let sortedVersions = result.versions.sorted {
            $0.version.compare(
                $1.version,
                options: .numeric
            ) == .orderedDescending
        }

        guard let latest = sortedVersions.first else {
            throw ChromeVersionError.noVersionsFound
        }

        return latest.version
    }
}

enum ChromeVersionError: Error {
    case invalidURL
    case invalidResponse
    case noVersionsFound
}
