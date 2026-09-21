//
//  AppFeed.swift
//  MyTool
//
//  Created by Zach Baldino on 9/17/26.
//

import Foundation

struct AppFeed: Codable {
    let feedVersion: String
    let lastCheck: String
    let applications: [ApplicationRequirement]

    enum CodingKeys: String, CodingKey {
        case feedVersion = "FeedVersion"
        case lastCheck = "LastCheck"
        case applications = "Applications"
    }
}
