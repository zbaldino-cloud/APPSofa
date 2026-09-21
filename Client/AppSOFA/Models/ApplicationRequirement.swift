//
//  ApplicationRequirement.swift
//  MyTool
//
//  Created by Zach Baldino on 9/17/26.
//


import Foundation

struct ApplicationRequirement: Codable, Identifiable {

    let name: String
    let bundleID: String
    let applicationPath: String
    let latestVersion: String
    let minimumSecureVersion: String
    let security: SecurityInformation

    var id: String {
        bundleID
    }

    enum CodingKeys: String, CodingKey {
        case name = "Name"
        case bundleID = "BundleID"
        case applicationPath = "ApplicationPath"
        case latestVersion = "LatestVersion"
        case minimumSecureVersion = "MinimumSecureVersion"
        case security = "Security"
    }
}
