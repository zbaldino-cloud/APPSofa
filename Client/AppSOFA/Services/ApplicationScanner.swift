//
//  ApplicationScanner.swift
//  MyTool
//
//  Created by Zach Baldino on 9/17/26.
//

import Foundation

struct InstalledApplication {
    let name: String
    let bundleID: String
    let path: String
    let version: String
}

enum ApplicationScanner {

    static func scan(path: String) -> InstalledApplication? {

        guard let bundle = Bundle(path: path) else {
            return nil
        }

        guard
            let bundleID = bundle.bundleIdentifier,
            let version = bundle.object(
                forInfoDictionaryKey: "CFBundleShortVersionString"
            ) as? String
        else {
            return nil
        }

        let name =
            bundle.object(
                forInfoDictionaryKey: "CFBundleDisplayName"
            ) as? String
            ?? bundle.object(
                forInfoDictionaryKey: "CFBundleName"
            ) as? String
            ?? URL(fileURLWithPath: path)
                .deletingPathExtension()
                .lastPathComponent

        return InstalledApplication(
            name: name,
            bundleID: bundleID,
            path: path,
            version: version
        )
    }
}
