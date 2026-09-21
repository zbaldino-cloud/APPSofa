//
//  VersonComparator.swift
//  MyTool
//
//  Created by Zach Baldino on 9/17/26.
//

import Foundation

enum VersionComparator {

    static func compare(
        _ lhs: String,
        _ rhs: String
    ) -> ComparisonResult {

        lhs.compare(
            rhs,
            options: .numeric
        )
    }

    static func isOlder(
        _ installed: String,
        than required: String
    ) -> Bool {

        compare(installed, required) == .orderedAscending
    }

    static func meetsRequirement(
        _ installed: String,
        required: String
    ) -> Bool {

        compare(installed, required) != .orderedAscending
    }
}
