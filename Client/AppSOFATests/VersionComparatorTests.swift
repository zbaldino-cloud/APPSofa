import XCTest
@testable import AppSOFACore

final class VersionComparatorTests: XCTestCase {
    func testChromeStyleVersions() {
        XCTAssertTrue(
            VersionComparator.isOlder("153.0.8010.48", than: "153.0.8010.52")
        )
        XCTAssertFalse(
            VersionComparator.isOlder("154.0.8037.44", than: "153.0.8010.52")
        )
    }

    func testOfficePatchVersion() {
        XCTAssertTrue(
            VersionComparator.isOlder("16.113", than: "16.113.1")
        )
        XCTAssertTrue(
            VersionComparator.meetsRequirement("16.113.1", required: "16.113")
        )
    }

    func testZoomBuildSuffixDoesNotMakeVersionOlder() {
        XCTAssertFalse(
            VersionComparator.isOlder("7.2.1 (88329)", than: "7.2.1")
        )
    }

    func testEqualVersionsMeetRequirement() {
        XCTAssertTrue(
            VersionComparator.meetsRequirement("156.0", required: "156.0")
        )
    }
}
