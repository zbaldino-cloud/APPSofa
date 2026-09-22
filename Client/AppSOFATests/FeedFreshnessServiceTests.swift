import XCTest
@testable import AppSOFA

final class FeedFreshnessServiceTests: XCTestCase {
    private let formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter
    }()

    func testFreshFeed() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let generated = formatter.string(from: now.addingTimeInterval(-24 * 60 * 60))
        XCTAssertEqual(
            FeedFreshnessService.evaluate(generated: generated, now: now),
            .fresh(ageHours: 24)
        )
    }

    func testExactlyFortyEightHoursIsFresh() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let generated = formatter.string(from: now.addingTimeInterval(-48 * 60 * 60))
        XCTAssertEqual(
            FeedFreshnessService.evaluate(generated: generated, now: now),
            .fresh(ageHours: 48)
        )
    }

    func testOlderThanFortyEightHoursIsStale() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let generated = formatter.string(from: now.addingTimeInterval(-49 * 60 * 60))
        XCTAssertEqual(
            FeedFreshnessService.evaluate(generated: generated, now: now),
            .stale(ageHours: 49)
        )
    }

    func testInvalidTimestampFailsClosed() {
        XCTAssertEqual(
            FeedFreshnessService.evaluate(generated: "not-a-date"),
            .invalidTimestamp
        )
    }

    func testFutureTimestampFailsClosed() {
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let generated = formatter.string(from: now.addingTimeInterval(10 * 60))
        XCTAssertEqual(
            FeedFreshnessService.evaluate(generated: generated, now: now),
            .futureTimestamp
        )
    }
}
