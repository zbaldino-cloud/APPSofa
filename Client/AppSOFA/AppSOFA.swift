import Foundation

@main
struct AppSOFA {
    static func main() async {
        print("""
        ==============================
               AppSOFA v0.7
        ==============================

        Hosted Application Security Engine
        """)

        do {
            print("Downloading AppSOFA feed...")
            let feed = try await FeedLoader.loadRemoteFeed()
            print("Feed Version:        \(feed.feedVersion)")
            print("Feed Generated:      \(feed.generated)")
            print("")

            guard let requirement = feed.applications.first(where: {
                $0.bundleID == "com.google.Chrome"
            }) else {
                throw FeedError.applicationNotFound("com.google.Chrome")
            }

            guard let installed = ApplicationScanner.scan(path: requirement.applicationPath) else {
                print("\(requirement.name) is not installed.")
                return
            }

            print("Application:         \(installed.name)")
            print("Bundle ID:           \(installed.bundleID)")
            print("Installed Version:   \(installed.version)")
            print("Latest Stable:       \(requirement.latestVersion)")

            guard let minimumSecure = requirement.minimumSecureVersion else {
                print("Minimum Secure:      unavailable")
                print("")
                print("Security Status:     UNKNOWN")
                print("Reason:              AppSOFA has no verified security floor.")
                return
            }

            print("Minimum Secure:      \(minimumSecure)")
            print("")

            let securityUpdateRequired =
                VersionComparator.isOlder(installed.version, than: minimumSecure)
            let normalUpdateAvailable =
                VersionComparator.isOlder(installed.version, than: requirement.latestVersion)

            guard let feedRelease = requirement.securityReleases.first(where: {
                $0.version == minimumSecure
            }) ?? requirement.securityReleases.first else {
                throw FeedError.noSecurityRelease(requirement.bundleID)
            }

            let release = ChromeSecurityRelease(
                minimumSecureVersion: minimumSecure,
                releaseDate: ISO8601DateFormatter().date(from: feedRelease.releaseDate + "T00:00:00Z")
                    ?? Date.distantPast,
                cves: feedRelease.cves.map {
                    ChromeCVE(cveID: $0.cve, severity: $0.severity)
                }
            )

            let exploited = feedRelease.cves
                .filter(\.cisaKEV)
                .map { ChromeCVE(cveID: $0.cve, severity: $0.severity) }

            if securityUpdateRequired {
                let sla = SecuritySLAService.calculate(
                    release: release,
                    exploitedCVEs: exploited
                )

                print("Security Status:     VULNERABLE")
                print("Security Priority:   \(sla.priority.rawValue)")
                print("Security CVEs:       \(release.cves.count)")
                print("Critical CVEs:       \(release.criticalCVEs.count)")
                print("CISA KEV:            \(exploited.count)")
                print("")
                print("Security SLA:        \(sla.days) day(s)")
                print("Reason:              \(sla.reason)")
                print("")
                print("Remediation:         REQUIRED")
            } else {
                print("Security Status:     SECURE")
                print("CISA KEV:            \(exploited.count)")

                if normalUpdateAvailable {
                    print("Update Status:       UPDATE AVAILABLE")
                    print("Remediation:         OPTIONAL")
                } else {
                    print("Update Status:       CURRENT")
                    print("Remediation:         NONE")
                }
            }
        } catch {
            print("")
            print("ERROR: Security check failed.")
            print(error)
        }
    }
}
