import Foundation

@main
struct AppSOFA {
    static func main() async {
        print("""
        ==============================
               AppSOFA v0.9
        ==============================

        Hosted Application Security Engine
        """)

        do {
            print("Downloading AppSOFA feed...")
            let feed = try await FeedLoader.loadRemoteFeed()
            print("Feed Version:        \(feed.feedVersion)")
            print("Feed Generated:      \(feed.generated)")
            print("Applications:        \(feed.applications.count)")
            print("")

            var installedCount = 0

            for requirement in feed.applications {
                guard let installed = ApplicationScanner.scan(path: requirement.applicationPath) else {
                    continue
                }

                installedCount += 1
                print("================================")
                print("Application:         \(installed.name)")
                print("Bundle ID:           \(installed.bundleID)")
                print("Installed Version:   \(installed.version)")
                print("Latest Stable:       \(requirement.latestVersion)")

                guard let minimumSecure = requirement.minimumSecureVersion else {
                    print("Minimum Secure:      unavailable")
                    print("Security Status:     UNKNOWN")
                    print("Reason:              AppSOFA has no verified security floor.")
                    print("")
                    continue
                }

                print("Minimum Secure:      \(minimumSecure)")

                // Fail closed: the security release describing the floor must
                // exactly match MinimumSecureVersion. Never silently substitute
                // another release.
                guard let release = requirement.securityReleases.first(where: {
                    $0.version == minimumSecure
                }) else {
                    print("Security Status:     UNKNOWN")
                    print("Reason:              Security-floor evidence does not match the feed.")
                    print("")
                    continue
                }

                guard ["ExplicitMac", "VendorAdvisory"].contains(release.platformEvidence ?? "") else {
                    print("Security Status:     UNKNOWN")
                    print("Reason:              Security floor lacks trusted vendor evidence.")
                    print("")
                    continue
                }

                let securityUpdateRequired =
                    VersionComparator.isOlder(installed.version, than: minimumSecure)
                let normalUpdateAvailable =
                    VersionComparator.isOlder(installed.version, than: requirement.latestVersion)

                if securityUpdateRequired {
                    let sla = SecuritySLAService.calculate(release: release)
                    let criticalCount = release.cves.filter { $0.severity == .critical }.count

                    print("Security Status:     VULNERABLE")
                    print("Security Priority:   \(sla.priority.rawValue)")
                    print("Security CVEs:       \(release.cves.count)")
                    print("Critical CVEs:       \(criticalCount)")
                    print("CISA KEV:            \(release.cisaKEVCount)")
                    print("Security SLA:        \(sla.days) day(s)")
                    print("Reason:              \(sla.reason)")
                    print("Remediation:         REQUIRED")
                } else {
                    print("Security Status:     SECURE")
                    print("CISA KEV:            \(release.cisaKEVCount)")

                    if normalUpdateAvailable {
                        print("Update Status:       UPDATE AVAILABLE")
                        print("Remediation:         OPTIONAL")
                    } else {
                        print("Update Status:       CURRENT")
                        print("Remediation:         NONE")
                    }
                }

                print("")
            }

            if installedCount == 0 {
                print("No AppSOFA-managed applications are installed.")
            }
        } catch {
            print("")
            print("ERROR: Security check failed.")
            print(error)
        }
    }
}
