//
//  AppSOFA.swift
//  MyTool
//
//  Created by Zach Baldino on 9/17/26.
//

import Foundation

@main
struct AppSOFA {

    static func main() async {

        print("""
        ==============================
               AppSOFA v0.4
        ==============================

        Application Security Engine
        """)

        let chromePath =
            "/Applications/Google Chrome.app"

        guard let chrome =
                ApplicationScanner.scan(
                    path: chromePath
                )
        else {

            print("Google Chrome is not installed.")
            return
        }

        print("Application:       \(chrome.name)")
        print("Bundle ID:         \(chrome.bundleID)")
        print("Installed Version: \(chrome.version)")
        print("")

        do {

            // MARK: Latest Chrome

            let latestVersion =
                try await ChromeVersionService
                    .fetchLatestStableVersion()

            print("Latest Stable:     \(latestVersion)")

            // MARK: Security Release

            //
            // Temporary release definition.
            //
            // In the next version this will come
            // from our AppSOFA feed generator.
            //

            let releaseDate =
                Calendar.current.date(
                    from: DateComponents(
                        year: 2026,
                        month: 9,
                        day: 17
                    )
                )!

            let securityRelease =
                ChromeSecurityRelease(

                    minimumSecureVersion:
                        "153.0.8010.52",

                    releaseDate:
                        releaseDate,

                    cves: [

                        ChromeCVE(
                            cveID:
                                "CVE-2026-93374",
                            severity:
                                .critical
                        ),

                        ChromeCVE(
                            cveID:
                                "CVE-2026-93372",
                            severity:
                                .critical
                        )
                    ]
                )

            print(
                "Minimum Secure:    \(securityRelease.minimumSecureVersion)"
            )

            print("")

            // MARK: Version Check

            let securityUpdateRequired =
                VersionComparator.isOlder(

                    chrome.version,

                    than:
                        securityRelease
                            .minimumSecureVersion
                )

            let normalUpdateAvailable =
                VersionComparator.isOlder(

                    chrome.version,

                    than:
                        latestVersion
                )

            // MARK: CISA KEV

            print("Checking CISA KEV...")
            print("")

            let kevCatalog =
                try await CISAKEVService
                    .fetchCatalog()

            let exploited =
                CISAKEVService
                    .exploitedCVEs(

                        from:
                            securityRelease.cves,

                        catalog:
                            kevCatalog
                    )

            // MARK: Security Decision

            if securityUpdateRequired {

                let sla =
                    SecuritySLAService
                        .calculate(

                            release:
                                securityRelease,

                            exploitedCVEs:
                                exploited
                        )

                print(
                    "Security Status:    VULNERABLE"
                )

                print(
                    "Security Priority:  \(sla.priority.rawValue)"
                )

                print(
                    "Security CVEs:      \(securityRelease.cves.count)"
                )

                print(
                    "Critical CVEs:      \(securityRelease.criticalCVEs.count)"
                )

                print(
                    "CISA KEV:           \(exploited.count)"
                )

                print("")

                print(
                    "Security SLA:       \(sla.days) day(s)"
                )

                print(
                    "Reason:             \(sla.reason)"
                )

                print("")

                print(
                    "Remediation:        REQUIRED"
                )

            } else {

                print(
                    "Security Status:    SECURE"
                )

                if normalUpdateAvailable {

                    print(
                        "Update Status:      UPDATE AVAILABLE"
                    )

                    print(
                        "Remediation:        OPTIONAL"
                    )

                } else {

                    print(
                        "Update Status:      CURRENT"
                    )

                    print(
                        "Remediation:        NONE"
                    )
                }
            }

        } catch {

            print("")
            print(
                "ERROR: Security check failed."
            )

            print(error)
        }
    }
}
