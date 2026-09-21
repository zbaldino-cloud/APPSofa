//
//  CISAKEVService.swift
//  MyTool
//
//  Created by Zach Baldino on 9/21/26.
//

import Foundation

struct CISAKEVCatalog: Codable {
    let title: String?
    let catalogVersion: String?
    let dateReleased: String?
    let count: Int?
    let vulnerabilities: [CISAKEVVulnerability]
}

struct CISAKEVVulnerability: Codable, Identifiable {

    let cveID: String
    let vendorProject: String?
    let product: String?
    let vulnerabilityName: String?
    let dateAdded: String?
    let shortDescription: String?
    let requiredAction: String?
    let dueDate: String?
    let knownRansomwareCampaignUse: String?
    let notes: String?

    var id: String {
        cveID
    }
}

enum CISAKEVService {

    static let feedURL =
        URL(
            string:
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )!

    static func fetchCatalog() async throws -> CISAKEVCatalog {

        let (data, response) =
            try await URLSession.shared.data(
                from: feedURL
            )

        guard
            let httpResponse =
                response as? HTTPURLResponse,
            (200...299).contains(
                httpResponse.statusCode
            )
        else {
            throw CISAKEVError.invalidResponse
        }

        return try JSONDecoder().decode(
            CISAKEVCatalog.self,
            from: data
        )
    }

    static func find(
        cveID: String,
        in catalog: CISAKEVCatalog
    ) -> CISAKEVVulnerability? {

        catalog.vulnerabilities.first {

            $0.cveID.caseInsensitiveCompare(
                cveID
            ) == .orderedSame
        }
    }

    static func exploitedCVEs(
        from cves: [ChromeCVE],
        catalog: CISAKEVCatalog
    ) -> [ChromeCVE] {

        cves.filter { cve in

            find(
                cveID: cve.cveID,
                in: catalog
            ) != nil
        }
    }
}

enum CISAKEVError: Error {
    case invalidResponse
}
