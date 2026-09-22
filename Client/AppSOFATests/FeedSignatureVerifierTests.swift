import XCTest
import CryptoKit
@testable import AppSOFACore

final class FeedSignatureVerifierTests: XCTestCase {
    func testRejectsTamperedFeed() throws {
        let privateKey = Curve25519.Signing.PrivateKey()
        let original = Data(#"{"FeedVersion":"1.0"}"#.utf8)
        let tampered = Data(#"{"FeedVersion":"9.9"}"#.utf8)
        let signature = try privateKey.signature(for: original)
        let signatureText = Data(signature.base64EncodedString().utf8)

        let publicKey = privateKey.publicKey

        XCTAssertFalse(publicKey.isValidSignature(signature, for: tampered))
        XCTAssertTrue(publicKey.isValidSignature(signature, for: original))
        XCTAssertFalse(signatureText.isEmpty)
    }

    func testEmbeddedPublicKeyIsValidEd25519Key() throws {
        let raw = try XCTUnwrap(
            Data(base64Encoded: FeedSignatureVerifier.publicKeyBase64)
        )
        XCTAssertEqual(raw.count, 32)
        XCTAssertNoThrow(
            try Curve25519.Signing.PublicKey(rawRepresentation: raw)
        )
    }

    func testRejectsInvalidSignatureEncoding() {
        XCTAssertThrowsError(
            try FeedSignatureVerifier.verify(
                feedData: Data("feed".utf8),
                signatureData: Data("not-base64!".utf8)
            )
        )
    }
}
