import Foundation
import CryptoKit

enum FeedSignatureError: Error {
    case invalidPublicKey
    case invalidSignatureEncoding
    case signatureVerificationFailed
}

enum FeedSignatureVerifier {
    static let publicKeyBase64 = "4rgT9RjcrKVCXMy9ayBI2D9djWjkS8DdkMQUqxqlNf8="

    static func verify(feedData: Data, signatureData: Data) throws {
        guard let publicKeyData = Data(base64Encoded: publicKeyBase64) else {
            throw FeedSignatureError.invalidPublicKey
        }

        let signatureText = String(decoding: signatureData, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard let signature = Data(base64Encoded: signatureText) else {
            throw FeedSignatureError.invalidSignatureEncoding
        }

        let publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKeyData)

        guard publicKey.isValidSignature(signature, for: feedData) else {
            throw FeedSignatureError.signatureVerificationFailed
        }
    }
}
